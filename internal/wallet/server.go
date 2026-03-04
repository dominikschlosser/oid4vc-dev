// Copyright 2026 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wallet

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
	"github.com/dominikschlosser/oid4vc-dev/internal/statuslist"
)

// Server is the wallet HTTP server.
type Server struct {
	wallet           *Wallet
	port             int
	mux              *http.ServeMux
	onSave           func()
	onConsentRequest func(req *ConsentRequest)
	logFunc          func(format string, args ...any)
	httpSrv          *http.Server
	parseOpts        oid4vc.ParseOptions
}

// NewServer creates a new wallet HTTP server.
// onSave is called after credential-changing operations (import, delete, issuance).
func NewServer(w *Wallet, port int, onSave func()) *Server {
	s := &Server{wallet: w, port: port, onSave: onSave}
	s.mux = http.NewServeMux()
	s.setupRoutes()
	// Set up ParseOptions with wallet-aware request_uri fetcher.
	// The logFunc is captured lazily so it works even if SetLogger is called after NewServer.
	s.parseOpts = oid4vc.ParseOptions{
		FetchRequestURI: MakeFetchRequestURI(w, func(format string, args ...any) {
			s.log(format, args...)
		}),
	}
	return s
}

func (s *Server) setupRoutes() {
	// OID4VP Authorization Endpoint
	s.mux.HandleFunc("GET /authorize", s.handleAuthorize)
	s.mux.HandleFunc("POST /authorize", s.handleAuthorize)

	// API: feed authorization request URIs
	s.mux.HandleFunc("POST /api/presentations", s.handlePresentationAPI)

	// API: credential offers
	s.mux.HandleFunc("POST /api/offers", s.handleOfferAPI)

	// API: credential management
	s.mux.HandleFunc("GET /api/credentials", s.handleListCredentials)
	s.mux.HandleFunc("POST /api/credentials", s.handleImportCredential)
	s.mux.HandleFunc("DELETE /api/credentials/{id}", s.handleDeleteCredential)

	// API: consent requests
	s.mux.HandleFunc("GET /api/requests", s.handleListRequests)
	s.mux.HandleFunc("GET /api/requests/stream", s.handleRequestStream)
	s.mux.HandleFunc("POST /api/requests/{id}/approve", s.handleApproveRequest)
	s.mux.HandleFunc("POST /api/requests/{id}/deny", s.handleDenyRequest)

	// API: trust list
	s.mux.HandleFunc("GET /api/trustlist", s.handleTrustList)

	// API: status list
	s.mux.HandleFunc("GET /api/statuslist", s.handleStatusList)
	s.mux.HandleFunc("POST /api/credentials/{id}/status", s.handleSetCredentialStatus)

	// API: testing overrides
	s.mux.HandleFunc("POST /api/next-error", s.handleSetNextError)
	s.mux.HandleFunc("DELETE /api/next-error", s.handleClearNextError)
	s.mux.HandleFunc("PUT /api/config/preferred-format", s.handleSetPreferredFormat)

	// API: log
	s.mux.HandleFunc("GET /api/log", s.handleLog)

	// API: last error (polled on page load)
	s.mux.HandleFunc("GET /api/error", s.handleLastError)

	// Static files
	sub, _ := fs.Sub(staticFiles, "static")
	s.mux.Handle("/", http.FileServer(http.FS(sub)))
}

// ListenAndServe starts the wallet server.
func (s *Server) ListenAndServe() error {
	s.httpSrv = &http.Server{Addr: fmt.Sprintf(":%d", s.port), Handler: s.mux}
	return s.httpSrv.ListenAndServe()
}

// ListenAndServeBackground starts the server on a random port and returns the address.
func (s *Server) ListenAndServeBackground() (string, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return "", err
	}
	addr := fmt.Sprintf("http://localhost:%d", ln.Addr().(*net.TCPAddr).Port)
	s.httpSrv = &http.Server{Handler: s.mux}
	go func() { _ = s.httpSrv.Serve(ln) }()
	return addr, nil
}

// SetOnConsentRequest sets a callback invoked when a new consent request is created.
func (s *Server) SetOnConsentRequest(fn func(req *ConsentRequest)) {
	s.onConsentRequest = fn
}

// SetLogger sets a logging function for verbose terminal output.
func (s *Server) SetLogger(fn func(format string, args ...any)) {
	s.logFunc = fn
}

func (s *Server) log(format string, args ...any) {
	if s.logFunc != nil {
		s.logFunc(format, args...)
	}
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown() {
	if s.httpSrv != nil {
		s.httpSrv.Close()
	}
}

// handleAuthorize processes an OID4VP authorization request from query params or form data.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	var authReq *AuthorizationRequestParams
	var err error

	if r.Method == "GET" {
		authReq, err = parseAuthParams(r.URL.Query(), s.parseOpts)
	} else {
		if parseErr := r.ParseForm(); parseErr != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}
		authReq, err = parseAuthParams(r.Form, s.parseOpts)
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("invalid authorization request: %v", err), http.StatusBadRequest)
		return
	}

	s.handleAuthFlow(w, authReq)
}

// handlePresentationAPI processes a presentation request URI via API.
func (s *Server) handlePresentationAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URI string `json:"uri"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	s.log("Received authorization request")
	// Truncate URI for display
	uriDisplay := format.Truncate(body.URI, 120)
	s.log("  URI: %s", uriDisplay)

	parsed, err := ParseAuthorizationRequestWithOptions(body.URI, s.parseOpts)
	if err != nil {
		s.log("  ERROR: %v", err)
		s.wallet.AddLog("presentation", fmt.Sprintf("Failed to parse request: %v", err), false)
		s.wallet.NotifyError(WalletError{
			Message: "Failed to parse authorization request",
			Detail:  err.Error(),
		})
		if s.onConsentRequest != nil {
			s.onConsentRequest(nil)
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.log("  Client ID:     %s", parsed.ClientID)
	s.log("  Response Mode: %s", parsed.ResponseMode)
	s.log("  Response URI:  %s", parsed.ResponseURI)
	if parsed.Nonce != "" {
		s.log("  Nonce:         %s", parsed.Nonce)
	}
	if parsed.RequestURIMethod != "" {
		s.log("  Request URI Method: %s", parsed.RequestURIMethod)
	}

	parsedResponseURI := parsed.ResponseURI
	if parsedResponseURI == "" {
		parsedResponseURI = parsed.RedirectURI
	}
	if warning := VerifyClientID(parsed.ClientID, parsed.RequestObject, parsedResponseURI); warning != "" {
		s.log("  WARNING: %s", warning)
		s.wallet.AddLog("presentation", fmt.Sprintf("client_id warning: %s", warning), false)
	}

	authReq := &AuthorizationRequestParams{
		ClientID:      parsed.ClientID,
		ResponseType:  parsed.ResponseType,
		ResponseMode:  parsed.ResponseMode,
		Nonce:         parsed.Nonce,
		State:         parsed.State,
		RedirectURI:   parsed.RedirectURI,
		ResponseURI:   parsed.ResponseURI,
		DCQLQuery:     parsed.DCQLQuery,
		RequestObject: parsed.RequestObject,
	}

	s.handleAuthFlow(w, authReq)
}

// handleOfferAPI processes a credential offer URI.
func (s *Server) handleOfferAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URI    string `json:"uri"`
		TxCode string `json:"tx_code,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	s.log("Received credential offer")
	uriDisplay := format.Truncate(body.URI, 120)
	s.log("  URI: %s", uriDisplay)

	if body.TxCode != "" {
		s.wallet.mu.Lock()
		s.wallet.TxCode = body.TxCode
		s.wallet.mu.Unlock()
	}

	result, err := s.wallet.ProcessCredentialOffer(body.URI)
	if err != nil {
		s.log("  ERROR: %v", err)
		s.wallet.AddLog("issuance", fmt.Sprintf("Failed: %v", err), false)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.log("  Received:      %s credential from %s", result.Format, result.Issuer)
	s.wallet.AddLog("issuance", fmt.Sprintf("Received %s credential from %s", result.Format, result.Issuer), true)
	s.triggerSave()
	writeJSON(w, http.StatusOK, result)
}

// handleListCredentials returns all stored credentials.
func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	data, err := s.wallet.CredentialsJSON()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// handleImportCredential imports a credential from the request body.
func (s *Server) handleImportCredential(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "reading body", http.StatusBadRequest)
		return
	}

	raw := strings.TrimSpace(string(body))
	if raw == "" {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	imported, err := s.wallet.ImportCredential(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.triggerSave()
	writeJSON(w, http.StatusCreated, CredentialSummary(*imported))
}

// handleDeleteCredential removes a credential by ID.
func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.wallet.RemoveCredential(id) {
		http.Error(w, "credential not found", http.StatusNotFound)
		return
	}
	s.triggerSave()
	w.WriteHeader(http.StatusNoContent)
}

// handleListRequests returns all pending consent requests.
func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request) {
	requests := s.wallet.GetPendingRequests()
	items := make([]map[string]any, len(requests))
	for i, req := range requests {
		items[i] = MarshalConsentRequest(req)
	}
	writeJSON(w, http.StatusOK, items)
}

// handleRequestStream provides SSE for new consent requests and error events.
func (s *Server) handleRequestStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	flusher.Flush()

	reqCh, reqUnsub := s.wallet.Subscribe()
	defer reqUnsub()
	errCh, errUnsub := s.wallet.SubscribeErrors()
	defer errUnsub()

	for {
		select {
		case req := <-reqCh:
			data, err := json.Marshal(MarshalConsentRequest(req))
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: consent\ndata: %s\n\n", data)
			flusher.Flush()
		case walletErr := <-errCh:
			data, err := json.Marshal(walletErr)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// handleApproveRequest approves a consent request and waits for the submission result.
func (s *Server) handleApproveRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, ok := s.wallet.ResolveRequest(id, "approved")
	if !ok {
		if req == nil {
			http.Error(w, "request not found", http.StatusNotFound)
		} else {
			http.Error(w, "request already resolved", http.StatusConflict)
		}
		return
	}

	var body struct {
		SelectedClaims map[string][]string `json:"selected_claims"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}

	req.ResultCh <- ConsentResult{
		Approved:       true,
		SelectedClaims: body.SelectedClaims,
	}

	// Wait for the VP submission to complete so we can return the result to the UI
	select {
	case submission := <-req.SubmissionCh:
		writeJSON(w, http.StatusOK, map[string]any{
			"status":       "approved",
			"redirect_uri": submission.RedirectURI,
			"error":        submission.Error,
			"status_code":  submission.StatusCode,
		})
	case <-time.After(30 * time.Second):
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "approved",
			"error":  "submission timeout",
		})
	}
}

// handleDenyRequest denies a consent request.
func (s *Server) handleDenyRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	req, ok := s.wallet.ResolveRequest(id, "denied")
	if !ok {
		if req == nil {
			http.Error(w, "request not found", http.StatusNotFound)
		} else {
			http.Error(w, "request already resolved", http.StatusConflict)
		}
		return
	}

	req.ResultCh <- ConsentResult{Approved: false}

	writeJSON(w, http.StatusOK, map[string]string{"status": "denied"})
}

// handleLog returns the activity log.
func (s *Server) handleLog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.wallet.GetLog())
}

// handleLastError returns and clears the last error, if any.
func (s *Server) handleLastError(w http.ResponseWriter, r *http.Request) {
	err := s.wallet.PopLastError()
	if err == nil {
		writeJSON(w, http.StatusOK, nil)
		return
	}
	writeJSON(w, http.StatusOK, err)
}

// handleTrustList generates and serves an ETSI trust list JWT from the wallet's issuer key.
func (s *Server) handleTrustList(w http.ResponseWriter, r *http.Request) {
	if len(s.wallet.CertChain) < 2 {
		http.Error(w, "wallet has no CA certificate chain", http.StatusInternalServerError)
		return
	}
	jwt, err := GenerateTrustListJWT(s.wallet.IssuerKey, s.wallet.CertChain[len(s.wallet.CertChain)-1])
	if err != nil {
		http.Error(w, fmt.Sprintf("generating trust list: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(jwt))
}

// handleStatusList generates and serves a status list JWT.
func (s *Server) handleStatusList(w http.ResponseWriter, r *http.Request) {
	bitstring := s.wallet.BuildStatusBitstring()
	jwt, err := statuslist.GenerateStatusListJWT(bitstring, s.wallet.IssuerKey, s.wallet.CertChain...)
	if err != nil {
		http.Error(w, fmt.Sprintf("generating status list: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/statuslist+jwt")
	w.Write([]byte(jwt))
}

// handleSetCredentialStatus sets the revocation status for a credential.
func (s *Server) handleSetCredentialStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var body struct {
		Status int `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	entry, ok := s.wallet.SetCredentialStatus(id, body.Status)
	if !ok {
		http.Error(w, "credential has no status entry", http.StatusNotFound)
		return
	}

	s.triggerSave()
	writeJSON(w, http.StatusOK, entry)
}

// handleSetNextError sets a one-shot error override.
func (s *Server) handleSetNextError(w http.ResponseWriter, r *http.Request) {
	var body NextErrorOverride
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	s.wallet.SetNextError(&body)
	writeJSON(w, http.StatusOK, body)
}

// handleClearNextError clears the error override without consuming.
func (s *Server) handleClearNextError(w http.ResponseWriter, r *http.Request) {
	s.wallet.SetNextError(nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleSetPreferredFormat sets the global credential format preference.
func (s *Server) handleSetPreferredFormat(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Format string `json:"format"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	s.wallet.mu.Lock()
	s.wallet.PreferredFormat = body.Format
	s.wallet.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"format": body.Format})
}

func mapKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

func (s *Server) triggerSave() {
	if s.onSave != nil {
		s.onSave()
	}
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(data)
}
