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

	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
	"github.com/fatih/color"
	"github.com/google/uuid"
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
}

// NewServer creates a new wallet HTTP server.
// onSave is called after credential-changing operations (import, delete, issuance).
func NewServer(w *Wallet, port int, onSave func()) *Server {
	s := &Server{wallet: w, port: port, onSave: onSave}
	s.mux = http.NewServeMux()
	s.setupRoutes()
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
	go s.httpSrv.Serve(ln)
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
		authReq, err = parseAuthParams(r.URL.Query())
	} else {
		if parseErr := r.ParseForm(); parseErr != nil {
			http.Error(w, "invalid form data", http.StatusBadRequest)
			return
		}
		authReq, err = parseAuthParams(r.Form)
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
	uriDisplay := body.URI
	if len(uriDisplay) > 120 {
		uriDisplay = uriDisplay[:120] + "..."
	}
	s.log("  URI: %s", uriDisplay)

	parsed, err := ParseAuthorizationRequest(body.URI)
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

	if warning := VerifyClientID(parsed.ClientID, parsed.RequestObject); warning != "" {
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
		URI string `json:"uri"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	s.log("Received credential offer")
	uriDisplay := body.URI
	if len(uriDisplay) > 120 {
		uriDisplay = uriDisplay[:120] + "..."
	}
	s.log("  URI: %s", uriDisplay)

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

	if err := s.wallet.ImportCredential(raw); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	s.triggerSave()
	creds := s.wallet.GetCredentials()
	last := creds[len(creds)-1]
	writeJSON(w, http.StatusCreated, CredentialSummary(last))
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
	req, ok := s.wallet.GetRequest(id)
	if !ok {
		http.Error(w, "request not found", http.StatusNotFound)
		return
	}
	if req.Status != "pending" {
		http.Error(w, "request already resolved", http.StatusConflict)
		return
	}

	var body struct {
		SelectedClaims map[string][]string `json:"selected_claims"`
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&body)
	}

	req.Status = "approved"
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
	req, ok := s.wallet.GetRequest(id)
	if !ok {
		http.Error(w, "request not found", http.StatusNotFound)
		return
	}
	if req.Status != "pending" {
		http.Error(w, "request already resolved", http.StatusConflict)
		return
	}

	req.Status = "denied"
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
	jwt, err := GenerateTrustListJWT(s.wallet.IssuerKey)
	if err != nil {
		http.Error(w, fmt.Sprintf("generating trust list: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwt")
	w.Write([]byte(jwt))
}

// handleAuthFlow is the core OID4VP flow handler.
func (s *Server) handleAuthFlow(w http.ResponseWriter, authReq *AuthorizationRequestParams) {
	// Check client_id against x5c SAN
	if warning := VerifyClientID(authReq.ClientID, authReq.RequestObject); warning != "" {
		s.log("  WARNING: %s", warning)
		s.wallet.AddLog("presentation", fmt.Sprintf("client_id warning: %s", warning), false)
	}

	// Log DCQL query
	if authReq.DCQLQuery != nil {
		if dcqlJSON, err := json.Marshal(authReq.DCQLQuery); err == nil {
			s.log("  DCQL Query:    %s", string(dcqlJSON))
		}
	}

	// Evaluate DCQL query
	var matches []CredentialMatch
	if authReq.DCQLQuery != nil {
		matches = s.wallet.EvaluateDCQL(authReq.DCQLQuery)
	}

	s.log("  Matched:       %d credential(s)", len(matches))
	for _, m := range matches {
		s.log("    - %s %s (%s), disclosing %d claims", m.Format, credTypeLabel(m), m.CredentialID[:8], len(m.SelectedKeys))
	}

	if len(matches) == 0 {
		s.log("  Result:        no matching credentials")
		s.wallet.AddLog("presentation", fmt.Sprintf("No matching credentials for %s", authReq.ClientID), false)
		s.wallet.NotifyError(WalletError{
			Message: "No matching credentials",
			Detail:  fmt.Sprintf("Verifier %s requested credentials but none matched the query", authReq.ClientID),
		})
		if s.onConsentRequest != nil {
			s.onConsentRequest(nil)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "no_match",
			"error":  "no matching credentials found",
		})
		return
	}

	// Auto-accept mode: skip consent
	if s.wallet.AutoAccept {
		s.log("  Mode:          auto-accept")
		s.autoAcceptPresentation(w, authReq, matches)
		return
	}

	// Interactive mode: create consent request and wait
	s.log("  Mode:          interactive — waiting for consent...")
	consentReq := &ConsentRequest{
		ID:           uuid.New().String(),
		Type:         "presentation",
		MatchedCreds: matches,
		Status:       "pending",
		ResultCh:     make(chan ConsentResult, 1),
		SubmissionCh: make(chan SubmissionResult, 1),
		CreatedAt:    time.Now(),
		ClientID:     authReq.ClientID,
		Nonce:        authReq.Nonce,
		ResponseURI:  authReq.ResponseURI,
		DCQLQuery:    authReq.DCQLQuery,
	}

	s.wallet.CreateConsentRequest(consentReq)

	if s.onConsentRequest != nil {
		s.onConsentRequest(consentReq)
	}

	// Wait for user consent (with timeout)
	select {
	case result := <-consentReq.ResultCh:
		if !result.Approved {
			s.log("  Consent:       denied")
			s.wallet.AddLog("presentation", fmt.Sprintf("Denied presentation to %s", authReq.ClientID), false)
			consentReq.SubmissionCh <- SubmissionResult{Error: "denied"}
			writeJSON(w, http.StatusOK, map[string]string{"status": "denied"})
			return
		}

		s.log("  Consent:       approved")

		// Apply user's claim selections if provided
		if result.SelectedClaims != nil {
			for i, m := range matches {
				if selectedKeys, ok := result.SelectedClaims[m.CredentialID]; ok {
					matches[i].SelectedKeys = selectedKeys
					cred, _ := s.wallet.GetCredential(m.CredentialID)
					matches[i].Claims = filterClaims(cred.Claims, selectedKeys)
					s.log("    - %s: disclosing %v", m.CredentialID[:8], selectedKeys)
				}
			}
		}

		s.submitPresentationWithNotify(w, authReq, matches, consentReq.SubmissionCh)

	case <-time.After(5 * time.Minute):
		consentReq.Status = "denied"
		s.wallet.AddLog("presentation", "Consent timeout", false)
		consentReq.SubmissionCh <- SubmissionResult{Error: "consent timeout"}
		writeJSON(w, http.StatusRequestTimeout, map[string]string{"error": "consent timeout"})
	}
}

// autoAcceptPresentation handles auto-accept mode.
func (s *Server) autoAcceptPresentation(w http.ResponseWriter, authReq *AuthorizationRequestParams, matches []CredentialMatch) {
	dim := color.New(color.Faint)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	dim.Println("───────────────────────────────────────")
	yellow.Printf("  Verifier: %s\n", authReq.ClientID)
	for _, m := range matches {
		fmt.Printf("  Credential: %s (%s)\n", m.Format, credTypeLabel(m))
		fmt.Printf("  Disclosing: %v\n", m.SelectedKeys)
	}

	s.submitPresentation(w, authReq, matches)
	green.Printf("  Auto-accepted\n")
	dim.Println("───────────────────────────────────────")
}

// submitPresentationWithNotify creates VP tokens, submits them, and notifies via the submission channel.
func (s *Server) submitPresentationWithNotify(w http.ResponseWriter, authReq *AuthorizationRequestParams, matches []CredentialMatch, submissionCh chan SubmissionResult) {
	result := s.submitPresentation(w, authReq, matches)
	if submissionCh != nil {
		submissionCh <- result
	}
}

// submitPresentation creates VP tokens and submits them to the verifier.
func (s *Server) submitPresentation(w http.ResponseWriter, authReq *AuthorizationRequestParams, matches []CredentialMatch) SubmissionResult {
	responseURI := authReq.ResponseURI
	if responseURI == "" {
		responseURI = authReq.RedirectURI
	}

	s.log("  Submitting VP token to %s", responseURI)

	// Create VP tokens
	params := PresentationParams{
		Nonce:         authReq.Nonce,
		ClientID:      authReq.ClientID,
		ResponseURI:   responseURI,
		ResponseMode:  authReq.ResponseMode,
		RequestObject: authReq.RequestObject,
	}
	vpResult, err := s.wallet.CreateVPTokenMap(matches, params)
	if err != nil {
		s.log("  ERROR: VP token creation failed: %v", err)
		s.wallet.AddLog("presentation", fmt.Sprintf("VP token creation failed: %v", err), false)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return SubmissionResult{Error: err.Error()}
	}

	s.log("  VP tokens:     %d created", len(vpResult.TokenMap))

	// Determine what to submit as vp_token
	var vpToken any
	if len(vpResult.TokenMap) == 1 {
		for _, v := range vpResult.TokenMap {
			vpToken = v
		}
	} else {
		vpToken = vpResult.TokenMap
	}

	// Submit to verifier — encrypt if direct_post.jwt with encryption key
	var result *DirectPostResult
	if authReq.ResponseMode == "direct_post.jwt" && HasEncryptionKey(authReq.RequestObject) {
		s.log("  Encrypting response (JARM)")
		jwe, encErr := s.wallet.EncryptResponse(vpToken, authReq.State, vpResult.MDocNonce, params)
		if encErr != nil {
			s.log("  ERROR: JWE encryption failed: %v", encErr)
			s.wallet.AddLog("presentation", fmt.Sprintf("JWE encryption failed: %v", encErr), false)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": encErr.Error()})
			return SubmissionResult{Error: encErr.Error()}
		}
		result, err = SubmitDirectPostJWT(responseURI, authReq.State, vpToken, jwe)
	} else {
		result, err = SubmitDirectPost(responseURI, authReq.State, vpToken)
	}
	if err != nil {
		s.log("  ERROR: Submission failed: %v", err)
		s.wallet.AddLog("presentation", fmt.Sprintf("Submission failed: %v", err), false)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return SubmissionResult{Error: err.Error()}
	}

	s.log("  Response:      HTTP %d", result.StatusCode)
	if result.RedirectURI != "" {
		s.log("  Redirect:      %s", result.RedirectURI)
	}
	if result.StatusCode >= 400 {
		s.log("  ERROR:         %s", result.Body)
	}

	s.wallet.AddLog("presentation", fmt.Sprintf("Presented to %s: %s", authReq.ClientID, FormatDirectPostResult(result)), true)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "submitted",
		"response":      result,
		"vp_token_keys": mapKeys(vpResult.TokenMap),
	})

	return SubmissionResult{
		RedirectURI: result.RedirectURI,
		StatusCode:  result.StatusCode,
		Error: func() string {
			if result.StatusCode >= 400 {
				return result.Body
			}
			return ""
		}(),
	}
}

// AuthorizationRequestParams holds the extracted fields from an authorization request.
type AuthorizationRequestParams struct {
	ClientID      string
	ResponseType  string
	ResponseMode  string
	Nonce         string
	State         string
	RedirectURI   string
	ResponseURI   string
	DCQLQuery     map[string]any
	RequestObject *oid4vc.RequestObjectJWT
}

// parseAuthParams extracts authorization request params from URL values.
func parseAuthParams(values map[string][]string) (*AuthorizationRequestParams, error) {
	get := func(key string) string {
		if vs, ok := values[key]; ok && len(vs) > 0 {
			return vs[0]
		}
		return ""
	}

	params := &AuthorizationRequestParams{
		ClientID:     get("client_id"),
		ResponseType: get("response_type"),
		ResponseMode: get("response_mode"),
		Nonce:        get("nonce"),
		State:        get("state"),
		RedirectURI:  get("redirect_uri"),
		ResponseURI:  get("response_uri"),
	}

	// Parse dcql_query if present
	if dq := get("dcql_query"); dq != "" {
		var query map[string]any
		if err := json.Unmarshal([]byte(dq), &query); err != nil {
			return nil, fmt.Errorf("parsing dcql_query: %w", err)
		}
		params.DCQLQuery = query
	}

	// If request_uri is present, fetch and parse it
	if requestURI := get("request_uri"); requestURI != "" {
		parsed, err := ParseAuthorizationRequest(requestURI)
		if err == nil {
			if params.ClientID == "" {
				params.ClientID = parsed.ClientID
			}
			if params.Nonce == "" {
				params.Nonce = parsed.Nonce
			}
			if params.State == "" {
				params.State = parsed.State
			}
			if params.ResponseURI == "" {
				params.ResponseURI = parsed.ResponseURI
			}
			if params.RedirectURI == "" {
				params.RedirectURI = parsed.RedirectURI
			}
			if params.ResponseMode == "" {
				params.ResponseMode = parsed.ResponseMode
			}
			if params.DCQLQuery == nil {
				params.DCQLQuery = parsed.DCQLQuery
			}
			if params.RequestObject == nil {
				params.RequestObject = parsed.RequestObject
			}
		}
	}

	// If request (JWT) is present, parse it
	if requestJWT := get("request"); requestJWT != "" {
		parsed, err := ParseAuthorizationRequest(requestJWT)
		if err == nil {
			if params.ClientID == "" {
				params.ClientID = parsed.ClientID
			}
			if params.Nonce == "" {
				params.Nonce = parsed.Nonce
			}
			if params.State == "" {
				params.State = parsed.State
			}
			if params.ResponseURI == "" {
				params.ResponseURI = parsed.ResponseURI
			}
			if params.RedirectURI == "" {
				params.RedirectURI = parsed.RedirectURI
			}
			if params.ResponseMode == "" {
				params.ResponseMode = parsed.ResponseMode
			}
			if params.DCQLQuery == nil {
				params.DCQLQuery = parsed.DCQLQuery
			}
			if params.RequestObject == nil {
				params.RequestObject = parsed.RequestObject
			}
		}
	}

	if params.ClientID == "" {
		return nil, fmt.Errorf("missing client_id")
	}

	return params, nil
}

func credTypeLabel(m CredentialMatch) string {
	if m.VCT != "" {
		return m.VCT
	}
	if m.DocType != "" {
		return m.DocType
	}
	return m.Format
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
