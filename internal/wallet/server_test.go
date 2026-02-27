package wallet

import (
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
	"github.com/dominikschlosser/oid4vc-dev/internal/trustlist"
)

func newTestServer(t *testing.T, autoAccept bool) *Server {
	t.Helper()
	w := generateTestWallet(t)
	w.AutoAccept = autoAccept
	if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
		t.Fatalf("generating credentials: %v", err)
	}
	return NewServer(w, 0, nil)
}

func serverRequest(t *testing.T, srv *Server, method, path string, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	return w
}

func decodeJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v\nbody: %s", err, w.Body.String())
	}
	return result
}

func decodeJSONArray(t *testing.T, w *httptest.ResponseRecorder) []any {
	t.Helper()
	var result []any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON array: %v\nbody: %s", err, w.Body.String())
	}
	return result
}

// --- Credential Management API Tests ---

func TestListCredentials(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "GET", "/api/credentials", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	creds := decodeJSONArray(t, w)
	if len(creds) != 2 {
		t.Errorf("expected 2 credentials, got %d", len(creds))
	}
}

func TestImportCredentialAPI(t *testing.T) {
	srv := newTestServer(t, false)

	// Import an SD-JWT credential via API
	sdjwt := generateSDJWTForTest(t, srv)

	req := httptest.NewRequest("POST", "/api/credentials", strings.NewReader(sdjwt))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeJSON(t, w)
	if result["format"] != "dc+sd-jwt" {
		t.Errorf("expected format dc+sd-jwt, got %v", result["format"])
	}
	if result["id"] == nil {
		t.Error("expected id in response")
	}
}

func TestImportCredentialAPI_Empty(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "POST", "/api/credentials", "")

	// Request with empty body
	req := httptest.NewRequest("POST", "/api/credentials", strings.NewReader(""))
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty body, got %d: %s", rec.Code, rec.Body.String())
	}
	_ = w
}

func TestImportCredentialAPI_Invalid(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("POST", "/api/credentials", strings.NewReader("not-a-credential"))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid credential, got %d", w.Code)
	}
}

func TestDeleteCredentialAPI(t *testing.T) {
	srv := newTestServer(t, false)

	// Get credentials first
	w := serverRequest(t, srv, "GET", "/api/credentials", "")
	creds := decodeJSONArray(t, w)
	id := creds[0].(map[string]any)["id"].(string)

	// Delete it
	req := httptest.NewRequest("DELETE", "/api/credentials/"+id, nil)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}

	// Verify it's gone
	w2 := serverRequest(t, srv, "GET", "/api/credentials", "")
	creds2 := decodeJSONArray(t, w2)
	if len(creds2) != 1 {
		t.Errorf("expected 1 credential after deletion, got %d", len(creds2))
	}
}

func TestDeleteCredentialAPI_NotFound(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("DELETE", "/api/credentials/nonexistent", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// --- Consent Request API Tests ---

func TestListPendingRequests_Empty(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "GET", "/api/requests", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	requests := decodeJSONArray(t, w)
	if len(requests) != 0 {
		t.Errorf("expected 0 pending requests, got %d", len(requests))
	}
}

func TestApproveRequest_NotFound(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("POST", "/api/requests/nonexistent/approve", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestDenyRequest_NotFound(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("POST", "/api/requests/nonexistent/deny", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// --- Activity Log API Tests ---

func TestLogAPI_Empty(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "GET", "/api/log", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// --- Static Files Tests ---

func TestStaticFiles_Index(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "GET", "/", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "OID4VC Dev Wallet") {
		t.Error("expected index.html to contain 'OID4VC Dev Wallet'")
	}
	if !strings.Contains(body, "app.js") {
		t.Error("expected index.html to reference app.js")
	}
}

func TestStaticFiles_CSS(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "GET", "/style.css", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "--bg") {
		t.Error("expected CSS to contain --bg custom property")
	}
}

func TestStaticFiles_JS(t *testing.T) {
	srv := newTestServer(t, false)
	w := serverRequest(t, srv, "GET", "/app.js", "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "/api/credentials") {
		t.Error("expected app.js to reference /api/credentials")
	}
}

// --- Presentation API Tests ---

func TestPresentationAPI_InvalidJSON(t *testing.T) {
	srv := newTestServer(t, true)

	req := httptest.NewRequest("POST", "/api/presentations", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestPresentationAPI_InvalidURI(t *testing.T) {
	srv := newTestServer(t, true)
	w := serverRequest(t, srv, "POST", "/api/presentations", `{"uri":"not-a-valid-uri"}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// --- Full Presentation E2E Test (auto-accept) ---

func TestPresentationFlow_AutoAccept(t *testing.T) {
	srv := newTestServer(t, true)

	// Create a mock verifier that receives the VP token
	var receivedBody string
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"redirect_uri": "https://verifier.example/done"}`))
	}))
	defer verifier.Close()

	// Build a DCQL authorization request
	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
					map[string]any{"path": []any{"family_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	// Send request to /authorize
	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"nonce":         {"test-nonce-123"},
		"state":         {"test-state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeJSON(t, w)
	if result["status"] != "submitted" {
		t.Errorf("expected status 'submitted', got %v", result["status"])
	}

	// Verify the verifier received the VP token
	if receivedBody == "" {
		t.Fatal("verifier did not receive VP token")
	}

	parsedForm, err := url.ParseQuery(receivedBody)
	if err != nil {
		t.Fatalf("parsing verifier body: %v", err)
	}

	vpToken := parsedForm.Get("vp_token")
	if vpToken == "" {
		t.Fatal("expected vp_token in verifier request")
	}

	state := parsedForm.Get("state")
	if state != "test-state" {
		t.Errorf("expected state 'test-state', got %s", state)
	}

	// Response should contain redirect_uri from verifier
	response, ok := result["response"].(map[string]any)
	if !ok {
		t.Fatal("expected response object in result")
	}
	if response["redirect_uri"] != "https://verifier.example/done" {
		t.Errorf("expected redirect_uri, got %v", response["redirect_uri"])
	}
}

func TestPresentationFlow_AutoAccept_NoMatch(t *testing.T) {
	srv := newTestServer(t, true)

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "mdl",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{"urn:eudi:mdl:1"},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"n"},
		"state":         {"s"},
		"response_uri":  {"https://verifier.example/response"},
		"dcql_query":    {string(dcqlJSON)},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeJSON(t, w)
	if result["status"] != "no_match" {
		t.Errorf("expected status 'no_match', got %v", result["status"])
	}
}

func TestPresentationFlow_AutoAccept_MultipleCredentials(t *testing.T) {
	srv := newTestServer(t, true)

	// Create verifier
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	// Request both SD-JWT and mDoc credentials
	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid_sdjwt",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
			map[string]any{
				"id":     "pid_mdoc",
				"format": "mso_mdoc",
				"meta": map[string]any{
					"doctype_value": "eu.europa.ec.eudi.pid.1",
				},
				"claims": []any{
					map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeJSON(t, w)
	if result["status"] != "submitted" {
		t.Errorf("expected status 'submitted', got %v", result["status"])
	}

	// Should have submitted tokens for both credentials
	vpTokenKeys, ok := result["vp_token_keys"].([]any)
	if !ok {
		t.Fatal("expected vp_token_keys in result")
	}
	if len(vpTokenKeys) != 2 {
		t.Errorf("expected 2 vp_token_keys, got %d", len(vpTokenKeys))
	}
}

func TestPresentationFlow_AutoAccept_POST(t *testing.T) {
	srv := newTestServer(t, true)

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	form := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeJSON(t, w)
	if result["status"] != "submitted" {
		t.Errorf("expected status 'submitted', got %v", result["status"])
	}
}

func TestAuthorize_MissingClientID(t *testing.T) {
	srv := newTestServer(t, true)

	req := httptest.NewRequest("GET", "/authorize?response_type=vp_token", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing client_id, got %d", w.Code)
	}
}

// --- Consent Flow (Interactive) ---

func TestConsentFlow_ApproveAndDeny(t *testing.T) {
	srv := newTestServer(t, false) // interactive mode

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	// Start the authorize flow in a goroutine (it blocks waiting for consent)
	resultCh := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, req)
		resultCh <- w
	}()

	// Wait for the consent request to appear
	var reqID string
	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		pending := srv.wallet.GetPendingRequests()
		if len(pending) > 0 {
			reqID = pending[0].ID
			break
		}
	}

	if reqID == "" {
		t.Fatal("no pending consent request found")
	}

	// Approve via API
	approveReq := httptest.NewRequest("POST", "/api/requests/"+reqID+"/approve",
		strings.NewReader(`{"selected_claims":{}}`))
	approveReq.Header.Set("Content-Type", "application/json")
	approveRec := httptest.NewRecorder()
	srv.mux.ServeHTTP(approveRec, approveReq)

	if approveRec.Code != http.StatusOK {
		t.Fatalf("approve failed: %d %s", approveRec.Code, approveRec.Body.String())
	}

	// The authorize should now complete
	w := <-resultCh
	if w.Code != http.StatusOK {
		t.Fatalf("authorize expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeJSON(t, w)
	if result["status"] != "submitted" {
		t.Errorf("expected status 'submitted', got %v", result["status"])
	}
}

func TestConsentFlow_Deny(t *testing.T) {
	srv := newTestServer(t, false)

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {"https://verifier.example/response"},
		"dcql_query":    {string(dcqlJSON)},
	}

	resultCh := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, req)
		resultCh <- w
	}()

	// Wait for consent request
	var reqID string
	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		pending := srv.wallet.GetPendingRequests()
		if len(pending) > 0 {
			reqID = pending[0].ID
			break
		}
	}

	if reqID == "" {
		t.Fatal("no pending consent request found")
	}

	// Deny
	denyReq := httptest.NewRequest("POST", "/api/requests/"+reqID+"/deny", nil)
	denyRec := httptest.NewRecorder()
	srv.mux.ServeHTTP(denyRec, denyReq)

	if denyRec.Code != http.StatusOK {
		t.Fatalf("deny failed: %d", denyRec.Code)
	}

	w := <-resultCh
	result := decodeJSON(t, w)
	if result["status"] != "denied" {
		t.Errorf("expected status 'denied', got %v", result["status"])
	}
}

// --- Trust List API Tests ---

func TestTrustListAPI(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("GET", "/api/trustlist", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/jwt" {
		t.Errorf("expected Content-Type application/jwt, got %s", ct)
	}

	// Should be a valid 3-part JWT
	jwt := w.Body.String()
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	// Payload should be parseable and contain trust list fields
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parsing payload: %v", err)
	}

	if _, ok := payload["TrustedEntitiesList"]; !ok {
		t.Error("expected TrustedEntitiesList in payload")
	}
	if _, ok := payload["ListAndSchemeInformation"]; !ok {
		t.Error("expected ListAndSchemeInformation in payload")
	}
}

func TestTrustListAPI_ParseableByTrustlistParser(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("GET", "/api/trustlist", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	tl, err := trustlist.Parse(w.Body.String())
	if err != nil {
		t.Fatalf("trust list parser failed: %v", err)
	}

	if tl.SchemeInfo == nil {
		t.Fatal("expected SchemeInfo to be parsed")
	}
	if tl.SchemeInfo.SchemeOperatorName != "OID4VC Dev Wallet" {
		t.Errorf("expected operator name 'OID4VC Dev Wallet', got %q", tl.SchemeInfo.SchemeOperatorName)
	}
	if tl.SchemeInfo.LoTEType != "http://uri.etsi.org/19602/LoTEType/local" {
		t.Errorf("unexpected LoTEType: %s", tl.SchemeInfo.LoTEType)
	}

	if len(tl.Entities) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(tl.Entities))
	}
	if tl.Entities[0].Name != "Wallet Issuer" {
		t.Errorf("expected entity name 'Wallet Issuer', got %q", tl.Entities[0].Name)
	}
	if len(tl.Entities[0].Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(tl.Entities[0].Services))
	}
	svc := tl.Entities[0].Services[0]
	if svc.ServiceType != "http://uri.etsi.org/19602/SvcType/Issuance" {
		t.Errorf("unexpected service type: %s", svc.ServiceType)
	}
	if len(svc.Certificates) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(svc.Certificates))
	}

	// The certificate's public key should match the wallet's issuer key
	certPub, ok := svc.Certificates[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("expected ECDSA public key in certificate")
	}
	if !certPub.Equal(&srv.wallet.IssuerKey.PublicKey) {
		t.Error("certificate public key does not match wallet issuer key")
	}
}

// --- Offer API Tests ---

func TestOfferAPI_InvalidJSON(t *testing.T) {
	srv := newTestServer(t, false)

	req := httptest.NewRequest("POST", "/api/offers", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// --- OnConsentRequest Callback Tests ---

func TestOnConsentRequest_CalledOnInteractiveFlow(t *testing.T) {
	srv := newTestServer(t, false) // interactive mode

	var callbackCalled bool
	var callbackReqID string
	srv.SetOnConsentRequest(func(req *ConsentRequest) {
		callbackCalled = true
		callbackReqID = req.ID
	})

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	// Start authorize flow in goroutine (blocks waiting for consent)
	resultCh := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, req)
		resultCh <- w
	}()

	// Wait for consent request to appear
	var reqID string
	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		pending := srv.wallet.GetPendingRequests()
		if len(pending) > 0 {
			reqID = pending[0].ID
			break
		}
	}

	if reqID == "" {
		t.Fatal("no pending consent request found")
	}

	if !callbackCalled {
		t.Error("expected onConsentRequest callback to be called")
	}
	if callbackReqID != reqID {
		t.Errorf("callback received request ID %s, expected %s", callbackReqID, reqID)
	}

	// Approve to let the goroutine finish
	approveReq := httptest.NewRequest("POST", "/api/requests/"+reqID+"/approve",
		strings.NewReader(`{"selected_claims":{}}`))
	approveReq.Header.Set("Content-Type", "application/json")
	approveRec := httptest.NewRecorder()
	srv.mux.ServeHTTP(approveRec, approveReq)

	<-resultCh
}

func TestOnConsentRequest_NotCalledOnAutoAccept(t *testing.T) {
	srv := newTestServer(t, true) // auto-accept mode

	callbackCalled := false
	srv.SetOnConsentRequest(func(req *ConsentRequest) {
		callbackCalled = true
	})

	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlQuery := map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []any{mock.DefaultPIDVCT},
				},
				"claims": []any{
					map[string]any{"path": []any{"given_name"}},
				},
			},
		},
	}
	dcqlJSON, _ := json.Marshal(dcqlQuery)

	params := url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}

	req := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if callbackCalled {
		t.Error("onConsentRequest callback should not be called in auto-accept mode")
	}
}

// --- Helper ---

func generateSDJWTForTest(t *testing.T, srv *Server) string {
	t.Helper()
	result, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://test.example",
		VCT:       "TestCred",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"test": "value"},
		Key:       srv.wallet.IssuerKey,
	})
	if err != nil {
		t.Fatalf("generating test SD-JWT: %v", err)
	}
	return result
}
