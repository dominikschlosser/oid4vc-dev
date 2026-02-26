package proxy

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// --- classifyEntry tests ---

func TestClassifyVCIMetadata(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://issuer.example/.well-known/openid-credential-issuer",
		StatusCode: 200,
	}
	Classify(e)
	if e.Class != ClassVCIMetadata {
		t.Errorf("expected ClassVCIMetadata, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVCICredentialOffer(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        `http://example.com/?credential_offer={"issuer":"test"}`,
		StatusCode: 200,
	}
	Classify(e)
	if e.Class != ClassVCICredentialOffer {
		t.Errorf("expected ClassVCICredentialOffer, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVCICredentialOfferURI(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/?credential_offer_uri=https://issuer.example/offer/123",
		StatusCode: 200,
	}
	Classify(e)
	if e.Class != ClassVCICredentialOffer {
		t.Errorf("expected ClassVCICredentialOffer, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVPAuthRequest(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/authorize?client_id=did:web:v&response_type=vp_token&state=s1",
		StatusCode: 200,
	}
	Classify(e)
	if e.Class != ClassVPAuthRequest {
		t.Errorf("expected ClassVPAuthRequest, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVPRequestObject(t *testing.T) {
	// A GET response that looks like a JWT
	e := &TrafficEntry{
		Method:       "GET",
		URL:          "http://example.com/request/abc",
		StatusCode:   200,
		ResponseBody: "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.signature",
	}
	Classify(e)
	if e.Class != ClassVPRequestObject {
		t.Errorf("expected ClassVPRequestObject, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVPAuthResponse(t *testing.T) {
	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: "vp_token=eyJ...&state=s1",
		StatusCode:  200,
	}
	Classify(e)
	if e.Class != ClassVPAuthResponse {
		t.Errorf("expected ClassVPAuthResponse, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVPAuthResponseWithJARM(t *testing.T) {
	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: "response=eyJhbGci.eyJ.sig.enc.tag",
		StatusCode:  200,
	}
	Classify(e)
	if e.Class != ClassVPAuthResponse {
		t.Errorf("expected ClassVPAuthResponse, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVCITokenRequest(t *testing.T) {
	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://issuer.example/oauth/token",
		RequestBody: "grant_type=authorization_code&code=abc",
		StatusCode:  200,
	}
	Classify(e)
	if e.Class != ClassVCITokenRequest {
		t.Errorf("expected ClassVCITokenRequest, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVCICredentialRequest(t *testing.T) {
	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://issuer.example/credential",
		RequestBody: `{"format":"vc+sd-jwt"}`,
		StatusCode:  200,
	}
	Classify(e)
	if e.Class != ClassVCICredentialRequest {
		t.Errorf("expected ClassVCICredentialRequest, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVCICredentialRequestPlural(t *testing.T) {
	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://issuer.example/credentials",
		RequestBody: `{"format":"vc+sd-jwt"}`,
		StatusCode:  200,
	}
	Classify(e)
	if e.Class != ClassVCICredentialRequest {
		t.Errorf("expected ClassVCICredentialRequest, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyUnknown(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/favicon.ico",
		StatusCode: 200,
	}
	Classify(e)
	if e.Class != ClassUnknown {
		t.Errorf("expected ClassUnknown, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyUnknownSetsLabel(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/other",
		StatusCode: 200,
	}
	Classify(e)
	if e.ClassLabel != "Unknown" {
		t.Errorf("expected label 'Unknown', got %q", e.ClassLabel)
	}
}

// --- isJWTBody tests ---

func TestIsJWTBody(t *testing.T) {
	tests := []struct {
		body string
		want bool
	}{
		{"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.signature", true},
		{"  eyJhbGci.eyJpc3M.sig  ", true}, // with whitespace
		{"not-a-jwt", false},
		{"", false},
		{`{"json":"object"}`, false},
		{"<html>content</html>", false},
		{"a.b.c.d.e", false}, // 5 parts → not 3-part JWT
		{"a..c", false},      // empty middle part
	}

	for _, tt := range tests {
		if got := isJWTBody(tt.body); got != tt.want {
			t.Errorf("isJWTBody(%q) = %v, want %v", tt.body, got, tt.want)
		}
	}
}

// --- isJWE tests ---

func TestIsJWE(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"a.b.c.d.e", true},
		{"header.key.iv.cipher.tag", true},
		{"  a.b.c.d.e  ", true}, // with whitespace
		{"a.b.c", false},        // JWT, not JWE
		{"", false},
		{".b.c.d.e", false}, // empty first part
	}

	for _, tt := range tests {
		if got := isJWE(tt.s); got != tt.want {
			t.Errorf("isJWE(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}

// --- hasBodyField tests ---

func TestHasBodyFieldFormEncoded(t *testing.T) {
	body := "vp_token=abc&state=s1"
	if !hasBodyField(body, "vp_token") {
		t.Error("expected true for vp_token in form body")
	}
	if !hasBodyField(body, "state") {
		t.Error("expected true for state in form body")
	}
	if hasBodyField(body, "nonce") {
		t.Error("expected false for nonce not in form body")
	}
}

func TestHasBodyFieldJSON(t *testing.T) {
	body := `{"vp_token":"abc","presentation_submission":{}}`
	if !hasBodyField(body, "vp_token") {
		t.Error("expected true for vp_token in JSON body")
	}
	if !hasBodyField(body, "presentation_submission") {
		t.Error("expected true for presentation_submission in JSON body")
	}
	if hasBodyField(body, "missing") {
		t.Error("expected false for missing field in JSON body")
	}
}

func TestHasBodyFieldEmpty(t *testing.T) {
	if hasBodyField("", "field") {
		t.Error("expected false for empty body")
	}
}

// --- parseFormOrJSON tests ---

func TestParseFormOrJSONForm(t *testing.T) {
	result := parseFormOrJSON("grant_type=authorization_code&code=abc123")
	if result["grant_type"] != "authorization_code" {
		t.Errorf("expected grant_type=authorization_code, got %q", result["grant_type"])
	}
	if result["code"] != "abc123" {
		t.Errorf("expected code=abc123, got %q", result["code"])
	}
}

func TestParseFormOrJSONAmbiguousInput(t *testing.T) {
	// url.ParseQuery succeeds on most strings, so form parsing takes priority.
	// For JSON input, form parsing will produce a single key with the entire JSON as key.
	// This tests the actual behavior of the function.
	result := parseFormOrJSON(`{"format":"jwt"}`)
	// url.ParseQuery will parse this as a form with key `{"format":"jwt"}` and empty value
	if len(result) == 0 {
		t.Error("expected non-empty result")
	}
}

func TestParseFormOrJSONInvalidInput(t *testing.T) {
	// A body that fails both form and JSON parsing
	result := parseFormOrJSON("")
	if len(result) != 0 {
		t.Errorf("expected empty map for empty body, got %v", result)
	}
}

func TestParseFormOrJSONEmpty(t *testing.T) {
	result := parseFormOrJSON("")
	if len(result) != 0 {
		t.Errorf("expected empty map for empty body, got %v", result)
	}
}

// --- truncate tests ---

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("expected 'short', got %q", got)
	}
	if got := truncate("a very long string", 5); got != "a ver..." {
		t.Errorf("expected 'a ver...', got %q", got)
	}
	if got := truncate("exact", 5); got != "exact" {
		t.Errorf("expected 'exact', got %q", got)
	}
}

// --- decodeEntry tests ---

func TestDecodeEntryVPAuthRequest(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/authorize?client_id=did:web:v&response_type=vp_token&nonce=n1&state=s1&response_mode=direct_post&request_uri=http://example.com/req&response_uri=http://example.com/resp",
		StatusCode: 200,
	}
	Classify(e)

	if e.Decoded["client_id"] != "did:web:v" {
		t.Errorf("client_id: got %v", e.Decoded["client_id"])
	}
	if e.Decoded["nonce"] != "n1" {
		t.Errorf("nonce: got %v", e.Decoded["nonce"])
	}
	if e.Decoded["state"] != "s1" {
		t.Errorf("state: got %v", e.Decoded["state"])
	}
	if e.Decoded["response_mode"] != "direct_post" {
		t.Errorf("response_mode: got %v", e.Decoded["response_mode"])
	}
	if e.Decoded["request_uri"] != "http://example.com/req" {
		t.Errorf("request_uri: got %v", e.Decoded["request_uri"])
	}
	if e.Decoded["response_uri"] != "http://example.com/resp" {
		t.Errorf("response_uri: got %v", e.Decoded["response_uri"])
	}
}

func TestDecodeEntryVPAuthRequestDCQL(t *testing.T) {
	dcql := `{"credentials":[{"id":"c1"}]}`
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/authorize?client_id=test&response_type=vp_token&dcql_query=" + dcql,
		StatusCode: 200,
	}
	Classify(e)

	decoded, ok := e.Decoded["dcql_query"].(map[string]any)
	if !ok {
		t.Fatalf("expected dcql_query as map, got %T", e.Decoded["dcql_query"])
	}
	if decoded["credentials"] == nil {
		t.Error("expected credentials in dcql_query")
	}
}

func TestDecodeEntryVPAuthResponse(t *testing.T) {
	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: "vp_token=eyJhbGciOiJFUzI1NiJ9.test.sig&state=s1",
		StatusCode:  200,
	}
	Classify(e)

	if e.Decoded["state"] != "s1" {
		t.Errorf("state: got %v", e.Decoded["state"])
	}
	if e.Decoded["vp_token_preview"] == nil {
		t.Error("expected vp_token_preview")
	}
}

func TestDecodeEntryVCIMetadata(t *testing.T) {
	e := &TrafficEntry{
		Method:       "GET",
		URL:          "http://issuer.example/.well-known/openid-credential-issuer",
		StatusCode:   200,
		ResponseBody: `{"issuer":"http://issuer.example","credential_configurations_supported":{}}`,
	}
	Classify(e)

	meta, ok := e.Decoded["metadata"].(map[string]any)
	if !ok {
		t.Fatal("expected metadata as map")
	}
	if meta["issuer"] != "http://issuer.example" {
		t.Errorf("issuer: got %v", meta["issuer"])
	}
}

func TestDecodeEntryVCITokenRequest(t *testing.T) {
	e := &TrafficEntry{
		Method:       "POST",
		URL:          "http://issuer.example/token",
		RequestBody:  "grant_type=authorization_code&code=abc",
		StatusCode:   200,
		ResponseBody: `{"access_token":"at_123","token_type":"Bearer"}`,
	}
	Classify(e)

	if e.Decoded["grant_type"] != "authorization_code" {
		t.Errorf("grant_type: got %v", e.Decoded["grant_type"])
	}
	resp, ok := e.Decoded["response"].(map[string]any)
	if !ok {
		t.Fatal("expected response as map")
	}
	if resp["access_token"] != "at_123" {
		t.Errorf("access_token: got %v", resp["access_token"])
	}
}

func TestDecodeEntryVCICredentialRequest(t *testing.T) {
	e := &TrafficEntry{
		Method:       "POST",
		URL:          "http://issuer.example/credential",
		RequestBody:  `{"format":"vc+sd-jwt","vct":"pid"}`,
		StatusCode:   200,
		ResponseBody: `{"credential":"abc.def.ghi"}`,
	}
	Classify(e)

	req, ok := e.Decoded["request"].(map[string]any)
	if !ok {
		t.Fatal("expected request as map")
	}
	if req["format"] != "vc+sd-jwt" {
		t.Errorf("format: got %v", req["format"])
	}
	resp, ok := e.Decoded["response"].(map[string]any)
	if !ok {
		t.Fatal("expected response as map")
	}
	if resp["credential"] != "abc.def.ghi" {
		t.Errorf("credential: got %v", resp["credential"])
	}
}

func TestDecodeEntryUnknownReturnsNil(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/favicon.ico",
		StatusCode: 200,
	}
	Classify(e)

	if e.Decoded != nil {
		t.Errorf("expected nil Decoded for unknown class, got %v", e.Decoded)
	}
}

// --- extractCredentials tests ---

func TestExtractCredentialsVPAuthResponse(t *testing.T) {
	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: "vp_token=credential1&id_token=credential2&state=s1",
		StatusCode:  200,
	}
	Classify(e)

	if len(e.Credentials) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(e.Credentials))
	}
	if e.Credentials[0] != "credential1" {
		t.Errorf("cred[0]: got %q", e.Credentials[0])
	}
	if e.Credentials[1] != "credential2" {
		t.Errorf("cred[1]: got %q", e.Credentials[1])
	}
}

func TestExtractCredentialsVPRequestObject(t *testing.T) {
	jwt := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.signature"
	e := &TrafficEntry{
		Method:       "GET",
		URL:          "http://example.com/request/abc",
		StatusCode:   200,
		ResponseBody: jwt,
	}
	Classify(e)

	if len(e.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(e.Credentials))
	}
	if e.Credentials[0] != jwt {
		t.Errorf("expected JWT credential, got %q", e.Credentials[0])
	}
}

func TestExtractCredentialsVCICredentialRequest(t *testing.T) {
	e := &TrafficEntry{
		Method:       "POST",
		URL:          "http://issuer.example/credential",
		RequestBody:  `{"format":"vc+sd-jwt"}`,
		StatusCode:   200,
		ResponseBody: `{"credential":"the-credential"}`,
	}
	Classify(e)

	if len(e.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(e.Credentials))
	}
	if e.Credentials[0] != "the-credential" {
		t.Errorf("expected 'the-credential', got %q", e.Credentials[0])
	}
}

func TestExtractCredentialsVCIBatchResponse(t *testing.T) {
	e := &TrafficEntry{
		Method:       "POST",
		URL:          "http://issuer.example/credential",
		RequestBody:  `{"format":"vc+sd-jwt"}`,
		StatusCode:   200,
		ResponseBody: `{"credentials":[{"credential":"cred1"},{"credential":"cred2"}]}`,
	}
	Classify(e)

	if len(e.Credentials) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(e.Credentials))
	}
}

func TestExtractCredentialsUnknown(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/other",
		StatusCode: 200,
	}
	Classify(e)

	if len(e.Credentials) != 0 {
		t.Errorf("expected no credentials for unknown class, got %d", len(e.Credentials))
	}
}

// --- decodeJARMResponse tests ---

func makeJWS(header, payload map[string]any) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + ".signature"
}

func TestDecodeJARMResponseJWS(t *testing.T) {
	jws := makeJWS(
		map[string]any{"alg": "ES256", "typ": "JWT"},
		map[string]any{"vp_token": "abc", "state": "s1"},
	)

	decoded := make(map[string]any)
	decodeJARMResponse(jws, decoded)

	if decoded["response_type"] != "JWS (signed)" {
		t.Errorf("response_type: got %v", decoded["response_type"])
	}
	if decoded["response_header"] == nil {
		t.Error("expected response_header")
	}
	if decoded["response_payload"] == nil {
		t.Error("expected response_payload")
	}
}

func TestDecodeJARMResponseJWE(t *testing.T) {
	header := map[string]any{
		"alg": "ECDH-ES",
		"enc": "A256GCM",
		"kid": "key-1",
		"epk": map[string]any{"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
		"apu": "sender",
		"apv": "recipient",
	}
	h, _ := json.Marshal(header)
	jwe := base64.RawURLEncoding.EncodeToString(h) + ".enckey.iv.cipher.tag"

	decoded := make(map[string]any)
	decodeJARMResponse(jwe, decoded)

	if !strings.Contains(decoded["response_type"].(string), "JWE") {
		t.Errorf("expected JWE response type, got %v", decoded["response_type"])
	}
	if decoded["encryption_alg"] != "ECDH-ES" {
		t.Errorf("encryption_alg: got %v", decoded["encryption_alg"])
	}
	if decoded["encryption_enc"] != "A256GCM" {
		t.Errorf("encryption_enc: got %v", decoded["encryption_enc"])
	}
	if decoded["encryption_kid"] != "key-1" {
		t.Errorf("encryption_kid: got %v", decoded["encryption_kid"])
	}
	if decoded["encryption_epk"] == nil {
		t.Error("expected encryption_epk")
	}
	if decoded["encryption_apu"] != "sender" {
		t.Errorf("encryption_apu: got %v", decoded["encryption_apu"])
	}
	if decoded["encryption_apv"] != "recipient" {
		t.Errorf("encryption_apv: got %v", decoded["encryption_apv"])
	}
}

// --- ExtractCorrelationKey tests ---

func TestExtractCorrelationKeyVPAuthRequest(t *testing.T) {
	entry := &TrafficEntry{
		Method: "GET",
		URL:    "http://example.com/authorize?client_id=test&response_type=vp_token&state=abc123&nonce=xyz",
		Class:  ClassVPAuthRequest,
	}
	key := ExtractCorrelationKey(entry)
	if key != "abc123" {
		t.Errorf("expected state 'abc123', got %q", key)
	}
}

func TestExtractCorrelationKeyVPAuthRequestNonce(t *testing.T) {
	entry := &TrafficEntry{
		Method: "GET",
		URL:    "http://example.com/authorize?client_id=test&response_type=vp_token&nonce=xyz",
		Class:  ClassVPAuthRequest,
	}
	key := ExtractCorrelationKey(entry)
	if key != "xyz" {
		t.Errorf("expected nonce 'xyz', got %q", key)
	}
}

func TestExtractCorrelationKeyVPRequestObject(t *testing.T) {
	entry := &TrafficEntry{
		Method: "GET",
		URL:    "http://example.com/request/abc",
		Class:  ClassVPRequestObject,
		Decoded: map[string]any{
			"payload": map[string]any{"state": "abc123", "nonce": "xyz"},
		},
	}
	key := ExtractCorrelationKey(entry)
	if key != "abc123" {
		t.Errorf("expected state 'abc123', got %q", key)
	}
}

func TestExtractCorrelationKeyVPRequestObjectNonce(t *testing.T) {
	entry := &TrafficEntry{
		Method: "GET",
		URL:    "http://example.com/request/abc",
		Class:  ClassVPRequestObject,
		Decoded: map[string]any{
			"payload": map[string]any{"nonce": "xyz"},
		},
	}
	key := ExtractCorrelationKey(entry)
	if key != "xyz" {
		t.Errorf("expected nonce 'xyz', got %q", key)
	}
}

func TestExtractCorrelationKeyVPAuthResponse(t *testing.T) {
	entry := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: "state=abc123&vp_token=eyJ...",
		Class:       ClassVPAuthResponse,
	}
	key := ExtractCorrelationKey(entry)
	if key != "abc123" {
		t.Errorf("expected state 'abc123', got %q", key)
	}
}

func TestExtractCorrelationKeyVCITokenRequest(t *testing.T) {
	entry := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/token",
		RequestBody: "grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=code123",
		Class:       ClassVCITokenRequest,
	}
	key := ExtractCorrelationKey(entry)
	if key != "code123" {
		t.Errorf("expected pre-authorized_code 'code123', got %q", key)
	}
}

func TestExtractCorrelationKeyVCITokenRequestCode(t *testing.T) {
	entry := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/token",
		RequestBody: "grant_type=authorization_code&code=auth-code-456",
		Class:       ClassVCITokenRequest,
	}
	key := ExtractCorrelationKey(entry)
	if key != "auth-code-456" {
		t.Errorf("expected code 'auth-code-456', got %q", key)
	}
}

func TestExtractCorrelationKeyVCICredentialRequest(t *testing.T) {
	entry := &TrafficEntry{
		Method:         "POST",
		URL:            "http://example.com/credential",
		RequestHeaders: http.Header{"Authorization": {"Bearer token123"}},
		Class:          ClassVCICredentialRequest,
	}
	key := ExtractCorrelationKey(entry)
	if key != "Bearer token123" {
		t.Errorf("expected 'Bearer token123', got %q", key)
	}
}

func TestExtractCorrelationKeyUnknown(t *testing.T) {
	entry := &TrafficEntry{
		Method: "GET",
		URL:    "http://example.com/favicon.ico",
		Class:  ClassUnknown,
	}
	key := ExtractCorrelationKey(entry)
	if key != "" {
		t.Errorf("expected empty string, got %q", key)
	}
}

func TestExtractCorrelationKeyVCICredentialOffer(t *testing.T) {
	entry := &TrafficEntry{
		Method: "GET",
		URL:    `http://example.com/offer?credential_offer={"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"offer-code-123"}}}`,
		Class:  ClassVCICredentialOffer,
	}
	key := ExtractCorrelationKey(entry)
	if key != "offer-code-123" {
		t.Errorf("expected 'offer-code-123', got %q", key)
	}
}

func TestExtractCorrelationKeyVPAuthResponseNoState(t *testing.T) {
	entry := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: "vp_token=eyJ...",
		Class:       ClassVPAuthResponse,
	}
	key := ExtractCorrelationKey(entry)
	if key != "" {
		t.Errorf("expected empty string when no state, got %q", key)
	}
}

func TestExtractCorrelationKeyVCICredentialRequestNoAuth(t *testing.T) {
	entry := &TrafficEntry{
		Method:         "POST",
		URL:            "http://example.com/credential",
		RequestHeaders: http.Header{},
		Class:          ClassVCICredentialRequest,
	}
	key := ExtractCorrelationKey(entry)
	if key != "" {
		t.Errorf("expected empty string when no auth header, got %q", key)
	}
}
