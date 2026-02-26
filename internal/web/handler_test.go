// Copyright 2025 Dominik Schlosser
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

package web

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// apiPost is a test helper that posts JSON to /api/decode and returns the recorder.
func apiPost(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/decode", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	NewMux("").ServeHTTP(w, req)
	return w
}

// decodeResponse unmarshals the response body into a map.
func decodeResponse(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON response: %v\nbody: %s", err, w.Body.String())
	}
	return result
}

func makeJWT(header, payload map[string]any) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + "."
}

func makeSDJWT(payload map[string]any, disclosures [][]any) string {
	header := map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"}
	h, _ := json.Marshal(header)

	if _, has := payload["_sd"]; has && len(disclosures) > 0 {
		var digests []string
		for _, d := range disclosures {
			dJSON, _ := json.Marshal(d)
			dB64 := base64.RawURLEncoding.EncodeToString(dJSON)
			hash := sha256.Sum256([]byte(dB64))
			digests = append(digests, base64.RawURLEncoding.EncodeToString(hash[:]))
		}
		payload["_sd"] = digests
	}

	p, _ := json.Marshal(payload)
	jwt := base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + ".fakesig"

	result := jwt
	for _, d := range disclosures {
		dJSON, _ := json.Marshal(d)
		result += "~" + base64.RawURLEncoding.EncodeToString(dJSON)
	}
	result += "~"
	return result
}

func TestHandleDecode_JWT(t *testing.T) {
	jwt := makeJWT(
		map[string]any{"alg": "none", "typ": "JWT"},
		map[string]any{"sub": "1234567890", "name": "John Doe"},
	)

	w := apiPost(t, `{"input":"`+jwt+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeResponse(t, w)
	if result["format"] != "jwt" {
		t.Errorf("expected format 'jwt', got %v", result["format"])
	}
	p := result["payload"].(map[string]any)
	if p["name"] != "John Doe" {
		t.Errorf("expected name 'John Doe', got %v", p["name"])
	}
}

func TestHandleDecode_JWTResponseStructure(t *testing.T) {
	jwt := makeJWT(
		map[string]any{"alg": "RS256", "kid": "key-1"},
		map[string]any{"iss": "https://auth.example", "sub": "user"},
	)

	w := apiPost(t, `{"input":"`+jwt+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeResponse(t, w)

	// Must have exactly format, header, payload
	for _, key := range []string{"format", "header", "payload"} {
		if _, ok := result[key]; !ok {
			t.Errorf("missing key %q in response", key)
		}
	}

	header := result["header"].(map[string]any)
	if header["kid"] != "key-1" {
		t.Errorf("header.kid = %v, want key-1", header["kid"])
	}
}

func TestHandleDecode_SDJWT(t *testing.T) {
	sdjwt := makeSDJWT(
		map[string]any{
			"iss":     "https://issuer.example",
			"_sd_alg": "sha-256",
			"_sd":     nil,
		},
		[][]any{
			{"salt1", "given_name", "Erika"},
			{"salt2", "family_name", "Mustermann"},
		},
	)

	w := apiPost(t, `{"input":"`+sdjwt+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	result := decodeResponse(t, w)
	if result["format"] != "dc+sd-jwt" {
		t.Errorf("expected format 'dc+sd-jwt', got %v", result["format"])
	}

	discs, ok := result["disclosures"].([]any)
	if !ok {
		t.Fatalf("disclosures should be an array, got %T", result["disclosures"])
	}
	if len(discs) != 2 {
		t.Errorf("expected 2 disclosures, got %d", len(discs))
	}

	if _, ok := result["resolvedClaims"]; !ok {
		t.Error("SD-JWT response should have resolvedClaims")
	}
}

func TestHandleDecode_SDJWTDisclosureFields(t *testing.T) {
	sdjwt := makeSDJWT(
		map[string]any{
			"iss":     "https://issuer.example",
			"_sd_alg": "sha-256",
			"_sd":     nil,
		},
		[][]any{
			{"salt-abc", "email", "test@example.com"},
		},
	)

	w := apiPost(t, `{"input":"`+sdjwt+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeResponse(t, w)
	discs := result["disclosures"].([]any)
	d := discs[0].(map[string]any)

	if d["name"] != "email" {
		t.Errorf("disclosure.name = %v, want email", d["name"])
	}
	if d["value"] != "test@example.com" {
		t.Errorf("disclosure.value = %v, want test@example.com", d["value"])
	}
	if d["salt"] != "salt-abc" {
		t.Errorf("disclosure.salt = %v, want salt-abc", d["salt"])
	}
	if _, ok := d["digest"]; !ok {
		t.Error("disclosure should have digest field")
	}
	if d["isArrayEntry"] != false {
		t.Errorf("disclosure.isArrayEntry = %v, want false", d["isArrayEntry"])
	}
}

func TestHandleDecode_EmptyInput(t *testing.T) {
	w := apiPost(t, `{"input":""}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	result := decodeResponse(t, w)
	if result["error"] != "input is required" {
		t.Errorf("expected error 'input is required', got %v", result["error"])
	}
}

func TestHandleDecode_MissingInputField(t *testing.T) {
	w := apiPost(t, `{}`)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	result := decodeResponse(t, w)
	if result["error"] != "input is required" {
		t.Errorf("expected 'input is required', got %v", result["error"])
	}
}

func TestHandleDecode_InvalidCredential(t *testing.T) {
	w := apiPost(t, `{"input":"not-a-credential"}`)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Code)
	}

	result := decodeResponse(t, w)
	if _, ok := result["error"]; !ok {
		t.Error("expected error field in response")
	}
}

func TestHandleDecode_InvalidJSON(t *testing.T) {
	w := apiPost(t, "not json")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleDecode_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/decode", nil)
	w := httptest.NewRecorder()

	NewMux("").ServeHTTP(w, req)

	// Go 1.22+ method-based routing returns 405 for wrong method
	if w.Code == http.StatusOK {
		t.Fatal("expected non-200 for GET /api/decode")
	}
}

func TestHandleDecode_PutMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/api/decode", strings.NewReader(`{"input":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	NewMux("").ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Fatal("expected non-200 for PUT /api/decode")
	}
}

func TestHandleDecode_ResponseContentType(t *testing.T) {
	jwt := makeJWT(
		map[string]any{"alg": "none"},
		map[string]any{"sub": "test"},
	)

	w := apiPost(t, `{"input":"`+jwt+`"}`)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestHandleDecode_ErrorResponseContentType(t *testing.T) {
	w := apiPost(t, `{"input":""}`)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestHandleDecode_MalformedJWT(t *testing.T) {
	// Three dots make it look like JWT to format detection, but content is invalid
	w := apiPost(t, `{"input":"aaa.bbb.ccc"}`)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", w.Code, w.Body.String())
	}
}

func TestStaticFiles_Index(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	NewMux("").ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "SSI Debugger") {
		t.Error("expected index.html to contain 'SSI Debugger'")
	}
	if !strings.Contains(body, "app.js") {
		t.Error("expected index.html to reference app.js")
	}
	if !strings.Contains(body, "style.css") {
		t.Error("expected index.html to reference style.css")
	}
}

func TestStaticFiles_CSS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/style.css", nil)
	w := httptest.NewRecorder()

	NewMux("").ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for style.css, got %d", w.Code)
	}

	if !strings.Contains(w.Body.String(), "--bg") {
		t.Error("expected CSS to contain custom property --bg")
	}
}

func TestStaticFiles_JS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/app.js", nil)
	w := httptest.NewRecorder()

	NewMux("").ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for app.js, got %d", w.Code)
	}

	if !strings.Contains(w.Body.String(), "/api/decode") {
		t.Error("expected app.js to reference /api/decode endpoint")
	}
}

func TestStaticFiles_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/nonexistent.txt", nil)
	w := httptest.NewRecorder()

	NewMux("").ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestPrefill_WithCredential(t *testing.T) {
	jwt := makeJWT(
		map[string]any{"alg": "none"},
		map[string]any{"sub": "prefilled"},
	)

	req := httptest.NewRequest(http.MethodGet, "/api/prefill", nil)
	w := httptest.NewRecorder()

	NewMux(jwt).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeResponse(t, w)
	if result["credential"] != jwt {
		t.Errorf("expected credential to be the JWT, got %q", result["credential"])
	}
}

func TestPrefill_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/prefill", nil)
	w := httptest.NewRecorder()

	NewMux("").ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	result := decodeResponse(t, w)
	if result["credential"] != "" {
		t.Errorf("expected empty credential, got %q", result["credential"])
	}
}

func TestPrefill_ContentType(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/prefill", nil)
	w := httptest.NewRecorder()

	NewMux("something").ServeHTTP(w, req)

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}
