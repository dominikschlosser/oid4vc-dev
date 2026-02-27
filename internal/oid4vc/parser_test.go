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

package oid4vc

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"testing"
)

func TestParseVCIInlineOffer(t *testing.T) {
	offer := `{"credential_issuer":"https://example.com","credential_configuration_ids":["org.iso.18013.5.1.mDL"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"abc123","tx_code":{"input_mode":"numeric","length":6}}}}`
	uri := "openid-credential-offer://?credential_offer=" + url.QueryEscape(offer)

	reqType, result, err := Parse(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVCI {
		t.Fatalf("expected TypeVCI, got %d", reqType)
	}

	co, ok := result.(*CredentialOffer)
	if !ok {
		t.Fatalf("expected *CredentialOffer, got %T", result)
	}
	if co.CredentialIssuer != "https://example.com" {
		t.Errorf("expected issuer https://example.com, got %s", co.CredentialIssuer)
	}
	if len(co.CredentialConfigurationIDs) != 1 || co.CredentialConfigurationIDs[0] != "org.iso.18013.5.1.mDL" {
		t.Errorf("unexpected credential_configuration_ids: %v", co.CredentialConfigurationIDs)
	}
	if co.Grants.PreAuthorizedCode != "abc123" {
		t.Errorf("expected pre-authorized code abc123, got %s", co.Grants.PreAuthorizedCode)
	}
	if co.Grants.TxCode == nil {
		t.Fatal("expected tx_code to be present")
	}
	if co.Grants.TxCode["input_mode"] != "numeric" {
		t.Errorf("expected input_mode numeric, got %v", co.Grants.TxCode["input_mode"])
	}
}

func TestParseVCIRawJSON(t *testing.T) {
	raw := `{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"],"grants":{}}`
	reqType, result, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVCI {
		t.Fatalf("expected TypeVCI, got %d", reqType)
	}
	co := result.(*CredentialOffer)
	if co.CredentialIssuer != "https://issuer.example" {
		t.Errorf("unexpected issuer: %s", co.CredentialIssuer)
	}
}

func TestParseVCIJWT(t *testing.T) {
	payload := map[string]any{
		"credential_issuer":            "https://jwt-issuer.example",
		"credential_configuration_ids": []string{"pid"},
		"grants":                       map[string]any{},
	}
	jwt := makeTestJWT(map[string]any{"alg": "ES256"}, payload)

	reqType, result, err := Parse(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVCI {
		t.Fatalf("expected TypeVCI, got %d", reqType)
	}
	co := result.(*CredentialOffer)
	if co.CredentialIssuer != "https://jwt-issuer.example" {
		t.Errorf("unexpected issuer: %s", co.CredentialIssuer)
	}
}

func TestParseVPInlineParams(t *testing.T) {
	uri := "openid4vp://?client_id=https://verifier.example&response_type=vp_token&nonce=abc&response_mode=direct_post&response_uri=https://verifier.example/cb"

	reqType, result, err := Parse(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVP {
		t.Fatalf("expected TypeVP, got %d", reqType)
	}

	ar, ok := result.(*AuthorizationRequest)
	if !ok {
		t.Fatalf("expected *AuthorizationRequest, got %T", result)
	}
	if ar.ClientID != "https://verifier.example" {
		t.Errorf("unexpected client_id: %s", ar.ClientID)
	}
	if ar.ResponseType != "vp_token" {
		t.Errorf("unexpected response_type: %s", ar.ResponseType)
	}
	if ar.Nonce != "abc" {
		t.Errorf("unexpected nonce: %s", ar.Nonce)
	}
	if ar.ResponseMode != "direct_post" {
		t.Errorf("unexpected response_mode: %s", ar.ResponseMode)
	}
	if ar.ResponseURI != "https://verifier.example/cb" {
		t.Errorf("unexpected response_uri: %s", ar.ResponseURI)
	}
}

func TestParseVPWithPresentationDefinition(t *testing.T) {
	pd := `{"id":"test","input_descriptors":[{"id":"d1"}]}`
	uri := "openid4vp://?client_id=v&response_type=vp_token&presentation_definition=" + url.QueryEscape(pd)

	_, result, err := Parse(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ar := result.(*AuthorizationRequest)
	if ar.PresentationDefinition == nil {
		t.Fatal("expected presentation_definition to be parsed")
	}
	if ar.PresentationDefinition["id"] != "test" {
		t.Errorf("unexpected presentation_definition id: %v", ar.PresentationDefinition["id"])
	}
}

func TestParseVPDirectJWT(t *testing.T) {
	payload := map[string]any{
		"client_id":     "https://verifier.example",
		"response_type": "vp_token",
		"nonce":         "jwt-nonce",
	}
	jwt := makeTestJWT(map[string]any{"alg": "ES256"}, payload)

	reqType, result, err := Parse(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVP {
		t.Fatalf("expected TypeVP, got %d", reqType)
	}
	ar := result.(*AuthorizationRequest)
	if ar.ClientID != "https://verifier.example" {
		t.Errorf("unexpected client_id: %s", ar.ClientID)
	}
	if ar.Nonce != "jwt-nonce" {
		t.Errorf("unexpected nonce: %s", ar.Nonce)
	}
	if ar.RequestObject == nil {
		t.Fatal("expected request object to be set")
	}
	if ar.RequestObject.Header["alg"] != "ES256" {
		t.Errorf("unexpected header alg: %v", ar.RequestObject.Header["alg"])
	}
}

func TestParseAlternativeSchemes(t *testing.T) {
	tests := []struct {
		scheme string
	}{
		{"haip://"},
		{"eudi-openid4vp://"},
	}
	for _, tt := range tests {
		t.Run(tt.scheme, func(t *testing.T) {
			uri := tt.scheme + "?client_id=test&response_type=vp_token"
			reqType, result, err := Parse(uri)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if reqType != TypeVP {
				t.Fatalf("expected TypeVP, got %d", reqType)
			}
			ar := result.(*AuthorizationRequest)
			if ar.ClientID != "test" {
				t.Errorf("unexpected client_id: %s", ar.ClientID)
			}
		})
	}
}

func TestParseVPJSON(t *testing.T) {
	raw := `{"client_id":"https://v.example","response_type":"vp_token","nonce":"n123"}`
	reqType, result, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVP {
		t.Fatalf("expected TypeVP, got %d", reqType)
	}
	ar := result.(*AuthorizationRequest)
	if ar.ClientID != "https://v.example" {
		t.Errorf("unexpected client_id: %s", ar.ClientID)
	}
}

func TestParseErrorCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"random string", "not-a-valid-input"},
		{"invalid json", "{broken"},
		{"json without markers", `{"foo":"bar"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Parse(tt.input)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestParseHTTPURLVCI(t *testing.T) {
	offer := `{"credential_issuer":"https://example.com","credential_configuration_ids":["pid"]}`
	u := "https://issuer.example/offer?credential_offer=" + url.QueryEscape(offer)

	reqType, result, err := Parse(u)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVCI {
		t.Fatalf("expected TypeVCI, got %d", reqType)
	}
	co := result.(*CredentialOffer)
	if co.CredentialIssuer != "https://example.com" {
		t.Errorf("unexpected issuer: %s", co.CredentialIssuer)
	}
}

func TestParseHTTPURLVP(t *testing.T) {
	u := "https://verifier.example/auth?client_id=test&response_type=vp_token&nonce=n1"

	reqType, result, err := Parse(u)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVP {
		t.Fatalf("expected TypeVP, got %d", reqType)
	}
	ar := result.(*AuthorizationRequest)
	if ar.ClientID != "test" {
		t.Errorf("unexpected client_id: %s", ar.ClientID)
	}
}

func TestParseVCIWithAuthorizationCodeGrant(t *testing.T) {
	raw := `{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"],"grants":{"authorization_code":{"issuer_state":"state123"}}}`
	_, result, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	co := result.(*CredentialOffer)
	if co.Grants.IssuerState != "state123" {
		t.Errorf("expected issuer_state state123, got %s", co.Grants.IssuerState)
	}
}

func TestParseVCIMultipleCredentialConfigs(t *testing.T) {
	raw := `{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid","mdl","diploma"],"grants":{}}`
	_, result, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	co := result.(*CredentialOffer)
	if len(co.CredentialConfigurationIDs) != 3 {
		t.Fatalf("expected 3 configs, got %d", len(co.CredentialConfigurationIDs))
	}
	expected := []string{"pid", "mdl", "diploma"}
	for i, want := range expected {
		if co.CredentialConfigurationIDs[i] != want {
			t.Errorf("config[%d] = %s, want %s", i, co.CredentialConfigurationIDs[i], want)
		}
	}
}

func TestParseVCIFullJSONPreserved(t *testing.T) {
	raw := `{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"],"grants":{},"custom_field":"custom_value"}`
	_, result, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	co := result.(*CredentialOffer)
	if co.FullJSON == nil {
		t.Fatal("expected FullJSON to be preserved")
	}
	if co.FullJSON["custom_field"] != "custom_value" {
		t.Errorf("expected custom_field to be preserved, got %v", co.FullJSON["custom_field"])
	}
}

func TestParseVPWithDCQLQuery(t *testing.T) {
	dq := `{"credentials":[{"id":"pid","format":"dc+sd-jwt"}]}`
	uri := "openid4vp://?client_id=v&response_type=vp_token&dcql_query=" + url.QueryEscape(dq)

	_, result, err := Parse(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ar := result.(*AuthorizationRequest)
	if ar.DCQLQuery == nil {
		t.Fatal("expected dcql_query to be parsed")
	}
	creds, ok := ar.DCQLQuery["credentials"].([]any)
	if !ok {
		t.Fatalf("expected credentials array, got %T", ar.DCQLQuery["credentials"])
	}
	if len(creds) != 1 {
		t.Errorf("expected 1 credential query, got %d", len(creds))
	}
}

func TestParseVPFullParams(t *testing.T) {
	uri := "openid4vp://?client_id=v&response_type=vp_token&nonce=n&state=s&scope=openid&redirect_uri=https://r.example"

	_, result, err := Parse(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ar := result.(*AuthorizationRequest)
	if ar.State != "s" {
		t.Errorf("state = %s, want s", ar.State)
	}
	if ar.Scope != "openid" {
		t.Errorf("scope = %s, want openid", ar.Scope)
	}
	if ar.RedirectURI != "https://r.example" {
		t.Errorf("redirect_uri = %s, want https://r.example", ar.RedirectURI)
	}
	// FullParams should contain all query params
	if ar.FullParams["client_id"] != "v" {
		t.Errorf("FullParams[client_id] = %s, want v", ar.FullParams["client_id"])
	}
	if ar.FullParams["nonce"] != "n" {
		t.Errorf("FullParams[nonce] = %s, want n", ar.FullParams["nonce"])
	}
}

func TestParseVPJWTAutoDetectByResponseType(t *testing.T) {
	// JWT with response_type but no client_id
	payload := map[string]any{
		"response_type": "vp_token",
		"nonce":         "n1",
	}
	jwt := makeTestJWT(map[string]any{"alg": "RS256"}, payload)

	reqType, result, err := Parse(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVP {
		t.Fatalf("expected TypeVP, got %d", reqType)
	}
	ar := result.(*AuthorizationRequest)
	if ar.ResponseType != "vp_token" {
		t.Errorf("response_type = %s, want vp_token", ar.ResponseType)
	}
}

func TestParseVPJSONWithPresentationDefinition(t *testing.T) {
	raw := `{"client_id":"v","response_type":"vp_token","presentation_definition":{"id":"pd1","input_descriptors":[]}}`
	_, result, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ar := result.(*AuthorizationRequest)
	if ar.PresentationDefinition == nil {
		t.Fatal("expected presentation_definition")
	}
	if ar.PresentationDefinition["id"] != "pd1" {
		t.Errorf("pd.id = %v, want pd1", ar.PresentationDefinition["id"])
	}
}

func TestParseVPJSONWithDCQLQuery(t *testing.T) {
	raw := `{"client_id":"v","response_type":"vp_token","dcql_query":{"credentials":[]}}`
	_, result, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ar := result.(*AuthorizationRequest)
	if ar.DCQLQuery == nil {
		t.Fatal("expected dcql_query")
	}
}

func TestParseVCINoCredentialOffer(t *testing.T) {
	uri := "openid-credential-offer://?some_other_param=value"
	_, _, err := Parse(uri)
	if err == nil {
		t.Error("expected error when no credential_offer param")
	}
}

func TestParseWhitespace(t *testing.T) {
	raw := `  {"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"],"grants":{}}  `
	reqType, _, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVCI {
		t.Fatalf("expected TypeVCI, got %d", reqType)
	}
}

func TestParseJWTNoMarkers(t *testing.T) {
	// JWT with neither credential_issuer nor client_id/response_type
	payload := map[string]any{"sub": "user", "iss": "https://example.com"}
	jwt := makeTestJWT(map[string]any{"alg": "ES256"}, payload)
	_, _, err := Parse(jwt)
	if err == nil {
		t.Error("expected error for JWT without VCI/VP markers")
	}
}

func TestParseVPJWTPayloadMerge(t *testing.T) {
	payload := map[string]any{
		"client_id":     "https://verifier.example",
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"nonce":         "n1",
		"state":         "s1",
		"response_uri":  "https://verifier.example/cb",
		"scope":         "openid",
		"presentation_definition": map[string]any{
			"id": "pd-from-jwt",
		},
	}
	jwt := makeTestJWT(map[string]any{"alg": "ES256"}, payload)

	_, result, err := Parse(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ar := result.(*AuthorizationRequest)
	if ar.ResponseMode != "direct_post" {
		t.Errorf("response_mode = %s, want direct_post", ar.ResponseMode)
	}
	if ar.State != "s1" {
		t.Errorf("state = %s, want s1", ar.State)
	}
	if ar.ResponseURI != "https://verifier.example/cb" {
		t.Errorf("response_uri = %s, want https://verifier.example/cb", ar.ResponseURI)
	}
	if ar.Scope != "openid" {
		t.Errorf("scope = %s, want openid", ar.Scope)
	}
	if ar.PresentationDefinition == nil {
		t.Fatal("expected presentation_definition from JWT payload")
	}
	if ar.PresentationDefinition["id"] != "pd-from-jwt" {
		t.Errorf("pd.id = %v, want pd-from-jwt", ar.PresentationDefinition["id"])
	}
}

// makeTestJWT creates a test JWT string (unsigned) from header and payload maps.
func makeTestJWT(header, payload map[string]any) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("test-signature"))
}
