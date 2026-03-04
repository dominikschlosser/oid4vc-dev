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
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
	"github.com/dominikschlosser/oid4vc-dev/internal/sdjwt"
)

// testEncJWK creates a JWK map suitable for encryption tests, with the required "alg" field.
func testEncJWK(t *testing.T, pub *ecdsa.PublicKey) map[string]any {
	t.Helper()
	jwkJSON := mock.PublicKeyJWK(pub)
	var jwk map[string]any
	if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
		t.Fatalf("parsing JWK: %v", err)
	}
	jwk["alg"] = "ECDH-ES"
	return jwk
}

func TestCreateVPToken_SDJWT(t *testing.T) {
	w := generateTestWalletWithPID(t)

	creds := w.GetCredentials()
	var sdCred StoredCredential
	for _, c := range creds {
		if c.Format == "dc+sd-jwt" {
			sdCred = c
			break
		}
	}
	if sdCred.ID == "" {
		t.Fatal("no SD-JWT credential found")
	}

	match := CredentialMatch{
		QueryID:      "test_query",
		CredentialID: sdCred.ID,
		Format:       "dc+sd-jwt",
		SelectedKeys: []string{"given_name", "family_name"},
	}

	result, err := w.CreateVPToken(match, PresentationParams{Nonce: "test-nonce", ClientID: "https://verifier.example", ResponseURI: "https://verifier.example/response"})
	if err != nil {
		t.Fatalf("CreateVPToken error: %v", err)
	}

	if result.Token == "" {
		t.Fatal("expected non-empty VP token")
	}

	// Parse the resulting SD-JWT to validate structure
	parsed, err := sdjwt.Parse(result.Token)
	if err != nil {
		t.Fatalf("parsing VP token: %v", err)
	}

	// Should have a key binding JWT
	if parsed.KeyBindingJWT == nil {
		t.Fatal("expected key binding JWT in VP token")
	}

	// KB-JWT should have correct typ
	if typ, ok := parsed.KeyBindingJWT.Header["typ"].(string); !ok || typ != "kb+jwt" {
		t.Errorf("expected KB-JWT typ kb+jwt, got %v", parsed.KeyBindingJWT.Header["typ"])
	}

	// KB-JWT payload should contain nonce and aud
	if nonce, ok := parsed.KeyBindingJWT.Payload["nonce"].(string); !ok || nonce != "test-nonce" {
		t.Errorf("expected nonce test-nonce, got %v", parsed.KeyBindingJWT.Payload["nonce"])
	}
	if aud, ok := parsed.KeyBindingJWT.Payload["aud"].(string); !ok || aud != "https://verifier.example" {
		t.Errorf("expected aud https://verifier.example, got %v", parsed.KeyBindingJWT.Payload["aud"])
	}
	if _, ok := parsed.KeyBindingJWT.Payload["sd_hash"]; !ok {
		t.Error("expected sd_hash in KB-JWT payload")
	}

	// Only selected disclosures should be present
	discNames := make(map[string]bool)
	for _, d := range parsed.Disclosures {
		if !d.IsArrayEntry {
			discNames[d.Name] = true
		}
	}
	if !discNames["given_name"] {
		t.Error("expected given_name disclosure in VP token")
	}
	if !discNames["family_name"] {
		t.Error("expected family_name disclosure in VP token")
	}
}

func TestCreateVPToken_SDJWT_SelectiveDisclosure(t *testing.T) {
	w := generateTestWalletWithPID(t)

	creds := w.GetCredentials()
	var sdCred StoredCredential
	for _, c := range creds {
		if c.Format == "dc+sd-jwt" {
			sdCred = c
			break
		}
	}

	// Only disclose given_name
	match := CredentialMatch{
		QueryID:      "test",
		CredentialID: sdCred.ID,
		Format:       "dc+sd-jwt",
		SelectedKeys: []string{"given_name"},
	}

	result, err := w.CreateVPToken(match, PresentationParams{Nonce: "n", ClientID: "client", ResponseURI: "response"})
	if err != nil {
		t.Fatalf("CreateVPToken error: %v", err)
	}

	parsed, err := sdjwt.Parse(result.Token)
	if err != nil {
		t.Fatalf("parsing VP token: %v", err)
	}

	// Count non-array disclosures
	var names []string
	for _, d := range parsed.Disclosures {
		if !d.IsArrayEntry {
			names = append(names, d.Name)
		}
	}

	if len(names) != 1 {
		t.Errorf("expected 1 disclosure, got %d: %v", len(names), names)
	}
	if len(names) > 0 && names[0] != "given_name" {
		t.Errorf("expected given_name, got %s", names[0])
	}
}

func TestCreateVPToken_PlainJWT(t *testing.T) {
	w := generateTestWallet(t)

	// Create and import a plain JWT
	jwt, err := signJWT(
		map[string]any{"alg": "ES256", "typ": "JWT"},
		map[string]any{"sub": "user123", "vct": "urn:test:credential", "given_name": "Erika"},
		w.IssuerKey,
	)
	if err != nil {
		t.Fatalf("creating test JWT: %v", err)
	}
	if _, err := w.ImportCredential(jwt); err != nil {
		t.Fatalf("importing plain JWT: %v", err)
	}

	cred := w.GetCredentials()[0]
	match := CredentialMatch{
		QueryID:      "test",
		CredentialID: cred.ID,
		Format:       "jwt_vc_json",
		SelectedKeys: []string{"given_name"},
	}

	result, err := w.CreateVPToken(match, PresentationParams{Nonce: "n", ClientID: "client", ResponseURI: "response"})
	if err != nil {
		t.Fatalf("CreateVPToken error: %v", err)
	}

	// Should return the raw JWT as-is (no ~ separator, no KB-JWT)
	if result.Token != jwt {
		t.Errorf("expected raw JWT to be returned as-is")
	}

	// Should be a 3-part JWT
	parts := strings.Split(result.Token, ".")
	if len(parts) != 3 {
		t.Errorf("expected 3 JWT parts, got %d", len(parts))
	}

	// Should NOT contain ~ (SD-JWT separator)
	if strings.Contains(result.Token, "~") {
		t.Error("plain JWT presentation should not contain ~ separator")
	}
}

func TestCreateVPToken_MDoc(t *testing.T) {
	w := generateTestWalletWithPID(t)

	creds := w.GetCredentials()
	var mdocCred StoredCredential
	for _, c := range creds {
		if c.Format == "mso_mdoc" {
			mdocCred = c
			break
		}
	}
	if mdocCred.ID == "" {
		t.Fatal("no mDoc credential found")
	}

	// Select a few claims
	var selectedKeys []string
	for k := range mdocCred.Claims {
		selectedKeys = append(selectedKeys, k)
		if len(selectedKeys) >= 2 {
			break
		}
	}

	match := CredentialMatch{
		QueryID:      "mdoc_query",
		CredentialID: mdocCred.ID,
		Format:       "mso_mdoc",
		SelectedKeys: selectedKeys,
	}

	result, err := w.CreateVPToken(match, PresentationParams{Nonce: "nonce123", ClientID: "https://verifier.example", ResponseURI: "https://verifier.example/response"})
	if err != nil {
		t.Fatalf("CreateVPToken error: %v", err)
	}

	if result.Token == "" {
		t.Fatal("expected non-empty VP token")
	}

	// Token should be base64url encoded
	if strings.Contains(result.Token, " ") || strings.Contains(result.Token, "\n") {
		t.Error("VP token should not contain whitespace")
	}
}

func TestCreateVPToken_CredentialNotFound(t *testing.T) {
	w := generateTestWallet(t)

	match := CredentialMatch{
		QueryID:      "test",
		CredentialID: "nonexistent",
		Format:       "dc+sd-jwt",
	}

	_, err := w.CreateVPToken(match, PresentationParams{Nonce: "n", ClientID: "c", ResponseURI: "r"})
	if err == nil {
		t.Fatal("expected error for nonexistent credential")
	}
}

func TestCreateVPTokenMap(t *testing.T) {
	w := generateTestWalletWithPID(t)

	creds := w.GetCredentials()
	var matches []CredentialMatch
	for _, c := range creds {
		keys := make([]string, 0, 2)
		i := 0
		for k := range c.Claims {
			keys = append(keys, k)
			i++
			if i >= 2 {
				break
			}
		}
		matches = append(matches, CredentialMatch{
			QueryID:      "q_" + c.Format,
			CredentialID: c.ID,
			Format:       c.Format,
			SelectedKeys: keys,
		})
	}

	vpResult, err := w.CreateVPTokenMap(matches, PresentationParams{Nonce: "nonce", ClientID: "client", ResponseURI: "response_uri"})
	if err != nil {
		t.Fatalf("CreateVPTokenMap error: %v", err)
	}

	if len(vpResult.TokenMap) != len(matches) {
		t.Errorf("expected %d tokens, got %d", len(matches), len(vpResult.TokenMap))
	}

	for _, m := range matches {
		if _, ok := vpResult.TokenMap[m.QueryID]; !ok {
			t.Errorf("missing token for query ID %s", m.QueryID)
		}
	}
}

func TestBuildSessionTranscriptOID4VP(t *testing.T) {
	clientID := "https://verifier.example"
	nonce := "test-nonce"
	responseURI := "https://verifier.example/response"

	transcript, err := buildSessionTranscriptOID4VP(clientID, nonce, nil, responseURI)
	if err != nil {
		t.Fatalf("buildSessionTranscriptOID4VP error: %v", err)
	}

	// Decode and verify structure: [null, null, ["OpenID4VPHandover", hash]]
	var decoded []cbor.RawMessage
	if err := cbor.Unmarshal(transcript, &decoded); err != nil {
		t.Fatalf("decoding SessionTranscript: %v", err)
	}
	if len(decoded) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(decoded))
	}

	// First two elements should be null
	for i := 0; i < 2; i++ {
		var v any
		if err := cbor.Unmarshal(decoded[i], &v); err != nil {
			t.Fatalf("decoding element %d: %v", i, err)
		}
		if v != nil {
			t.Errorf("element %d: expected null, got %v", i, v)
		}
	}

	// Third element should be ["OpenID4VPHandover", <hash bytes>]
	var handover []cbor.RawMessage
	if err := cbor.Unmarshal(decoded[2], &handover); err != nil {
		t.Fatalf("decoding OID4VPHandover: %v", err)
	}
	if len(handover) != 2 {
		t.Fatalf("OID4VPHandover: expected 2 elements, got %d", len(handover))
	}

	var marker string
	if err := cbor.Unmarshal(handover[0], &marker); err != nil {
		t.Fatalf("decoding handover marker: %v", err)
	}
	if marker != "OpenID4VPHandover" {
		t.Errorf("expected 'OpenID4VPHandover', got %q", marker)
	}

	var hashBytes []byte
	if err := cbor.Unmarshal(handover[1], &hashBytes); err != nil {
		t.Fatalf("decoding handover hash: %v", err)
	}

	// Verify hash matches SHA256(CBOR([clientId, nonce, null, responseUri]))
	handoverInfo, _ := cbor.Marshal([]any{clientID, nonce, nil, responseURI})
	expectedHash := sha256.Sum256(handoverInfo)
	if string(hashBytes) != string(expectedHash[:]) {
		t.Error("handover hash does not match expected SHA256(CBOR(HandoverInfo))")
	}
}

func TestSignJWT(t *testing.T) {
	key, _ := mock.GenerateKey()

	header := map[string]any{"alg": "ES256", "typ": "test+jwt"}
	payload := map[string]any{"sub": "test", "iat": time.Now().Unix()}

	jwt, err := signJWT(header, payload, key)
	if err != nil {
		t.Fatalf("signJWT error: %v", err)
	}

	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	// All parts should be non-empty
	for i, p := range parts {
		if p == "" {
			t.Errorf("JWT part %d is empty", i)
		}
	}
}

func TestCreateVPToken_ImportedSDJWT_PreservesDisclosures(t *testing.T) {
	// Simulates importing an externally-issued SD-JWT and presenting it
	w := generateTestWallet(t)

	// Generate an SD-JWT from an "external" issuer (different key, with holder binding)
	externalKey, _ := mock.GenerateKey()
	rawSDJWT, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://external-issuer.example",
		VCT:       "urn:test:user_binding",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"user_id": "abc123", "role": "admin", "department": "engineering"},
		Key:       externalKey,
		HolderKey: &w.HolderKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("generating external SD-JWT: %v", err)
	}

	// Import it
	if _, err := w.ImportCredential(rawSDJWT); err != nil {
		t.Fatalf("importing SD-JWT: %v", err)
	}

	cred := w.GetCredentials()[0]
	if cred.Format != "dc+sd-jwt" {
		t.Fatalf("expected dc+sd-jwt format, got %s", cred.Format)
	}
	if len(cred.Disclosures) == 0 {
		t.Fatal("expected disclosures after import")
	}

	// Simulate persist + reload
	cred.Disclosures = nil
	if err := cred.Rehydrate(); err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}

	w.mu.Lock()
	w.Credentials[0] = cred
	w.mu.Unlock()

	// Present with selective disclosure
	match := CredentialMatch{
		QueryID:      "test",
		CredentialID: cred.ID,
		Format:       "dc+sd-jwt",
		SelectedKeys: []string{"user_id"},
	}

	result, err := w.CreateVPToken(match, PresentationParams{
		Nonce:       "test-nonce",
		ClientID:    "https://verifier.example",
		ResponseURI: "https://verifier.example/callback",
	})
	if err != nil {
		t.Fatalf("CreateVPToken error: %v", err)
	}

	// Parse the VP token and verify user_id disclosure is present
	parsed, err := sdjwt.Parse(result.Token)
	if err != nil {
		t.Fatalf("parsing VP token: %v", err)
	}

	foundUserID := false
	for _, d := range parsed.Disclosures {
		if d.Name == "user_id" {
			foundUserID = true
			if d.Value != "abc123" {
				t.Errorf("expected user_id value abc123, got %v", d.Value)
			}
		}
	}
	if !foundUserID {
		t.Error("user_id disclosure missing from VP token — disclosures were stripped during import/persist/present")
	}

	// Resolved claims should contain user_id
	if parsed.ResolvedClaims["user_id"] != "abc123" {
		t.Errorf("expected user_id in resolved claims, got %v", parsed.ResolvedClaims["user_id"])
	}
}

func TestEncryptResponse_UsesEncryptedResponseEncValuesSupported(t *testing.T) {
	w := generateTestWallet(t)
	key, _ := mock.GenerateKey()
	jwk := testEncJWK(t, &key.PublicKey)

	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"jwks": map[string]any{
					"keys": []any{jwk},
				},
				"encrypted_response_enc_values_supported": []any{"A256GCM", "A128GCM"},
			},
		},
	}

	params := PresentationParams{
		Nonce:         "test-nonce",
		ClientID:      "https://verifier.example",
		ResponseURI:   "https://verifier.example/response",
		ResponseMode:  "direct_post.jwt",
		RequestObject: reqObj,
	}

	jweStr, _, err := w.EncryptResponse(map[string]any{"test": "value"}, "", "state", "", params)
	if err != nil {
		t.Fatalf("EncryptResponse error: %v", err)
	}

	// Parse JWE header to verify enc algorithm
	parts := strings.Split(jweStr, ".")
	if len(parts) != 5 {
		t.Fatalf("expected 5 JWE parts, got %d", len(parts))
	}
	headerJSON, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}
	if header["enc"] != "A256GCM" {
		t.Errorf("expected enc=A256GCM (first supported value), got %v", header["enc"])
	}
}

func TestEncryptResponse_DefaultsToA128GCMWhenNoEncValues(t *testing.T) {
	w := generateTestWallet(t)
	key, _ := mock.GenerateKey()
	jwk := testEncJWK(t, &key.PublicKey)

	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"jwks": map[string]any{
					"keys": []any{jwk},
				},
			},
		},
	}

	params := PresentationParams{
		Nonce:         "test-nonce",
		ClientID:      "https://verifier.example",
		ResponseURI:   "https://verifier.example/response",
		ResponseMode:  "direct_post.jwt",
		RequestObject: reqObj,
	}

	jweStr, _, err := w.EncryptResponse(map[string]any{"test": "value"}, "", "state", "", params)
	if err != nil {
		t.Fatalf("EncryptResponse error: %v", err)
	}

	parts := strings.Split(jweStr, ".")
	headerJSON, _ := format.DecodeBase64URL(parts[0])
	var header map[string]any
	json.Unmarshal(headerJSON, &header)
	if header["enc"] != "A128GCM" {
		t.Errorf("expected default enc=A128GCM, got %v", header["enc"])
	}
}

func TestEncryptResponse_TopLevelJWKSNotUsed(t *testing.T) {
	w := generateTestWallet(t)
	key, _ := mock.GenerateKey()
	jwk := testEncJWK(t, &key.PublicKey)

	// JWK only at top-level jwks (not in client_metadata) — wallet should reject
	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"encrypted_response_enc_values_supported": []any{"A256GCM"},
			},
			"jwks": map[string]any{
				"keys": []any{jwk},
			},
		},
	}

	params := PresentationParams{
		Nonce:         "test-nonce",
		ClientID:      "https://verifier.example",
		ResponseURI:   "https://verifier.example/response",
		ResponseMode:  "direct_post.jwt",
		RequestObject: reqObj,
	}

	_, _, err := w.EncryptResponse(map[string]any{"test": "value"}, "", "state", "", params)
	if err == nil {
		t.Fatal("expected error when JWK is only in top-level jwks (not client_metadata.jwks)")
	}
}

func TestEncryptResponse_LegacyFieldNamesIgnored(t *testing.T) {
	w := generateTestWallet(t)
	key, _ := mock.GenerateKey()
	jwk := testEncJWK(t, &key.PublicKey)

	// Legacy field names only — wallet should ignore them and use default A128GCM
	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"authorization_encrypted_response_alg": "ECDH-ES",
				"authorization_encrypted_response_enc": "A256GCM",
				"jwks": map[string]any{
					"keys": []any{jwk},
				},
			},
		},
	}

	params := PresentationParams{
		Nonce:         "test-nonce",
		ClientID:      "https://verifier.example",
		ResponseURI:   "https://verifier.example/response",
		ResponseMode:  "direct_post.jwt",
		RequestObject: reqObj,
	}

	jweStr, _, err := w.EncryptResponse(map[string]any{"test": "value"}, "", "state", "", params)
	if err != nil {
		t.Fatalf("EncryptResponse error: %v", err)
	}

	parts := strings.Split(jweStr, ".")
	headerJSON, _ := format.DecodeBase64URL(parts[0])
	var header map[string]any
	json.Unmarshal(headerJSON, &header)
	// Legacy authorization_encrypted_response_enc should be ignored; default A128GCM used
	if header["enc"] != "A128GCM" {
		t.Errorf("expected default enc=A128GCM (legacy fields ignored), got %v", header["enc"])
	}
}

func TestCreateVPToken_SDJWT_SurvivesPersistReload(t *testing.T) {
	// Simulates: import → save to disk (Disclosures lost) → reload + Rehydrate → present
	w := generateTestWalletWithPID(t)

	creds := w.GetCredentials()
	var sdCred StoredCredential
	for _, c := range creds {
		if c.Format == "dc+sd-jwt" {
			sdCred = c
			break
		}
	}
	if sdCred.ID == "" {
		t.Fatal("no SD-JWT credential found")
	}

	originalDisclosureCount := len(sdCred.Disclosures)
	if originalDisclosureCount == 0 {
		t.Fatal("expected disclosures in original credential")
	}

	// Simulate persistence: clear non-serialized fields (json:"-")
	sdCred.Disclosures = nil
	sdCred.NameSpaces = nil

	// Simulate reload: rehydrate from Raw
	if err := sdCred.Rehydrate(); err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}

	if len(sdCred.Disclosures) != originalDisclosureCount {
		t.Fatalf("expected %d disclosures after rehydrate, got %d", originalDisclosureCount, len(sdCred.Disclosures))
	}

	// Put the rehydrated credential back into the wallet
	w.mu.Lock()
	for i, c := range w.Credentials {
		if c.ID == sdCred.ID {
			w.Credentials[i] = sdCred
			break
		}
	}
	w.mu.Unlock()

	// Now present — should include disclosures
	match := CredentialMatch{
		QueryID:      "test",
		CredentialID: sdCred.ID,
		Format:       "dc+sd-jwt",
		SelectedKeys: []string{"given_name", "family_name"},
	}

	result, err := w.CreateVPToken(match, PresentationParams{Nonce: "n", ClientID: "client", ResponseURI: "response"})
	if err != nil {
		t.Fatalf("CreateVPToken error: %v", err)
	}

	parsed, err := sdjwt.Parse(result.Token)
	if err != nil {
		t.Fatalf("parsing VP token: %v", err)
	}

	// Must have disclosures in the presentation
	var names []string
	for _, d := range parsed.Disclosures {
		if !d.IsArrayEntry {
			names = append(names, d.Name)
		}
	}
	if len(names) != 2 {
		t.Errorf("expected 2 disclosures after persist/reload round-trip, got %d: %v", len(names), names)
	}

	// Must have KB-JWT
	if parsed.KeyBindingJWT == nil {
		t.Error("expected KB-JWT in VP token after persist/reload round-trip")
	}
}

func TestSubmitPresentation_DirectPostJWT_NoEncryptionKey(t *testing.T) {
	w := generateTestWallet(t)

	vpResult := &VPTokenMapResult{
		TokenMap: map[string]string{"q1": "dummy-token"},
	}

	// response_mode=direct_post.jwt but no encryption key in request object
	params := PresentationParams{
		Nonce:        "n",
		ClientID:     "c",
		ResponseURI:  "https://verifier.example/response",
		ResponseMode: "direct_post.jwt",
		RequestObject: &oid4vc.RequestObjectJWT{
			Payload: map[string]any{
				"client_metadata": map[string]any{},
			},
		},
	}

	_, err := w.SubmitPresentation(vpResult, "", "state", params.ResponseURI, params)
	if err == nil {
		t.Fatal("expected error when direct_post.jwt is used without encryption key")
	}
	if !strings.Contains(err.Error(), "no encryption key") {
		t.Errorf("expected 'no encryption key' in error, got: %v", err)
	}
}

func TestEncryptResponse_UsesAlgFromJWK(t *testing.T) {
	w := generateTestWallet(t)
	key, _ := mock.GenerateKey()
	jwk := testEncJWK(t, &key.PublicKey)

	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"jwks": map[string]any{
					"keys": []any{jwk},
				},
			},
		},
	}

	params := PresentationParams{
		Nonce:         "test-nonce",
		ClientID:      "https://verifier.example",
		ResponseURI:   "https://verifier.example/response",
		ResponseMode:  "direct_post.jwt",
		RequestObject: reqObj,
	}

	jweStr, _, err := w.EncryptResponse(map[string]any{"test": "value"}, "", "state", "", params)
	if err != nil {
		t.Fatalf("EncryptResponse error: %v", err)
	}

	parts := strings.Split(jweStr, ".")
	headerJSON, _ := format.DecodeBase64URL(parts[0])
	var header map[string]any
	json.Unmarshal(headerJSON, &header)
	if header["alg"] != "ECDH-ES" {
		t.Errorf("expected alg=ECDH-ES from JWK, got %v", header["alg"])
	}
}

func TestEncryptResponse_ErrorWhenJWKMissingAlg(t *testing.T) {
	w := generateTestWallet(t)
	key, _ := mock.GenerateKey()

	// Create JWK without alg field
	jwkJSON := mock.PublicKeyJWK(&key.PublicKey)
	var jwk map[string]any
	json.Unmarshal([]byte(jwkJSON), &jwk)
	// Intentionally no jwk["alg"]

	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"jwks": map[string]any{
					"keys": []any{jwk},
				},
			},
		},
	}

	params := PresentationParams{
		Nonce:         "test-nonce",
		ClientID:      "https://verifier.example",
		ResponseURI:   "https://verifier.example/response",
		ResponseMode:  "direct_post.jwt",
		RequestObject: reqObj,
	}

	_, _, err := w.EncryptResponse(map[string]any{"test": "value"}, "", "state", "", params)
	if err == nil {
		t.Fatal("expected error when JWK is missing 'alg' field")
	}
	if !strings.Contains(err.Error(), "alg") {
		t.Errorf("expected error about missing 'alg', got: %v", err)
	}
}

func TestEncryptJWE_A128CBCHS256(t *testing.T) {
	key, _ := mock.GenerateKey()
	payload := []byte(`{"vp_token":"test","state":"s"}`)

	jweStr, cek, err := EncryptJWE(payload, &key.PublicKey, "kid1", "ECDH-ES", "A128CBC-HS256", nil)
	if err != nil {
		t.Fatalf("EncryptJWE error: %v", err)
	}

	parts := strings.Split(jweStr, ".")
	if len(parts) != 5 {
		t.Fatalf("expected 5 JWE parts, got %d", len(parts))
	}

	// Verify header
	headerJSON, _ := format.DecodeBase64URL(parts[0])
	var header map[string]any
	json.Unmarshal(headerJSON, &header)
	if header["enc"] != "A128CBC-HS256" {
		t.Errorf("expected enc=A128CBC-HS256, got %v", header["enc"])
	}
	if header["alg"] != "ECDH-ES" {
		t.Errorf("expected alg=ECDH-ES, got %v", header["alg"])
	}

	// CEK should be 32 bytes (256-bit: 128 MAC + 128 enc)
	if len(cek) != 32 {
		t.Errorf("expected 32-byte CEK, got %d bytes", len(cek))
	}

	// Encrypted key part should be empty (ECDH-ES direct key agreement)
	if parts[1] != "" {
		t.Errorf("expected empty encrypted key for ECDH-ES, got %q", parts[1])
	}

	// IV should be 16 bytes (128-bit for AES-CBC)
	ivBytes, _ := format.DecodeBase64URL(parts[2])
	if len(ivBytes) != 16 {
		t.Errorf("expected 16-byte IV, got %d bytes", len(ivBytes))
	}

	// Tag should be 16 bytes (128-bit truncated HMAC)
	tagBytes, _ := format.DecodeBase64URL(parts[4])
	if len(tagBytes) != 16 {
		t.Errorf("expected 16-byte tag, got %d bytes", len(tagBytes))
	}
}
