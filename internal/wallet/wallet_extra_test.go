package wallet

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
)

func TestSubscribeErrors(t *testing.T) {
	w := generateTestWallet(t)

	ch, unsub := w.SubscribeErrors()
	defer unsub()

	go w.NotifyError(WalletError{Message: "test error", Detail: "detail"})

	select {
	case err := <-ch:
		if err.Message != "test error" {
			t.Errorf("expected 'test error', got %s", err.Message)
		}
		if err.Detail != "detail" {
			t.Errorf("expected 'detail', got %s", err.Detail)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for error notification")
	}
}

func TestPopLastError(t *testing.T) {
	w := generateTestWallet(t)

	// No error yet
	if err := w.PopLastError(); err != nil {
		t.Errorf("expected nil, got %v", err)
	}

	// Notify error
	w.NotifyError(WalletError{Message: "first"})
	w.NotifyError(WalletError{Message: "second"})

	// Pop should return last error
	err := w.PopLastError()
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if err.Message != "second" {
		t.Errorf("expected 'second', got %s", err.Message)
	}

	// Pop again should return nil
	if err := w.PopLastError(); err != nil {
		t.Errorf("expected nil after pop, got %v", err)
	}
}

func TestRehydrate_SDJWT(t *testing.T) {
	key, _ := mock.GenerateKey()
	sdjwt, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://test.example",
		VCT:       "TestCred",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"name": "Test"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("generating SD-JWT: %v", err)
	}

	cred := StoredCredential{
		ID:     "test-id",
		Format: "dc+sd-jwt",
		Raw:    sdjwt,
	}

	if err := cred.Rehydrate(); err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}

	if len(cred.Disclosures) == 0 {
		t.Error("expected disclosures after rehydrate")
	}
	if cred.Claims == nil || len(cred.Claims) == 0 {
		t.Error("expected claims after rehydrate")
	}
}

func TestRehydrate_MDoc(t *testing.T) {
	key, _ := mock.GenerateKey()
	mdocRaw, err := mock.GenerateMDOC(mock.MDOCConfig{
		DocType:   "org.test.cred",
		Namespace: "org.test.cred",
		Claims:    map[string]any{"field": "value"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("generating mDoc: %v", err)
	}

	cred := StoredCredential{
		ID:     "test-id",
		Format: "mso_mdoc",
		Raw:    mdocRaw,
	}

	if err := cred.Rehydrate(); err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}

	if cred.NameSpaces == nil || len(cred.NameSpaces) == 0 {
		t.Error("expected namespaces after rehydrate")
	}
	if cred.Claims == nil || len(cred.Claims) == 0 {
		t.Error("expected claims after rehydrate")
	}
}

func TestRehydrate_EmptyRaw(t *testing.T) {
	cred := StoredCredential{ID: "test-id"}
	if err := cred.Rehydrate(); err != nil {
		t.Errorf("expected no error for empty raw, got %v", err)
	}
}

func TestRehydrate_PreservesExistingClaims(t *testing.T) {
	key, _ := mock.GenerateKey()
	sdjwt, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://test.example",
		VCT:       "TestCred",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"name": "Test"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("generating SD-JWT: %v", err)
	}

	existingClaims := map[string]any{"custom": "value"}
	cred := StoredCredential{
		ID:     "test-id",
		Format: "dc+sd-jwt",
		Raw:    sdjwt,
		Claims: existingClaims,
	}

	if err := cred.Rehydrate(); err != nil {
		t.Fatalf("Rehydrate: %v", err)
	}

	// Should preserve existing claims
	if cred.Claims["custom"] != "value" {
		t.Error("expected existing claims to be preserved")
	}
}

func TestMarshalConsentRequest(t *testing.T) {
	now := time.Now()
	req := &ConsentRequest{
		ID:       "req-1",
		Type:     "presentation",
		Status:   "pending",
		ClientID: "https://verifier.example",
		Nonce:    "nonce123",
		ResponseURI: "https://verifier.example/callback",
		CreatedAt: now,
		MatchedCreds: []CredentialMatch{
			{QueryID: "pid", Format: "dc+sd-jwt"},
		},
		DCQLQuery: map[string]any{"credentials": []any{}},
	}

	m := MarshalConsentRequest(req)

	if m["id"] != "req-1" {
		t.Errorf("expected id req-1, got %v", m["id"])
	}
	if m["type"] != "presentation" {
		t.Errorf("expected type presentation, got %v", m["type"])
	}
	if m["client_id"] != "https://verifier.example" {
		t.Errorf("expected client_id, got %v", m["client_id"])
	}
	if m["nonce"] != "nonce123" {
		t.Errorf("expected nonce, got %v", m["nonce"])
	}
	if m["response_uri"] != "https://verifier.example/callback" {
		t.Errorf("expected response_uri, got %v", m["response_uri"])
	}
	if m["dcql_query"] == nil {
		t.Error("expected dcql_query")
	}
}

func TestMarshalConsentRequest_MinimalFields(t *testing.T) {
	req := &ConsentRequest{
		ID:        "req-2",
		Type:      "issuance",
		Status:    "approved",
		ClientID:  "test",
		CreatedAt: time.Now(),
	}

	m := MarshalConsentRequest(req)

	if _, ok := m["nonce"]; ok {
		t.Error("expected no nonce field when empty")
	}
	if _, ok := m["response_uri"]; ok {
		t.Error("expected no response_uri field when empty")
	}
	if _, ok := m["dcql_query"]; ok {
		t.Error("expected no dcql_query field when nil")
	}
}

func TestHasEncryptionKey_NoRequestObject(t *testing.T) {
	if HasEncryptionKey(nil) {
		t.Error("expected false for nil request object")
	}
}

func TestHasEncryptionKey_NoPayload(t *testing.T) {
	reqObj := &oid4vc.RequestObjectJWT{}
	if HasEncryptionKey(reqObj) {
		t.Error("expected false for nil payload")
	}
}

func TestHasEncryptionKey_NoClientMetadata(t *testing.T) {
	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{},
	}
	if HasEncryptionKey(reqObj) {
		t.Error("expected false for missing client_metadata")
	}
}

func TestHasEncryptionKey_WithKey(t *testing.T) {
	key, _ := mock.GenerateKey()
	jwkJSON := mock.PublicKeyJWK(&key.PublicKey)

	var jwk map[string]any
	if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
		t.Fatalf("parsing JWK: %v", err)
	}

	reqObj := &oid4vc.RequestObjectJWT{
		Payload: map[string]any{
			"client_metadata": map[string]any{
				"jwks": map[string]any{
					"keys": []any{jwk},
				},
			},
		},
	}
	if !HasEncryptionKey(reqObj) {
		t.Error("expected true for valid encryption key")
	}
}
