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

package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/dominikschlosser/oid4vc-dev/internal/wallet"
)

func TestDecryptJWEWithCEK(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := map[string]any{"vp_token": "test-credential", "state": "abc123"}
	payloadJSON, _ := json.Marshal(payload)

	jwe, cek, err := wallet.EncryptJWE(payloadJSON, &key.PublicKey, "test-kid", "A128GCM", nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(cek) == 0 {
		t.Fatal("expected non-empty CEK")
	}

	plaintext, err := DecryptJWEWithCEK(jwe, cek)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(plaintext, &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if result["vp_token"] != "test-credential" {
		t.Errorf("expected vp_token=test-credential, got %v", result["vp_token"])
	}
	if result["state"] != "abc123" {
		t.Errorf("expected state=abc123, got %v", result["state"])
	}
}

func TestDecryptJWEWithCEK_A256GCM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"test":"value"}`)
	jwe, cek, err := wallet.EncryptJWE(payload, &key.PublicKey, "kid", "A256GCM", nil)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := DecryptJWEWithCEK(jwe, cek)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if string(plaintext) != `{"test":"value"}` {
		t.Errorf("unexpected plaintext: %s", plaintext)
	}
}

func TestDecryptJWEWithCEK_InvalidParts(t *testing.T) {
	_, err := DecryptJWEWithCEK("not.a.jwe", []byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for invalid JWE")
	}
}

func TestDecryptJWEWithCEK_WrongKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := []byte(`{"test":"value"}`)
	jwe, _, err := wallet.EncryptJWE(payload, &key.PublicKey, "kid", "A128GCM", nil)
	if err != nil {
		t.Fatal(err)
	}

	wrongKey := make([]byte, 16)
	rand.Read(wrongKey)

	_, err = DecryptJWEWithCEK(jwe, wrongKey)
	if err == nil {
		t.Error("expected error with wrong key")
	}
}
