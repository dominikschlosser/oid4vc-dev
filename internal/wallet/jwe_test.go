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
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
)

func TestEncryptJWE_CompactFormat(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"vp_token":"test","state":"abc123"}`)
	jwe, _, err := EncryptJWE(payload, &key.PublicKey, "test-kid", "A128GCM", nil)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		t.Fatalf("expected 5 parts, got %d", len(parts))
	}

	// Encrypted key must be empty for ECDH-ES
	if parts[1] != "" {
		t.Errorf("expected empty encrypted key, got %q", parts[1])
	}

	// Decode and verify protected header
	headerJSON, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		t.Fatal(err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}

	if header["alg"] != "ECDH-ES" {
		t.Errorf("expected alg=ECDH-ES, got %v", header["alg"])
	}
	if header["enc"] != "A128GCM" {
		t.Errorf("expected enc=A128GCM, got %v", header["enc"])
	}
	if header["kid"] != "test-kid" {
		t.Errorf("expected kid=test-kid, got %v", header["kid"])
	}
	if _, ok := header["epk"]; !ok {
		t.Error("expected epk in header")
	}
	if _, ok := header["apu"]; ok {
		t.Error("expected no apu when nil")
	}
}

func TestEncryptJWE_WithAPU(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	apu := []byte("mdoc-nonce-value")
	jwe, _, err := EncryptJWE([]byte(`{}`), &key.PublicKey, "kid2", "A256GCM", apu)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(jwe, ".")
	headerJSON, _ := format.DecodeBase64URL(parts[0])

	var header map[string]any
	json.Unmarshal(headerJSON, &header)

	apuVal, ok := header["apu"].(string)
	if !ok {
		t.Fatal("expected apu in header")
	}
	decoded, err := format.DecodeBase64URL(apuVal)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "mdoc-nonce-value" {
		t.Errorf("expected apu=mdoc-nonce-value, got %s", decoded)
	}
}

func TestEncryptJWE_A256GCM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"test":"value"}`)
	jwe, _, err := EncryptJWE(payload, &key.PublicKey, "kid3", "A256GCM", nil)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		t.Fatalf("expected 5 parts, got %d", len(parts))
	}

	headerJSON, _ := format.DecodeBase64URL(parts[0])
	var header map[string]any
	json.Unmarshal(headerJSON, &header)

	if header["enc"] != "A256GCM" {
		t.Errorf("expected enc=A256GCM, got %v", header["enc"])
	}
}

func TestEncryptJWE_ReturnsCEK(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"test":"value"}`)

	// A128GCM → 16-byte key
	_, cek128, err := EncryptJWE(payload, &key.PublicKey, "kid", "A128GCM", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cek128) != 16 {
		t.Errorf("expected 16-byte CEK for A128GCM, got %d bytes", len(cek128))
	}

	// A256GCM → 32-byte key
	_, cek256, err := EncryptJWE(payload, &key.PublicKey, "kid", "A256GCM", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cek256) != 32 {
		t.Errorf("expected 32-byte CEK for A256GCM, got %d bytes", len(cek256))
	}
}
