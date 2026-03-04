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
	"strings"
	"testing"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
	"github.com/dominikschlosser/oid4vc-dev/internal/sdjwt"
)

func TestGenerateTrustListJWT_ValidSignature(t *testing.T) {
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatalf("GenerateCACert: %v", err)
	}

	jwt, err := GenerateTrustListJWT(caKey, caCert)
	if err != nil {
		t.Fatalf("GenerateTrustListJWT: %v", err)
	}

	// Parse the JWT and verify signature
	token, err := sdjwt.Parse(jwt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	result := sdjwt.Verify(token, &caKey.PublicKey)
	if !result.SignatureValid {
		t.Errorf("expected valid signature, got errors: %v", result.Errors)
	}
}

func TestGenerateTrustListJWT_Header(t *testing.T) {
	caKey, _ := mock.GenerateKey()
	caCert, _ := mock.GenerateCACert(caKey)

	jwt, err := GenerateTrustListJWT(caKey, caCert)
	if err != nil {
		t.Fatalf("GenerateTrustListJWT: %v", err)
	}

	// Decode header
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		t.Fatalf("decoding header: %v", err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("parsing header: %v", err)
	}

	if alg, _ := header["alg"].(string); alg != "ES256" {
		t.Errorf("expected alg ES256, got %q", alg)
	}
	if typ, _ := header["typ"].(string); typ != "JWT" {
		t.Errorf("expected typ JWT, got %q", typ)
	}
}

func TestGenerateTrustListJWT_PayloadStructure(t *testing.T) {
	caKey, _ := mock.GenerateKey()
	caCert, _ := mock.GenerateCACert(caKey)

	jwt, err := GenerateTrustListJWT(caKey, caCert)
	if err != nil {
		t.Fatalf("GenerateTrustListJWT: %v", err)
	}

	parts := strings.SplitN(jwt, ".", 3)
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parsing payload: %v", err)
	}

	if _, ok := payload["ListAndSchemeInformation"]; !ok {
		t.Error("expected ListAndSchemeInformation in payload")
	}
	if _, ok := payload["TrustedEntitiesList"]; !ok {
		t.Error("expected TrustedEntitiesList in payload")
	}

	// Verify the trusted entities list has entries with certificate data
	entities, ok := payload["TrustedEntitiesList"].([]any)
	if !ok || len(entities) == 0 {
		t.Fatal("expected non-empty TrustedEntitiesList")
	}
}

func TestGenerateTrustListJWT_WrongKeyVerification(t *testing.T) {
	caKey, _ := mock.GenerateKey()
	otherKey, _ := mock.GenerateKey()
	caCert, _ := mock.GenerateCACert(caKey)

	jwt, err := GenerateTrustListJWT(caKey, caCert)
	if err != nil {
		t.Fatalf("GenerateTrustListJWT: %v", err)
	}

	token, _ := sdjwt.Parse(jwt)
	result := sdjwt.Verify(token, &otherKey.PublicKey)
	if result.SignatureValid {
		t.Error("expected invalid signature with wrong key")
	}
}
