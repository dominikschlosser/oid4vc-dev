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

package mock

import (
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/sdjwt"
)

func TestGenerateSDJWT_DefaultClaims(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cfg := SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "urn:eudi:pid:1",
		ExpiresIn: 24 * time.Hour,
		Claims:    DefaultClaims,
		Key:       key,
	}

	result, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	// Must end with ~
	if !strings.HasSuffix(result, "~") {
		t.Error("SD-JWT should end with ~")
	}

	// Parse with existing parser
	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	// Check header
	if alg, _ := token.Header["alg"].(string); alg != "ES256" {
		t.Errorf("expected alg ES256, got %s", alg)
	}
	if typ, _ := token.Header["typ"].(string); typ != "vc+sd-jwt" {
		t.Errorf("expected typ vc+sd-jwt, got %s", typ)
	}

	// Check payload fields
	if iss, _ := token.Payload["iss"].(string); iss != "https://issuer.example" {
		t.Errorf("expected iss https://issuer.example, got %s", iss)
	}
	if vct, _ := token.Payload["vct"].(string); vct != "urn:eudi:pid:1" {
		t.Errorf("expected vct urn:eudi:pid:1, got %s", vct)
	}

	// Check disclosures match claims
	if len(token.Disclosures) != len(DefaultClaims) {
		t.Errorf("expected %d disclosures, got %d", len(DefaultClaims), len(token.Disclosures))
	}

	// Check resolved claims contain all expected values
	for name, expected := range DefaultClaims {
		val, ok := token.ResolvedClaims[name]
		if !ok {
			t.Errorf("missing resolved claim %q", name)
			continue
		}
		if val != expected {
			t.Errorf("claim %q: expected %v, got %v", name, expected, val)
		}
	}

	// Verify signature using the key
	verifyResult := sdjwt.Verify(token, &key.PublicKey)
	if !verifyResult.SignatureValid {
		t.Errorf("signature verification failed: %v", verifyResult.Errors)
	}
}

func TestGenerateSDJWT_PIDClaims(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cfg := SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "urn:eudi:pid:1",
		ExpiresIn: 24 * time.Hour,
		Claims:    SDJWTPIDClaims,
		Key:       key,
	}

	result, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	// SD-JWT PID claims: top-level disclosures + address subclaim disclosures (5) + nationalities element disclosures (1)
	expectedTopLevel := len(SDJWTPIDClaims)
	expectedAddressSubs := len(SDJWTPIDClaims["address"].(map[string]any))
	expectedNationalitiesElems := len(SDJWTPIDClaims["nationalities"].([]any))
	expectedTotal := expectedTopLevel + expectedAddressSubs + expectedNationalitiesElems
	if len(token.Disclosures) != expectedTotal {
		t.Errorf("expected %d disclosures (top=%d + address=%d + nationalities=%d), got %d",
			expectedTotal, expectedTopLevel, expectedAddressSubs, expectedNationalitiesElems, len(token.Disclosures))
	}

	// Check that resolved claims contain address subclaims
	addr, ok := token.ResolvedClaims["address"].(map[string]any)
	if !ok {
		t.Fatal("expected address to be a map in resolved claims")
	}
	for _, field := range []string{"street_address", "locality", "postal_code", "country", "region"} {
		if _, ok := addr[field]; !ok {
			t.Errorf("address missing subclaim %q", field)
		}
	}

	// Check that nationalities is resolved as array
	nats, ok := token.ResolvedClaims["nationalities"].([]any)
	if !ok {
		t.Fatal("expected nationalities to be an array in resolved claims")
	}
	if len(nats) != 1 || nats[0] != "DE" {
		t.Errorf("expected nationalities=[DE], got %v", nats)
	}

	// Verify signature
	verifyResult := sdjwt.Verify(token, &key.PublicKey)
	if !verifyResult.SignatureValid {
		t.Errorf("signature verification failed: %v", verifyResult.Errors)
	}
}

func TestGenerateSDJWT_CustomClaims(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	claims := map[string]any{"name": "Test", "score": float64(42)}

	cfg := SDJWTConfig{
		Issuer:    "https://test.example",
		VCT:       "test-type",
		ExpiresIn: time.Hour,
		Claims:    claims,
		Key:       key,
	}

	result, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	if len(token.Disclosures) != 2 {
		t.Errorf("expected 2 disclosures, got %d", len(token.Disclosures))
	}

	verifyResult := sdjwt.Verify(token, &key.PublicKey)
	if !verifyResult.SignatureValid {
		t.Errorf("signature verification failed: %v", verifyResult.Errors)
	}
}

func TestGenerateSDJWT_EmptyClaims(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cfg := SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "urn:eudi:pid:1",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{},
		Key:       key,
	}

	result, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	if len(token.Disclosures) != 0 {
		t.Errorf("expected 0 disclosures, got %d", len(token.Disclosures))
	}

	verifyResult := sdjwt.Verify(token, &key.PublicKey)
	if !verifyResult.SignatureValid {
		t.Errorf("signature verification failed: %v", verifyResult.Errors)
	}
}

func TestGenerateSDJWT_CustomIssuerAndVCT(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cfg := SDJWTConfig{
		Issuer:    "https://custom-issuer.de",
		VCT:       "urn:custom:type:2",
		ExpiresIn: 48 * time.Hour,
		Claims:    map[string]any{"foo": "bar"},
		Key:       key,
	}

	result, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	if iss, _ := token.Payload["iss"].(string); iss != "https://custom-issuer.de" {
		t.Errorf("expected iss https://custom-issuer.de, got %s", iss)
	}
	if vct, _ := token.Payload["vct"].(string); vct != "urn:custom:type:2" {
		t.Errorf("expected vct urn:custom:type:2, got %s", vct)
	}

	// Check exp is ~48h from iat
	iat, _ := token.Payload["iat"].(float64)
	exp, _ := token.Payload["exp"].(float64)
	diff := exp - iat
	if diff < 47*3600 || diff > 49*3600 {
		t.Errorf("expected ~48h between iat and exp, got %.0fs", diff)
	}
}

func TestGenerateSDJWT_WrongKeyFailsVerify(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()

	cfg := SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "urn:eudi:pid:1",
		ExpiresIn: 24 * time.Hour,
		Claims:    DefaultClaims,
		Key:       key1,
	}

	result, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	// Verify with different key should fail
	verifyResult := sdjwt.Verify(token, &key2.PublicKey)
	if verifyResult.SignatureValid {
		t.Error("signature should not verify with a different key")
	}
}

func TestGenerateSDJWT_NestedClaimValues(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	claims := map[string]any{
		"address": map[string]any{
			"street": "Main St",
			"city":   "Berlin",
		},
		"tags": []any{"admin", "user"},
	}

	cfg := SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "test",
		ExpiresIn: time.Hour,
		Claims:    claims,
		Key:       key,
	}

	result, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	// 2 top-level + 2 address subclaims + 2 array elements = 6 disclosures
	if len(token.Disclosures) != 6 {
		t.Errorf("expected 6 disclosures, got %d", len(token.Disclosures))
	}

	// Check address resolved correctly
	addr, ok := token.ResolvedClaims["address"].(map[string]any)
	if !ok {
		t.Fatal("expected address to be a map")
	}
	if addr["street"] != "Main St" {
		t.Errorf("expected street=Main St, got %v", addr["street"])
	}
	if addr["city"] != "Berlin" {
		t.Errorf("expected city=Berlin, got %v", addr["city"])
	}

	// Check tags resolved correctly
	tags, ok := token.ResolvedClaims["tags"].([]any)
	if !ok {
		t.Fatal("expected tags to be an array")
	}
	if len(tags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(tags))
	}

	verifyResult := sdjwt.Verify(token, &key.PublicKey)
	if !verifyResult.SignatureValid {
		t.Errorf("signature verification failed: %v", verifyResult.Errors)
	}
}

func TestGenerateSDJWT_UniqueDisclosures(t *testing.T) {
	key, _ := GenerateKey()

	cfg := SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "test",
		ExpiresIn: time.Hour,
		Claims:    SDJWTPIDClaims,
		Key:       key,
	}

	result, _ := GenerateSDJWT(cfg)
	token, _ := sdjwt.Parse(result)

	// All disclosure digests should be unique
	seen := make(map[string]bool)
	for _, d := range token.Disclosures {
		if seen[d.Digest] {
			t.Errorf("duplicate disclosure digest: %s", d.Digest)
		}
		seen[d.Digest] = true
	}

	// All disclosure salts should be unique
	seenSalts := make(map[string]bool)
	for _, d := range token.Disclosures {
		if seenSalts[d.Salt] {
			t.Errorf("duplicate disclosure salt: %s", d.Salt)
		}
		seenSalts[d.Salt] = true
	}
}

func TestGenerateSDJWT_WithNotBefore(t *testing.T) {
	key, _ := GenerateKey()
	nbf := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	cfg := SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "test",
		ExpiresIn: 24 * time.Hour,
		NotBefore: &nbf,
		Claims:    map[string]any{"name": "test"},
		Key:       key,
	}

	result, err := GenerateSDJWT(cfg)
	if err != nil {
		t.Fatal(err)
	}

	token, err := sdjwt.Parse(result)
	if err != nil {
		t.Fatal(err)
	}

	nbfVal, ok := token.Payload["nbf"].(float64)
	if !ok {
		t.Fatal("expected nbf in payload")
	}
	if int64(nbfVal) != nbf.Unix() {
		t.Errorf("expected nbf=%d, got %d", nbf.Unix(), int64(nbfVal))
	}
}

func TestGenerateSDJWT_WithoutNotBefore(t *testing.T) {
	key, _ := GenerateKey()

	cfg := SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       "test",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"name": "test"},
		Key:       key,
	}

	result, _ := GenerateSDJWT(cfg)
	token, _ := sdjwt.Parse(result)

	if _, ok := token.Payload["nbf"]; ok {
		t.Error("nbf should not be present when NotBefore is nil")
	}
}
