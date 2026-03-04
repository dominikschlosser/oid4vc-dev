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
	"fmt"
	"log"

	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
)

// extractJWKThumbprint extracts the encryption JWK from the request object
// and computes its RFC 7638 thumbprint (SHA-256).
// Returns nil if no encryption key is found.
func extractJWKThumbprint(reqObj *oid4vc.RequestObjectJWT) []byte {
	jwk := findEncryptionJWK(reqObj)
	if jwk == nil {
		return nil
	}
	return computeJWKThumbprint(jwk)
}

// findEncryptionJWK locates the first encryption JWK from client_metadata.jwks
// per OID4VP 1.0. No fallback to other locations — the wallet enforces strict
// spec compliance so verifiers can detect misconfigurations.
func findEncryptionJWK(reqObj *oid4vc.RequestObjectJWT) map[string]any {
	if reqObj == nil || reqObj.Payload == nil {
		return nil
	}

	clientMeta, ok := reqObj.Payload["client_metadata"].(map[string]any)
	if !ok {
		return nil
	}
	return firstJWK(clientMeta["jwks"])
}

// firstJWK extracts the first key from a JWKS value ({"keys": [...]}).
func firstJWK(jwksVal any) map[string]any {
	jwks, ok := jwksVal.(map[string]any)
	if !ok {
		return nil
	}
	keysSlice, ok := jwks["keys"].([]any)
	if !ok || len(keysSlice) == 0 {
		return nil
	}
	jwk, ok := keysSlice[0].(map[string]any)
	if !ok {
		return nil
	}
	return jwk
}

// computeJWKThumbprint computes the RFC 7638 JWK Thumbprint using SHA-256.
// For EC keys, the required members in lexicographic order are: crv, kty, x, y.
// For RSA keys: e, kty, n.
func computeJWKThumbprint(jwk map[string]any) []byte {
	kty, _ := jwk["kty"].(string)

	var canonical map[string]string
	switch kty {
	case "EC":
		crv, _ := jwk["crv"].(string)
		x, _ := jwk["x"].(string)
		y, _ := jwk["y"].(string)
		if crv == "" || x == "" || y == "" {
			return nil
		}
		canonical = map[string]string{"crv": crv, "kty": kty, "x": x, "y": y}
	case "RSA":
		e, _ := jwk["e"].(string)
		n, _ := jwk["n"].(string)
		if e == "" || n == "" {
			return nil
		}
		canonical = map[string]string{"e": e, "kty": kty, "n": n}
	default:
		return nil
	}

	// RFC 7638: JSON must have members in lexicographic order, no whitespace
	canonicalJSON, err := json.Marshal(canonical)
	if err != nil {
		return nil
	}

	hash := sha256.Sum256(canonicalJSON)
	return hash[:]
}

// encryptionKeyInfo holds the extracted encryption key parameters from a JWK.
type encryptionKeyInfo struct {
	Key *ecdsa.PublicKey
	Kid string
	Alg string // JWE algorithm (e.g. "ECDH-ES") — MUST be present per OID4VP 1.0
}

// extractEncryptionKey extracts the EC public key, kid, and alg from
// client_metadata.jwks per OID4VP 1.0.
func extractEncryptionKey(reqObj *oid4vc.RequestObjectJWT) (*encryptionKeyInfo, error) {
	jwk := findEncryptionJWK(reqObj)
	if jwk == nil {
		return nil, fmt.Errorf("no encryption JWK found in client_metadata.jwks")
	}

	x, _ := jwk["x"].(string)
	y, _ := jwk["y"].(string)
	kid, _ := jwk["kid"].(string)
	alg, _ := jwk["alg"].(string)

	if x == "" || y == "" {
		return nil, fmt.Errorf("missing x or y in JWK")
	}
	if alg == "" {
		return nil, fmt.Errorf("JWK missing required 'alg' parameter (OID4VP 1.0 requires alg in each JWK)")
	}

	pubKey, err := ecdsaPublicKeyFromJWK(x, y)
	if err != nil {
		return nil, fmt.Errorf("constructing EC key: %w", err)
	}

	return &encryptionKeyInfo{Key: pubKey, Kid: kid, Alg: alg}, nil
}

// HasEncryptionKey checks if the request object contains a valid encryption JWK.
func HasEncryptionKey(reqObj *oid4vc.RequestObjectJWT) bool {
	_, err := extractEncryptionKey(reqObj)
	return err == nil
}

// EncryptResponse encrypts vp_token and state as a JWE for direct_post.jwt response mode.
// Returns the JWE string and the derived content encryption key (CEK) for debugging.
func (w *Wallet) EncryptResponse(vpToken any, state string, mdocNonce string, params PresentationParams) (string, []byte, error) {
	log.Printf("[VP] Encrypting response: response_mode=direct_post.jwt")
	payload := map[string]any{
		"vp_token": vpToken,
		"state":    state,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", nil, fmt.Errorf("marshaling response payload: %w", err)
	}

	keyInfo, err := extractEncryptionKey(params.RequestObject)
	if err != nil {
		return "", nil, fmt.Errorf("extracting encryption key: %w", err)
	}

	// Determine enc algorithm from client_metadata
	// OID4VP 1.0: encrypted_response_enc_values_supported (array)
	enc := "A128GCM"
	if params.RequestObject != nil && params.RequestObject.Payload != nil {
		enc = detectEncAlgorithm(params.RequestObject.Payload, enc)
	}

	// For ISO mode with mdoc_generated_nonce, set apu
	var apu []byte
	if mdocNonce != "" {
		apu = []byte(mdocNonce)
	}

	return EncryptJWE(payloadJSON, keyInfo.Key, keyInfo.Kid, keyInfo.Alg, enc, apu)
}

// detectEncAlgorithm finds the content encryption algorithm from
// client_metadata.encrypted_response_enc_values_supported per OID4VP 1.0.
// No fallback to legacy field names — strict spec compliance.
func detectEncAlgorithm(payload map[string]any, fallback string) string {
	clientMeta, ok := payload["client_metadata"].(map[string]any)
	if !ok {
		return fallback
	}

	if arr, ok := clientMeta["encrypted_response_enc_values_supported"].([]any); ok && len(arr) > 0 {
		if v, ok := arr[0].(string); ok && v != "" {
			return v
		}
	}

	return fallback
}
