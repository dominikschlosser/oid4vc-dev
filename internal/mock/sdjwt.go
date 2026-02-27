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

package mock

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
)

// SDJWTConfig holds options for generating a mock SD-JWT credential.
type SDJWTConfig struct {
	Issuer        string
	VCT           string
	ExpiresIn     time.Duration
	Claims        map[string]any
	Key           *ecdsa.PrivateKey
	HolderKey     *ecdsa.PublicKey // optional: adds cnf claim for holder binding
	StatusListURI string          // optional: status list URI for revocation
	StatusListIdx int             // optional: index in the status list
}

// GenerateSDJWT creates a mock SD-JWT credential with all claims selectively disclosable.
// Map values produce nested disclosures (subclaims with their own _sd array).
// Slice values produce array element disclosures ({"...": digest} entries).
func GenerateSDJWT(cfg SDJWTConfig) (string, error) {
	now := time.Now()

	// Generate disclosures and compute digests
	var disclosures []string
	var digests []string

	for name, value := range cfg.Claims {
		claimDisclosures, claimValue, err := makeDisclosure(name, value)
		if err != nil {
			return "", err
		}
		disclosures = append(disclosures, claimDisclosures...)

		// The top-level disclosure for this claim
		topDisc, topDigest, err := createDisclosure(name, claimValue)
		if err != nil {
			return "", err
		}
		disclosures = append(disclosures, topDisc)
		digests = append(digests, topDigest)
	}

	// Build payload
	payload := map[string]any{
		"iss":     cfg.Issuer,
		"iat":     now.Unix(),
		"exp":     now.Add(cfg.ExpiresIn).Unix(),
		"vct":     cfg.VCT,
		"_sd_alg": "sha-256",
		"_sd":     digests,
	}

	// Add holder binding (cnf claim with JWK)
	if cfg.HolderKey != nil {
		payload["cnf"] = map[string]any{
			"jwk": PublicKeyJWKMap(cfg.HolderKey),
		}
	}

	// Add status list reference (non-disclosed)
	if cfg.StatusListURI != "" {
		payload["status"] = map[string]any{
			"status_list": map[string]any{
				"uri": cfg.StatusListURI,
				"idx": cfg.StatusListIdx,
			},
		}
	}

	// Build header
	header := map[string]any{
		"alg": "ES256",
		"typ": "vc+sd-jwt",
	}

	// Encode header and payload
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshaling header: %w", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshaling payload: %w", err)
	}

	headerB64 := format.EncodeBase64URL(headerJSON)
	payloadB64 := format.EncodeBase64URL(payloadJSON)

	// Sign with ECDSA (JWS r||s format)
	sigInput := headerB64 + "." + payloadB64
	h := sha256.Sum256([]byte(sigInput))

	r, s, err := ecdsa.Sign(rand.Reader, cfg.Key, h[:])
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}

	// Encode r||s with fixed-size padding (32 bytes each for P-256)
	keySize := (cfg.Key.Curve.Params().BitSize + 7) / 8
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 2*keySize)
	copy(sig[keySize-len(rBytes):keySize], rBytes)
	copy(sig[2*keySize-len(sBytes):], sBytes)

	sigB64 := format.EncodeBase64URL(sig)

	// Assemble: header.payload.sig~disc1~disc2~
	jwt := headerB64 + "." + payloadB64 + "." + sigB64
	result := jwt + "~" + strings.Join(disclosures, "~") + "~"

	return result, nil
}

// makeDisclosure handles nested structures. It returns any sub-disclosures and
// the (possibly transformed) value to use in the parent disclosure.
// For plain values, it returns no sub-disclosures and the value as-is.
// For map values, it creates sub-disclosures and returns an object with _sd.
// For slice values, it creates element disclosures and returns an array with {"...": digest}.
func makeDisclosure(name string, value any) (subDisclosures []string, transformedValue any, err error) {
	switch v := value.(type) {
	case map[string]any:
		// Nested object: create disclosures for each subclaim
		var subDigests []string
		for subName, subValue := range v {
			disc, digest, err := createDisclosure(subName, subValue)
			if err != nil {
				return nil, nil, err
			}
			subDisclosures = append(subDisclosures, disc)
			subDigests = append(subDigests, digest)
		}
		transformedValue = map[string]any{"_sd": subDigests}
		return subDisclosures, transformedValue, nil

	case []any:
		// Array: create element disclosures for each item
		var elements []any
		for _, item := range v {
			disc, digest, err := createArrayElementDisclosure(item)
			if err != nil {
				return nil, nil, err
			}
			subDisclosures = append(subDisclosures, disc)
			elements = append(elements, map[string]any{"...": digest})
		}
		transformedValue = elements
		return subDisclosures, transformedValue, nil

	default:
		// Plain value: no sub-disclosures needed
		return nil, value, nil
	}
}

// createDisclosure creates a named disclosure [salt, name, value] and returns
// the encoded disclosure string and its digest.
func createDisclosure(name string, value any) (encoded string, digest string, err error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", fmt.Errorf("generating salt: %w", err)
	}

	disclosure := []any{format.EncodeBase64URL(salt), name, value}
	discJSON, err := json.Marshal(disclosure)
	if err != nil {
		return "", "", fmt.Errorf("marshaling disclosure: %w", err)
	}

	enc := format.EncodeBase64URL(discJSON)
	h := sha256.Sum256([]byte(enc))
	return enc, format.EncodeBase64URL(h[:]), nil
}

// createArrayElementDisclosure creates an array element disclosure [salt, value]
// and returns the encoded disclosure string and its digest.
func createArrayElementDisclosure(value any) (encoded string, digest string, err error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", fmt.Errorf("generating salt: %w", err)
	}

	disclosure := []any{format.EncodeBase64URL(salt), value}
	discJSON, err := json.Marshal(disclosure)
	if err != nil {
		return "", "", fmt.Errorf("marshaling disclosure: %w", err)
	}

	enc := format.EncodeBase64URL(discJSON)
	h := sha256.Sum256([]byte(enc))
	return enc, format.EncodeBase64URL(h[:]), nil
}

// signECDSA signs a digest and returns the JWS r||s encoded signature.
func signECDSA(key *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, err
	}

	keySize := (key.Curve.Params().BitSize + 7) / 8
	rBytes := padToSize(r.Bytes(), keySize)
	sBytes := padToSize(s.Bytes(), keySize)

	return append(rBytes, sBytes...), nil
}

func padToSize(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

// verifyRoundTrip is a helper to verify a generated signature is valid (used in tests).
func verifyRoundTrip(key *ecdsa.PublicKey, sigInput []byte, sig []byte) bool {
	h := sha256.Sum256(sigInput)
	keySize := (key.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*keySize {
		return false
	}
	r := new(big.Int).SetBytes(sig[:keySize])
	s := new(big.Int).SetBytes(sig[keySize:])
	return ecdsa.Verify(key, h[:], r, s)
}
