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
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
)

// GenerateTrustListJWT generates an ETSI TS 119 602 trust list JWT
// containing the CA certificate as the trust anchor. The trust list is
// signed with the provided signing key.
func GenerateTrustListJWT(signingKey *ecdsa.PrivateKey, caCert *x509.Certificate) (string, error) {
	certB64 := base64.StdEncoding.EncodeToString(caCert.Raw)

	// Build ETSI trust list payload
	payload := map[string]any{
		"ListAndSchemeInformation": map[string]any{
			"LoTEType":           "http://uri.etsi.org/19602/LoTEType/local",
			"SchemeOperatorName": []map[string]string{{"lang": "en", "value": "OID4VC Dev Wallet"}},
			"ListIssueDatetime":  time.Now().UTC().Format(time.RFC3339),
		},
		"TrustedEntitiesList": []map[string]any{
			{
				"TrustedEntityInformation": map[string]any{
					"TEName": []map[string]string{{"lang": "en", "value": "Wallet Issuer"}},
				},
				"TrustedEntityServices": []map[string]any{
					{
						"ServiceInformation": map[string]any{
							"ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance",
							"ServiceName":           []map[string]string{{"lang": "en", "value": "PID Issuance Service"}},
							"ServiceDigitalIdentity": map[string]any{
								"X509Certificates": []map[string]string{{"val": certB64}},
							},
						},
					},
					{
						"ServiceInformation": map[string]any{
							"ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Revocation",
							"ServiceName":           []map[string]string{{"lang": "en", "value": "PID Revocation Service"}},
							"ServiceDigitalIdentity": map[string]any{
								"X509Certificates": []map[string]string{{"val": certB64}},
							},
						},
					},
				},
			},
		},
	}

	// Build JWT header
	header := map[string]any{
		"alg": "ES256",
		"typ": "JWT",
	}

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

	r, s, err := ecdsa.Sign(rand.Reader, signingKey, h[:])
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}

	keySize := (signingKey.Curve.Params().BitSize + 7) / 8
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 2*keySize)
	copy(sig[keySize-len(rBytes):keySize], rBytes)
	copy(sig[2*keySize-len(sBytes):], sBytes)

	sigB64 := format.EncodeBase64URL(sig)

	return headerB64 + "." + payloadB64 + "." + sigB64, nil
}
