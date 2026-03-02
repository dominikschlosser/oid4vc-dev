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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
)

// VerifyClientID validates the client_id prefix against the request object and
// response URI per OID4VP 1.0 Client Identifier Prefixes.
// Returns a warning string if there's a mismatch, or "" if OK / not applicable.
func VerifyClientID(clientID string, reqObj *oid4vc.RequestObjectJWT, responseURI string) string {
	switch {
	case strings.HasPrefix(clientID, "x509_san_dns:"):
		return verifyX509SAN(clientID, "x509_san_dns:", "dns", reqObj)
	case strings.HasPrefix(clientID, "x509_hash:"):
		return verifyX509Hash(clientID, reqObj)
	case strings.HasPrefix(clientID, "redirect_uri:"):
		return verifyRedirectURI(clientID, reqObj, responseURI)
	default:
		return ""
	}
}

// verifyX509SAN checks that the leaf certificate SAN contains the expected DNS name.
func verifyX509SAN(clientID, prefix, scheme string, reqObj *oid4vc.RequestObjectJWT) string {
	expected := strings.TrimPrefix(clientID, prefix)

	cert, warning := extractLeafCert(reqObj)
	if warning != "" {
		return warning
	}

	switch scheme {
	case "dns":
		for _, name := range cert.DNSNames {
			if name == expected {
				return ""
			}
		}
		return fmt.Sprintf("client_id expects DNS SAN %q but leaf certificate has DNSNames=%v", expected, cert.DNSNames)
	}

	return ""
}

// verifyX509Hash checks that SHA-256(leaf cert DER) matches the hash in client_id.
func verifyX509Hash(clientID string, reqObj *oid4vc.RequestObjectJWT) string {
	expectedHash := strings.TrimPrefix(clientID, "x509_hash:")

	expectedBytes, err := format.DecodeBase64URL(expectedHash)
	if err != nil {
		return fmt.Sprintf("x509_hash: client_id value is not valid base64url: %v", err)
	}

	cert, warning := extractLeafCert(reqObj)
	if warning != "" {
		return warning
	}

	actualHash := sha256.Sum256(cert.Raw)
	if string(expectedBytes) != string(actualHash[:]) {
		return fmt.Sprintf("x509_hash: SHA-256 of leaf certificate does not match client_id hash")
	}

	return ""
}

// verifyRedirectURI checks that the redirect_uri: prefix value matches the
// response URI and that no signed request object is used.
func verifyRedirectURI(clientID string, reqObj *oid4vc.RequestObjectJWT, responseURI string) string {
	expected := strings.TrimPrefix(clientID, "redirect_uri:")

	if reqObj != nil && reqObj.Header != nil {
		return "redirect_uri: prefix MUST NOT use signed request objects (OID4VP 1.0)"
	}

	if responseURI != "" && expected != responseURI {
		return fmt.Sprintf("redirect_uri: prefix value %q does not match response_uri %q", expected, responseURI)
	}

	return ""
}

// extractLeafCert extracts and parses the leaf certificate from the request
// object's x5c header. Returns a warning if extraction fails.
func extractLeafCert(reqObj *oid4vc.RequestObjectJWT) (*x509.Certificate, string) {
	if reqObj == nil || reqObj.Header == nil {
		return nil, "client_id uses x509 scheme but request object has no x5c header"
	}

	x5cRaw, ok := reqObj.Header["x5c"]
	if !ok {
		return nil, "client_id uses x509 scheme but request object has no x5c header"
	}

	x5cArr, ok := x5cRaw.([]any)
	if !ok || len(x5cArr) == 0 {
		return nil, "client_id uses x509 scheme but x5c header is empty"
	}

	leafB64, ok := x5cArr[0].(string)
	if !ok {
		return nil, "client_id uses x509 scheme but x5c[0] is not a string"
	}

	der, err := format.DecodeBase64Std(leafB64)
	if err != nil {
		return nil, fmt.Sprintf("client_id uses x509 scheme but failed to decode x5c[0]: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Sprintf("client_id uses x509 scheme but failed to parse leaf certificate: %v", err)
	}

	return cert, ""
}

// prefixRequiresSigning returns true if the client_id prefix requires a signed
// Request Object per OID4VP 1.0.
func prefixRequiresSigning(clientID string) bool {
	prefixes := []string{"x509_san_dns:", "x509_hash:", "decentralized_identifier:", "verifier_attestation:"}
	for _, p := range prefixes {
		if strings.HasPrefix(clientID, p) {
			return true
		}
	}
	return false
}

// ValidateRequestObject checks that the Request Object's typ header is
// "oauth-authz-req+jwt" per OID4VP 1.0 / RFC 9101.
// Also warns if the client_id prefix requires signing but no Request Object is present.
func ValidateRequestObject(clientID string, reqObj *oid4vc.RequestObjectJWT) string {
	if reqObj == nil {
		if prefixRequiresSigning(clientID) {
			return fmt.Sprintf("client_id prefix requires a signed Request Object but none was provided")
		}
		return ""
	}

	if reqObj.Header == nil {
		return "Request Object has no header"
	}

	typ, _ := reqObj.Header["typ"].(string)
	if typ == "" {
		return "Request Object missing 'typ' header (OID4VP 1.0 requires typ: oauth-authz-req+jwt)"
	}
	if typ != "oauth-authz-req+jwt" {
		return fmt.Sprintf("Request Object has typ %q but OID4VP 1.0 requires 'oauth-authz-req+jwt'", typ)
	}

	// Verify that the alg header matches the key type in the x5c certificate.
	if warning := verifyAlgMatchesCert(reqObj); warning != "" {
		return warning
	}

	return ""
}

// verifyAlgMatchesCert checks that the JWT "alg" header is compatible with the
// public key type in the x5c leaf certificate. Returns a warning on mismatch,
// or "" if OK or if x5c is not present.
func verifyAlgMatchesCert(reqObj *oid4vc.RequestObjectJWT) string {
	alg, _ := reqObj.Header["alg"].(string)
	if alg == "" {
		return ""
	}

	// Only check when x5c is present.
	cert, warning := extractLeafCert(reqObj)
	if warning != "" {
		// No x5c — nothing to cross-check.
		return ""
	}

	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !strings.HasPrefix(alg, "ES") {
			return fmt.Sprintf("Request Object alg %q is not compatible with EC key in x5c certificate", alg)
		}
	case *rsa.PublicKey:
		if !strings.HasPrefix(alg, "RS") && !strings.HasPrefix(alg, "PS") {
			return fmt.Sprintf("Request Object alg %q is not compatible with RSA key in x5c certificate", alg)
		}
	}

	return ""
}
