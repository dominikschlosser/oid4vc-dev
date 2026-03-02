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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
)

func testCertDER(dnsNames []string) (string, []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return base64.StdEncoding.EncodeToString(der), der
}

func testRSACertDER() (string, []byte) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-rsa"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.com"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return base64.StdEncoding.EncodeToString(der), der
}

func reqObjWithX5C(certs ...string) *oid4vc.RequestObjectJWT {
	x5c := make([]any, len(certs))
	for i, c := range certs {
		x5c[i] = c
	}
	return &oid4vc.RequestObjectJWT{
		Header: map[string]any{"x5c": x5c},
	}
}

func TestVerifyClientID_X509SanDNS(t *testing.T) {
	certB64, _ := testCertDER([]string{"example.com", "other.com"})

	tests := []struct {
		name      string
		clientID  string
		reqObj    *oid4vc.RequestObjectJWT
		wantEmpty bool
	}{
		{"no prefix", "https://verifier.example", reqObjWithX5C(certB64), true},
		{"dns match", "x509_san_dns:example.com", reqObjWithX5C(certB64), true},
		{"dns mismatch", "x509_san_dns:wrong.example", reqObjWithX5C(certB64), false},
		{"nil request object", "x509_san_dns:example.com", nil, false},
		{"no x5c header", "x509_san_dns:example.com", &oid4vc.RequestObjectJWT{Header: map[string]any{}}, false},
		{"empty x5c array", "x509_san_dns:example.com", &oid4vc.RequestObjectJWT{Header: map[string]any{"x5c": []any{}}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := VerifyClientID(tt.clientID, tt.reqObj, "")
			if tt.wantEmpty && warning != "" {
				t.Errorf("expected no warning, got: %s", warning)
			}
			if !tt.wantEmpty && warning == "" {
				t.Error("expected a warning, got empty string")
			}
		})
	}
}

func TestVerifyClientID_X509Hash(t *testing.T) {
	certB64, der := testCertDER([]string{"example.com"})
	hash := sha256.Sum256(der)
	correctHash := format.EncodeBase64URL(hash[:])
	wrongHash := format.EncodeBase64URL([]byte("wrong-hash-value-1234567890123"))

	tests := []struct {
		name      string
		clientID  string
		wantEmpty bool
	}{
		{"matching hash", "x509_hash:" + correctHash, true},
		{"mismatched hash", "x509_hash:" + wrongHash, false},
		{"invalid base64url", "x509_hash:not-valid!!", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := VerifyClientID(tt.clientID, reqObjWithX5C(certB64), "")
			if tt.wantEmpty && warning != "" {
				t.Errorf("expected no warning, got: %s", warning)
			}
			if !tt.wantEmpty && warning == "" {
				t.Error("expected a warning, got empty string")
			}
		})
	}
}

func TestVerifyClientID_RedirectURI(t *testing.T) {
	tests := []struct {
		name        string
		clientID    string
		reqObj      *oid4vc.RequestObjectJWT
		responseURI string
		wantEmpty   bool
	}{
		{
			name:        "matching URI",
			clientID:    "redirect_uri:https://verifier.example/callback",
			responseURI: "https://verifier.example/callback",
			wantEmpty:   true,
		},
		{
			name:        "mismatched URI",
			clientID:    "redirect_uri:https://verifier.example/callback",
			responseURI: "https://other.example/callback",
			wantEmpty:   false,
		},
		{
			name:      "with request object (not allowed)",
			clientID:  "redirect_uri:https://verifier.example/callback",
			reqObj:    &oid4vc.RequestObjectJWT{Header: map[string]any{"typ": "oauth-authz-req+jwt"}},
			wantEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := VerifyClientID(tt.clientID, tt.reqObj, tt.responseURI)
			if tt.wantEmpty && warning != "" {
				t.Errorf("expected no warning, got: %s", warning)
			}
			if !tt.wantEmpty && warning == "" {
				t.Error("expected a warning, got empty string")
			}
		})
	}
}

func TestValidateRequestObject(t *testing.T) {
	tests := []struct {
		name      string
		clientID  string
		reqObj    *oid4vc.RequestObjectJWT
		wantEmpty bool
		wantMsg   string
	}{
		{
			name:      "correct typ",
			clientID:  "x509_san_dns:example.com",
			reqObj:    &oid4vc.RequestObjectJWT{Header: map[string]any{"typ": "oauth-authz-req+jwt"}},
			wantEmpty: true,
		},
		{
			name:     "missing typ",
			clientID: "x509_san_dns:example.com",
			reqObj:   &oid4vc.RequestObjectJWT{Header: map[string]any{"alg": "ES256"}},
			wantMsg:  "missing 'typ'",
		},
		{
			name:     "wrong typ",
			clientID: "x509_san_dns:example.com",
			reqObj:   &oid4vc.RequestObjectJWT{Header: map[string]any{"typ": "JWT"}},
			wantMsg:  "has typ",
		},
		{
			name:     "no request object with signing prefix",
			clientID: "x509_san_dns:example.com",
			reqObj:   nil,
			wantMsg:  "requires a signed Request Object",
		},
		{
			name:      "no request object without signing prefix",
			clientID:  "https://verifier.example",
			reqObj:    nil,
			wantEmpty: true,
		},
		{
			name:      "no request object with redirect_uri prefix",
			clientID:  "redirect_uri:https://verifier.example",
			reqObj:    nil,
			wantEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := ValidateRequestObject(tt.clientID, tt.reqObj)
			if tt.wantEmpty && warning != "" {
				t.Errorf("expected no warning, got: %s", warning)
			}
			if tt.wantMsg != "" && !strings.Contains(warning, tt.wantMsg) {
				t.Errorf("expected warning containing %q, got: %s", tt.wantMsg, warning)
			}
		})
	}
}

func TestVerifyAlgMatchesCert(t *testing.T) {
	ecCertB64, _ := testCertDER([]string{"example.com"})
	rsaCertB64, _ := testRSACertDER()

	tests := []struct {
		name      string
		alg       string
		certB64   string
		wantEmpty bool
	}{
		{"ES256 with EC cert", "ES256", ecCertB64, true},
		{"ES384 with EC cert", "ES384", ecCertB64, true},
		{"RS256 with RSA cert", "RS256", rsaCertB64, true},
		{"PS256 with RSA cert", "PS256", rsaCertB64, true},
		{"RS256 with EC cert", "RS256", ecCertB64, false},
		{"PS256 with EC cert", "PS256", ecCertB64, false},
		{"ES256 with RSA cert", "ES256", rsaCertB64, false},
		{"no alg header", "", ecCertB64, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqObj := reqObjWithX5C(tt.certB64)
			reqObj.Header["typ"] = "oauth-authz-req+jwt"
			if tt.alg != "" {
				reqObj.Header["alg"] = tt.alg
			}
			warning := verifyAlgMatchesCert(reqObj)
			if tt.wantEmpty && warning != "" {
				t.Errorf("expected no warning, got: %s", warning)
			}
			if !tt.wantEmpty && warning == "" {
				t.Error("expected a warning, got empty string")
			}
		})
	}
}

func TestVerifyAlgMatchesCert_NoX5C(t *testing.T) {
	reqObj := &oid4vc.RequestObjectJWT{
		Header: map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt"},
	}
	if warning := verifyAlgMatchesCert(reqObj); warning != "" {
		t.Errorf("expected no warning without x5c, got: %s", warning)
	}
}
