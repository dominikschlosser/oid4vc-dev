package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
)

func testCert(dnsNames []string, uris []*url.URL) string {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dnsNames,
		URIs:         uris,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return base64.StdEncoding.EncodeToString(der)
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

func TestVerifyClientID(t *testing.T) {
	matchingDNS := testCert([]string{"example.com", "other.com"}, nil)
	matchingURI := testCert(nil, []*url.URL{{Scheme: "https", Host: "verifier.example"}})

	tests := []struct {
		name      string
		clientID  string
		reqObj    *oid4vc.RequestObjectJWT
		wantEmpty bool // true = no warning expected
	}{
		{
			name:      "no prefix",
			clientID:  "https://verifier.example",
			reqObj:    reqObjWithX5C(matchingDNS),
			wantEmpty: true,
		},
		{
			name:      "dns match",
			clientID:  "x509_san_dns:example.com",
			reqObj:    reqObjWithX5C(matchingDNS),
			wantEmpty: true,
		},
		{
			name:     "dns mismatch",
			clientID: "x509_san_dns:wrong.example",
			reqObj:   reqObjWithX5C(matchingDNS),
		},
		{
			name:      "uri match",
			clientID:  "x509_san_uri:https://verifier.example",
			reqObj:    reqObjWithX5C(matchingURI),
			wantEmpty: true,
		},
		{
			name:     "uri mismatch",
			clientID: "x509_san_uri:https://wrong.example",
			reqObj:   reqObjWithX5C(matchingURI),
		},
		{
			name:     "nil request object",
			clientID: "x509_san_dns:example.com",
			reqObj:   nil,
		},
		{
			name:     "no x5c header",
			clientID: "x509_san_dns:example.com",
			reqObj:   &oid4vc.RequestObjectJWT{Header: map[string]any{}},
		},
		{
			name:     "empty x5c array",
			clientID: "x509_san_dns:example.com",
			reqObj:   &oid4vc.RequestObjectJWT{Header: map[string]any{"x5c": []any{}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := VerifyClientID(tt.clientID, tt.reqObj)
			if tt.wantEmpty && warning != "" {
				t.Errorf("expected no warning, got: %s", warning)
			}
			if !tt.wantEmpty && warning == "" {
				t.Error("expected a warning, got empty string")
			}
			if !tt.wantEmpty && warning != "" {
				// Sanity check: warning should contain something useful
				if !strings.Contains(warning, "x509") && !strings.Contains(warning, "client_id") && !strings.Contains(warning, "SAN") {
					t.Errorf("warning doesn't seem informative: %s", warning)
				}
			}
		})
	}
}
