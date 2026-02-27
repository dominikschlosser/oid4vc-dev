package validate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/trustlist"
)

func generateCACert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	return caCert, caKey, caDER
}

func generateLeafCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return leafCert, leafKey, leafDER
}

func TestValidateCertChain_ValidChain(t *testing.T) {
	caCert, caKey, caDER := generateCACert(t)
	_, _, leafDER := generateLeafCert(t, caCert, caKey)

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	tlCerts := []trustlist.CertInfo{
		{PublicKey: caCert.PublicKey, Raw: caDER},
	}

	key, err := ValidateCertChain([]*x509.Certificate{leafCert}, tlCerts)
	if err != nil {
		t.Fatalf("ValidateCertChain() error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestValidateCertChain_InvalidChain(t *testing.T) {
	caCert, caKey, _ := generateCACert(t)
	_, _, leafDER := generateLeafCert(t, caCert, caKey)

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	// Different CA in trust list
	_, _, otherCADER := generateCACert(t)
	otherCACert, _ := x509.ParseCertificate(otherCADER)

	tlCerts := []trustlist.CertInfo{
		{PublicKey: otherCACert.PublicKey, Raw: otherCADER},
	}

	_, err = ValidateCertChain([]*x509.Certificate{leafCert}, tlCerts)
	if err == nil {
		t.Error("expected error for untrusted chain")
	}
}

func TestValidateCertChain_WithIntermediate(t *testing.T) {
	rootCert, rootKey, rootDER := generateCACert(t)

	// Intermediate CA
	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTemplate, rootCert, &intKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intCert, _ := x509.ParseCertificate(intDER)

	// Leaf signed by intermediate
	_, _, leafDER := generateLeafCert(t, intCert, intKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	tlCerts := []trustlist.CertInfo{
		{PublicKey: rootCert.PublicKey, Raw: rootDER},
	}

	key, err := ValidateCertChain([]*x509.Certificate{leafCert, intCert}, tlCerts)
	if err != nil {
		t.Fatalf("ValidateCertChain() error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestValidateCertChain_InvalidTrustListCert(t *testing.T) {
	caCert, caKey, _ := generateCACert(t)
	_, _, leafDER := generateLeafCert(t, caCert, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	// Trust list has garbage DER data — should be skipped without panic
	tlCerts := []trustlist.CertInfo{
		{PublicKey: nil, Raw: []byte("not a certificate")},
	}

	_, err := ValidateCertChain([]*x509.Certificate{leafCert}, tlCerts)
	if err == nil {
		t.Error("expected error when trust list has no valid certs")
	}
}

func TestExtractAndValidateX5C_NoX5C(t *testing.T) {
	header := map[string]any{"alg": "ES256"}
	key, err := ExtractAndValidateX5C(header, []trustlist.CertInfo{{Raw: []byte("x")}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("expected nil key when no x5c header")
	}
}

func TestExtractAndValidateX5C_EmptyTrustList(t *testing.T) {
	header := map[string]any{"x5c": []any{"abc"}}
	key, err := ExtractAndValidateX5C(header, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("expected nil key when no trust list certs")
	}
}

func TestExtractAndValidateX5C_NonStringEntry(t *testing.T) {
	header := map[string]any{"x5c": []any{12345}}
	tlCerts := []trustlist.CertInfo{{Raw: []byte("x")}}

	_, err := ExtractAndValidateX5C(header, tlCerts)
	if err == nil {
		t.Error("expected error for non-string x5c entry")
	}
}

func TestExtractAndValidateX5C_InvalidBase64(t *testing.T) {
	header := map[string]any{"x5c": []any{"not-valid-base64!!!"}}
	tlCerts := []trustlist.CertInfo{{Raw: []byte("x")}}

	_, err := ExtractAndValidateX5C(header, tlCerts)
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestExtractAndValidateX5C_ValidBase64InvalidDER(t *testing.T) {
	header := map[string]any{"x5c": []any{"bm90IGEgY2VydA=="}} // "not a cert"
	tlCerts := []trustlist.CertInfo{{Raw: []byte("x")}}

	_, err := ExtractAndValidateX5C(header, tlCerts)
	if err == nil {
		t.Error("expected error for invalid DER data")
	}
}
