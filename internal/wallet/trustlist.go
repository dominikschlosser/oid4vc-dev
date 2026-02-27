package wallet

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
)

// GenerateTrustListJWT generates an ETSI TS 119 602 trust list JWT
// containing a self-signed X.509 certificate wrapping the issuer's public key.
func GenerateTrustListJWT(issuerKey *ecdsa.PrivateKey) (string, error) {
	// Create a self-signed X.509 certificate from the issuer key
	certTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "OID4VC Dev Wallet Issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		return "", fmt.Errorf("creating certificate: %w", err)
	}

	certB64 := base64.StdEncoding.EncodeToString(certDER)

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
							"ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/Issuance",
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

	r, s, err := ecdsa.Sign(rand.Reader, issuerKey, h[:])
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}

	keySize := (issuerKey.Curve.Params().BitSize + 7) / 8
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 2*keySize)
	copy(sig[keySize-len(rBytes):keySize], rBytes)
	copy(sig[2*keySize-len(sBytes):], sBytes)

	sigB64 := format.EncodeBase64URL(sig)

	return headerB64 + "." + payloadB64 + "." + sigB64, nil
}
