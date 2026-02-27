package statuslist

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
)

// GenerateStatusListJWT creates a signed status list JWT (RFC 9596) from a bitstring.
func GenerateStatusListJWT(bitstring []byte, signingKey *ecdsa.PrivateKey) (string, error) {
	// zlib-compress the bitstring
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		return "", fmt.Errorf("creating zlib writer: %w", err)
	}
	if _, err := w.Write(bitstring); err != nil {
		return "", fmt.Errorf("compressing bitstring: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("closing zlib writer: %w", err)
	}

	lst := format.EncodeBase64URL(buf.Bytes())

	now := time.Now()
	payload := map[string]any{
		"iss": "https://issuer.example",
		"iat": now.Unix(),
		"exp": now.Add(24 * time.Hour).Unix(),
		"status_list": map[string]any{
			"bits": 1,
			"lst":  lst,
		},
	}

	header := map[string]any{
		"alg": "ES256",
		"typ": "statuslist+jwt",
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
