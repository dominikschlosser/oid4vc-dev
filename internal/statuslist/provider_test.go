package statuslist

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
)

func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return key
}

func TestGenerateStatusListJWT_ValidStructure(t *testing.T) {
	key := generateTestKey(t)
	bitstring := make([]byte, 16)

	jwt, err := GenerateStatusListJWT(bitstring, key)
	if err != nil {
		t.Fatalf("GenerateStatusListJWT: %v", err)
	}

	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	// Check header
	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		t.Fatalf("decoding header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("parsing header: %v", err)
	}
	if header["alg"] != "ES256" {
		t.Errorf("expected alg ES256, got %v", header["alg"])
	}
	if header["typ"] != "statuslist+jwt" {
		t.Errorf("expected typ statuslist+jwt, got %v", header["typ"])
	}

	// Check payload
	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parsing payload: %v", err)
	}

	sl, ok := payload["status_list"].(map[string]any)
	if !ok {
		t.Fatal("missing status_list in payload")
	}
	if sl["bits"] != float64(1) {
		t.Errorf("expected bits=1, got %v", sl["bits"])
	}
	if _, ok := sl["lst"].(string); !ok {
		t.Fatal("missing lst in status_list")
	}
}

func TestGenerateStatusListJWT_RoundTrip(t *testing.T) {
	key := generateTestKey(t)
	bitstring := make([]byte, 16)
	// Set index 3 to revoked
	bitstring[0] = 1 << 3

	jwt, err := GenerateStatusListJWT(bitstring, key)
	if err != nil {
		t.Fatalf("GenerateStatusListJWT: %v", err)
	}

	// Parse the JWT payload
	parts := strings.SplitN(jwt, ".", 3)
	payloadBytes, _ := format.DecodeBase64URL(parts[1])
	var payload map[string]any
	json.Unmarshal(payloadBytes, &payload)

	sl := payload["status_list"].(map[string]any)
	lst := sl["lst"].(string)

	// Decode and decompress
	compressed, err := format.DecodeBase64URL(lst)
	if err != nil {
		t.Fatalf("decoding lst: %v", err)
	}

	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("zlib reader: %v", err)
	}
	decompressed, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatalf("decompressing: %v", err)
	}

	// Verify bitstring matches
	if len(decompressed) != len(bitstring) {
		t.Fatalf("decompressed length %d != original %d", len(decompressed), len(bitstring))
	}
	if !bytes.Equal(decompressed, bitstring) {
		t.Error("decompressed bitstring does not match original")
	}

	// Check index 3 is revoked
	status, err := extractStatus(decompressed, 3, 1)
	if err != nil {
		t.Fatalf("extractStatus: %v", err)
	}
	if status != 1 {
		t.Errorf("expected index 3 to be revoked (1), got %d", status)
	}

	// Check index 0 is valid
	status, err = extractStatus(decompressed, 0, 1)
	if err != nil {
		t.Fatalf("extractStatus: %v", err)
	}
	if status != 0 {
		t.Errorf("expected index 0 to be valid (0), got %d", status)
	}
}

func TestGenerateStatusListJWT_AllZeros(t *testing.T) {
	key := generateTestKey(t)
	bitstring := make([]byte, 16)

	jwt, err := GenerateStatusListJWT(bitstring, key)
	if err != nil {
		t.Fatalf("GenerateStatusListJWT: %v", err)
	}

	if jwt == "" {
		t.Fatal("expected non-empty JWT")
	}
}
