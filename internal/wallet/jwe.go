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
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
)

// EncryptJWE encrypts payload as a compact JWE using ECDH-ES with AES-GCM.
// recipientKey is the verifier's public EC key, kid identifies it,
// enc is the content encryption algorithm (e.g. "A128GCM" or "A256GCM"),
// and apu is the Agreement PartyUInfo (set to mdoc_generated_nonce for ISO mode, nil otherwise).
// Returns the JWE compact serialization and the derived content encryption key (CEK).
func EncryptJWE(payload []byte, recipientKey *ecdsa.PublicKey, kid string, enc string, apu []byte) (string, []byte, error) {
	keyBitLen, err := encKeyBitLen(enc)
	if err != nil {
		return "", nil, err
	}

	// Generate ephemeral EC P-256 key pair
	ephemeralPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("generating ephemeral key: %w", err)
	}
	ephemeralPub := ephemeralPriv.PublicKey()

	// Convert recipient ECDSA public key to ECDH
	recipientECDH, err := recipientKey.ECDH()
	if err != nil {
		return "", nil, fmt.Errorf("converting recipient key to ECDH: %w", err)
	}

	// ECDH key agreement
	z, err := ephemeralPriv.ECDH(recipientECDH)
	if err != nil {
		return "", nil, fmt.Errorf("ECDH key agreement: %w", err)
	}

	// Derive key via Concat KDF (NIST SP 800-56A, RFC 7518 §4.6)
	derivedKey := concatKDF(z, enc, apu, nil, keyBitLen)

	// Build protected header
	epkX, epkY := unmarshalECDHPublicKey(ephemeralPub)
	header := map[string]any{
		"alg": "ECDH-ES",
		"enc": enc,
		"kid": kid,
		"epk": map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   format.EncodeBase64URL(epkX),
			"y":   format.EncodeBase64URL(epkY),
		},
	}
	if apu != nil {
		header["apu"] = format.EncodeBase64URL(apu)
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", nil, fmt.Errorf("marshaling header: %w", err)
	}
	headerB64 := format.EncodeBase64URL(headerJSON)

	// Generate random 96-bit IV
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return "", nil, fmt.Errorf("generating IV: %w", err)
	}

	// AES-GCM encrypt with AAD = ASCII(protected header)
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, fmt.Errorf("creating GCM: %w", err)
	}

	aad := []byte(headerB64)
	sealed := aead.Seal(nil, iv, payload, aad)

	// sealed = ciphertext || tag (tag is last 16 bytes)
	ciphertext := sealed[:len(sealed)-aead.Overhead()]
	tag := sealed[len(sealed)-aead.Overhead():]

	// Compact serialization: header.encryptedKey.iv.ciphertext.tag
	// ECDH-ES has no encrypted key (empty string)
	jweStr := headerB64 + ".." +
		format.EncodeBase64URL(iv) + "." +
		format.EncodeBase64URL(ciphertext) + "." +
		format.EncodeBase64URL(tag)
	return jweStr, derivedKey, nil
}

// concatKDF derives a key using the Concat KDF from NIST SP 800-56A (single round for <=256 bits).
func concatKDF(z []byte, enc string, apu, apv []byte, keyBitLen int) []byte {
	h := sha256.New()

	// round = 0x00000001
	var round [4]byte
	binary.BigEndian.PutUint32(round[:], 1)
	h.Write(round[:])

	// Z (shared secret)
	h.Write(z)

	// AlgorithmID = len(enc) || enc
	writeWithLength(h, []byte(enc))

	// PartyUInfo = len(apu) || apu
	writeWithLength(h, apu)

	// PartyVInfo = len(apv) || apv
	writeWithLength(h, apv)

	// SuppPubInfo = keyBitLen (4-byte big-endian)
	var suppPub [4]byte
	binary.BigEndian.PutUint32(suppPub[:], uint32(keyBitLen))
	h.Write(suppPub[:])

	derived := h.Sum(nil)
	return derived[:keyBitLen/8]
}

// writeWithLength writes a 4-byte big-endian length prefix followed by data.
// If data is nil, writes 0x00000000.
func writeWithLength(h io.Writer, data []byte) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	h.Write(lenBuf[:])
	if len(data) > 0 {
		h.Write(data)
	}
}

// encKeyBitLen returns the key bit length for the given content encryption algorithm.
func encKeyBitLen(enc string) (int, error) {
	switch enc {
	case "A128GCM":
		return 128, nil
	case "A256GCM":
		return 256, nil
	default:
		return 0, fmt.Errorf("unsupported content encryption algorithm: %s", enc)
	}
}

// unmarshalECDHPublicKey extracts the raw x, y coordinates from an ECDH public key.
func unmarshalECDHPublicKey(pub *ecdh.PublicKey) (x, y []byte) {
	raw := pub.Bytes() // uncompressed point: 0x04 || x || y
	coordLen := (len(raw) - 1) / 2
	return raw[1 : 1+coordLen], raw[1+coordLen:]
}

// ecdsaPublicKeyFromJWK constructs an *ecdsa.PublicKey from base64url-encoded x, y coordinates.
func ecdsaPublicKeyFromJWK(xB64, yB64 string) (*ecdsa.PublicKey, error) {
	xBytes, err := format.DecodeBase64URL(xB64)
	if err != nil {
		return nil, fmt.Errorf("decoding x coordinate: %w", err)
	}
	yBytes, err := format.DecodeBase64URL(yB64)
	if err != nil {
		return nil, fmt.Errorf("decoding y coordinate: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}
