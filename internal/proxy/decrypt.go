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

package proxy

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"strings"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
)

// DecryptJWEWithCEK decrypts a JWE compact serialization using the provided
// content encryption key (CEK). The CEK is the raw AES key bytes that were
// derived during ECDH-ES key agreement.
// This is intended for debugging: the wallet includes the CEK in a debug
// header so the proxy can decrypt JARM responses.
func DecryptJWEWithCEK(jwe string, cek []byte) ([]byte, error) {
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("invalid JWE: expected 5 parts, got %d", len(parts))
	}

	headerB64 := parts[0]
	// parts[1] is the encrypted key (empty for ECDH-ES)
	ivBytes, err := format.DecodeBase64URL(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decoding IV: %w", err)
	}
	ciphertext, err := format.DecodeBase64URL(parts[3])
	if err != nil {
		return nil, fmt.Errorf("decoding ciphertext: %w", err)
	}
	tag, err := format.DecodeBase64URL(parts[4])
	if err != nil {
		return nil, fmt.Errorf("decoding tag: %w", err)
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	// AAD is the ASCII bytes of the base64url-encoded protected header
	aad := []byte(headerB64)

	// AES-GCM expects ciphertext || tag
	sealed := append(ciphertext, tag...)

	plaintext, err := aead.Open(nil, ivBytes, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM decryption failed: %w", err)
	}

	return plaintext, nil
}
