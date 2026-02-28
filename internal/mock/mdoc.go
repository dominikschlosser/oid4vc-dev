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

package mock

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// MDOCConfig holds options for generating a mock mDOC credential.
type MDOCConfig struct {
	DocType       string
	Namespace     string
	Claims        map[string]any
	Key           *ecdsa.PrivateKey
	HolderKey     *ecdsa.PublicKey // optional: adds deviceKeyInfo to MSO
	ExpiresIn     time.Duration   // validity duration; defaults to 30 days if zero
	ValidFrom     *time.Time      // optional: override validFrom (defaults to now)
	StatusListURI string          // optional: status list URI for revocation
	StatusListIdx int             // optional: index in the status list
}

// GenerateMDOC creates a mock mDOC (IssuerSigned) credential.
func GenerateMDOC(cfg MDOCConfig) (string, error) {
	now := time.Now().UTC().Truncate(time.Second)
	expiresIn := cfg.ExpiresIn
	if expiresIn == 0 {
		expiresIn = 30 * 24 * time.Hour
	}
	validFrom := now
	if cfg.ValidFrom != nil {
		validFrom = cfg.ValidFrom.UTC().Truncate(time.Second)
	}
	validUntil := now.Add(expiresIn)

	// Build IssuerSignedItems and compute value digests
	var tag24Items []cbor.RawMessage
	valueDigests := make(map[uint64][]byte)

	var digestID uint64
	for name, value := range cfg.Claims {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", fmt.Errorf("generating random: %w", err)
		}

		// Build IssuerSignedItem as CBOR map
		item := map[string]any{
			"digestID":          digestID,
			"random":            random,
			"elementIdentifier": name,
			"elementValue":      value,
		}

		itemBytes, err := cbor.Marshal(item)
		if err != nil {
			return "", fmt.Errorf("encoding IssuerSignedItem: %w", err)
		}

		// Wrap in Tag 24 (embedded CBOR)
		tag24 := cbor.Tag{
			Number:  24,
			Content: itemBytes,
		}
		tag24Bytes, err := cbor.Marshal(tag24)
		if err != nil {
			return "", fmt.Errorf("encoding Tag-24: %w", err)
		}

		tag24Items = append(tag24Items, tag24Bytes)

		// Compute digest of Tag-24 wrapped item
		digest := sha256.Sum256(tag24Bytes)
		valueDigests[digestID] = digest[:]
		digestID++
	}

	// Build MSO (Mobile Security Object)
	mso := map[string]any{
		"version":         "1.0",
		"digestAlgorithm": "SHA-256",
		"docType":         cfg.DocType,
		"valueDigests": map[string]any{
			cfg.Namespace: valueDigests,
		},
		"validityInfo": map[string]any{
			"signed":     cbor.Tag{Number: 0, Content: now.Format(time.RFC3339)},
			"validFrom":  cbor.Tag{Number: 0, Content: validFrom.Format(time.RFC3339)},
			"validUntil": cbor.Tag{Number: 0, Content: validUntil.Format(time.RFC3339)},
		},
	}

	// Add status list reference
	if cfg.StatusListURI != "" {
		mso["status"] = map[string]any{
			"status_list": map[string]any{
				"uri": cfg.StatusListURI,
				"idx": cfg.StatusListIdx,
			},
		}
	}

	// Add deviceKeyInfo with holder's COSE_Key
	if cfg.HolderKey != nil {
		keySize := (cfg.HolderKey.Curve.Params().BitSize + 7) / 8
		xBytes := cfg.HolderKey.X.Bytes()
		yBytes := cfg.HolderKey.Y.Bytes()
		for len(xBytes) < keySize {
			xBytes = append([]byte{0}, xBytes...)
		}
		for len(yBytes) < keySize {
			yBytes = append([]byte{0}, yBytes...)
		}

		// COSE_Key: kty=2 (EC2), crv=1 (P-256), x, y
		// Using COSE key labels: 1=kty, -1=crv, -2=x, -3=y
		coseKey := map[any]any{
			int64(1):  int64(2), // kty: EC2
			int64(-1): int64(1), // crv: P-256
			int64(-2): xBytes,   // x coordinate
			int64(-3): yBytes,   // y coordinate
		}

		mso["deviceKeyInfo"] = map[string]any{
			"deviceKey": coseKey,
		}
	}

	msoBytes, err := cbor.Marshal(mso)
	if err != nil {
		return "", fmt.Errorf("encoding MSO: %w", err)
	}

	// Sign MSO with COSE_Sign1
	signer, err := cose.NewSigner(cose.AlgorithmES256, cfg.Key)
	if err != nil {
		return "", fmt.Errorf("creating COSE signer: %w", err)
	}

	msg := cose.NewSign1Message()
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Payload = msoBytes

	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return "", fmt.Errorf("COSE signing: %w", err)
	}

	issuerAuthBytes, err := msg.MarshalCBOR()
	if err != nil {
		return "", fmt.Errorf("encoding COSE_Sign1: %w", err)
	}

	// Build IssuerSigned structure
	issuerSigned := map[string]any{
		"nameSpaces": map[string]any{
			cfg.Namespace: tag24Items,
		},
		"issuerAuth": cbor.RawMessage(issuerAuthBytes),
	}

	issuerSignedBytes, err := cbor.Marshal(issuerSigned)
	if err != nil {
		return "", fmt.Errorf("encoding IssuerSigned: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(issuerSignedBytes), nil
}
