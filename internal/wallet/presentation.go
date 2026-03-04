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
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
)

// PresentationParams holds parameters for VP token creation.
type PresentationParams struct {
	Nonce         string
	ClientID      string
	ResponseURI   string
	RedirectURI   string                   // used for fragment response mode
	ResponseMode  string                   // e.g. "direct_post.jwt", "direct_post", "fragment"
	RequestObject *oid4vc.RequestObjectJWT // optional, used to extract JWK thumbprint for mDoc
}

// VPTokenResult holds the result of VP token creation.
type VPTokenResult struct {
	Token     string
	MDocNonce string // only set for ISO mode mDoc
}

// CreateVPToken creates a VP token for the given credential match.
func (w *Wallet) CreateVPToken(match CredentialMatch, params PresentationParams) (VPTokenResult, error) {
	cred, ok := w.GetCredential(match.CredentialID)
	if !ok {
		return VPTokenResult{}, fmt.Errorf("credential %s not found", match.CredentialID)
	}

	typeLabel := cred.VCT
	if typeLabel == "" {
		typeLabel = cred.DocType
	}
	log.Printf("[VP] Creating VP token: format=%s type=%s claims=%v", cred.Format, typeLabel, match.SelectedKeys)

	switch cred.Format {
	case "dc+sd-jwt":
		token, err := w.createSDJWTPresentation(cred, match.SelectedKeys, params.Nonce, params.ClientID)
		if err != nil {
			return VPTokenResult{}, err
		}
		log.Printf("[VP] SD-JWT presentation created: %d disclosures selected, aud=%s", len(match.SelectedKeys), params.ClientID)
		return VPTokenResult{Token: token}, nil
	case "jwt_vc_json":
		log.Printf("[VP] Plain JWT presentation (no selective disclosure)")
		return VPTokenResult{Token: cred.Raw}, nil
	case "mso_mdoc":
		result, err := w.createMDocPresentation(cred, match.SelectedKeys, params)
		if err != nil {
			return VPTokenResult{}, err
		}
		log.Printf("[VP] mDoc presentation created: docType=%s transcript=%s", cred.DocType, w.SessionTranscript)
		return result, nil
	default:
		return VPTokenResult{}, fmt.Errorf("unsupported credential format: %s", cred.Format)
	}
}

// createSDJWTPresentation creates an SD-JWT presentation with selective disclosure and KB-JWT.
func (w *Wallet) createSDJWTPresentation(cred StoredCredential, selectedKeys []string, nonce, clientID string) (string, error) {
	// Parse the raw SD-JWT to get the issuer JWT part
	parts := strings.Split(cred.Raw, "~")
	if len(parts) < 1 {
		return "", fmt.Errorf("invalid SD-JWT format")
	}
	issuerJWT := parts[0]

	// Build set of selected claim names for filtering
	selected := make(map[string]bool, len(selectedKeys))
	for _, k := range selectedKeys {
		selected[k] = true
	}

	// Collect digests of array entries referenced by selected disclosures.
	// When a disclosure's value contains {"...": digest} entries (array element
	// references), those digests identify which array entry disclosures to include.
	referencedArrayDigests := make(map[string]bool)
	for _, d := range cred.Disclosures {
		if !d.IsArrayEntry && selected[d.Name] {
			collectArrayDigests(d.Value, referencedArrayDigests)
		}
	}

	// Filter disclosures to only include selected claims and their array entries
	var selectedDisclosures []string
	for _, d := range cred.Disclosures {
		if d.IsArrayEntry {
			if referencedArrayDigests[d.Digest] {
				selectedDisclosures = append(selectedDisclosures, d.Raw)
			}
		} else if selected[d.Name] {
			selectedDisclosures = append(selectedDisclosures, d.Raw)
		}
	}

	// Build the SD-JWT without KB-JWT: issuer_jwt~disc1~disc2~...~
	withoutKB := issuerJWT + "~" + strings.Join(selectedDisclosures, "~") + "~"

	// Compute sd_hash = base64url(SHA-256(sd-jwt-without-kb))
	sdHash := sha256.Sum256([]byte(withoutKB))
	sdHashB64 := format.EncodeBase64URL(sdHash[:])

	// Create Key Binding JWT
	kbJWT, err := w.createKBJWT(nonce, clientID, sdHashB64)
	if err != nil {
		return "", fmt.Errorf("creating KB-JWT: %w", err)
	}

	// Final: issuer_jwt~disc1~disc2~...~kb_jwt
	return withoutKB + kbJWT, nil
}

// createKBJWT creates a Key Binding JWT.
func (w *Wallet) createKBJWT(nonce, audience, sdHash string) (string, error) {
	header := map[string]any{
		"alg": "ES256",
		"typ": "kb+jwt",
	}

	payload := map[string]any{
		"iat":     time.Now().Unix(),
		"aud":     audience,
		"nonce":   nonce,
		"sd_hash": sdHash,
	}

	return signJWT(header, payload, w.HolderKey)
}

// signJWT creates and signs a JWT with the given header, payload, and key.
func signJWT(header, payload map[string]any, key *ecdsa.PrivateKey) (string, error) {
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

	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}

	keySize := (key.Curve.Params().BitSize + 7) / 8
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 2*keySize)
	copy(sig[keySize-len(rBytes):keySize], rBytes)
	copy(sig[2*keySize-len(sBytes):], sBytes)

	return sigInput + "." + format.EncodeBase64URL(sig), nil
}

// VPTokenMapResult holds the result of creating VP tokens for all matches.
type VPTokenMapResult struct {
	TokenMap  map[string]string
	MDocNonce string // set if any mDoc credential produced a nonce (ISO mode)
}

// CreateVPTokenMap creates a vp_token as a JSON object for DCQL responses.
// Maps query credential ID → presentation string.
func (w *Wallet) CreateVPTokenMap(matches []CredentialMatch, params PresentationParams) (*VPTokenMapResult, error) {
	log.Printf("[VP] Creating VP token map: %d credentials, client=%s, response_mode=%s", len(matches), params.ClientID, params.ResponseMode)
	result := &VPTokenMapResult{
		TokenMap: make(map[string]string),
	}

	for _, match := range matches {
		tokenResult, err := w.CreateVPToken(match, params)
		if err != nil {
			return nil, fmt.Errorf("creating VP token for %s: %w", match.QueryID, err)
		}
		result.TokenMap[match.QueryID] = tokenResult.Token
		if tokenResult.MDocNonce != "" {
			result.MDocNonce = tokenResult.MDocNonce
		}
	}

	log.Printf("[VP] VP token map created: queries=%v", mapKeys(result.TokenMap))
	return result, nil
}

// VPToken builds the spec-compliant vp_token JSON object.
// Per OID4VP 1.0: values are arrays of one or more presentations.
func (r *VPTokenMapResult) VPToken() map[string][]string {
	vpToken := make(map[string][]string, len(r.TokenMap))
	for k, v := range r.TokenMap {
		vpToken[k] = []string{v}
	}
	return vpToken
}

// QueryIDs returns the credential query IDs in the token map.
func (r *VPTokenMapResult) QueryIDs() []string {
	return mapKeys(r.TokenMap)
}

// SubmitPresentation builds the vp_token, optionally encrypts it, and submits to the verifier.
func (w *Wallet) SubmitPresentation(vpResult *VPTokenMapResult, state, responseURI string, params PresentationParams) (*DirectPostResult, error) {
	vpToken := vpResult.VPToken()

	switch params.ResponseMode {
	case "direct_post.jwt":
		if !HasEncryptionKey(params.RequestObject) {
			return nil, fmt.Errorf("response_mode is direct_post.jwt but no encryption key found in client_metadata.jwks — verifier must provide JWK per OID4VP 1.0")
		}
		jwe, cek, err := w.EncryptResponse(vpToken, state, vpResult.MDocNonce, params)
		if err != nil {
			return nil, fmt.Errorf("encrypting response: %w", err)
		}
		return SubmitDirectPostJWT(responseURI, jwe, cek)

	case "fragment":
		redirectURI := params.RedirectURI
		if redirectURI == "" {
			redirectURI = responseURI
		}
		redirectURL, err := BuildFragmentRedirect(redirectURI, state, vpToken)
		if err != nil {
			return nil, fmt.Errorf("building fragment redirect: %w", err)
		}
		log.Printf("[VP] Fragment response mode: redirect to %s", format.Truncate(redirectURL, 120))
		return &DirectPostResult{
			StatusCode:  302,
			RedirectURI: redirectURL,
		}, nil

	default:
		// direct_post (default)
		return SubmitDirectPost(responseURI, state, vpToken)
	}
}

// collectArrayDigests walks a disclosure value and collects digests from
// array element references ({"...": digest} objects).
func collectArrayDigests(value any, digests map[string]bool) {
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			if obj, ok := item.(map[string]any); ok {
				if digest, ok := obj["..."].(string); ok {
					digests[digest] = true
				}
			}
		}
	}
}
