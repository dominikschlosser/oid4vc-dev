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
	"github.com/dominikschlosser/oid4vc-dev/internal/sdjwt"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// PresentationParams holds parameters for VP token creation.
type PresentationParams struct {
	Nonce         string
	ClientID      string
	ResponseURI   string
	ResponseMode  string                    // e.g. "direct_post.jwt"
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

// createMDocPresentation creates an mDoc DeviceResponse with selected data elements.
func (w *Wallet) createMDocPresentation(cred StoredCredential, selectedKeys []string, params PresentationParams) (VPTokenResult, error) {
	nonce := params.Nonce
	clientID := params.ClientID
	responseURI := params.ResponseURI
	// Build set of selected namespace:element pairs
	selected := make(map[string]bool, len(selectedKeys))
	for _, k := range selectedKeys {
		selected[k] = true
	}

	// Parse the raw credential to get the IssuerSigned structure
	rawBytes, err := format.DecodeHexOrBase64URL(cred.Raw)
	if err != nil {
		return VPTokenResult{}, fmt.Errorf("decoding mDoc: %w", err)
	}

	var issuerSigned map[string]cbor.RawMessage
	if err := cbor.Unmarshal(rawBytes, &issuerSigned); err != nil {
		return VPTokenResult{}, fmt.Errorf("parsing IssuerSigned CBOR: %w", err)
	}

	// Filter namespaces to only include selected data elements
	filteredNS := make(map[string][]cbor.RawMessage)
	for ns, items := range cred.NameSpaces {
		// Re-parse the raw namespace items from the original
		var rawNSItems []cbor.RawMessage
		var allNS map[string][]cbor.RawMessage
		if nsRaw, ok := issuerSigned["nameSpaces"]; ok {
			if err := cbor.Unmarshal(nsRaw, &allNS); err == nil {
				rawNSItems = allNS[ns]
			}
		}

		var filtered []cbor.RawMessage
		for i, item := range items {
			key := ns + ":" + item.ElementIdentifier
			if selected[key] {
				if i < len(rawNSItems) {
					filtered = append(filtered, rawNSItems[i])
				}
			}
		}
		if len(filtered) > 0 {
			filteredNS[ns] = filtered
		}
	}

	docType := cred.DocType

	// Build session transcript based on mode
	mode := w.SessionTranscript
	if mode == "" {
		mode = SessionTranscriptOID4VP
	}

	var mdocNonce string
	if mode == SessionTranscriptISO {
		// ISO mode needs mdocGeneratedNonce
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			return VPTokenResult{}, fmt.Errorf("generating nonce: %w", err)
		}
		mdocNonce = format.EncodeBase64URL(nonceBytes)
	}

	jwkThumbprint := extractJWKThumbprint(params.RequestObject)
	sessionTranscriptBytes, err := w.buildSessionTranscript(clientID, responseURI, nonce, mdocNonce, jwkThumbprint)
	if err != nil {
		return VPTokenResult{}, fmt.Errorf("building SessionTranscript: %w", err)
	}

	// Create DeviceAuth using COSE_Sign1
	deviceAuthBytes, err := w.createDeviceAuth(sessionTranscriptBytes, docType)
	if err != nil {
		return VPTokenResult{}, fmt.Errorf("creating DeviceAuth: %w", err)
	}

	// Build Document structure
	document := map[string]any{
		"docType": docType,
		"issuerSigned": map[string]any{
			"nameSpaces": filteredNS,
			"issuerAuth": issuerSigned["issuerAuth"],
		},
		"deviceSigned": map[string]any{
			"nameSpaces": map[string]any{},
			"deviceAuth": map[string]any{
				"deviceSignature": cbor.RawMessage(deviceAuthBytes),
			},
		},
	}

	deviceResponse := map[string]any{
		"version":   "1.0",
		"documents": []any{document},
		"status":    0,
	}

	responseBytes, err := cbor.Marshal(deviceResponse)
	if err != nil {
		return VPTokenResult{}, fmt.Errorf("encoding DeviceResponse: %w", err)
	}

	return VPTokenResult{
		Token:     format.EncodeBase64URL(responseBytes),
		MDocNonce: mdocNonce,
	}, nil
}

// buildSessionTranscript constructs the SessionTranscript CBOR bytes using the
// configured mode (ISO 18013-7 or OID4VP).
func (w *Wallet) buildSessionTranscript(clientID, responseURI, nonce, mdocNonce string, jwkThumbprint []byte) ([]byte, error) {
	mode := w.SessionTranscript
	if mode == "" {
		mode = SessionTranscriptOID4VP // default
	}

	switch mode {
	case SessionTranscriptISO:
		return buildSessionTranscriptISO(clientID, responseURI, nonce, mdocNonce)
	case SessionTranscriptOID4VP:
		return buildSessionTranscriptOID4VP(clientID, nonce, jwkThumbprint, responseURI)
	default:
		return nil, fmt.Errorf("unknown session transcript mode: %s", mode)
	}
}

// buildSessionTranscriptISO builds the ISO 18013-7 Annex B.4.4 session transcript.
// Hash inputs are CBOR-encoded [value, mdocGeneratedNonce] arrays.
func buildSessionTranscriptISO(clientID, responseURI, nonce, mdocNonce string) ([]byte, error) {
	// clientIdToHash = CBOR_encode([clientId, mdocGeneratedNonce])
	clientIDToHash, err := cbor.Marshal([]string{clientID, mdocNonce})
	if err != nil {
		return nil, fmt.Errorf("encoding clientIdToHash: %w", err)
	}
	clientIDHash := sha256.Sum256(clientIDToHash)

	// responseUriToHash = CBOR_encode([responseUri, mdocGeneratedNonce])
	responseURIToHash, err := cbor.Marshal([]string{responseURI, mdocNonce})
	if err != nil {
		return nil, fmt.Errorf("encoding responseUriToHash: %w", err)
	}
	responseURIHash := sha256.Sum256(responseURIToHash)

	// Handover = [clientIdHash, responseUriHash, nonce]
	handover := []any{
		clientIDHash[:],
		responseURIHash[:],
		nonce,
	}

	// SessionTranscript = [null, null, Handover]
	sessionTranscript := []any{nil, nil, handover}
	return cbor.Marshal(sessionTranscript)
}

// buildSessionTranscriptOID4VP builds the OID4VP 1.0 session transcript.
// HandoverInfo = CBOR([clientId, nonce, jwkThumbprint, responseUri])
// OID4VPHandover = ["OpenID4VPHandover", SHA256(HandoverInfo)]
// SessionTranscript = [null, null, OID4VPHandover]
func buildSessionTranscriptOID4VP(clientID, nonce string, jwkThumbprint []byte, responseURI string) ([]byte, error) {
	// HandoverInfo = CBOR([clientId, nonce, jwkThumbprint|null, responseUri])
	var thumbprintValue any
	if len(jwkThumbprint) > 0 {
		thumbprintValue = jwkThumbprint
	}
	handoverInfo, err := cbor.Marshal([]any{clientID, nonce, thumbprintValue, responseURI})
	if err != nil {
		return nil, fmt.Errorf("encoding HandoverInfo: %w", err)
	}
	hash := sha256.Sum256(handoverInfo)

	// OID4VPHandover = ["OpenID4VPHandover", hash]
	oid4vpHandover := []any{"OpenID4VPHandover", hash[:]}

	// SessionTranscript = [null, null, OID4VPHandover]
	sessionTranscript := []any{nil, nil, oid4vpHandover}
	return cbor.Marshal(sessionTranscript)
}

// createDeviceAuth creates a COSE_Sign1 DeviceAuth with proper DeviceAuthentication payload.
// DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpaces]
// The payload is Tag24(CBOR(DeviceAuthentication)).
func (w *Wallet) createDeviceAuth(sessionTranscriptBytes []byte, docType string) ([]byte, error) {
	signer, err := cose.NewSigner(cose.AlgorithmES256, w.HolderKey)
	if err != nil {
		return nil, fmt.Errorf("creating COSE signer: %w", err)
	}

	// Decode sessionTranscriptBytes back to structured CBOR value
	var sessionTranscript cbor.RawMessage
	sessionTranscript = sessionTranscriptBytes

	// DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType, {}]
	deviceAuth := []any{
		"DeviceAuthentication",
		sessionTranscript,
		docType,
		map[string]any{}, // empty DeviceNameSpaces
	}

	deviceAuthBytes, err := cbor.Marshal(deviceAuth)
	if err != nil {
		return nil, fmt.Errorf("encoding DeviceAuthentication: %w", err)
	}

	// Wrap in Tag 24
	tag24Payload, err := cbor.Marshal(cbor.Tag{Number: 24, Content: deviceAuthBytes})
	if err != nil {
		return nil, fmt.Errorf("encoding Tag24(DeviceAuthentication): %w", err)
	}

	msg := cose.NewSign1Message()
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Payload = tag24Payload

	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("COSE signing: %w", err)
	}

	return msg.MarshalCBOR()
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


// extractJWKThumbprint extracts the encryption JWK from the request object's
// client_metadata.jwks.keys[0] and computes its RFC 7638 thumbprint (SHA-256).
// Returns nil if no encryption key is found.
func extractJWKThumbprint(reqObj *oid4vc.RequestObjectJWT) []byte {
	if reqObj == nil {
		return nil
	}

	payload := reqObj.Payload
	if payload == nil {
		return nil
	}

	clientMeta, ok := payload["client_metadata"].(map[string]any)
	if !ok {
		return nil
	}

	jwks, ok := clientMeta["jwks"].(map[string]any)
	if !ok {
		return nil
	}

	keysSlice, ok := jwks["keys"].([]any)
	if !ok || len(keysSlice) == 0 {
		return nil
	}

	jwk, ok := keysSlice[0].(map[string]any)
	if !ok {
		return nil
	}

	return computeJWKThumbprint(jwk)
}

// computeJWKThumbprint computes the RFC 7638 JWK Thumbprint using SHA-256.
// For EC keys, the required members in lexicographic order are: crv, kty, x, y.
// For RSA keys: e, kty, n.
func computeJWKThumbprint(jwk map[string]any) []byte {
	kty, _ := jwk["kty"].(string)

	var canonical map[string]string
	switch kty {
	case "EC":
		crv, _ := jwk["crv"].(string)
		x, _ := jwk["x"].(string)
		y, _ := jwk["y"].(string)
		if crv == "" || x == "" || y == "" {
			return nil
		}
		canonical = map[string]string{"crv": crv, "kty": kty, "x": x, "y": y}
	case "RSA":
		e, _ := jwk["e"].(string)
		n, _ := jwk["n"].(string)
		if e == "" || n == "" {
			return nil
		}
		canonical = map[string]string{"e": e, "kty": kty, "n": n}
	default:
		return nil
	}

	// RFC 7638: JSON must have members in lexicographic order, no whitespace
	canonicalJSON, err := json.Marshal(canonical)
	if err != nil {
		return nil
	}

	hash := sha256.Sum256(canonicalJSON)
	return hash[:]
}

// extractEncryptionKey extracts the EC public key and kid from the request object's
// client_metadata.jwks.keys[0].
func extractEncryptionKey(reqObj *oid4vc.RequestObjectJWT) (*ecdsa.PublicKey, string, error) {
	if reqObj == nil || reqObj.Payload == nil {
		return nil, "", fmt.Errorf("no request object")
	}

	clientMeta, ok := reqObj.Payload["client_metadata"].(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("no client_metadata")
	}

	jwks, ok := clientMeta["jwks"].(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("no jwks in client_metadata")
	}

	keysSlice, ok := jwks["keys"].([]any)
	if !ok || len(keysSlice) == 0 {
		return nil, "", fmt.Errorf("no keys in jwks")
	}

	jwk, ok := keysSlice[0].(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("invalid key format")
	}

	x, _ := jwk["x"].(string)
	y, _ := jwk["y"].(string)
	kid, _ := jwk["kid"].(string)

	if x == "" || y == "" {
		return nil, "", fmt.Errorf("missing x or y in JWK")
	}

	pubKey, err := ecdsaPublicKeyFromJWK(x, y)
	if err != nil {
		return nil, "", fmt.Errorf("constructing EC key: %w", err)
	}

	return pubKey, kid, nil
}

// HasEncryptionKey checks if the request object contains an encryption JWK.
func HasEncryptionKey(reqObj *oid4vc.RequestObjectJWT) bool {
	_, _, err := extractEncryptionKey(reqObj)
	return err == nil
}

// EncryptResponse encrypts vp_token and state as a JWE for direct_post.jwt response mode.
func (w *Wallet) EncryptResponse(vpToken any, state string, mdocNonce string, params PresentationParams) (string, error) {
	log.Printf("[VP] Encrypting response: response_mode=direct_post.jwt")
	payload := map[string]any{
		"vp_token": vpToken,
		"state":    state,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshaling response payload: %w", err)
	}

	encKey, kid, err := extractEncryptionKey(params.RequestObject)
	if err != nil {
		return "", fmt.Errorf("extracting encryption key: %w", err)
	}

	// Determine enc algorithm from client_metadata
	enc := "A128GCM"
	if params.RequestObject != nil && params.RequestObject.Payload != nil {
		if clientMeta, ok := params.RequestObject.Payload["client_metadata"].(map[string]any); ok {
			if supported, ok := clientMeta["authorization_encrypted_response_enc"].(string); ok && supported != "" {
				enc = supported
			}
		}
	}

	// For ISO mode with mdoc_generated_nonce, set apu
	var apu []byte
	if mdocNonce != "" {
		apu = []byte(mdocNonce)
	}

	return EncryptJWE(payloadJSON, encKey, kid, enc, apu)
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

// sdJWTDisclosureNames returns the disclosure names from an SD-JWT token.
func sdJWTDisclosureNames(disclosures []sdjwt.Disclosure) []string {
	var names []string
	for _, d := range disclosures {
		if !d.IsArrayEntry {
			names = append(names, d.Name)
		}
	}
	return names
}
