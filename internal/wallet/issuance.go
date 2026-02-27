package wallet

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
)

// IssuanceResult captures the result of an OID4VCI flow.
type IssuanceResult struct {
	CredentialID string `json:"credential_id"`
	Format       string `json:"format"`
	Issuer       string `json:"issuer"`
	Error        string `json:"error,omitempty"`
}

// ProcessCredentialOffer processes an OID4VCI credential offer URI.
func (w *Wallet) ProcessCredentialOffer(offerURI string) (*IssuanceResult, error) {
	// Parse the credential offer
	reqType, result, err := oid4vc.Parse(offerURI)
	if err != nil {
		return nil, fmt.Errorf("parsing credential offer: %w", err)
	}
	if reqType != oid4vc.TypeVCI {
		return nil, fmt.Errorf("expected VCI credential offer, got VP")
	}

	offer, ok := result.(*oid4vc.CredentialOffer)
	if !ok {
		return nil, fmt.Errorf("unexpected result type")
	}

	// Fetch issuer metadata
	metadata, err := fetchIssuerMetadata(offer.CredentialIssuer)
	if err != nil {
		return nil, fmt.Errorf("fetching issuer metadata: %w", err)
	}

	// Get token endpoint
	tokenEndpoint := getTokenEndpoint(metadata, offer.CredentialIssuer)
	credentialEndpoint := getCredentialEndpoint(metadata, offer.CredentialIssuer)

	// Token exchange (pre-authorized code flow)
	tokenResp, err := exchangeToken(tokenEndpoint, offer)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	accessToken, _ := tokenResp["access_token"].(string)
	cNonce, _ := tokenResp["c_nonce"].(string)

	log.Printf("[VCI] Token endpoint: %s", tokenEndpoint)
	log.Printf("[VCI] Credential endpoint: %s", credentialEndpoint)
	log.Printf("[VCI] c_nonce: %q", cNonce)
	if tokenJSON, err := json.MarshalIndent(tokenResp, "", "  "); err == nil {
		log.Printf("[VCI] Token response:\n%s", tokenJSON)
	}

	// Create proof of possession JWT
	proofJWT, err := createProofJWT(w.HolderKey, offer.CredentialIssuer, cNonce)
	if err != nil {
		return nil, fmt.Errorf("creating proof JWT: %w", err)
	}
	log.Printf("[VCI] Proof JWT: %s", proofJWT)

	// Request credential
	credFormat := ""
	if len(offer.CredentialConfigurationIDs) > 0 {
		credFormat = resolveCredentialFormat(metadata, offer.CredentialConfigurationIDs[0])
	}

	// Extract credential_identifiers from authorization_details in token response
	credentialIdentifier := resolveCredentialIdentifier(tokenResp, offer.CredentialConfigurationIDs)

	// If no c_nonce in token response, try a nonce endpoint or send without
	// proof first to get a c_nonce from the error response.
	if cNonce == "" {
		cNonce = fetchNonce(metadata, offer.CredentialIssuer)
		if cNonce != "" {
			proofJWT, err = createProofJWT(w.HolderKey, offer.CredentialIssuer, cNonce)
			if err != nil {
				return nil, fmt.Errorf("creating proof JWT with nonce: %w", err)
			}
			log.Printf("[VCI] Recreated proof JWT with nonce from nonce endpoint")
		}
	}

	if cNonce == "" {
		// Try credential request without proof to get c_nonce from error response
		log.Printf("[VCI] No c_nonce available, attempting credential request to obtain one")
		nonceResp, nonceErr := requestCredential(credentialEndpoint, accessToken, proofJWT, credentialIdentifier)
		if nonceErr != nil {
			// Check if the error response contained a c_nonce
			if n, ok := nonceResp["c_nonce"].(string); ok && n != "" {
				cNonce = n
				log.Printf("[VCI] Got c_nonce from error response: %s", cNonce)
				// Recreate proof with the real nonce
				proofJWT, err = createProofJWT(w.HolderKey, offer.CredentialIssuer, cNonce)
				if err != nil {
					return nil, fmt.Errorf("creating proof JWT with nonce: %w", err)
				}
			} else {
				return nil, fmt.Errorf("requesting credential: %w", nonceErr)
			}
		} else {
			// First request succeeded without nonce — use the response directly
			credential := extractCredential(nonceResp)
			if credential == "" {
				return nil, fmt.Errorf("no credential in response")
			}
			if err := w.ImportCredential(credential); err != nil {
				return nil, fmt.Errorf("importing received credential: %w", err)
			}
			creds := w.GetCredentials()
			lastCred := creds[len(creds)-1]
			if credFormat == "" {
				credFormat = lastCred.Format
			}
			return &IssuanceResult{
				CredentialID: lastCred.ID,
				Format:       credFormat,
				Issuer:       offer.CredentialIssuer,
			}, nil
		}
	}

	credResp, err := requestCredential(credentialEndpoint, accessToken, proofJWT, credentialIdentifier)
	if err != nil {
		return nil, fmt.Errorf("requesting credential: %w", err)
	}

	if credJSON, err := json.MarshalIndent(credResp, "", "  "); err == nil {
		log.Printf("[VCI] Credential response:\n%s", credJSON)
	}

	credential := extractCredential(credResp)
	if credential == "" {
		return nil, fmt.Errorf("no credential in response")
	}

	// Import the received credential
	if err := w.ImportCredential(credential); err != nil {
		return nil, fmt.Errorf("importing received credential: %w", err)
	}

	creds := w.GetCredentials()
	lastCred := creds[len(creds)-1]

	if credFormat == "" {
		credFormat = lastCred.Format
	}

	return &IssuanceResult{
		CredentialID: lastCred.ID,
		Format:       credFormat,
		Issuer:       offer.CredentialIssuer,
	}, nil
}

// fetchIssuerMetadata fetches the OpenID Credential Issuer metadata.
func fetchIssuerMetadata(issuer string) (map[string]any, error) {
	metadataURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-credential-issuer"

	resp, err := http.Get(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("fetching metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("metadata request failed (%d): %s", resp.StatusCode, string(body))
	}

	var metadata map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("parsing metadata: %w", err)
	}

	return metadata, nil
}

func getTokenEndpoint(metadata map[string]any, issuer string) string {
	// OID4VCI: token_endpoint may be directly in credential issuer metadata
	if ep, ok := metadata["token_endpoint"].(string); ok {
		return ep
	}

	// Determine the authorization server URL. Per OID4VCI spec, if
	// authorization_servers is present, use the first entry; otherwise
	// the credential issuer URL itself acts as the authorization server.
	authServer := strings.TrimRight(issuer, "/")
	if servers, ok := metadata["authorization_servers"].([]any); ok && len(servers) > 0 {
		if s, ok := servers[0].(string); ok {
			authServer = strings.TrimRight(s, "/")
		}
	}

	// Fetch the OAuth authorization server metadata to find the token endpoint
	oauthMeta, err := fetchOAuthMetadata(authServer)
	if err == nil {
		if ep, ok := oauthMeta["token_endpoint"].(string); ok {
			return ep
		}
	}

	return authServer + "/token"
}

// fetchOAuthMetadata fetches the OAuth 2.0 Authorization Server metadata.
// Tries /.well-known/openid-configuration first, falls back to
// /.well-known/oauth-authorization-server.
func fetchOAuthMetadata(authServer string) (map[string]any, error) {
	base := strings.TrimRight(authServer, "/")
	urls := []string{
		base + "/.well-known/openid-configuration",
		base + "/.well-known/oauth-authorization-server",
	}

	for _, u := range urls {
		resp, err := http.Get(u)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		var meta map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
			continue
		}
		return meta, nil
	}

	return nil, fmt.Errorf("no OAuth metadata found at %s", authServer)
}

func getCredentialEndpoint(metadata map[string]any, issuer string) string {
	if ep, ok := metadata["credential_endpoint"].(string); ok {
		return ep
	}
	return strings.TrimRight(issuer, "/") + "/credential"
}

func resolveCredentialFormat(metadata map[string]any, configID string) string {
	configs, ok := metadata["credential_configurations_supported"].(map[string]any)
	if !ok {
		return ""
	}
	cfg, ok := configs[configID].(map[string]any)
	if !ok {
		return ""
	}
	f, _ := cfg["format"].(string)
	return f
}

// exchangeToken performs the pre-authorized code token exchange.
func exchangeToken(tokenEndpoint string, offer *oid4vc.CredentialOffer) (map[string]any, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
	form.Set("pre-authorized_code", offer.Grants.PreAuthorizedCode)

	resp, err := http.PostForm(tokenEndpoint, form)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	var tokenResp map[string]any
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}

	if errMsg, ok := tokenResp["error"].(string); ok {
		desc, _ := tokenResp["error_description"].(string)
		return nil, fmt.Errorf("token error: %s: %s", errMsg, desc)
	}

	return tokenResp, nil
}

// createProofJWT creates an OID4VCI proof of possession JWT.
func createProofJWT(holderKey *ecdsa.PrivateKey, audience, cNonce string) (string, error) {
	// Build JWK for holder public key
	jwkJSON := mock.PublicKeyJWK(&holderKey.PublicKey)
	var jwk map[string]any
	if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
		return "", fmt.Errorf("parsing holder JWK: %w", err)
	}

	header := map[string]any{
		"alg": "ES256",
		"typ": "openid4vci-proof+jwt",
		"jwk": jwk,
	}

	payload := map[string]any{
		"aud":   audience,
		"iat":   time.Now().Unix(),
		"nonce": cNonce,
	}

	return signJWT(header, payload, holderKey)
}

// resolveCredentialIdentifier extracts a credential_identifier from the token
// response's authorization_details. Per OID4VCI, the token response may contain
// authorization_details with credential_identifiers that should be used instead
// of the credential_configuration_id from the offer.
func resolveCredentialIdentifier(tokenResp map[string]any, configIDs []string) string {
	if authDetails, ok := tokenResp["authorization_details"].([]any); ok {
		for _, detail := range authDetails {
			d, ok := detail.(map[string]any)
			if !ok {
				continue
			}
			if ids, ok := d["credential_identifiers"].([]any); ok && len(ids) > 0 {
				if id, ok := ids[0].(string); ok {
					return id
				}
			}
		}
	}

	// Fallback to credential_configuration_id from the offer
	if len(configIDs) > 0 {
		return configIDs[0]
	}
	return ""
}

// extractCredential extracts the credential string from a credential response.
// Supports both the single "credential" field and the "credentials" array format.
func extractCredential(resp map[string]any) string {
	// Single credential field (OID4VCI draft 13 and earlier)
	if c, ok := resp["credential"].(string); ok && c != "" {
		return c
	}

	// Credentials array (OID4VCI draft 14+)
	if creds, ok := resp["credentials"].([]any); ok && len(creds) > 0 {
		if entry, ok := creds[0].(map[string]any); ok {
			if c, ok := entry["credential"].(string); ok {
				return c
			}
		}
		// Array of raw strings
		if c, ok := creds[0].(string); ok {
			return c
		}
	}

	return ""
}

// fetchNonce tries to obtain a c_nonce from a dedicated nonce endpoint.
// OID4VCI draft 15+ defines an optional nonce_endpoint in issuer metadata.
func fetchNonce(metadata map[string]any, issuer string) string {
	ep, ok := metadata["nonce_endpoint"].(string)
	if !ok || ep == "" {
		return ""
	}

	resp, err := http.Post(ep, "application/x-www-form-urlencoded", nil)
	if err != nil {
		log.Printf("[VCI] Nonce endpoint request failed: %v", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var nonceResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&nonceResp); err != nil {
		return ""
	}

	if n, ok := nonceResp["c_nonce"].(string); ok {
		log.Printf("[VCI] Got c_nonce from nonce endpoint: %s", n)
		return n
	}
	return ""
}

// requestCredential sends a credential request to the issuer.
func requestCredential(credentialEndpoint, accessToken, proofJWT string, credentialIdentifier string) (map[string]any, error) {
	reqBody := map[string]any{
		"proof": map[string]any{
			"proof_type": "jwt",
			"jwt":        proofJWT,
		},
	}

	if credentialIdentifier != "" {
		reqBody["credential_identifier"] = credentialIdentifier
	}

	bodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequest("POST", credentialEndpoint, strings.NewReader(string(bodyJSON)))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("credential request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading credential response: %w", err)
	}

	var credResp map[string]any
	if err := json.Unmarshal(body, &credResp); err != nil {
		// If not JSON, try treating the body as the raw credential
		return map[string]any{"credential": string(body)}, nil
	}

	if errMsg, ok := credResp["error"].(string); ok {
		desc, _ := credResp["error_description"].(string)
		// Return the response map alongside the error so callers can extract c_nonce
		return credResp, fmt.Errorf("credential error: %s: %s", errMsg, desc)
	}

	return credResp, nil
}
