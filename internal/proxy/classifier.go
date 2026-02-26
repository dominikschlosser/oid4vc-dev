package proxy

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/dominikschlosser/ssi-debugger/internal/format"
	"github.com/dominikschlosser/ssi-debugger/internal/web"
)

// Classify determines the OID4VP/VCI traffic class from the request/response.
func Classify(entry *TrafficEntry) {
	entry.Class = classifyEntry(entry)
	entry.ClassLabel = entry.Class.Label()
	entry.Decoded = decodeEntry(entry)
	entry.Credentials = extractCredentials(entry)
}

func classifyEntry(e *TrafficEntry) TrafficClass {
	u, _ := url.Parse(e.URL)
	path := ""
	query := url.Values{}
	if u != nil {
		path = u.Path
		query = u.Query()
	}

	// VCI: .well-known/openid-credential-issuer
	if strings.Contains(path, ".well-known/openid-credential-issuer") {
		return ClassVCIMetadata
	}

	// VCI: credential_offer or credential_offer_uri in query
	if query.Has("credential_offer") || query.Has("credential_offer_uri") {
		return ClassVCICredentialOffer
	}

	// VP Auth Request: client_id + response_type=vp_token
	if query.Get("client_id") != "" && query.Get("response_type") == "vp_token" {
		return ClassVPAuthRequest
	}

	// VP Request Object: response body is a JWT
	if e.Method == "GET" && isJWTBody(e.ResponseBody) {
		return ClassVPRequestObject
	}

	// POST-based classification
	if e.Method == "POST" {
		// VP Auth Response (direct_post or direct_post.jwt)
		if hasBodyField(e.RequestBody, "vp_token") ||
			hasBodyField(e.RequestBody, "presentation_submission") ||
			hasBodyField(e.RequestBody, "id_token") ||
			hasBodyField(e.RequestBody, "response") {
			return ClassVPAuthResponse
		}

		// VCI Token Request: path ends with /token
		if strings.HasSuffix(path, "/token") {
			return ClassVCITokenRequest
		}

		// VCI Credential Request: path ends with /credential
		if strings.HasSuffix(path, "/credential") || strings.HasSuffix(path, "/credentials") {
			return ClassVCICredentialRequest
		}
	}

	return ClassUnknown
}

func decodeEntry(e *TrafficEntry) map[string]any {
	decoded := make(map[string]any)

	switch e.Class {
	case ClassVPAuthRequest:
		u, _ := url.Parse(e.URL)
		if u != nil {
			q := u.Query()
			decoded["client_id"] = q.Get("client_id")
			decoded["response_type"] = q.Get("response_type")
			if v := q.Get("response_mode"); v != "" {
				decoded["response_mode"] = v
			}
			if v := q.Get("nonce"); v != "" {
				decoded["nonce"] = v
			}
			if v := q.Get("state"); v != "" {
				decoded["state"] = v
			}
			if v := q.Get("request_uri"); v != "" {
				decoded["request_uri"] = v
			}
			if v := q.Get("response_uri"); v != "" {
				decoded["response_uri"] = v
			}
			// Parse JSON query params into proper objects
			if v := q.Get("dcql_query"); v != "" {
				var m map[string]any
				if err := json.Unmarshal([]byte(v), &m); err == nil {
					decoded["dcql_query"] = m
				} else {
					decoded["dcql_query"] = v
				}
			}
			if v := q.Get("presentation_definition"); v != "" {
				var m map[string]any
				if err := json.Unmarshal([]byte(v), &m); err == nil {
					decoded["presentation_definition"] = m
				} else {
					decoded["presentation_definition"] = v
				}
			}
		}

	case ClassVPRequestObject:
		if header, payload, _, err := format.ParseJWTParts(strings.TrimSpace(e.ResponseBody)); err == nil {
			decoded["header"] = header
			decoded["payload"] = payload
			// Surface the verifier's ephemeral encryption key if present
			// (used by the wallet to encrypt the JARM response in direct_post.jwt)
			if jwks, ok := payload["jwks"].(map[string]any); ok {
				decoded["encryption_jwks"] = jwks
			}
		}

	case ClassVPAuthResponse:
		fields := parseFormOrJSON(e.RequestBody)

		// direct_post.jwt: encrypted/signed JARM response in "response" field
		if jarm, ok := fields["response"]; ok && jarm != "" {
			decoded["response_preview"] = truncate(jarm, 100)
			decodeJARMResponse(jarm, decoded)
		}

		if vpToken, ok := fields["vp_token"]; ok {
			decoded["vp_token_preview"] = truncate(vpToken, 100)
			if cred, err := web.Decode(vpToken); err == nil {
				decoded["vp_token_decoded"] = cred
			}
		}
		if idToken, ok := fields["id_token"]; ok {
			decoded["id_token_preview"] = truncate(idToken, 100)
			if header, payload, _, err := format.ParseJWTParts(idToken); err == nil {
				decoded["id_token_header"] = header
				decoded["id_token_payload"] = payload
			}
		}
		if v, ok := fields["state"]; ok {
			decoded["state"] = v
		}
		if v, ok := fields["presentation_submission"]; ok {
			var ps map[string]any
			if err := json.Unmarshal([]byte(v), &ps); err == nil {
				decoded["presentation_submission"] = ps
			}
		}

	case ClassVCICredentialOffer:
		u, _ := url.Parse(e.URL)
		if u != nil {
			if offer := u.Query().Get("credential_offer"); offer != "" {
				var m map[string]any
				if err := json.Unmarshal([]byte(offer), &m); err == nil {
					decoded["credential_offer"] = m
				}
			}
			if uri := u.Query().Get("credential_offer_uri"); uri != "" {
				decoded["credential_offer_uri"] = uri
			}
		}

	case ClassVCIMetadata:
		if e.ResponseBody != "" {
			var m map[string]any
			if err := json.Unmarshal([]byte(e.ResponseBody), &m); err == nil {
				decoded["metadata"] = m
			}
		}

	case ClassVCITokenRequest:
		fields := parseFormOrJSON(e.RequestBody)
		for k, v := range fields {
			decoded[k] = v
		}
		if e.ResponseBody != "" {
			var resp map[string]any
			if err := json.Unmarshal([]byte(e.ResponseBody), &resp); err == nil {
				decoded["response"] = resp
			}
		}

	case ClassVCICredentialRequest:
		if e.RequestBody != "" {
			var reqBody map[string]any
			if err := json.Unmarshal([]byte(e.RequestBody), &reqBody); err == nil {
				decoded["request"] = reqBody
			}
		}
		if e.ResponseBody != "" {
			var resp map[string]any
			if err := json.Unmarshal([]byte(e.ResponseBody), &resp); err == nil {
				decoded["response"] = resp
				// Try to decode the credential inside the response
				if cred, ok := resp["credential"].(string); ok {
					if credDecoded, err := web.Decode(cred); err == nil {
						decoded["credential_decoded"] = credDecoded
					}
				}
			}
		}
	}

	if len(decoded) == 0 {
		return nil
	}
	return decoded
}

func isJWTBody(body string) bool {
	body = strings.TrimSpace(body)
	parts := strings.SplitN(body, ".", 4)
	return len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0 && !strings.ContainsAny(body, " \n\t{<")
}

// isJWE checks whether a string looks like a JWE compact serialization (5 dot-separated parts).
func isJWE(s string) bool {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ".")
	return len(parts) == 5 && len(parts[0]) > 0
}

// decodeJARMResponse decodes a JARM response (direct_post.jwt).
// JWE (5 parts): only the protected header is readable (payload is encrypted
// with the verifier's ephemeral key — see encryption_jwks in the request object).
// JWS (3 parts): header and payload are readable.
func decodeJARMResponse(raw string, decoded map[string]any) {
	raw = strings.TrimSpace(raw)

	if isJWE(raw) {
		decoded["response_type"] = "JWE (encrypted — payload not readable without verifier's ephemeral private key)"
		headerBytes, err := format.DecodeBase64URL(strings.SplitN(raw, ".", 2)[0])
		if err != nil {
			return
		}
		var header map[string]any
		if err := json.Unmarshal(headerBytes, &header); err != nil {
			return
		}
		decoded["response_header"] = header

		// Surface key fields for easier debugging
		if alg, ok := header["alg"].(string); ok {
			decoded["encryption_alg"] = alg
		}
		if enc, ok := header["enc"].(string); ok {
			decoded["encryption_enc"] = enc
		}
		if kid, ok := header["kid"].(string); ok {
			decoded["encryption_kid"] = kid
		}
		// Ephemeral public key from the JWE sender (wallet)
		if epk, ok := header["epk"].(map[string]any); ok {
			decoded["encryption_epk"] = epk
		}
		if apu, ok := header["apu"].(string); ok {
			decoded["encryption_apu"] = apu
		}
		if apv, ok := header["apv"].(string); ok {
			decoded["encryption_apv"] = apv
		}
		return
	}

	// JWS: decode header + payload
	if header, payload, _, err := format.ParseJWTParts(raw); err == nil {
		decoded["response_type"] = "JWS (signed)"
		decoded["response_header"] = header
		decoded["response_payload"] = payload
	}
}

// hasBodyField checks whether a field exists in either URL-encoded form data or JSON body.
func hasBodyField(body, field string) bool {
	if values, err := url.ParseQuery(body); err == nil && values.Has(field) {
		return true
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err == nil {
		if _, ok := m[field]; ok {
			return true
		}
	}
	return false
}

func parseFormOrJSON(body string) map[string]string {
	result := make(map[string]string)

	// Try URL-encoded form first
	values, err := url.ParseQuery(body)
	if err == nil && len(values) > 0 {
		for k := range values {
			result[k] = values.Get(k)
		}
		return result
	}

	// Try JSON
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err == nil {
		for k, v := range m {
			switch val := v.(type) {
			case string:
				result[k] = val
			default:
				if b, err := json.Marshal(v); err == nil {
					result[k] = string(b)
				}
			}
		}
	}

	return result
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// extractCredentials pulls raw credential strings from the entry so the
// dashboard can offer "View in Decoder" links.
func extractCredentials(e *TrafficEntry) []string {
	var creds []string

	switch e.Class {
	case ClassVPAuthResponse:
		fields := parseFormOrJSON(e.RequestBody)
		if vp, ok := fields["vp_token"]; ok && vp != "" {
			creds = append(creds, vp)
		}
		if id, ok := fields["id_token"]; ok && id != "" {
			creds = append(creds, id)
		}

	case ClassVPRequestObject:
		body := strings.TrimSpace(e.ResponseBody)
		if isJWTBody(body) {
			creds = append(creds, body)
		}

	case ClassVCICredentialRequest:
		if e.ResponseBody != "" {
			var resp map[string]any
			if err := json.Unmarshal([]byte(e.ResponseBody), &resp); err == nil {
				if cred, ok := resp["credential"].(string); ok && cred != "" {
					creds = append(creds, cred)
				}
				// batch response: credentials array
				if arr, ok := resp["credentials"].([]any); ok {
					for _, item := range arr {
						if obj, ok := item.(map[string]any); ok {
							if cred, ok := obj["credential"].(string); ok && cred != "" {
								creds = append(creds, cred)
							}
						}
					}
				}
			}
		}
	}

	return creds
}
