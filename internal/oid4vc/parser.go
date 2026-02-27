// Copyright 2025 Dominik Schlosser
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

package oid4vc

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
)

// Parse detects and parses an OID4VCI credential offer or OID4VP authorization request.
// It returns the request type, the parsed object (CredentialOffer or AuthorizationRequest), and any error.
func Parse(raw string) (RequestType, any, error) {
	raw = strings.TrimSpace(raw)

	// 1. URI scheme detection
	if strings.HasPrefix(raw, "openid-credential-offer://") {
		return parseVCIURI(raw)
	}
	if strings.HasPrefix(raw, "openid4vp://") || strings.HasPrefix(raw, "haip://") || strings.HasPrefix(raw, "eudi-openid4vp://") {
		return parseVPURI(raw)
	}

	// 2. HTTPS/HTTP URL
	if strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "http://") {
		return parseHTTPURL(raw)
	}

	// 3. JWT (3 dot-separated base64url parts)
	if isJWT(raw) {
		return parseJWTInput(raw)
	}

	// 4. JSON object
	if strings.HasPrefix(raw, "{") {
		return parseJSONInput(raw)
	}

	return 0, nil, fmt.Errorf("unable to detect OpenID4VCI/VP format: not a recognized URI, URL, JWT, or JSON")
}

func isJWT(s string) bool {
	parts := strings.SplitN(s, ".", 4)
	return len(parts) == 3 && len(parts[0]) > 0 && len(parts[1]) > 0
}

// parseVCIURI parses an openid-credential-offer:// URI.
func parseVCIURI(raw string) (RequestType, any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return TypeVCI, nil, fmt.Errorf("parsing VCI URI: %w", err)
	}
	return parseVCIParams(u.Query())
}

// parseVPURI parses an openid4vp://, haip://, or eudi-openid4vp:// URI.
func parseVPURI(raw string) (RequestType, any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return TypeVP, nil, fmt.Errorf("parsing VP URI: %w", err)
	}
	return parseVPParams(u.Query())
}

// parseHTTPURL parses an HTTPS/HTTP URL by checking query params.
func parseHTTPURL(raw string) (RequestType, any, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return 0, nil, fmt.Errorf("parsing URL: %w", err)
	}
	q := u.Query()
	if q.Has("credential_offer") || q.Has("credential_offer_uri") {
		return parseVCIParams(q)
	}
	return parseVPParams(q)
}

// parseVCIParams extracts a credential offer from URL query parameters.
func parseVCIParams(q url.Values) (RequestType, any, error) {
	var offerJSON []byte

	if inline := q.Get("credential_offer"); inline != "" {
		offerJSON = []byte(inline)
	} else if uri := q.Get("credential_offer_uri"); uri != "" {
		fetched, err := format.FetchURL(uri)
		if err != nil {
			return TypeVCI, nil, fmt.Errorf("fetching credential_offer_uri: %w", err)
		}
		offerJSON = []byte(fetched)
	} else {
		return TypeVCI, nil, fmt.Errorf("VCI URI has no credential_offer or credential_offer_uri parameter")
	}

	return parseVCIJSON(offerJSON)
}

// parseVCIJSON parses a credential offer JSON blob.
func parseVCIJSON(data []byte) (RequestType, any, error) {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return TypeVCI, nil, fmt.Errorf("parsing credential offer JSON: %w", err)
	}

	offer := &CredentialOffer{FullJSON: m}

	if issuer, ok := m["credential_issuer"].(string); ok {
		offer.CredentialIssuer = issuer
	}

	if ids, ok := m["credential_configuration_ids"].([]any); ok {
		for _, id := range ids {
			if s, ok := id.(string); ok {
				offer.CredentialConfigurationIDs = append(offer.CredentialConfigurationIDs, s)
			}
		}
	}

	if grants, ok := m["grants"].(map[string]any); ok {
		if preAuth, ok := grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]any); ok {
			if code, ok := preAuth["pre-authorized_code"].(string); ok {
				offer.Grants.PreAuthorizedCode = code
			}
			if txCode, ok := preAuth["tx_code"].(map[string]any); ok {
				offer.Grants.TxCode = txCode
			}
		}
		if authCode, ok := grants["authorization_code"].(map[string]any); ok {
			if state, ok := authCode["issuer_state"].(string); ok {
				offer.Grants.IssuerState = state
			}
			if code, ok := authCode["authorization_code"].(string); ok {
				offer.Grants.AuthorizationCode = code
			}
		}
	}

	return TypeVCI, offer, nil
}

// parseVPParams extracts an authorization request from URL query parameters.
func parseVPParams(q url.Values) (RequestType, any, error) {
	req := &AuthorizationRequest{
		FullParams: make(map[string]string),
	}

	for key := range q {
		req.FullParams[key] = q.Get(key)
	}

	req.ClientID = q.Get("client_id")
	req.ResponseType = q.Get("response_type")
	req.ResponseMode = q.Get("response_mode")
	req.Nonce = q.Get("nonce")
	req.State = q.Get("state")
	req.RedirectURI = q.Get("redirect_uri")
	req.ResponseURI = q.Get("response_uri")
	req.Scope = q.Get("scope")

	// Resolve request_uri (fetch and parse JWT)
	if requestURI := q.Get("request_uri"); requestURI != "" {
		fetched, err := format.FetchURL(requestURI)
		if err != nil {
			return TypeVP, nil, fmt.Errorf("fetching request_uri: %w", err)
		}
		if isJWT(fetched) {
			header, payload, _, err := format.ParseJWTParts(fetched)
			if err != nil {
				return TypeVP, nil, fmt.Errorf("parsing request object JWT: %w", err)
			}
			req.RequestObject = &RequestObjectJWT{Header: header, Payload: payload}
			mergeJWTPayloadIntoRequest(req, payload)
		}
	}

	// Parse presentation_definition
	if pd := q.Get("presentation_definition"); pd != "" {
		var m map[string]any
		if err := json.Unmarshal([]byte(pd), &m); err == nil {
			req.PresentationDefinition = m
		}
	}

	// Parse dcql_query
	if dq := q.Get("dcql_query"); dq != "" {
		var m map[string]any
		if err := json.Unmarshal([]byte(dq), &m); err == nil {
			req.DCQLQuery = m
		}
	}

	return TypeVP, req, nil
}

// mergeJWTPayloadIntoRequest fills empty request fields from JWT payload claims.
func mergeJWTPayloadIntoRequest(req *AuthorizationRequest, payload map[string]any) {
	setIfEmpty := func(target *string, key string) {
		if *target == "" {
			if v, ok := payload[key].(string); ok {
				*target = v
			}
		}
	}
	setIfEmpty(&req.ClientID, "client_id")
	setIfEmpty(&req.ResponseType, "response_type")
	setIfEmpty(&req.ResponseMode, "response_mode")
	setIfEmpty(&req.Nonce, "nonce")
	setIfEmpty(&req.State, "state")
	setIfEmpty(&req.RedirectURI, "redirect_uri")
	setIfEmpty(&req.ResponseURI, "response_uri")
	setIfEmpty(&req.Scope, "scope")

	if req.PresentationDefinition == nil {
		if pd, ok := payload["presentation_definition"].(map[string]any); ok {
			req.PresentationDefinition = pd
		}
	}
	if req.DCQLQuery == nil {
		if dq, ok := payload["dcql_query"].(map[string]any); ok {
			req.DCQLQuery = dq
		}
	}
}

// parseJWTInput decodes a JWT and auto-detects VCI vs VP.
func parseJWTInput(raw string) (RequestType, any, error) {
	header, payload, _, err := format.ParseJWTParts(raw)
	if err != nil {
		return 0, nil, fmt.Errorf("parsing JWT: %w", err)
	}

	// VCI: has credential_issuer
	if _, ok := payload["credential_issuer"]; ok {
		data, err := json.Marshal(payload)
		if err != nil {
			return TypeVCI, nil, fmt.Errorf("marshaling JWT payload: %w", err)
		}
		_, offer, err := parseVCIJSON(data)
		return TypeVCI, offer, err
	}

	// VP: has client_id or response_type
	if _, ok := payload["client_id"]; ok {
		rt, req := buildVPFromJWT(header, payload)
		return rt, req, nil
	}
	if _, ok := payload["response_type"]; ok {
		rt, req := buildVPFromJWT(header, payload)
		return rt, req, nil
	}

	return 0, nil, fmt.Errorf("JWT payload does not contain VCI or VP markers (credential_issuer, client_id, response_type)")
}

func buildVPFromJWT(header, payload map[string]any) (RequestType, *AuthorizationRequest) {
	req := &AuthorizationRequest{
		RequestObject: &RequestObjectJWT{Header: header, Payload: payload},
		FullParams:    make(map[string]string),
	}
	mergeJWTPayloadIntoRequest(req, payload)
	return TypeVP, req
}

// parseJSONInput parses a raw JSON object and auto-detects VCI vs VP.
func parseJSONInput(raw string) (RequestType, any, error) {
	// VCI: has credential_issuer
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return 0, nil, fmt.Errorf("parsing JSON: %w", err)
	}

	if _, ok := m["credential_issuer"]; ok {
		return parseVCIJSON([]byte(raw))
	}

	if _, ok := m["client_id"]; ok {
		rt, req := buildVPFromJSON(m)
		return rt, req, nil
	}

	return 0, nil, fmt.Errorf("JSON does not contain VCI or VP markers (credential_issuer, client_id)")
}

func buildVPFromJSON(m map[string]any) (RequestType, *AuthorizationRequest) {
	req := &AuthorizationRequest{
		FullJSON:   m,
		FullParams: make(map[string]string),
	}

	getString := func(key string) string {
		if v, ok := m[key].(string); ok {
			return v
		}
		return ""
	}

	req.ClientID = getString("client_id")
	req.ResponseType = getString("response_type")
	req.ResponseMode = getString("response_mode")
	req.Nonce = getString("nonce")
	req.State = getString("state")
	req.RedirectURI = getString("redirect_uri")
	req.ResponseURI = getString("response_uri")
	req.Scope = getString("scope")

	if pd, ok := m["presentation_definition"].(map[string]any); ok {
		req.PresentationDefinition = pd
	}
	if dq, ok := m["dcql_query"].(map[string]any); ok {
		req.DCQLQuery = dq
	}

	return TypeVP, req
}
