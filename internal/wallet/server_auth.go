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
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"

	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
)

// AuthorizationRequestParams holds the extracted fields from an authorization request.
type AuthorizationRequestParams struct {
	ClientID      string
	ResponseType  string
	ResponseMode  string
	Nonce         string
	State         string
	RedirectURI   string
	ResponseURI   string
	DCQLQuery     map[string]any
	RequestObject *oid4vc.RequestObjectJWT
}

// handleAuthFlow is the core OID4VP flow handler.
func (s *Server) handleAuthFlow(w http.ResponseWriter, authReq *AuthorizationRequestParams) {
	// Check one-shot error override
	if override := s.wallet.ConsumeNextError(); override != nil {
		s.log("  Next-error override consumed: %s", override.Error)
		s.wallet.AddLog("presentation", fmt.Sprintf("Returned error override: %s", override.Error), false)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":            "error",
			"error":             override.Error,
			"error_description": override.ErrorDescription,
		})
		return
	}

	// Check client_id against x5c SAN / redirect_uri
	responseURI := authReq.ResponseURI
	if responseURI == "" {
		responseURI = authReq.RedirectURI
	}
	if warning := VerifyClientID(authReq.ClientID, authReq.RequestObject, responseURI); warning != "" {
		s.log("  WARNING: %s", warning)
		s.wallet.AddLog("presentation", fmt.Sprintf("client_id warning: %s", warning), false)
	}

	// Validate Request Object typ header (OID4VP 1.0: MUST be oauth-authz-req+jwt)
	if warning := ValidateRequestObject(authReq.ClientID, authReq.RequestObject); warning != "" {
		s.log("  WARNING: %s", warning)
		s.wallet.AddLog("presentation", fmt.Sprintf("request object warning: %s", warning), false)
	}

	// HAIP 1.0 compliance check
	if s.wallet.RequireHAIP {
		if violations := ValidateHAIPCompliance(authReq, authReq.RequestObject); len(violations) > 0 {
			for _, v := range violations {
				s.log("  HAIP VIOLATION: %s", v)
			}
			s.wallet.AddLog("presentation", fmt.Sprintf("HAIP violations: %v", violations), false)
			s.wallet.NotifyError(WalletError{
				Message: "HAIP 1.0 compliance check failed",
				Detail:  strings.Join(violations, "; "),
			})
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":             "invalid_request",
				"error_description": "HAIP 1.0 compliance check failed: " + strings.Join(violations, "; "),
			})
			return
		}
	}

	// Log DCQL query
	if authReq.DCQLQuery != nil {
		if dcqlJSON, err := json.Marshal(authReq.DCQLQuery); err == nil {
			s.log("  DCQL Query:    %s", string(dcqlJSON))
		}
	}

	// Evaluate DCQL query
	var matches []CredentialMatch
	if authReq.DCQLQuery != nil {
		matches = s.wallet.EvaluateDCQL(authReq.DCQLQuery)
	}

	s.log("  Matched:       %d credential(s)", len(matches))
	for _, m := range matches {
		s.log("    - %s %s (%s), disclosing %d claims", m.Format, credTypeLabel(m), m.CredentialID[:8], len(m.SelectedKeys))
	}

	if len(matches) == 0 {
		s.log("  Result:        no matching credentials")
		s.wallet.AddLog("presentation", fmt.Sprintf("No matching credentials for %s", authReq.ClientID), false)
		s.wallet.NotifyError(WalletError{
			Message: "No matching credentials",
			Detail:  fmt.Sprintf("Verifier %s requested credentials but none matched the query", authReq.ClientID),
		})
		if s.onConsentRequest != nil {
			s.onConsentRequest(nil)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "no_match",
			"error":  "no matching credentials found",
		})
		return
	}

	// Auto-accept mode: skip consent
	if s.wallet.AutoAccept {
		s.log("  Mode:          auto-accept")
		s.autoAcceptPresentation(w, authReq, matches)
		return
	}

	// Interactive mode: create consent request and wait
	s.log("  Mode:          interactive — waiting for consent...")
	consentReq := &ConsentRequest{
		ID:           uuid.New().String(),
		Type:         "presentation",
		MatchedCreds: matches,
		Status:       "pending",
		ResultCh:     make(chan ConsentResult, 1),
		SubmissionCh: make(chan SubmissionResult, 1),
		CreatedAt:    time.Now(),
		ClientID:     authReq.ClientID,
		Nonce:        authReq.Nonce,
		ResponseURI:  authReq.ResponseURI,
		DCQLQuery:    authReq.DCQLQuery,
	}

	s.wallet.CreateConsentRequest(consentReq)

	if s.onConsentRequest != nil {
		s.onConsentRequest(consentReq)
	}

	// Wait for user consent (with timeout)
	select {
	case result := <-consentReq.ResultCh:
		if !result.Approved {
			s.log("  Consent:       denied")
			s.wallet.AddLog("presentation", fmt.Sprintf("Denied presentation to %s", authReq.ClientID), false)
			consentReq.SubmissionCh <- SubmissionResult{Error: "denied"}
			writeJSON(w, http.StatusOK, map[string]string{"status": "denied"})
			return
		}

		s.log("  Consent:       approved")

		// Apply user's claim selections if provided
		if result.SelectedClaims != nil {
			for i, m := range matches {
				if selectedKeys, ok := result.SelectedClaims[m.CredentialID]; ok {
					matches[i].SelectedKeys = selectedKeys
					cred, _ := s.wallet.GetCredential(m.CredentialID)
					matches[i].Claims = filterClaims(cred.Claims, selectedKeys)
					s.log("    - %s: disclosing %v", m.CredentialID[:8], selectedKeys)
				}
			}
		}

		s.submitPresentationWithNotify(w, authReq, matches, consentReq.SubmissionCh)

	case <-time.After(5 * time.Minute):
		consentReq.Status = "denied"
		s.wallet.AddLog("presentation", "Consent timeout", false)
		consentReq.SubmissionCh <- SubmissionResult{Error: "consent timeout"}
		writeJSON(w, http.StatusRequestTimeout, map[string]string{"error": "consent timeout"})
	}
}

// autoAcceptPresentation handles auto-accept mode.
func (s *Server) autoAcceptPresentation(w http.ResponseWriter, authReq *AuthorizationRequestParams, matches []CredentialMatch) {
	dim := color.New(color.Faint)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	dim.Println("───────────────────────────────────────")
	yellow.Printf("  Verifier: %s\n", authReq.ClientID)
	for _, m := range matches {
		fmt.Printf("  Credential: %s (%s)\n", m.Format, credTypeLabel(m))
		fmt.Printf("  Disclosing: %v\n", m.SelectedKeys)
	}

	s.submitPresentation(w, authReq, matches)
	green.Printf("  Auto-accepted\n")
	dim.Println("───────────────────────────────────────")
}

// submitPresentationWithNotify creates VP tokens, submits them, and notifies via the submission channel.
func (s *Server) submitPresentationWithNotify(w http.ResponseWriter, authReq *AuthorizationRequestParams, matches []CredentialMatch, submissionCh chan SubmissionResult) {
	result := s.submitPresentation(w, authReq, matches)
	if submissionCh != nil {
		submissionCh <- result
	}
}

// submitPresentation creates VP tokens and submits them to the verifier.
func (s *Server) submitPresentation(w http.ResponseWriter, authReq *AuthorizationRequestParams, matches []CredentialMatch) SubmissionResult {
	responseURI := authReq.ResponseURI
	if responseURI == "" {
		responseURI = authReq.RedirectURI
	}

	s.log("  Submitting VP token to %s", responseURI)

	// Create VP tokens
	params := PresentationParams{
		Nonce:         authReq.Nonce,
		ClientID:      authReq.ClientID,
		ResponseURI:   responseURI,
		RedirectURI:   authReq.RedirectURI,
		ResponseMode:  authReq.ResponseMode,
		RequestObject: authReq.RequestObject,
	}
	vpResult, err := s.wallet.CreateVPTokenMap(matches, params)
	if err != nil {
		s.log("  ERROR: VP token creation failed: %v", err)
		s.wallet.AddLog("presentation", fmt.Sprintf("VP token creation failed: %v", err), false)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return SubmissionResult{Error: err.Error()}
	}

	s.log("  VP tokens:     %d created", len(vpResult.TokenMap))

	// Submit to verifier (encrypts if direct_post.jwt with encryption key)
	result, err := s.wallet.SubmitPresentation(vpResult, authReq.State, responseURI, params)
	if err != nil {
		s.log("  ERROR: Submission failed: %v", err)
		s.wallet.AddLog("presentation", fmt.Sprintf("Submission failed: %v", err), false)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return SubmissionResult{Error: err.Error()}
	}

	s.log("  Response:      HTTP %d", result.StatusCode)
	if result.RedirectURI != "" {
		s.log("  Redirect:      %s", result.RedirectURI)
	}
	if result.StatusCode >= 400 {
		s.log("  ERROR:         %s", result.Body)
	}

	s.wallet.AddLog("presentation", fmt.Sprintf("Presented to %s: %s", authReq.ClientID, FormatDirectPostResult(result)), true)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "submitted",
		"response":      result,
		"vp_token_keys": vpResult.QueryIDs(),
	})

	return SubmissionResult{
		RedirectURI: result.RedirectURI,
		StatusCode:  result.StatusCode,
		Error: func() string {
			if result.StatusCode >= 400 {
				return result.Body
			}
			return ""
		}(),
	}
}

// parseAuthParams extracts authorization request params from URL values.
func parseAuthParams(values map[string][]string, opts oid4vc.ParseOptions) (*AuthorizationRequestParams, error) {
	get := func(key string) string {
		if vs, ok := values[key]; ok && len(vs) > 0 {
			return vs[0]
		}
		return ""
	}

	params := &AuthorizationRequestParams{
		ClientID:     get("client_id"),
		ResponseType: get("response_type"),
		ResponseMode: get("response_mode"),
		Nonce:        get("nonce"),
		State:        get("state"),
		RedirectURI:  get("redirect_uri"),
		ResponseURI:  get("response_uri"),
	}

	// Parse dcql_query if present
	if dq := get("dcql_query"); dq != "" {
		var query map[string]any
		if err := json.Unmarshal([]byte(dq), &query); err != nil {
			return nil, fmt.Errorf("parsing dcql_query: %w", err)
		}
		params.DCQLQuery = query
	}

	// If request_uri is present, build a synthetic openid4vp:// URI with all
	// params so the parser can handle request_uri_method and fetch the JWT.
	if requestURI := get("request_uri"); requestURI != "" {
		syntheticParams := url.Values{}
		for k, vs := range values {
			if len(vs) > 0 {
				syntheticParams.Set(k, vs[0])
			}
		}
		syntheticURI := "openid4vp://authorize?" + syntheticParams.Encode()

		parsed, err := ParseAuthorizationRequestWithOptions(syntheticURI, opts)
		if err != nil {
			log.Printf("[Wallet] Failed to parse request_uri %q: %v", requestURI, err)
		} else {
			if params.ClientID == "" {
				params.ClientID = parsed.ClientID
			}
			if params.Nonce == "" {
				params.Nonce = parsed.Nonce
			}
			if params.State == "" {
				params.State = parsed.State
			}
			if params.ResponseURI == "" {
				params.ResponseURI = parsed.ResponseURI
			}
			if params.RedirectURI == "" {
				params.RedirectURI = parsed.RedirectURI
			}
			if params.ResponseMode == "" {
				params.ResponseMode = parsed.ResponseMode
			}
			if params.DCQLQuery == nil {
				params.DCQLQuery = parsed.DCQLQuery
			}
			if params.RequestObject == nil {
				params.RequestObject = parsed.RequestObject
			}
		}
	}

	// If request (JWT) is present, parse it
	if requestJWT := get("request"); requestJWT != "" {
		parsed, err := ParseAuthorizationRequestWithOptions(requestJWT, opts)
		if err != nil {
			log.Printf("[Wallet] Failed to parse request JWT: %v", err)
		} else {
			if params.ClientID == "" {
				params.ClientID = parsed.ClientID
			}
			if params.Nonce == "" {
				params.Nonce = parsed.Nonce
			}
			if params.State == "" {
				params.State = parsed.State
			}
			if params.ResponseURI == "" {
				params.ResponseURI = parsed.ResponseURI
			}
			if params.RedirectURI == "" {
				params.RedirectURI = parsed.RedirectURI
			}
			if params.ResponseMode == "" {
				params.ResponseMode = parsed.ResponseMode
			}
			if params.DCQLQuery == nil {
				params.DCQLQuery = parsed.DCQLQuery
			}
			if params.RequestObject == nil {
				params.RequestObject = parsed.RequestObject
			}
		}
	}

	if params.ClientID == "" {
		return nil, fmt.Errorf("missing client_id")
	}

	return params, nil
}

func credTypeLabel(m CredentialMatch) string {
	if m.VCT != "" {
		return m.VCT
	}
	if m.DocType != "" {
		return m.DocType
	}
	return m.Format
}
