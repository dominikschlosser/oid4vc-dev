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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// SubmitDirectPost submits a VP token via direct_post to the response URI.
func SubmitDirectPost(responseURI, state string, vpToken any) (*DirectPostResult, error) {
	form := url.Values{}
	if state != "" {
		form.Set("state", state)
	}

	tokenJSON, err := json.Marshal(vpToken)
	if err != nil {
		return nil, fmt.Errorf("marshaling vp_token: %w", err)
	}
	form.Set("vp_token", string(tokenJSON))

	resp, err := http.PostForm(responseURI, form)
	if err != nil {
		return nil, fmt.Errorf("posting to response_uri: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	result := &DirectPostResult{
		StatusCode: resp.StatusCode,
		Body:       string(body),
	}

	// Try to parse redirect_uri from response
	var respJSON map[string]any
	if err := json.Unmarshal(body, &respJSON); err == nil {
		if redirectURI, ok := respJSON["redirect_uri"].(string); ok {
			result.RedirectURI = redirectURI
		}
	}

	// Also check Location header
	if loc := resp.Header.Get("Location"); loc != "" {
		result.RedirectURI = loc
	}

	return result, nil
}

// DirectPostResult represents the result of a direct_post submission.
type DirectPostResult struct {
	StatusCode  int    `json:"status_code"`
	Body        string `json:"body"`
	RedirectURI string `json:"redirect_uri,omitempty"`
}

// SubmitDirectPostJWT submits an encrypted JARM response via direct_post.jwt.
// The vp_token and state are inside the encrypted responseJWT payload.
// If cek is non-nil, it is included as X-Debug-JWE-CEK header for proxy debugging.
func SubmitDirectPostJWT(responseURI string, responseJWT string, cek []byte) (*DirectPostResult, error) {
	form := url.Values{}
	form.Set("response", responseJWT)

	req, err := http.NewRequest("POST", responseURI, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if len(cek) > 0 {
		cekB64 := base64.RawURLEncoding.EncodeToString(cek)
		req.Header.Set("X-Debug-JWE-CEK", cekB64)
		log.Printf("[VP] JWE content encryption key for proxy debugging: %s", cekB64)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("posting to response_uri: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	result := &DirectPostResult{
		StatusCode: resp.StatusCode,
		Body:       string(body),
	}

	var respJSON map[string]any
	if err := json.Unmarshal(body, &respJSON); err == nil {
		if redirectURI, ok := respJSON["redirect_uri"].(string); ok {
			result.RedirectURI = redirectURI
		}
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		result.RedirectURI = loc
	}

	return result, nil
}

// FormatDirectPostResult formats a direct post result for terminal output.
func FormatDirectPostResult(result *DirectPostResult) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Response: %d", result.StatusCode)
	if result.RedirectURI != "" {
		fmt.Fprintf(&sb, " → %s", result.RedirectURI)
	}
	return sb.String()
}
