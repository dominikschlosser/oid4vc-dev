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
	"strings"
	"testing"
)

func TestFormatDirectPostResult_Success(t *testing.T) {
	result := &DirectPostResult{
		StatusCode: 200,
	}
	got := FormatDirectPostResult(result)
	if got != "Response: 200" {
		t.Errorf("expected 'Response: 200', got %s", got)
	}
}

func TestFormatDirectPostResult_WithRedirect(t *testing.T) {
	result := &DirectPostResult{
		StatusCode:  200,
		RedirectURI: "https://verifier.example/success",
	}
	got := FormatDirectPostResult(result)
	expected := "Response: 200 → https://verifier.example/success"
	if got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}

func TestFormatDirectPostResult_Error(t *testing.T) {
	result := &DirectPostResult{
		StatusCode: 400,
		Body:       `{"error": "invalid_request"}`,
	}
	got := FormatDirectPostResult(result)
	if got != "Response: 400" {
		t.Errorf("expected 'Response: 400', got %s", got)
	}
}

func TestBuildFragmentRedirect(t *testing.T) {
	tests := []struct {
		name        string
		redirectURI string
		state       string
		vpToken     any
		wantContain []string
	}{
		{
			name:        "basic redirect with state",
			redirectURI: "https://verifier.example/callback",
			state:       "abc123",
			vpToken:     map[string][]string{"pid": {"token1"}},
			wantContain: []string{"https://verifier.example/callback#", "state=abc123", "vp_token="},
		},
		{
			name:        "redirect without state",
			redirectURI: "https://verifier.example/callback",
			state:       "",
			vpToken:     map[string][]string{"pid": {"token1"}},
			wantContain: []string{"https://verifier.example/callback#", "vp_token="},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildFragmentRedirect(tt.redirectURI, tt.state, tt.vpToken, "")
			if err != nil {
				t.Fatalf("BuildFragmentRedirect() error: %v", err)
			}
			for _, want := range tt.wantContain {
				if !strings.Contains(got, want) {
					t.Errorf("expected URL to contain %q, got: %s", want, got)
				}
			}
			if tt.state == "" && strings.Contains(got, "state=") {
				t.Errorf("expected no state parameter, got: %s", got)
			}
		})
	}
}
