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
	"testing"
)

func TestScanCEK(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantCEK string
	}{
		{
			name:    "wallet-style CEK log",
			line:    `2026/01/15 14:32:05 [VP] JWE content encryption key for proxy debugging: dGhpcyBpcyBhIHRlc3Qga2V5MTIz`,
			wantCEK: "dGhpcyBpcyBhIHRlc3Qga2V5MTIz",
		},
		{
			name:    "generic CEK log",
			line:    `CEK: abcdef0123456789ABCDEF`,
			wantCEK: "abcdef0123456789ABCDEF",
		},
		{
			name:    "content encryption key label",
			line:    `Content Encryption Key derived: AAAAAAAAAAAAAAAA_-test`,
			wantCEK: "AAAAAAAAAAAAAAAA_-test",
		},
		{
			name:    "no CEK",
			line:    `2026/01/15 14:32:05 Starting server on port 8080`,
			wantCEK: "",
		},
		{
			name:    "case insensitive cek",
			line:    `cek value: AAAAAAAAAAAAAAAA`,
			wantCEK: "AAAAAAAAAAAAAAAA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewOutputScanner()
			s.Scan(tt.line)
			if got := s.LastCEK(); got != tt.wantCEK {
				t.Errorf("LastCEK() = %q, want %q", got, tt.wantCEK)
			}
		})
	}
}

func TestScanCEKLastWins(t *testing.T) {
	s := NewOutputScanner()
	s.Scan(`CEK: firstkey1234567890`)
	s.Scan(`CEK: secondkey123456789`)
	if got := s.LastCEK(); got != "secondkey123456789" {
		t.Errorf("LastCEK() = %q, want last key", got)
	}
}

func TestScanCredentials(t *testing.T) {
	// A realistic-looking JWT (header.payload.signature, each part base64url)
	jwt := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	tests := []struct {
		name      string
		line      string
		wantCount int
		wantLabel string
	}{
		{
			name:      "vp_token line",
			line:      `Received vp_token: ` + jwt,
			wantCount: 1,
			wantLabel: "vp_token",
		},
		{
			name:      "credential line",
			line:      `Issued credential: ` + jwt,
			wantCount: 1,
			wantLabel: "credential",
		},
		{
			name:      "sd-jwt with disclosures",
			line:      `SD-JWT: ` + jwt + `~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~`,
			wantCount: 1,
			wantLabel: "sd-jwt",
		},
		{
			name:      "no credentials",
			line:      `Server started on port 8080`,
			wantCount: 0,
		},
		{
			name:      "generic jwt",
			line:      `Token: ` + jwt,
			wantCount: 1,
			wantLabel: "jwt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewOutputScanner()
			s.Scan(tt.line)
			creds := s.Credentials()
			if len(creds) != tt.wantCount {
				t.Fatalf("got %d credentials, want %d", len(creds), tt.wantCount)
			}
			if tt.wantCount > 0 && creds[0].Label != tt.wantLabel {
				t.Errorf("label = %q, want %q", creds[0].Label, tt.wantLabel)
			}
		})
	}
}

func TestScanJWK(t *testing.T) {
	s := NewOutputScanner()
	// A line containing a JWK with private key "d" parameter
	line := `Verifier key: {"kty":"EC","crv":"P-256","x":"abc","y":"def","d":"privatekeyvalue"}`
	s.Scan(line)
	// JWK scanning doesn't panic — best-effort detection
}

func TestDrainCredentials(t *testing.T) {
	jwt := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	s := NewOutputScanner()
	s.Scan("Token: " + jwt)

	drained := s.DrainCredentials()
	if len(drained) != 1 {
		t.Fatalf("DrainCredentials() returned %d, want 1", len(drained))
	}

	// After drain, credentials should be empty
	if remaining := s.Credentials(); len(remaining) != 0 {
		t.Errorf("after drain, Credentials() returned %d, want 0", len(remaining))
	}
}

func TestScanSkipsOAuthAuthzReqJWT(t *testing.T) {
	// oauth-authz-req+jwt header: {"alg":"ES256","typ":"oauth-authz-req+jwt"}
	reqObj := "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJjbGllbnRfaWQiOiJ4In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	s := NewOutputScanner()
	s.Scan("Request Object: " + reqObj)
	if len(s.Credentials()) != 0 {
		t.Error("oauth-authz-req+jwt should not be detected as a credential")
	}
}

func TestScanShortTokenIgnored(t *testing.T) {
	s := NewOutputScanner()
	// eyJ followed by very short content — should be ignored
	s.Scan("eyJhbGci.eyJz.abc")
	if len(s.Credentials()) != 0 {
		t.Error("short token should be ignored")
	}
}
