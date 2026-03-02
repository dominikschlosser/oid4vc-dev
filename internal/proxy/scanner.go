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
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"sync"
	"time"
)

// OutputScanner scans lines from a subprocess's stdout/stderr for encryption
// keys and credentials. It is thread-safe and designed for best-effort detection.
type OutputScanner struct {
	mu          sync.RWMutex
	lastCEK     string // most recent base64url-encoded CEK
	credentials []ScannedCredential
}

// ScannedCredential is a credential detected in subprocess output.
type ScannedCredential struct {
	Raw       string
	Label     string
	Timestamp time.Time
}

// Regex patterns for detection.
var (
	// Explicit CEK log lines, e.g. "[VP] JWE content encryption key for proxy debugging: <base64url>"
	// or any line mentioning CEK/cek followed by a base64url value.
	cekPattern = regexp.MustCompile(`(?i)(?:CEK|content.encryption.key)[^:]*:\s*([A-Za-z0-9_-]{16,})`)

	// JWT pattern: eyJ<base64url>.<base64url>.<base64url> optionally followed by ~disclosures (SD-JWT)
	jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(?:~[A-Za-z0-9_-]*)*`)
)

// NewOutputScanner creates a new OutputScanner.
func NewOutputScanner() *OutputScanner {
	return &OutputScanner{}
}

// Scan processes a single line of subprocess output, detecting keys and credentials.
func (s *OutputScanner) Scan(line string) {
	s.scanCEK(line)
	s.scanJWK(line)
	s.scanCredentials(line)
}

// scanCEK looks for explicit CEK values in the line.
func (s *OutputScanner) scanCEK(line string) {
	if m := cekPattern.FindStringSubmatch(line); len(m) > 1 {
		s.mu.Lock()
		s.lastCEK = m[1]
		s.mu.Unlock()
	}
}

// scanJWK looks for JWK objects with a "d" (private key) parameter.
// If found, the full JWK JSON is stored and can be used to derive decryption keys.
func (s *OutputScanner) scanJWK(line string) {
	// Look for JSON objects containing "kty" and "d" on the same line
	start := strings.Index(line, "{")
	if start < 0 {
		return
	}

	// Try each '{' in the line as a potential JSON start
	for i := start; i < len(line); i++ {
		if line[i] != '{' {
			continue
		}
		candidate := line[i:]
		// Find matching closing brace
		depth := 0
		end := -1
		for j, c := range candidate {
			if c == '{' {
				depth++
			} else if c == '}' {
				depth--
				if depth == 0 {
					end = j + 1
					break
				}
			}
		}
		if end < 0 {
			continue
		}
		jsonStr := candidate[:end]
		var jwk map[string]any
		if err := json.Unmarshal([]byte(jsonStr), &jwk); err != nil {
			continue
		}
		if _, hasKty := jwk["kty"]; !hasKty {
			continue
		}
		if _, hasD := jwk["d"]; !hasD {
			continue
		}
		// Found a JWK private key — try to derive CEK if it has the right structure
		// For ECDH-ES, the verifier's private key could be used to decrypt.
		// Store the raw JWK for potential later use.
		s.mu.Lock()
		// We don't currently use the JWK directly, but log detection for debugging.
		_ = jsonStr
		s.mu.Unlock()
		return
	}
}

// scanCredentials looks for JWT/SD-JWT tokens in the line.
func (s *OutputScanner) scanCredentials(line string) {
	matches := jwtPattern.FindAllString(line, -1)
	for _, m := range matches {
		// Skip very short matches that are likely false positives
		if len(m) < 50 {
			continue
		}
		if isRequestObjectJWT(m) {
			continue
		}
		// Determine label based on context
		label := detectCredentialLabel(line, m)

		s.mu.Lock()
		s.credentials = append(s.credentials, ScannedCredential{
			Raw:       m,
			Label:     label,
			Timestamp: time.Now(),
		})
		s.mu.Unlock()
	}
}

// isRequestObjectJWT returns true if the JWT header has typ "oauth-authz-req+jwt".
func isRequestObjectJWT(token string) bool {
	dot := strings.IndexByte(token, '.')
	if dot < 0 {
		return false
	}
	headerB64 := token[:dot]
	// Add padding if needed
	if m := len(headerB64) % 4; m != 0 {
		headerB64 += strings.Repeat("=", 4-m)
	}
	b, err := base64.URLEncoding.DecodeString(headerB64)
	if err != nil {
		return false
	}
	var hdr struct {
		Typ string `json:"typ"`
	}
	if json.Unmarshal(b, &hdr) != nil {
		return false
	}
	return strings.EqualFold(hdr.Typ, "oauth-authz-req+jwt")
}

// detectCredentialLabel tries to infer a label from the surrounding line context.
func detectCredentialLabel(line, token string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "vp_token") || strings.Contains(lower, "vp token"):
		return "vp_token"
	case strings.Contains(lower, "id_token") || strings.Contains(lower, "id token"):
		return "id_token"
	case strings.Contains(lower, "access_token") || strings.Contains(lower, "access token"):
		return "access_token"
	case strings.Contains(lower, "credential"):
		return "credential"
	case strings.Contains(lower, "sd-jwt") || strings.Contains(token, "~"):
		return "sd-jwt"
	default:
		return "jwt"
	}
}

// LastCEK returns the most recently detected CEK, or "" if none.
func (s *OutputScanner) LastCEK() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastCEK
}

// Credentials returns all detected credentials.
func (s *OutputScanner) Credentials() []ScannedCredential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ScannedCredential, len(s.credentials))
	copy(out, s.credentials)
	return out
}

// DrainCredentials returns and removes all credentials detected since the last drain.
func (s *OutputScanner) DrainCredentials() []ScannedCredential {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.credentials
	s.credentials = nil
	return out
}
