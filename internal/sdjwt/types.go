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

// Package sdjwt parses and verifies SD-JWT (Selective Disclosure JWT) credentials.
package sdjwt

// Token represents a parsed SD-JWT.
type Token struct {
	Raw           string
	Header        map[string]any
	Payload       map[string]any
	Signature     []byte
	Disclosures   []Disclosure
	KeyBindingJWT *JWT
	// ResolvedClaims contains all claims after resolving _sd digests.
	ResolvedClaims map[string]any
	// Warnings contains informational warnings about the credential structure.
	Warnings []string
}

// JWT represents a decoded JWT (header.payload.signature).
type JWT struct {
	Raw       string
	Header    map[string]any
	Payload   map[string]any
	Signature []byte
}

// Disclosure represents a single SD-JWT disclosure.
type Disclosure struct {
	Raw          string // base64url-encoded
	Decoded      string // JSON string
	Salt         string
	Name         string // empty for array element disclosures
	Value        any
	Digest       string // SHA-256 digest (base64url)
	IsArrayEntry bool
}
