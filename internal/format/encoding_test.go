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

package format

import (
	"bytes"
	"testing"
)

func TestDecodeBase64URL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"no padding", "aGVsbG8", "hello", false},
		{"with padding", "aGVsbG8=", "hello", false},
		{"empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeBase64URL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeBase64URL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if string(got) != tt.want {
				t.Errorf("DecodeBase64URL() = %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestEncodeBase64URL(t *testing.T) {
	got := EncodeBase64URL([]byte("hello"))
	if got != "aGVsbG8" {
		t.Errorf("EncodeBase64URL(hello) = %q, want %q", got, "aGVsbG8")
	}
}

func TestDecodeBase64Std(t *testing.T) {
	got, err := DecodeBase64Std("aGVsbG8=")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want %q", string(got), "hello")
	}
}

func TestDecodeHexOrBase64URL(t *testing.T) {
	got, err := DecodeHexOrBase64URL("68656c6c6f")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("hex decode got %q, want %q", string(got), "hello")
	}

	// Base64url input (not valid hex due to length/chars)
	got, err = DecodeHexOrBase64URL("aGVsbG8")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Errorf("base64url decode got %q, want %q", string(got), "hello")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name string
		s    string
		max  int
		want string
	}{
		{"short string", "hi", 10, "hi"},
		{"exact length", "hello", 5, "hello"},
		{"truncated", "hello world", 5, "hello..."},
		{"empty string", "", 5, ""},
		{"zero max", "hello", 0, "..."},
		{"negative max", "hello", -1, "..."},
		{"unicode", "héllo wörld", 5, "héllo..."},
		{"max 1", "hello", 1, "h..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Truncate(tt.s, tt.max)
			if got != tt.want {
				t.Errorf("Truncate(%q, %d) = %q, want %q", tt.s, tt.max, got, tt.want)
			}
		})
	}
}
