package cmd

import (
	"crypto"
	"testing"

	"github.com/dominikschlosser/oid4vc-dev/internal/wallet"
)

func TestTypeLabel(t *testing.T) {
	tests := []struct {
		name    string
		vct     string
		docType string
		format  string
		want    string
	}{
		{"vct preferred", "urn:eu.europa.ec:pid", "org.iso.mdl", "dc+sd-jwt", "urn:eu.europa.ec:pid"},
		{"docType fallback", "", "org.iso.mdl", "mso_mdoc", "org.iso.mdl"},
		{"format fallback", "", "", "dc+sd-jwt", "dc+sd-jwt"},
		{"all empty", "", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := typeLabel(tt.vct, tt.docType, tt.format)
			if got != tt.want {
				t.Errorf("typeLabel(%q, %q, %q) = %q, want %q", tt.vct, tt.docType, tt.format, got, tt.want)
			}
		})
	}
}

func TestCredLabel(t *testing.T) {
	tests := []struct {
		name string
		cred wallet.StoredCredential
		want string
	}{
		{"with VCT", wallet.StoredCredential{VCT: "urn:pid", DocType: "org.iso.mdl", Format: "dc+sd-jwt"}, "urn:pid"},
		{"with DocType only", wallet.StoredCredential{DocType: "org.iso.mdl", Format: "mso_mdoc"}, "org.iso.mdl"},
		{"format only", wallet.StoredCredential{Format: "dc+sd-jwt"}, "dc+sd-jwt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := credLabel(tt.cred)
			if got != tt.want {
				t.Errorf("credLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input string
		max   int
		want  string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 5, "hello..."},
		{"", 5, ""},
		{"ab", 1, "a..."},
	}

	for _, tt := range tests {
		got := truncate(tt.input, tt.max)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.want)
		}
	}
}

func TestParseClaimsOverrides(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		result, err := parseClaimsOverrides("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("valid JSON", func(t *testing.T) {
		result, err := parseClaimsOverrides(`{"given_name":"Max","age":30}`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result["given_name"] != "Max" {
			t.Errorf("expected given_name=Max, got %v", result["given_name"])
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := parseClaimsOverrides("{invalid")
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

func TestApplySessionTranscriptMode(t *testing.T) {
	tests := []struct {
		mode    string
		want    wallet.SessionTranscriptMode
		wantErr bool
	}{
		{"oid4vp", wallet.SessionTranscriptOID4VP, false},
		{"", wallet.SessionTranscriptOID4VP, false},
		{"iso", wallet.SessionTranscriptISO, false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run("mode="+tt.mode, func(t *testing.T) {
			w := &wallet.Wallet{}
			err := applySessionTranscriptMode(w, tt.mode)
			if (err != nil) != tt.wantErr {
				t.Fatalf("applySessionTranscriptMode(%q) error = %v, wantErr %v", tt.mode, err, tt.wantErr)
			}
			if !tt.wantErr && w.SessionTranscript != tt.want {
				t.Errorf("got transcript mode %q, want %q", w.SessionTranscript, tt.want)
			}
		})
	}
}

func TestIsHTTPURL(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"https://example.com", true},
		{"http://example.com", true},
		{"HTTP://EXAMPLE.COM", true},
		{"HTTPS://EXAMPLE.COM", true},
		{"openid4vp://authorize", false},
		{"eyJhbGci...", false},
		{"", false},
	}

	for _, tt := range tests {
		got := isHTTPURL(tt.input)
		if got != tt.want {
			t.Errorf("isHTTPURL(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestVerifyWithBestKey(t *testing.T) {
	type result struct {
		valid bool
		keyID string
	}

	// Mock keys as simple int pointers for testing
	key1 := new(int)
	*key1 = 1
	key2 := new(int)
	*key2 = 2

	t.Run("x5cKey takes priority", func(t *testing.T) {
		called := false
		r := verifyWithBestKey(
			[]crypto.PublicKey{key1},
			key2, // x5cKey
			func(key crypto.PublicKey) (result, bool) {
				called = true
				if key == key2 {
					return result{valid: true, keyID: "x5c"}, true
				}
				return result{valid: false, keyID: "fallback"}, false
			},
		)
		if !called {
			t.Error("verify function was not called")
		}
		if r.keyID != "x5c" {
			t.Errorf("expected x5c key used, got %s", r.keyID)
		}
	})

	t.Run("falls back to pubKeys when no x5cKey", func(t *testing.T) {
		callCount := 0
		r := verifyWithBestKey(
			[]crypto.PublicKey{key1, key2},
			nil, // no x5cKey
			func(key crypto.PublicKey) (result, bool) {
				callCount++
				if key == key2 {
					return result{valid: true, keyID: "key2"}, true
				}
				return result{valid: false, keyID: "key1"}, false
			},
		)
		if r.keyID != "key2" {
			t.Errorf("expected key2 to be selected, got %s", r.keyID)
		}
		if callCount != 2 {
			t.Errorf("expected 2 calls, got %d", callCount)
		}
	})

	t.Run("stops on first valid key", func(t *testing.T) {
		callCount := 0
		r := verifyWithBestKey(
			[]crypto.PublicKey{key1, key2},
			nil,
			func(key crypto.PublicKey) (result, bool) {
				callCount++
				return result{valid: true, keyID: "first"}, true
			},
		)
		if callCount != 1 {
			t.Errorf("expected 1 call (early exit), got %d", callCount)
		}
		if !r.valid {
			t.Error("expected valid result")
		}
	})

	t.Run("returns last result when none valid", func(t *testing.T) {
		r := verifyWithBestKey(
			[]crypto.PublicKey{key1, key2},
			nil,
			func(key crypto.PublicKey) (result, bool) {
				if key == key2 {
					return result{valid: false, keyID: "last"}, false
				}
				return result{valid: false, keyID: "first"}, false
			},
		)
		if r.keyID != "last" {
			t.Errorf("expected last result, got %s", r.keyID)
		}
	})
}
