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
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/fatih/color"
)

func TestTerminalWriterImplementsEntryWriter(t *testing.T) {
	var _ EntryWriter = &TerminalWriter{}
}

func TestTerminalWriterAllTrafficFalseSkipsUnknown(t *testing.T) {
	tw := &TerminalWriter{AllTraffic: false}
	// This entry is ClassUnknown — WriteEntry should not call PrintEntry.
	// We can't easily mock PrintEntry, but we verify no panic occurs.
	entry := &TrafficEntry{
		Class:      ClassUnknown,
		ClassLabel: "Unknown",
		Method:     "GET",
		URL:        "http://example.com/favicon.ico",
		StatusCode: 200,
	}
	// Should not panic
	tw.WriteEntry(entry)
}

func TestTerminalWriterAllTrafficTrueIncludesUnknown(t *testing.T) {
	tw := &TerminalWriter{AllTraffic: true}
	// This should call PrintEntry (which writes to stdout).
	// We verify it doesn't panic; output goes to terminal.
	entry := &TrafficEntry{
		Class:      ClassUnknown,
		ClassLabel: "Unknown",
		Method:     "GET",
		URL:        "http://example.com/other",
		StatusCode: 200,
	}
	// Should not panic
	tw.WriteEntry(entry)
}

// captureOutput redirects both os.Stdout and color.Output to capture all print output.
func captureOutput(t *testing.T, fn func()) string {
	t.Helper()
	oldStdout := os.Stdout
	oldColor := color.Output
	r, w, _ := os.Pipe()
	os.Stdout = w
	color.Output = w

	fn()

	w.Close()
	os.Stdout = oldStdout
	color.Output = oldColor

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestPrintEntryIncludesDecodeHints(t *testing.T) {
	entry := &TrafficEntry{
		Method:           "POST",
		URL:              "http://example.com/response",
		StatusCode:       200,
		Class:            ClassVPAuthResponse,
		ClassLabel:       "VP Auth Response",
		Credentials:      []string{"eyJhbGciOiJFUzI1NiJ9.test.sig"},
		CredentialLabels: []string{"vp_token"},
	}

	output := captureOutput(t, func() { PrintEntry(entry) })

	if !strings.Contains(output, "oid4vc-dev decode") {
		t.Error("expected decode hint in output")
	}
	if !strings.Contains(output, "eyJhbGciOiJFUzI1NiJ9.test.sig") {
		t.Error("expected credential in decode hint")
	}
	if !strings.Contains(output, "vp_token") {
		t.Error("expected credential label in decode hint")
	}
}

func TestPrintDecodeHintWithLabel(t *testing.T) {
	output := captureOutput(t, func() { printDecodeHint("cred-value", "id_token") })

	if !strings.Contains(output, "oid4vc-dev decode 'cred-value'") {
		t.Errorf("expected decode command with credential, got %q", output)
	}
	if !strings.Contains(output, "(id_token)") {
		t.Errorf("expected label in output, got %q", output)
	}
}

func TestPrintDecodeHintWithoutLabel(t *testing.T) {
	output := captureOutput(t, func() { printDecodeHint("cred-value", "") })

	if !strings.Contains(output, "oid4vc-dev decode 'cred-value'") {
		t.Errorf("expected decode command, got %q", output)
	}
	if strings.Contains(output, "(") {
		t.Errorf("expected no label parens, got %q", output)
	}
}

func TestTruncateURL(t *testing.T) {
	tests := []struct {
		url    string
		maxLen int
		want   string
	}{
		{"http://example.com/short", 100, "http://example.com/short"},
		{"http://example.com/very-long-path", 20, "http://example.com/v..."},
		{"exact", 5, "exact"},
		{"", 10, ""},
	}

	for _, tt := range tests {
		got := truncateURL(tt.url, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncateURL(%q, %d) = %q, want %q", tt.url, tt.maxLen, got, tt.want)
		}
	}
}
