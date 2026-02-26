package proxy

import "testing"

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
