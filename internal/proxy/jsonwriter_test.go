package proxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestJSONWriterWritesNDJSON(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriterTo(&buf, false)

	entry := &TrafficEntry{
		ID:         1,
		Timestamp:  time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC),
		Method:     "GET",
		URL:        "http://example.com/authorize?client_id=test&response_type=vp_token",
		StatusCode: 200,
		Class:      ClassVPAuthRequest,
		ClassLabel: "VP Auth Request",
		DurationMS: 42,
	}

	w.WriteEntry(entry)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if parsed["method"] != "GET" {
		t.Errorf("expected method GET, got %v", parsed["method"])
	}
	if parsed["classLabel"] != "VP Auth Request" {
		t.Errorf("expected classLabel VP Auth Request, got %v", parsed["classLabel"])
	}
}

func TestJSONWriterFiltersUnknown(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriterTo(&buf, false)

	entry := &TrafficEntry{
		ID:         1,
		Method:     "GET",
		URL:        "http://example.com/favicon.ico",
		StatusCode: 200,
		Class:      ClassUnknown,
		ClassLabel: "Unknown",
	}

	w.WriteEntry(entry)

	if buf.Len() != 0 {
		t.Errorf("expected no output for ClassUnknown without allTraffic, got %q", buf.String())
	}
}

func TestJSONWriterAllTrafficIncludesUnknown(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriterTo(&buf, true)

	entry := &TrafficEntry{
		ID:         1,
		Method:     "GET",
		URL:        "http://example.com/favicon.ico",
		StatusCode: 200,
		Class:      ClassUnknown,
		ClassLabel: "Unknown",
	}

	w.WriteEntry(entry)

	if buf.Len() == 0 {
		t.Error("expected output for ClassUnknown with allTraffic=true")
	}
}

func TestJSONWriterMultipleEntries(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriterTo(&buf, false)

	for i := 0; i < 3; i++ {
		w.WriteEntry(&TrafficEntry{
			ID:         int64(i + 1),
			Method:     "POST",
			URL:        "http://example.com/response",
			StatusCode: 200,
			Class:      ClassVPAuthResponse,
			ClassLabel: "VP Auth Response",
		})
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 NDJSON lines, got %d", len(lines))
	}

	for i, line := range lines {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			t.Errorf("line %d: invalid JSON: %v", i, err)
		}
	}
}
