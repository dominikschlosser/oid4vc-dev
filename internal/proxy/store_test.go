package proxy

import (
	"testing"
	"time"
)

func TestStoreAddAndEntries(t *testing.T) {
	s := NewStore(10)

	s.Add(&TrafficEntry{Method: "GET", URL: "http://example.com/1"})
	s.Add(&TrafficEntry{Method: "POST", URL: "http://example.com/2"})

	entries := s.Entries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].ID != 1 || entries[1].ID != 2 {
		t.Errorf("unexpected IDs: %d, %d", entries[0].ID, entries[1].ID)
	}
}

func TestStoreEviction(t *testing.T) {
	s := NewStore(3)

	for i := 0; i < 5; i++ {
		s.Add(&TrafficEntry{Method: "GET", URL: "http://example.com/"})
	}

	entries := s.Entries()
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries after eviction, got %d", len(entries))
	}
	// Oldest should be ID 3 (IDs 1,2 evicted)
	if entries[0].ID != 3 {
		t.Errorf("expected oldest entry ID 3, got %d", entries[0].ID)
	}
}

func TestStoreFlowCorrelation(t *testing.T) {
	s := NewStore(100)

	// Add VP Auth Request with state
	e1 := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/authorize?client_id=test&response_type=vp_token&state=state123",
		Class:      ClassVPAuthRequest,
		ClassLabel: "VP Auth Request",
	}
	Classify(e1) // to set Decoded for correlation
	s.Add(e1)

	if e1.FlowID == "" {
		t.Fatal("expected FlowID to be set on first entry")
	}

	// Add VP Auth Response with same state
	e2 := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: "state=state123&vp_token=eyJ...",
		Class:       ClassVPAuthResponse,
		ClassLabel:  "VP Auth Response",
	}
	Classify(e2)
	s.Add(e2)

	if e2.FlowID != e1.FlowID {
		t.Errorf("expected same flow ID, got %q and %q", e1.FlowID, e2.FlowID)
	}

	// Verify FlowEntries
	flowEntries := s.FlowEntries(e1.FlowID)
	if len(flowEntries) != 2 {
		t.Fatalf("expected 2 flow entries, got %d", len(flowEntries))
	}
}

func TestStoreFlowEntriesEmpty(t *testing.T) {
	s := NewStore(100)
	entries := s.FlowEntries("nonexistent")
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for nonexistent flow, got %d", len(entries))
	}
}

func TestStoreNoFlowIDForUnknown(t *testing.T) {
	s := NewStore(100)
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/favicon.ico",
		Class:      ClassUnknown,
		ClassLabel: "Unknown",
	}
	s.Add(e)

	if e.FlowID != "" {
		t.Errorf("expected empty FlowID for unknown class, got %q", e.FlowID)
	}
}

func TestStoreSubscribe(t *testing.T) {
	s := NewStore(100)
	ch, unsub := s.Subscribe()

	go func() {
		s.Add(&TrafficEntry{Method: "GET", URL: "http://example.com/"})
	}()

	select {
	case entry := <-ch:
		if entry.Method != "GET" {
			t.Errorf("expected GET, got %s", entry.Method)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for subscriber notification")
	}

	go unsub()
}
