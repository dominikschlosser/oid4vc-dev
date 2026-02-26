package mdoc

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// buildIssuerSignedCBOR builds a minimal CBOR-encoded IssuerSigned map
// with the given namespace items. Each item is Tag-24 wrapped.
func buildIssuerSignedCBOR(t *testing.T, namespace string, items []map[string]any) []byte {
	t.Helper()

	var taggedItems []cbor.Tag
	for _, item := range items {
		itemBytes, err := cbor.Marshal(item)
		if err != nil {
			t.Fatalf("marshaling item: %v", err)
		}
		taggedItems = append(taggedItems, cbor.Tag{Number: 24, Content: itemBytes})
	}

	issuerSigned := map[string]any{
		"nameSpaces": map[string]any{
			namespace: taggedItems,
		},
	}

	data, err := cbor.Marshal(issuerSigned)
	if err != nil {
		t.Fatalf("marshaling issuerSigned: %v", err)
	}
	return data
}

func TestParseIssuerSigned_DeduplicatesClaims(t *testing.T) {
	items := []map[string]any{
		{"digestID": uint64(1), "random": []byte("r1"), "elementIdentifier": "resident_country", "elementValue": "DE"},
		{"digestID": uint64(2), "random": []byte("r2"), "elementIdentifier": "resident_country", "elementValue": "DE"},
		{"digestID": uint64(3), "random": []byte("r3"), "elementIdentifier": "family_name", "elementValue": "Mustermann"},
	}

	data := buildIssuerSignedCBOR(t, "eu.europa.ec.eudi.pid.1", items)
	doc, err := parseIssuerSigned(data)
	if err != nil {
		t.Fatalf("parseIssuerSigned() error: %v", err)
	}

	ns := doc.NameSpaces["eu.europa.ec.eudi.pid.1"]
	if len(ns) != 2 {
		t.Fatalf("expected 2 unique claims, got %d", len(ns))
	}

	seen := make(map[string]bool)
	for _, item := range ns {
		if seen[item.ElementIdentifier] {
			t.Errorf("duplicate claim %q found", item.ElementIdentifier)
		}
		seen[item.ElementIdentifier] = true
	}
}

func TestParseIssuerSigned_FirstOccurrenceWins(t *testing.T) {
	items := []map[string]any{
		{"digestID": uint64(1), "random": []byte("r1"), "elementIdentifier": "country", "elementValue": "DE"},
		{"digestID": uint64(2), "random": []byte("r2"), "elementIdentifier": "country", "elementValue": "FR"},
	}

	data := buildIssuerSignedCBOR(t, "ns1", items)
	doc, err := parseIssuerSigned(data)
	if err != nil {
		t.Fatalf("parseIssuerSigned() error: %v", err)
	}

	ns := doc.NameSpaces["ns1"]
	if len(ns) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(ns))
	}
	if ns[0].ElementValue != "DE" {
		t.Errorf("expected first value 'DE', got %v", ns[0].ElementValue)
	}
}

func TestParseIssuerAuth_TaggedInput(t *testing.T) {
	// Build a minimal COSE_Sign1 array
	coseArr := []any{
		[]byte{0xa1, 0x01, 0x26}, // protected: {1: -7} (ES256)
		map[any]any{},             // unprotected
		[]byte("payload"),         // payload
		make([]byte, 64),          // signature (64 bytes for ES256)
	}

	tagged := cbor.Tag{Number: 18, Content: coseArr}

	ia, err := parseIssuerAuth(tagged)
	if err != nil {
		t.Fatalf("parseIssuerAuth(tagged) error: %v", err)
	}

	// RawCOSE should be parseable by go-cose
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(ia.RawCOSE); err != nil {
		t.Errorf("go-cose UnmarshalCBOR failed on RawCOSE: %v", err)
	}
}

func TestParseIssuerAuth_UntaggedArrayInput(t *testing.T) {
	// Simulate what happens after DeviceResponse roundtrip:
	// issuerAuth arrives as []any (tag stripped during decode→re-encode)
	coseArr := []any{
		[]byte{0xa1, 0x01, 0x26}, // protected: {1: -7} (ES256)
		map[any]any{},             // unprotected
		[]byte("payload"),         // payload
		make([]byte, 64),          // signature
	}

	ia, err := parseIssuerAuth(coseArr)
	if err != nil {
		t.Fatalf("parseIssuerAuth([]any) error: %v", err)
	}

	// RawCOSE must include Tag 18 for go-cose
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(ia.RawCOSE); err != nil {
		t.Errorf("go-cose UnmarshalCBOR failed on RawCOSE from []any input: %v", err)
	}
}

func TestParseIssuerAuth_BytesInput(t *testing.T) {
	// Build tagged COSE_Sign1 bytes
	coseArr := []any{
		[]byte{0xa1, 0x01, 0x26},
		map[any]any{},
		[]byte("payload"),
		make([]byte, 64),
	}
	tagged := cbor.Tag{Number: 18, Content: coseArr}
	data, err := cbor.Marshal(tagged)
	if err != nil {
		t.Fatal(err)
	}

	ia, err := parseIssuerAuth(data)
	if err != nil {
		t.Fatalf("parseIssuerAuth([]byte) error: %v", err)
	}

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(ia.RawCOSE); err != nil {
		t.Errorf("go-cose UnmarshalCBOR failed on RawCOSE from []byte input: %v", err)
	}
}

func TestParseIssuerAuth_ExtractsUnprotectedHeader(t *testing.T) {
	coseArr := []any{
		[]byte{0xa1, 0x01, 0x26},                        // protected
		map[any]any{int64(33): []byte("cert-der-bytes")}, // unprotected with x5chain
		[]byte("payload"),
		make([]byte, 64),
	}

	ia, err := parseIssuerAuth(cbor.Tag{Number: 18, Content: coseArr})
	if err != nil {
		t.Fatalf("parseIssuerAuth() error: %v", err)
	}

	if ia.UnprotectedHeader == nil {
		t.Fatal("expected UnprotectedHeader to be set")
	}
	if _, ok := ia.UnprotectedHeader[int64(33)]; !ok {
		t.Error("expected x5chain (label 33) in UnprotectedHeader")
	}
}
