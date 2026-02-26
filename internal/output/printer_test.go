package output

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/dominikschlosser/ssi-debugger/internal/mdoc"
	"github.com/dominikschlosser/ssi-debugger/internal/sdjwt"
)

// captureOutput captures all terminal output (both fmt and color) during fn execution.
func captureOutput(fn func()) string {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	r, w, _ := os.Pipe()

	oldStdout := os.Stdout
	oldOutput := color.Output
	os.Stdout = w
	color.Output = w

	fn()

	w.Close()
	os.Stdout = oldStdout
	color.Output = oldOutput

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestPrintMapFiltered_HidesX5cByDefault(t *testing.T) {
	m := map[string]any{
		"alg": "ES256",
		"typ": "dc+sd-jwt",
		"x5c": []any{"MIIC...", "MIID..."},
	}

	out := captureOutput(func() {
		printMapFiltered(m, 1, false, "x5c")
	})

	if strings.Contains(out, "MIIC") {
		t.Error("x5c certificate data should be hidden when not verbose")
	}
	if !strings.Contains(out, "x5c: (2 entries, use -v to show)") {
		t.Error("expected x5c summary line")
	}
	if !strings.Contains(out, "alg: ES256") {
		t.Error("non-hidden keys should still be shown")
	}
}

func TestPrintMapFiltered_ShowsX5cWhenVerbose(t *testing.T) {
	m := map[string]any{
		"alg": "ES256",
		"x5c": []any{"MIIC...", "MIID..."},
	}

	out := captureOutput(func() {
		printMapFiltered(m, 1, true, "x5c")
	})

	if !strings.Contains(out, "MIIC") {
		t.Error("x5c certificate data should be shown in verbose mode")
	}
	if strings.Contains(out, "use -v to show") {
		t.Error("should not show summary hint in verbose mode")
	}
}

func TestPrintMapFiltered_NonArrayHiddenKey(t *testing.T) {
	m := map[string]any{
		"alg":    "ES256",
		"secret": "hidden-string",
	}

	out := captureOutput(func() {
		printMapFiltered(m, 1, false, "secret")
	})

	if strings.Contains(out, "hidden-string") {
		t.Error("hidden non-array key should not show its value")
	}
	// Non-array hidden keys are silently omitted (no summary line)
	if strings.Contains(out, "secret") {
		t.Error("non-array hidden key should be silently omitted")
	}
}

func TestBuildJWTJSON(t *testing.T) {
	token := &sdjwt.Token{
		Header:  map[string]any{"alg": "ES256", "typ": "JWT"},
		Payload: map[string]any{"sub": "user123", "iss": "https://example.com"},
	}

	result := BuildJWTJSON(token)

	if result["format"] != "jwt" {
		t.Errorf("format = %v, want jwt", result["format"])
	}
	header := result["header"].(map[string]any)
	if header["alg"] != "ES256" {
		t.Errorf("header.alg = %v, want ES256", header["alg"])
	}
	payload := result["payload"].(map[string]any)
	if payload["sub"] != "user123" {
		t.Errorf("payload.sub = %v, want user123", payload["sub"])
	}
}

func TestBuildSDJWTJSON_Basic(t *testing.T) {
	token := &sdjwt.Token{
		Header:  map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"},
		Payload: map[string]any{"iss": "https://issuer.example", "vct": "urn:eudi:pid:1"},
		Disclosures: []sdjwt.Disclosure{
			{Name: "given_name", Value: "Erika", Salt: "salt1", Digest: "digest1"},
			{Name: "family_name", Value: "Mustermann", Salt: "salt2", Digest: "digest2"},
		},
		ResolvedClaims: map[string]any{
			"given_name":  "Erika",
			"family_name": "Mustermann",
			"iss":         "https://issuer.example",
		},
	}

	result := BuildSDJWTJSON(token)

	if result["format"] != "dc+sd-jwt" {
		t.Errorf("format = %v, want dc+sd-jwt", result["format"])
	}
	discs := result["disclosures"].([]map[string]any)
	if len(discs) != 2 {
		t.Fatalf("got %d disclosures, want 2", len(discs))
	}
	if discs[0]["name"] != "given_name" {
		t.Errorf("disclosures[0].name = %v, want given_name", discs[0]["name"])
	}
	if discs[1]["value"] != "Mustermann" {
		t.Errorf("disclosures[1].value = %v, want Mustermann", discs[1]["value"])
	}

	resolved := result["resolvedClaims"].(map[string]any)
	if resolved["given_name"] != "Erika" {
		t.Errorf("resolvedClaims.given_name = %v, want Erika", resolved["given_name"])
	}
}

func TestBuildSDJWTJSON_WithWarnings(t *testing.T) {
	token := &sdjwt.Token{
		Header:         map[string]any{"alg": "ES256"},
		Payload:        map[string]any{"iss": "test"},
		Disclosures:    []sdjwt.Disclosure{},
		ResolvedClaims: map[string]any{},
		Warnings:       []string{"some warning"},
	}

	result := BuildSDJWTJSON(token)

	warnings, ok := result["warnings"].([]string)
	if !ok {
		t.Fatalf("warnings should be []string, got %T", result["warnings"])
	}
	if len(warnings) != 1 || warnings[0] != "some warning" {
		t.Errorf("warnings = %v, want [some warning]", warnings)
	}
}

func TestBuildSDJWTJSON_NoWarningsOmitted(t *testing.T) {
	token := &sdjwt.Token{
		Header:         map[string]any{"alg": "ES256"},
		Payload:        map[string]any{"iss": "test"},
		Disclosures:    []sdjwt.Disclosure{},
		ResolvedClaims: map[string]any{},
	}

	result := BuildSDJWTJSON(token)

	if _, ok := result["warnings"]; ok {
		t.Error("warnings should be omitted when empty")
	}
}

func TestBuildSDJWTJSON_WithKeyBindingJWT(t *testing.T) {
	token := &sdjwt.Token{
		Header:         map[string]any{"alg": "ES256"},
		Payload:        map[string]any{"iss": "test"},
		Disclosures:    []sdjwt.Disclosure{},
		ResolvedClaims: map[string]any{},
		KeyBindingJWT: &sdjwt.JWT{
			Header:  map[string]any{"alg": "ES256", "typ": "kb+jwt"},
			Payload: map[string]any{"aud": "verifier", "nonce": "abc123"},
		},
	}

	result := BuildSDJWTJSON(token)

	kb, ok := result["keyBindingJWT"].(map[string]any)
	if !ok {
		t.Fatalf("keyBindingJWT should be a map, got %T", result["keyBindingJWT"])
	}
	kbHeader := kb["header"].(map[string]any)
	if kbHeader["typ"] != "kb+jwt" {
		t.Errorf("keyBindingJWT.header.typ = %v, want kb+jwt", kbHeader["typ"])
	}
	kbPayload := kb["payload"].(map[string]any)
	if kbPayload["nonce"] != "abc123" {
		t.Errorf("keyBindingJWT.payload.nonce = %v, want abc123", kbPayload["nonce"])
	}
}

func TestBuildSDJWTJSON_NoKeyBindingOmitted(t *testing.T) {
	token := &sdjwt.Token{
		Header:         map[string]any{"alg": "ES256"},
		Payload:        map[string]any{},
		Disclosures:    []sdjwt.Disclosure{},
		ResolvedClaims: map[string]any{},
	}

	result := BuildSDJWTJSON(token)

	if _, ok := result["keyBindingJWT"]; ok {
		t.Error("keyBindingJWT should be omitted when nil")
	}
}

func TestBuildSDJWTJSON_ArrayDisclosure(t *testing.T) {
	token := &sdjwt.Token{
		Header:  map[string]any{"alg": "ES256"},
		Payload: map[string]any{},
		Disclosures: []sdjwt.Disclosure{
			{Name: "", Value: "array-value", Salt: "salt", Digest: "digest", IsArrayEntry: true},
		},
		ResolvedClaims: map[string]any{},
	}

	result := BuildSDJWTJSON(token)

	discs := result["disclosures"].([]map[string]any)
	if !discs[0]["isArrayEntry"].(bool) {
		t.Error("expected isArrayEntry=true")
	}
	if discs[0]["name"] != "" {
		t.Errorf("expected empty name for array disclosure, got %v", discs[0]["name"])
	}
}

func TestBuildMDOCJSON_Basic(t *testing.T) {
	doc := &mdoc.Document{
		DocType: "eu.europa.ec.eudi.pid.1",
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"eu.europa.ec.eudi.pid.1": {
				{DigestID: 0, ElementIdentifier: "given_name", ElementValue: "ERIKA"},
				{DigestID: 1, ElementIdentifier: "family_name", ElementValue: "MUSTERMANN"},
			},
		},
	}

	result := BuildMDOCJSON(doc)

	if result["format"] != "mso_mdoc" {
		t.Errorf("format = %v, want mso_mdoc", result["format"])
	}
	if result["docType"] != "eu.europa.ec.eudi.pid.1" {
		t.Errorf("docType = %v, want eu.europa.ec.eudi.pid.1", result["docType"])
	}

	claims := result["claims"].(map[string]any)
	ns := claims["eu.europa.ec.eudi.pid.1"].(map[string]any)
	if ns["given_name"] != "ERIKA" {
		t.Errorf("given_name = %v, want ERIKA", ns["given_name"])
	}
	if ns["family_name"] != "MUSTERMANN" {
		t.Errorf("family_name = %v, want MUSTERMANN", ns["family_name"])
	}
}

func TestBuildMDOCJSON_WithMSO(t *testing.T) {
	signed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	validFrom := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	validUntil := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)

	doc := &mdoc.Document{
		DocType:    "eu.europa.ec.eudi.pid.1",
		NameSpaces: map[string][]mdoc.IssuerSignedItem{},
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				Version:         "1.0",
				DigestAlgorithm: "SHA-256",
				DocType:         "eu.europa.ec.eudi.pid.1",
				ValidityInfo: &mdoc.ValidityInfo{
					Signed:     &signed,
					ValidFrom:  &validFrom,
					ValidUntil: &validUntil,
				},
			},
		},
	}

	result := BuildMDOCJSON(doc)

	mso, ok := result["mso"].(map[string]any)
	if !ok {
		t.Fatalf("mso should be a map, got %T", result["mso"])
	}
	if mso["version"] != "1.0" {
		t.Errorf("mso.version = %v, want 1.0", mso["version"])
	}
	if mso["digestAlgorithm"] != "SHA-256" {
		t.Errorf("mso.digestAlgorithm = %v, want SHA-256", mso["digestAlgorithm"])
	}

	vi := mso["validityInfo"].(map[string]any)
	if vi["signed"] != "2026-01-01T00:00:00Z" {
		t.Errorf("validityInfo.signed = %v", vi["signed"])
	}
	if vi["validFrom"] != "2026-01-01T00:00:00Z" {
		t.Errorf("validityInfo.validFrom = %v", vi["validFrom"])
	}
	if vi["validUntil"] != "2027-01-01T00:00:00Z" {
		t.Errorf("validityInfo.validUntil = %v", vi["validUntil"])
	}
}

func TestBuildMDOCJSON_NoMSO(t *testing.T) {
	doc := &mdoc.Document{
		DocType:    "test.doctype",
		NameSpaces: map[string][]mdoc.IssuerSignedItem{},
	}

	result := BuildMDOCJSON(doc)

	if _, ok := result["mso"]; ok {
		t.Error("mso should be omitted when IssuerAuth is nil")
	}
}

func TestBuildMDOCJSON_WithDeviceAuth(t *testing.T) {
	doc := &mdoc.Document{
		DocType:    "test.doctype",
		NameSpaces: map[string][]mdoc.IssuerSignedItem{},
		DeviceSigned: &mdoc.DeviceSigned{
			DeviceAuth: map[string]any{"type": "deviceSignature"},
		},
	}

	result := BuildMDOCJSON(doc)

	da, ok := result["deviceAuth"].(map[string]any)
	if !ok {
		t.Fatalf("deviceAuth should be a map, got %T", result["deviceAuth"])
	}
	if da["type"] != "deviceSignature" {
		t.Errorf("deviceAuth.type = %v, want deviceSignature", da["type"])
	}
}

func TestBuildMDOCJSON_NoDeviceAuth(t *testing.T) {
	doc := &mdoc.Document{
		DocType:    "test.doctype",
		NameSpaces: map[string][]mdoc.IssuerSignedItem{},
	}

	result := BuildMDOCJSON(doc)

	if _, ok := result["deviceAuth"]; ok {
		t.Error("deviceAuth should be omitted when DeviceSigned is nil")
	}
}

func TestBuildMDOCJSON_WithStatus(t *testing.T) {
	doc := &mdoc.Document{
		DocType:    "test.doctype",
		NameSpaces: map[string][]mdoc.IssuerSignedItem{},
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				Version:         "1.0",
				DigestAlgorithm: "SHA-256",
				DocType:         "test.doctype",
				Status:          map[string]any{"uri": "https://status.example"},
			},
		},
	}

	result := BuildMDOCJSON(doc)

	mso := result["mso"].(map[string]any)
	status := mso["status"].(map[string]any)
	if status["uri"] != "https://status.example" {
		t.Errorf("status.uri = %v, want https://status.example", status["uri"])
	}
}

func TestBuildMDOCJSON_WithDeviceKeyInfo(t *testing.T) {
	doc := &mdoc.Document{
		DocType:    "test.doctype",
		NameSpaces: map[string][]mdoc.IssuerSignedItem{},
		IssuerAuth: &mdoc.IssuerAuth{
			MSO: &mdoc.MSO{
				Version:         "1.0",
				DigestAlgorithm: "SHA-256",
				DocType:         "test.doctype",
				DeviceKeyInfo:   map[string]any{"kty": "EC"},
			},
		},
	}

	result := BuildMDOCJSON(doc)

	mso := result["mso"].(map[string]any)
	dki := mso["deviceKeyInfo"].(map[string]any)
	if dki["kty"] != "EC" {
		t.Errorf("deviceKeyInfo.kty = %v, want EC", dki["kty"])
	}
}

func TestBuildMDOCJSON_MultipleNamespaces(t *testing.T) {
	doc := &mdoc.Document{
		DocType: "eu.europa.ec.eudi.pid.1",
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"eu.europa.ec.eudi.pid.1": {
				{ElementIdentifier: "given_name", ElementValue: "ERIKA"},
			},
			"org.iso.18013.5.1": {
				{ElementIdentifier: "portrait", ElementValue: "base64data"},
			},
		},
	}

	result := BuildMDOCJSON(doc)

	claims := result["claims"].(map[string]any)
	if len(claims) != 2 {
		t.Errorf("expected 2 namespaces, got %d", len(claims))
	}

	ns1 := claims["eu.europa.ec.eudi.pid.1"].(map[string]any)
	if ns1["given_name"] != "ERIKA" {
		t.Errorf("ns1.given_name = %v, want ERIKA", ns1["given_name"])
	}

	ns2 := claims["org.iso.18013.5.1"].(map[string]any)
	if ns2["portrait"] != "base64data" {
		t.Errorf("ns2.portrait = %v, want base64data", ns2["portrait"])
	}
}

func TestRelativeTime(t *testing.T) {
	now := time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC)
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = time.Now })

	tests := []struct {
		name string
		t    time.Time
		want string
	}{
		{"future 13 days", now.Add(13 * 24 * time.Hour), "in 13 days"},
		{"past 1 day", now.Add(-24 * time.Hour), "1 day ago"},
		{"past 3 days", now.Add(-3 * 24 * time.Hour), "3 days ago"},
		{"future 2 hours", now.Add(2 * time.Hour), "in 2 hours"},
		{"future 1 hour", now.Add(1 * time.Hour), "in 1 hour"},
		{"future 90 days", now.Add(90 * 24 * time.Hour), "in 3 months"},
		{"past 60 days", now.Add(-60 * 24 * time.Hour), "2 months ago"},
		{"future 30 minutes", now.Add(30 * time.Minute), "in 30 minutes"},
		{"past 30 seconds", now.Add(-30 * time.Second), "1 minute ago"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := relativeTime(tt.t)
			if got != tt.want {
				t.Errorf("relativeTime() = %q, want %q", got, tt.want)
			}
		})
	}
}
