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

package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/dominikschlosser/ssi-debugger/internal/mdoc"
	"github.com/dominikschlosser/ssi-debugger/internal/sdjwt"
)

var (
	headerColor  = color.New(color.FgCyan, color.Bold)
	labelColor   = color.New(color.FgYellow)
	valueColor   = color.New(color.FgWhite)
	dimColor     = color.New(color.Faint)
	successColor = color.New(color.FgGreen)
	errorColor   = color.New(color.FgRed)
	warnColor    = color.New(color.FgYellow)

	// timeNow is the function used to get the current time. Override in tests.
	timeNow = time.Now
)

// relativeTime returns a human-readable relative duration string for t.
// Future times return "in X units", past times return "X units ago".
func relativeTime(t time.Time) string {
	now := timeNow()
	d := t.Sub(now)
	if d < 0 {
		d = -d
		return formatDuration(d) + " ago"
	}
	return "in " + formatDuration(d)
}

func formatDuration(d time.Duration) string {
	const day = 24 * time.Hour
	switch {
	case d >= 60*day:
		months := int(d / (30 * day))
		if months == 1 {
			return "1 month"
		}
		return fmt.Sprintf("%d months", months)
	case d >= 2*day:
		days := int(d / day)
		return fmt.Sprintf("%d days", days)
	case d >= day:
		return "1 day"
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	case d >= time.Hour:
		return "1 hour"
	case d >= 2*time.Minute:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	default:
		return "1 minute"
	}
}

// BuildSDJWTJSON returns the JSON-serializable map for an SD-JWT token.
func BuildSDJWTJSON(token *sdjwt.Token) map[string]any {
	out := map[string]any{
		"format":         "dc+sd-jwt",
		"header":         token.Header,
		"payload":        token.Payload,
		"disclosures":    formatDisclosuresJSON(token.Disclosures),
		"resolvedClaims": token.ResolvedClaims,
	}
	if len(token.Warnings) > 0 {
		out["warnings"] = token.Warnings
	}
	if token.KeyBindingJWT != nil {
		out["keyBindingJWT"] = map[string]any{
			"header":  token.KeyBindingJWT.Header,
			"payload": token.KeyBindingJWT.Payload,
		}
	}
	return out
}

// PrintSDJWT prints a decoded SD-JWT to the terminal.
func PrintSDJWT(token *sdjwt.Token, opts Options) {
	if opts.JSON {
		PrintJSON(BuildSDJWTJSON(token))
		return
	}

	headerColor.Println("SD-JWT Credential")
	headerColor.Println(strings.Repeat("─", 50))

	// Header
	printSection("Header")
	printMapFiltered(token.Header, 1, opts.Verbose, "x5c")

	// Payload (without resolving disclosures)
	printSection("Payload (signed claims)")
	printMap(token.Payload, 1)

	// Disclosed claims (resolved disclosures)
	if len(token.Disclosures) > 0 {
		printSection(fmt.Sprintf("Disclosed Claims (%d)", len(token.Disclosures)))
		for i, d := range token.Disclosures {
			if d.IsArrayEntry {
				dimColor.Printf("  [%d] ", i+1)
				labelColor.Print("(array element) ")
				fmt.Println(formatValue(d.Value))
			} else {
				dimColor.Printf("  [%d] ", i+1)
				labelColor.Printf("%s: ", d.Name)
				fmt.Println(formatValue(d.Value))
			}
			if opts.Verbose {
				dimColor.Printf("       salt=%s digest=%s\n", d.Salt, d.Digest)
			}
		}
	}

	// Warnings
	if len(token.Warnings) > 0 {
		printSection("Warnings")
		for _, w := range token.Warnings {
			warnColor.Printf("  ⚠ %s\n", w)
		}
	}

	// Key Binding JWT
	if token.KeyBindingJWT != nil {
		printSection("Key Binding JWT")
		printMap(token.KeyBindingJWT.Payload, 1)
	}

	// Holder key (cnf)
	if cnf, ok := token.Payload["cnf"].(map[string]any); ok {
		printSection("Holder Key (cnf)")
		printMap(cnf, 1)
	}

	fmt.Println()
}

// BuildJWTJSON returns the JSON-serializable map for a plain JWT token.
func BuildJWTJSON(token *sdjwt.Token) map[string]any {
	return map[string]any{
		"format":  "jwt",
		"header":  token.Header,
		"payload": token.Payload,
	}
}

// PrintJWT prints a decoded plain JWT to the terminal.
func PrintJWT(token *sdjwt.Token, opts Options) {
	if opts.JSON {
		PrintJSON(BuildJWTJSON(token))
		return
	}

	headerColor.Println("JWT")
	headerColor.Println(strings.Repeat("─", 50))

	// Header
	printSection("Header")
	printMapFiltered(token.Header, 1, opts.Verbose, "x5c")

	// Payload
	printSection("Payload")
	printMap(token.Payload, 1)

	fmt.Println()
}

// BuildMDOCJSON returns the JSON-serializable map for an mDOC document.
func BuildMDOCJSON(doc *mdoc.Document) map[string]any {
	out := map[string]any{
		"format":  "mso_mdoc",
		"docType": doc.DocType,
		"claims":  formatMDOCClaimsJSON(doc),
	}
	if doc.IssuerAuth != nil && doc.IssuerAuth.MSO != nil {
		mso := doc.IssuerAuth.MSO
		msoOut := map[string]any{
			"version":         mso.Version,
			"digestAlgorithm": mso.DigestAlgorithm,
			"docType":         mso.DocType,
		}
		if mso.ValidityInfo != nil {
			vi := map[string]any{}
			if mso.ValidityInfo.Signed != nil {
				vi["signed"] = mso.ValidityInfo.Signed.Format(time.RFC3339)
			}
			if mso.ValidityInfo.ValidFrom != nil {
				vi["validFrom"] = mso.ValidityInfo.ValidFrom.Format(time.RFC3339)
			}
			if mso.ValidityInfo.ValidUntil != nil {
				vi["validUntil"] = mso.ValidityInfo.ValidUntil.Format(time.RFC3339)
			}
			msoOut["validityInfo"] = vi
		}
		if mso.Status != nil {
			msoOut["status"] = mso.Status
		}
		if mso.DeviceKeyInfo != nil {
			msoOut["deviceKeyInfo"] = mso.DeviceKeyInfo
		}
		out["mso"] = msoOut
	}
	if doc.DeviceSigned != nil && doc.DeviceSigned.DeviceAuth != nil {
		out["deviceAuth"] = doc.DeviceSigned.DeviceAuth
	}
	return out
}

// PrintMDOC prints a decoded mDOC to the terminal.
func PrintMDOC(doc *mdoc.Document, opts Options) {
	if opts.JSON {
		PrintJSON(BuildMDOCJSON(doc))
		return
	}

	headerColor.Println("mDOC Credential")
	headerColor.Println(strings.Repeat("─", 50))

	if doc.IsDeviceResponse {
		dimColor.Println("  (parsed from DeviceResponse)")
	}

	printSection("Document Info")
	printKV("DocType", doc.DocType, 1)

	if doc.IssuerAuth != nil && doc.IssuerAuth.MSO != nil {
		mso := doc.IssuerAuth.MSO
		if mso.Version != "" {
			printKV("MSO Version", mso.Version, 1)
		}
		printKV("Digest Algorithm", mso.DigestAlgorithm, 1)
		if mso.ValidityInfo != nil {
			if mso.ValidityInfo.Signed != nil {
				printKV("Signed", mso.ValidityInfo.Signed.Format(time.RFC3339), 1)
			}
			if mso.ValidityInfo.ValidFrom != nil {
				printKV("Valid From", mso.ValidityInfo.ValidFrom.Format(time.RFC3339), 1)
			}
			if mso.ValidityInfo.ValidUntil != nil {
				printKV("Valid Until", mso.ValidityInfo.ValidUntil.Format(time.RFC3339)+dimColor.Sprintf(" (%s)", relativeTime(*mso.ValidityInfo.ValidUntil)), 1)
			}
		}

		// Status
		if mso.Status != nil {
			printSection("Status")
			printMap(mso.Status, 1)
		}

		// Device Key (verbose only)
		if mso.DeviceKeyInfo != nil && opts.Verbose {
			printSection("Device Key")
			printMap(mso.DeviceKeyInfo, 1)
		}
	}

	// Claims by namespace
	namespaces := sortedKeys(doc.NameSpaces)
	for _, ns := range namespaces {
		items := doc.NameSpaces[ns]
		printSection(fmt.Sprintf("Namespace: %s (%d claims)", ns, len(items)))
		// Sort by element identifier
		sort.Slice(items, func(i, j int) bool {
			return items[i].ElementIdentifier < items[j].ElementIdentifier
		})
		for _, item := range items {
			labelColor.Printf("  %s: ", item.ElementIdentifier)
			fmt.Println(formatValue(item.ElementValue))
			if opts.Verbose {
				dimColor.Printf("    digestID=%d\n", item.DigestID)
			}
		}
	}

	// Device Auth
	if doc.DeviceSigned != nil && doc.DeviceSigned.DeviceAuth != nil {
		printSection("Device Auth")
		printMap(doc.DeviceSigned.DeviceAuth, 1)
	}

	fmt.Println()
}

// PrintVerifyResultSDJWT prints SD-JWT verification results.
func PrintVerifyResultSDJWT(r *sdjwt.VerifyResult, opts Options) {
	if opts.JSON {
		PrintJSON(r)
		return
	}

	printSection("Signature Verification")
	if r.SignatureValid {
		successColor.Println("  ✓ Signature valid")
	} else {
		errorColor.Println("  ✗ Signature invalid")
	}

	printKV("Algorithm", r.Algorithm, 1)
	if r.KeyID != "" {
		printKV("Key ID", r.KeyID, 1)
	}
	if r.Issuer != "" {
		printKV("Issuer", r.Issuer, 1)
	}

	if r.IssuedAt != nil {
		printKV("Issued", r.IssuedAt.Format(time.RFC3339), 1)
	}
	printTimeValidity(r.ExpiresAt, r.NotBefore, r.Expired, r.NotYetValid)

	for _, e := range r.Errors {
		errorColor.Printf("  ✗ %s\n", e)
	}
}

// PrintVerifyResultMDOC prints mDOC verification results.
func PrintVerifyResultMDOC(r *mdoc.VerifyResult, opts Options) {
	if opts.JSON {
		PrintJSON(r)
		return
	}

	printSection("Signature Verification")
	if r.SignatureValid {
		successColor.Println("  ✓ Signature valid")
	} else {
		errorColor.Println("  ✗ Signature invalid")
	}

	printKV("Algorithm", r.Algorithm, 1)
	printKV("DocType", r.DocType, 1)

	printTimeValidity(r.ValidUntil, r.ValidFrom, r.Expired, r.NotYetValid)

	for _, e := range r.Errors {
		errorColor.Printf("  ✗ %s\n", e)
	}
}

func printTimeValidity(expires *time.Time, validFrom *time.Time, expired, notYetValid bool) {
	if validFrom != nil {
		printKV("Valid From", validFrom.Format(time.RFC3339), 1)
	}
	if expires != nil {
		label := "Expires"
		rel := dimColor.Sprintf(" (%s)", relativeTime(*expires))
		if expired {
			label = "Expired"
			warnColor.Printf("  ⚠ %s: %s%s\n", label, expires.Format(time.RFC3339), rel)
		} else {
			printKV(label, expires.Format(time.RFC3339)+rel, 1)
		}
	}
	if notYetValid {
		warnColor.Println("  ⚠ Credential not yet valid")
	}
}

func printSection(title string) {
	fmt.Println()
	headerColor.Printf("┌ %s\n", title)
}

func printKV(key, value string, indent int) {
	prefix := strings.Repeat("  ", indent)
	labelColor.Printf("%s%s: ", prefix, key)
	valueColor.Println(value)
}

// printMapFiltered prints a map but hides verbose-only keys unless verbose is true.
// When a key is hidden, a summary line is shown instead.
func printMapFiltered(m map[string]any, indent int, verbose bool, hiddenKeys ...string) {
	if verbose {
		printMap(m, indent)
		return
	}
	hidden := make(map[string]bool, len(hiddenKeys))
	for _, k := range hiddenKeys {
		hidden[k] = true
	}
	keys := sortedKeys(m)
	prefix := strings.Repeat("  ", indent)
	for _, k := range keys {
		if hidden[k] {
			if arr, ok := m[k].([]any); ok {
				dimColor.Printf("%s%s: (%d entries, use -v to show)\n", prefix, k, len(arr))
			}
			continue
		}
		labelColor.Printf("%s%s: ", prefix, k)
		fmt.Println(formatValue(m[k]))
	}
}

func printMap(m map[string]any, indent int) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	prefix := strings.Repeat("  ", indent)
	for _, k := range keys {
		labelColor.Printf("%s%s: ", prefix, k)
		fmt.Println(formatValue(m[k]))
	}
}

func formatValue(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case float64:
		if val == float64(int64(val)) {
			return fmt.Sprintf("%d", int64(val))
		}
		return fmt.Sprintf("%g", val)
	case bool:
		if val {
			return "true"
		}
		return "false"
	case nil:
		return "null"
	case []byte:
		return fmt.Sprintf("(%d bytes)", len(val))
	case map[string]any:
		b, _ := json.MarshalIndent(val, "    ", "  ")
		return string(b)
	case []any:
		if isSimpleArray(val) {
			b, _ := json.Marshal(val)
			return string(b)
		}
		b, _ := json.MarshalIndent(val, "    ", "  ")
		return string(b)
	default:
		b, _ := json.Marshal(val)
		return string(b)
	}
}

func isSimpleArray(arr []any) bool {
	for _, v := range arr {
		switch v.(type) {
		case map[string]any, []any:
			return false
		}
	}
	return true
}

func formatDisclosuresJSON(disclosures []sdjwt.Disclosure) []map[string]any {
	result := make([]map[string]any, len(disclosures))
	for i, d := range disclosures {
		result[i] = map[string]any{
			"name":         d.Name,
			"value":        d.Value,
			"salt":         d.Salt,
			"digest":       d.Digest,
			"isArrayEntry": d.IsArrayEntry,
		}
	}
	return result
}

func formatMDOCClaimsJSON(doc *mdoc.Document) map[string]any {
	claims := make(map[string]any)
	for ns, items := range doc.NameSpaces {
		nsClaims := make(map[string]any)
		for _, item := range items {
			nsClaims[item.ElementIdentifier] = item.ElementValue
		}
		claims[ns] = nsClaims
	}
	return claims
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// PrintError prints an error message.
func PrintError(msg string) {
	fmt.Fprintf(os.Stderr, "%s %s\n", errorColor.Sprint("Error:"), msg)
}
