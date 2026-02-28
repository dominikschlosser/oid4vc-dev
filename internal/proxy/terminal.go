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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/fatih/color"
)

var (
	headerColor  = color.New(color.FgCyan, color.Bold)
	labelColor   = color.New(color.FgYellow)
	valueColor   = color.New(color.FgWhite)
	dimColor     = color.New(color.Faint)
	successColor = color.New(color.FgGreen)
	errorColor   = color.New(color.FgRed)
	classColor   = color.New(color.FgMagenta, color.Bold)
)

// TerminalWriter writes traffic entries to the terminal with color formatting.
type TerminalWriter struct {
	AllTraffic bool
}

func (tw *TerminalWriter) WriteEntry(entry *TrafficEntry) {
	if entry.Class == ClassUnknown && !tw.AllTraffic {
		return
	}
	PrintEntry(entry)
}

// PrintEntry prints a traffic entry to the terminal with color formatting.
func PrintEntry(entry *TrafficEntry) {
	ts := entry.Timestamp.Format("15:04:05")

	// Status color
	statusFn := successColor.Sprintf
	if entry.StatusCode >= 400 {
		statusFn = errorColor.Sprintf
	}

	// Header line
	fmt.Printf("%s %s %s %s  %s  %s\n",
		dimColor.Sprint("━━━"),
		dimColor.Sprintf("[%s]", ts),
		headerColor.Sprintf("%s %s", entry.Method, truncateURL(entry.URL, 80)),
		statusFn("← %d", entry.StatusCode),
		dimColor.Sprintf("(%dms)", entry.DurationMS),
		classColor.Sprintf("[%s]", entry.ClassLabel),
	)

	// Decoded fields
	if entry.Decoded != nil {
		for key, val := range entry.Decoded {
			printDecodedField(key, val, 1)
		}
	}

	// Decode commands for detected credentials
	for i, cred := range entry.Credentials {
		label := ""
		if i < len(entry.CredentialLabels) {
			label = entry.CredentialLabels[i]
		}
		printDecodeHint(cred, label)
	}

	fmt.Println()
}

func printDecodedField(key string, val any, depth int) {
	prefix := strings.Repeat("  ", depth)

	switch v := val.(type) {
	case map[string]any:
		labelColor.Printf("%s┌ %s:\n", prefix, key)
		for k, inner := range v {
			printDecodedField(k, inner, depth+1)
		}
	case string:
		labelColor.Printf("%s┌ ", prefix)
		labelColor.Printf("%s: ", key)
		valueColor.Println(format.Truncate(v, 120))
	default:
		// Marshal slices, nested maps, etc. as indented JSON
		labelColor.Printf("%s┌ ", prefix)
		labelColor.Printf("%s: ", key)
		if b, err := json.MarshalIndent(val, prefix+"  ", "  "); err == nil {
			valueColor.Println(string(b))
		} else {
			valueColor.Println(fmt.Sprintf("%v", val))
		}
	}
}

func printDecodeHint(credential, label string) {
	hint := fmt.Sprintf("  → oid4vc-dev decode '%s'", credential)
	if label != "" {
		hint += fmt.Sprintf("  (%s)", label)
	}
	dimColor.Println(hint)
}

func truncateURL(u string, maxLen int) string {
	if len(u) <= maxLen {
		return u
	}
	return u[:maxLen] + "..."
}
