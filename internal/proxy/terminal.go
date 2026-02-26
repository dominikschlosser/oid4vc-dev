package proxy

import (
	"encoding/json"
	"fmt"
	"strings"

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
		valueColor.Println(truncate(v, 120))
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

func truncateURL(u string, maxLen int) string {
	if len(u) <= maxLen {
		return u
	}
	return u[:maxLen] + "..."
}
