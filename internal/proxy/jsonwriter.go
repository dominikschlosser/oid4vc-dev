package proxy

import (
	"encoding/json"
	"io"
	"os"
)

// JSONWriter writes traffic entries as NDJSON (one JSON object per line).
type JSONWriter struct {
	enc        *json.Encoder
	allTraffic bool
}

// NewJSONWriter creates a writer that emits NDJSON to stdout.
func NewJSONWriter(allTraffic bool) *JSONWriter {
	return NewJSONWriterTo(os.Stdout, allTraffic)
}

// NewJSONWriterTo creates a writer that emits NDJSON to the given writer.
func NewJSONWriterTo(w io.Writer, allTraffic bool) *JSONWriter {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &JSONWriter{enc: enc, allTraffic: allTraffic}
}

func (j *JSONWriter) WriteEntry(entry *TrafficEntry) {
	if entry.Class == ClassUnknown && !j.allTraffic {
		return
	}
	j.enc.Encode(entry)
}
