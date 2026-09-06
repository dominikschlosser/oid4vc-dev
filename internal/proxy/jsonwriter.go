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
	"io"
	"os"
)

// JSONWriter writes traffic entries as NDJSON (one JSON object per line).
type JSONWriter struct {
	enc        *json.Encoder
	allTraffic bool
}

func NewJSONWriter(allTraffic bool) *JSONWriter {
	return NewJSONWriterTo(os.Stdout, allTraffic)
}

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
