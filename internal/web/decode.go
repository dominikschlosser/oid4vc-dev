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

package web

import (
	"fmt"

	"github.com/dominikschlosser/ssi-debugger/internal/format"
	"github.com/dominikschlosser/ssi-debugger/internal/mdoc"
	"github.com/dominikschlosser/ssi-debugger/internal/output"
	"github.com/dominikschlosser/ssi-debugger/internal/sdjwt"
)

// Decode detects the credential format and returns a JSON-serializable map.
func Decode(input string) (map[string]any, error) {
	detected := format.Detect(input)

	switch detected {
	case format.FormatSDJWT:
		token, err := sdjwt.Parse(input)
		if err != nil {
			return nil, fmt.Errorf("parsing SD-JWT: %w", err)
		}
		return output.BuildSDJWTJSON(token), nil

	case format.FormatJWT:
		token, err := sdjwt.Parse(input)
		if err != nil {
			return nil, fmt.Errorf("parsing JWT: %w", err)
		}
		return output.BuildJWTJSON(token), nil

	case format.FormatMDOC:
		doc, err := mdoc.Parse(input)
		if err != nil {
			return nil, fmt.Errorf("parsing mDOC: %w", err)
		}
		return output.BuildMDOCJSON(doc), nil

	default:
		return nil, fmt.Errorf("unable to auto-detect credential format (not JWT, SD-JWT, or mDOC)")
	}
}
