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

package format

import (
	"encoding/json"
	"fmt"
	"strings"
)

func ParseJWTParts(raw string) (header, payload map[string]any, sig []byte, err error) {
	parts := strings.SplitN(raw, ".", 3)
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("expected 3 parts separated by '.', got %d", len(parts))
	}

	headerBytes, err := DecodeBase64URL(parts[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding header: %w", err)
	}

	payloadBytes, err := DecodeBase64URL(parts[1])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding payload: %w", err)
	}

	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, nil, fmt.Errorf("unmarshaling header: %w", err)
	}

	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, nil, nil, fmt.Errorf("unmarshaling payload: %w", err)
	}

	sig, _ = DecodeBase64URL(parts[2])

	return header, payload, sig, nil
}
