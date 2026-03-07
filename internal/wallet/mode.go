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

package wallet

import "fmt"

// ValidationMode controls whether the wallet enforces all normative checks.
type ValidationMode string

const (
	ValidationModeDebug  ValidationMode = "debug"
	ValidationModeStrict ValidationMode = "strict"
)

// ParseValidationMode validates and normalizes the user-provided mode.
func ParseValidationMode(raw string) (ValidationMode, error) {
	switch ValidationMode(raw) {
	case "", ValidationModeDebug:
		return ValidationModeDebug, nil
	case ValidationModeStrict:
		return ValidationModeStrict, nil
	default:
		return "", fmt.Errorf("invalid validation mode %q (must be 'debug' or 'strict')", raw)
	}
}
