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

// Package statuslist checks credential revocation status using Token Status Lists (RFC 9596).
package statuslist

// StatusRef is a reference to a status list entry in a credential.
type StatusRef struct {
	URI string `json:"uri"`
	Idx int    `json:"idx"`
}

// StatusResult contains the revocation check result.
type StatusResult struct {
	URI       string `json:"uri"`
	Index     int    `json:"index"`
	Status    int    `json:"status"`
	IsValid   bool   `json:"isValid"`
	BitsPerEntry int `json:"bitsPerEntry"`
	Error     string `json:"error,omitempty"`
}
