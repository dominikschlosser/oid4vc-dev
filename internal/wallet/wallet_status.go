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

// SetCredentialStatus sets the status value for a credential.
func (w *Wallet) SetCredentialStatus(credID string, status int) (StatusEntry, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	entry, ok := w.StatusEntries[credID]
	if !ok {
		return StatusEntry{}, false
	}
	entry.Status = status
	w.StatusEntries[credID] = entry
	return entry, true
}

// BuildStatusBitstring builds a bitstring from status entries (1 bit per entry).
func (w *Wallet) BuildStatusBitstring() []byte {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.StatusListCounter == 0 {
		// Minimum 1 byte
		return make([]byte, 1)
	}

	// Calculate number of bytes needed
	numBytes := (w.StatusListCounter + 7) / 8
	// Minimum 16 bytes as per RFC 9596
	if numBytes < 16 {
		numBytes = 16
	}
	bitstring := make([]byte, numBytes)

	for _, entry := range w.StatusEntries {
		if entry.Status != 0 {
			byteIdx := entry.Index / 8
			bitOffset := entry.Index % 8
			if byteIdx < len(bitstring) {
				bitstring[byteIdx] |= byte(1 << bitOffset)
			}
		}
	}

	return bitstring
}

// nextStatusIndex returns the next status list index and increments the counter.
func (w *Wallet) nextStatusIndex() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	idx := w.StatusListCounter
	w.StatusListCounter++
	return idx
}

// registerStatusEntry records a status entry for a credential.
func (w *Wallet) registerStatusEntry(credID string, idx int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.StatusEntries == nil {
		w.StatusEntries = make(map[string]StatusEntry)
	}
	w.StatusEntries[credID] = StatusEntry{Index: idx, Status: 0}
}
