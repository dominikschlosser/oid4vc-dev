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

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/storage"
)

// On the memory and database backends the wallet is stored as one blob per
// entity under <prefix>/state/ rather than as one wallet.json. A save writes
// the entities that changed since the wallet was loaded and deletes the ones
// that went away, so several wallet servers on one database only clash when
// they change the same entity. The activity log, the hot path under load, is
// append-only rows.
//
// Sections under state/:
//
//	credentials/<id>         {"seq": n, "value": StoredCredential}, seq keeps the order
//	log/<time>-<hash>        one LogEntry
//	status/<credential id>   one StatusEntry with its credential id
//	deferred/<id>            {"seq": n, "value": DeferredIssuance}
//	attestations/<hash>      one IssuedAttestationSpec
//	settings                 base and issuer URL
//	status-counter           the next status list index, moved with WriteIf
//	revision                 rewritten on every save, its stamp is the wallet's
//
// Every key is derived from the entity's identity alone, so a server whose
// view is behind rewrites the same row rather than adding a second one.
const (
	stateSection        = "state"
	credentialsSection  = "credentials"
	logSection          = "log"
	statusSection       = "status"
	deferredSection     = "deferred"
	attestationsSection = "attestations"
	settingsEntity      = "settings"
	statusCounterEntity = "status-counter"
	revisionEntity      = "revision"
)

// stateSnapshot is what the wallet knows to be stored: entity key to JSON. A
// save compares the wallet against it. It is never changed in place, so a
// save can read it without holding the wallet lock.
type stateSnapshot map[string][]byte

// walletSettings is the settings entity.
type walletSettings struct {
	BaseURL   string `json:"base_url,omitempty"`
	IssuerURL string `json:"issuer_url,omitempty"`
}

// statusRecord is the status entity. It carries the credential id, so the id
// does not have to be recoverable from the key.
type statusRecord struct {
	CredentialID string `json:"credential_id"`
	StatusEntry
}

// orderedEntity wraps an entity of an ordered section with its position.
type orderedEntity struct {
	Seq   int             `json:"seq"`
	Value json.RawMessage `json:"value"`
}

// entityMode reports whether this store keeps the wallet as entities.
func (s *WalletStore) entityMode() bool {
	return s.backend.Kind() != storage.KindFile
}

func (s *WalletStore) stateKey(parts ...string) string {
	return s.key(append([]string{stateSection}, parts...)...)
}

func (s *WalletStore) sectionPrefix(section string) string {
	return s.stateKey(section) + "/"
}

// loadEntities fills w from the stored entities and records the snapshot.
func (s *WalletStore) loadEntities(w *Wallet) error {
	blobs, err := s.backend.ReadAll(s.stateKey())
	if err != nil {
		return fmt.Errorf("reading wallet state: %w", err)
	}
	keys := make([]string, 0, len(blobs))
	for key := range blobs {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var settings walletSettings
	statusEntries := make(map[string]StatusEntry)
	var log []LogEntry
	var attestations []IssuedAttestationSpec
	var credentials, deferred []orderedEntity
	for _, key := range keys {
		data := blobs[key]
		section, _, _ := strings.Cut(strings.TrimPrefix(key, s.stateKey()+"/"), "/")
		var err error
		switch section {
		case credentialsSection:
			var entity orderedEntity
			if err = json.Unmarshal(data, &entity); err == nil {
				credentials = append(credentials, entity)
			}
		case deferredSection:
			var entity orderedEntity
			if err = json.Unmarshal(data, &entity); err == nil {
				deferred = append(deferred, entity)
			}
		case logSection:
			var entry LogEntry
			if err = json.Unmarshal(data, &entry); err == nil {
				log = append(log, entry)
			}
		case statusSection:
			var record statusRecord
			if err = json.Unmarshal(data, &record); err == nil {
				statusEntries[record.CredentialID] = record.StatusEntry
			}
		case attestationsSection:
			var spec IssuedAttestationSpec
			if err = json.Unmarshal(data, &spec); err == nil {
				attestations = append(attestations, spec)
			}
		case settingsEntity:
			err = json.Unmarshal(data, &settings)
		case statusCounterEntity:
			w.StatusListCounter, err = strconv.Atoi(string(data))
		}
		if err != nil {
			return fmt.Errorf("parsing wallet state %s: %w", key, err)
		}
	}
	sort.SliceStable(credentials, func(i, j int) bool { return credentials[i].Seq < credentials[j].Seq })
	for _, entity := range credentials {
		var cred StoredCredential
		if err := json.Unmarshal(entity.Value, &cred); err != nil {
			return fmt.Errorf("parsing a stored credential: %w", err)
		}
		w.Credentials = append(w.Credentials, cred)
	}
	sort.SliceStable(deferred, func(i, j int) bool { return deferred[i].Seq < deferred[j].Seq })
	for _, entity := range deferred {
		var d DeferredIssuance
		if err := json.Unmarshal(entity.Value, &d); err != nil {
			return fmt.Errorf("parsing a stored deferred issuance: %w", err)
		}
		w.DeferredIssuances = append(w.DeferredIssuances, d)
	}
	w.IssuedAttestations = dedupeIssuedAttestations(attestations)
	w.Log = s.filterLogEntries(log)
	if len(statusEntries) > 0 {
		w.StatusEntries = statusEntries
	}
	w.BaseURL = settings.BaseURL
	w.IssuerURL = settings.IssuerURL
	// The revision is not an entity a save compares: its version has to keep
	// climbing for the reload's change check, so it is only ever rewritten.
	delete(blobs, s.stateKey(revisionEntity))
	w.persisted = stateSnapshot(blobs)
	w.allocateStatusIndex = s.allocateStatusIndex
	return nil
}

// saveEntities writes what changed since the snapshot and deletes what went
// away. The wallet state and the snapshot it is compared against are read
// under one lock, so a reload between them cannot pair an older state with a
// newer snapshot.
func (s *WalletStore) saveEntities(w *Wallet) error {
	w.mu.RLock()
	snapshot := w.persisted
	current, err := s.currentEntities(w, snapshot)
	w.mu.RUnlock()
	if err != nil {
		return err
	}
	if s.saveDelay != nil {
		s.saveDelay()
	}

	for key, data := range current {
		if bytes.Equal(snapshot[key], data) {
			continue
		}
		if err := s.backend.Write(key, data, 0o600); err != nil {
			return fmt.Errorf("writing wallet state: %w", err)
		}
	}
	for key := range snapshot {
		if _, kept := current[key]; kept {
			continue
		}
		if err := s.backend.Delete(key); err != nil {
			return fmt.Errorf("deleting wallet state: %w", err)
		}
	}
	if err := s.backend.Write(s.stateKey(revisionEntity), []byte(strconv.FormatInt(time.Now().UnixNano(), 10)), 0o600); err != nil {
		return fmt.Errorf("writing wallet state: %w", err)
	}

	// A reload may have replaced the snapshot (and the wallet's state)
	// meanwhile. Then the reload's snapshot stands: it describes the state
	// the wallet holds now, and what was written here is at worst written
	// again by the next save.
	w.mu.Lock()
	if w.persisted.is(snapshot) {
		w.persisted = current
	}
	w.mu.Unlock()
	return nil
}

// currentEntities marshals the wallet into entities. Caller holds w.mu.
func (s *WalletStore) currentEntities(w *Wallet, snapshot stateSnapshot) (stateSnapshot, error) {
	current := make(stateSnapshot)
	put := func(key string, v any) error {
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("encoding wallet state %s: %w", key, err)
		}
		current[key] = data
		return nil
	}
	putOrdered := func(section, id string, seq int, v any) error {
		value, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("encoding wallet state %s: %w", id, err)
		}
		return put(s.stateKey(section, entityName(id)), orderedEntity{Seq: seq, Value: value})
	}

	creds := s.withStoredAssets(append([]StoredCredential(nil), w.Credentials...))
	credentialSeqs := s.orderedSeqs(credentialsSection, snapshot, len(creds), func(i int) string { return creds[i].ID })
	for i, cred := range creds {
		if err := putOrdered(credentialsSection, cred.ID, credentialSeqs[i], cred); err != nil {
			return nil, err
		}
	}
	deferred := w.DeferredIssuances
	deferredSeqs := s.orderedSeqs(deferredSection, snapshot, len(deferred), func(i int) string { return deferred[i].ID })
	for i, d := range deferred {
		if err := putOrdered(deferredSection, d.ID, deferredSeqs[i], d); err != nil {
			return nil, err
		}
	}
	for _, entry := range s.filterLogEntries(w.Log) {
		data, err := json.Marshal(entry)
		if err != nil {
			return nil, fmt.Errorf("encoding wallet state log: %w", err)
		}
		current[s.stateKey(logSection, logEntryName(entry, data))] = data
	}
	for id, entry := range w.StatusEntries {
		if err := put(s.stateKey(statusSection, entityName(id)), statusRecord{CredentialID: id, StatusEntry: entry}); err != nil {
			return nil, err
		}
	}
	for _, spec := range dedupeIssuedAttestations(w.IssuedAttestations) {
		if err := put(s.stateKey(attestationsSection, shortHash(spec.Format+"|"+spec.VCT+"|"+spec.DocType)), spec); err != nil {
			return nil, err
		}
	}
	if err := put(s.stateKey(settingsEntity), walletSettings{BaseURL: w.BaseURL, IssuerURL: w.IssuerURL}); err != nil {
		return nil, err
	}
	// The counter is moved by the allocator alone, so a save with a counter
	// behind the store's never sets it back. A reset to zero is written.
	counterKey := s.stateKey(statusCounterEntity)
	if w.StatusListCounter == 0 {
		current[counterKey] = []byte("0")
	} else if stored, ok := snapshot[counterKey]; ok {
		current[counterKey] = stored
	}
	return current, nil
}

// orderedSeqs returns the position of each item of an ordered section. An
// item keeps the position it was stored under, a new one gets the next, so
// a load returns the items in the order they were added.
func (s *WalletStore) orderedSeqs(section string, snapshot stateSnapshot, n int, idAt func(int) string) []int {
	prefix := s.sectionPrefix(section)
	existing := make(map[string]int)
	next := 0
	for key, data := range snapshot {
		name, ok := strings.CutPrefix(key, prefix)
		if !ok {
			continue
		}
		var entity orderedEntity
		if json.Unmarshal(data, &entity) != nil {
			continue
		}
		existing[name] = entity.Seq
		if entity.Seq >= next {
			next = entity.Seq + 1
		}
	}
	seqs := make([]int, n)
	for i := range seqs {
		if seq, ok := existing[entityName(idAt(i))]; ok {
			seqs[i] = seq
			continue
		}
		seqs[i] = next
		next++
	}
	return seqs
}

// logEntryName keys a log entry by its time, so a load returns the log in
// order, and by its content, so two entries in one nanosecond stay apart.
func logEntryName(entry LogEntry, data []byte) string {
	return fmt.Sprintf("%020d-%s", entry.Time.UnixNano(), shortHash(string(data)))
}

// entityName makes an identifier safe as one key segment.
func entityName(id string) string {
	if id == "" || strings.Contains(id, "/") || strings.HasPrefix(id, ".") {
		return shortHash(id)
	}
	return id
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// allocateStatusIndex moves the shared status counter forward with a
// compare-and-swap, so two servers issuing at the same time never hand out
// the same status list index.
func (s *WalletStore) allocateStatusIndex(w *Wallet) (int, error) {
	key := s.stateKey(statusCounterEntity)
	for attempt := 0; attempt < 100; attempt++ {
		// The stamp is taken before the value. A value newer than the stamp
		// fails the write below, and the loop reads again.
		next, expected := 0, ""
		if stamp, ok := s.backend.Stat(key); ok {
			expected = stamp.Version
			data, err := s.backend.Read(key)
			if err != nil {
				continue
			}
			if next, err = strconv.Atoi(string(data)); err != nil {
				return 0, fmt.Errorf("parsing the status counter: %w", err)
			}
		}
		stored := []byte(strconv.Itoa(next + 1))
		err := s.backend.WriteIf(key, stored, 0o600, expected)
		if errors.Is(err, storage.ErrConflict) {
			continue
		}
		if err != nil {
			return 0, err
		}
		w.mu.Lock()
		w.StatusListCounter = next + 1
		w.persisted = w.persisted.with(key, stored)
		w.mu.Unlock()
		return next, nil
	}
	return 0, errors.New("the status counter kept changing under the allocation")
}

// is reports whether both are the same snapshot.
func (snap stateSnapshot) is(other stateSnapshot) bool {
	return reflect.ValueOf(snap).Pointer() == reflect.ValueOf(other).Pointer()
}

// with returns a copy of the snapshot with one entity replaced.
func (snap stateSnapshot) with(key string, data []byte) stateSnapshot {
	next := make(stateSnapshot, len(snap)+1)
	for k, v := range snap {
		next[k] = v
	}
	next[key] = data
	return next
}

// withSectionFrom returns a copy of the snapshot whose entities under prefix
// are taken from other instead.
func (snap stateSnapshot) withSectionFrom(prefix string, other stateSnapshot) stateSnapshot {
	next := make(stateSnapshot, len(snap))
	for k, v := range snap {
		if !strings.HasPrefix(k, prefix) {
			next[k] = v
		}
	}
	for k, v := range other {
		if strings.HasPrefix(k, prefix) {
			next[k] = v
		}
	}
	return next
}

// storedCredentialsFromEntities returns the credentials as stored, for the
// asset pruning.
func (s *WalletStore) storedCredentialsFromEntities() []StoredCredential {
	blobs, err := s.backend.ReadAll(s.stateKey(credentialsSection))
	if err != nil {
		return nil
	}
	creds := make([]StoredCredential, 0, len(blobs))
	for _, data := range blobs {
		var entity orderedEntity
		var cred StoredCredential
		if json.Unmarshal(data, &entity) == nil && json.Unmarshal(entity.Value, &cred) == nil {
			creds = append(creds, cred)
		}
	}
	return creds
}
