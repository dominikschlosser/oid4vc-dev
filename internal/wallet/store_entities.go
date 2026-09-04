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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/storage"
)

// On the memory and database backends the wallet is stored as one blob per
// entity under <prefix>/state/. A save writes the entities that changed
// since the wallet was loaded and deletes the ones that went away, so several
// wallet servers on one database only clash when they change the same
// entity. The activity log, the hot path under load, is append-only rows.
//
// Sections under state/:
//
//	credentials/<id>         {"seq": n, "value": StoredCredential}, seq keeps the order
//	log/<time>-<hash>        one LogEntry
//	status/<credential id>   one StatusEntry with its credential id
//	status-counter           the next status list index, moved with WriteIf
//	deferred/<id>            {"seq": n, "value": DeferredIssuance}
//	attestations/<hash>      one IssuedAttestationSpec
//	settings                 base and issuer URL
//	revision/<section>       rewritten whenever the section changes
//
// Every key is derived from the entity's identity alone, so a server whose
// view is behind rewrites the same row and never adds a second one.
//
// A server reloads at every request boundary. It compares the revision rows
// with the ones its wallet was loaded from, and for a section that changed
// it compares the stamps of the section's rows with the ones it holds and
// reads only the rows that are new or changed. The revision of a section a
// server changed itself is written with WriteIf, and when that succeeds
// nobody else changed the section since it was loaded, so the server records
// the new stamp and skips its own change. The log is loaded on demand by the
// log views, so a presentation on one server costs the others nothing.
const (
	stateSection        = "state"
	credentialsSection  = "credentials"
	logSection          = "log"
	statusSection       = "status"
	deferredSection     = "deferred"
	attestationsSection = "attestations"
	settingsSection     = "settings"
	revisionSection     = "revision"
	statusCounterEntity = "status-counter"
)

// allSections are the sections a full load reads. A running server refreshes
// serverSections only: its deferred issuances live in memory and its serving
// URLs come from its own flags.
var (
	allSections    = []string{credentialsSection, logSection, statusSection, deferredSection, attestationsSection, settingsSection}
	serverSections = []string{credentialsSection, logSection, statusSection, attestationsSection}
)

// logTrimEvery is how many saves a server makes between trims of the stored
// log to maxLogEntries.
const logTrimEvery = 64

// readAllAbove is the number of changed rows of a section from which the
// section is read in one query rather than row by row.
const readAllAbove = 16

// stateSnapshot is what the wallet knows to be stored: entity key to the
// blob as loaded or written. A save compares the wallet against it and a
// reload compares the store's stamps against it. It is never changed in
// place, so a save can read it without holding the wallet lock.
type stateSnapshot map[string]storage.Blob

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

func (s *WalletStore) revisionKey(section string) string {
	return s.stateKey(revisionSection, section)
}

// sectionOf returns the section an entity key belongs to.
func (s *WalletStore) sectionOf(key string) string {
	rest := strings.TrimPrefix(key, s.stateKey()+"/")
	section, _, _ := strings.Cut(rest, "/")
	if section == statusCounterEntity {
		return statusSection
	}
	return section
}

// Loaded reports whether w was loaded from an entity store.
func (s *WalletStore) Loaded(w *Wallet) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.persisted != nil
}

// hasEntities reports whether the store holds a wallet: one that was saved
// at least once has revision rows.
func (s *WalletStore) hasEntities() bool {
	revisions, err := s.backend.ReadAll(s.stateKey(revisionSection))
	return err == nil && len(revisions) > 0
}

// loadEntities fills a fresh wallet from the store.
func (s *WalletStore) loadEntities(w *Wallet) error {
	return s.LoadSections(w, allSections)
}

// ChangedSections returns the sections a running server refreshes whose
// stored revision differs from the one w was loaded from. The log is
// included only when asked.
func (s *WalletStore) ChangedSections(w *Wallet, includeLog bool) ([]string, error) {
	revisions, err := s.backend.ReadAll(s.stateKey(revisionSection))
	if err != nil {
		return nil, fmt.Errorf("reading wallet revisions: %w", err)
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	var changed []string
	for _, section := range serverSections {
		if section == logSection && !includeLog {
			continue
		}
		if revisions[s.revisionKey(section)].Stamp != w.revisions[section] {
			changed = append(changed, section)
		}
	}
	return changed, nil
}

// LoadSections brings the given sections of w up to date with the store. It
// reads the rows whose stamps differ from the ones w holds, drops the rows
// that are gone and keeps the parsed form of everything unchanged. The
// revisions are read first, so a change that lands while a section is read
// is loaded again on the next check.
func (s *WalletStore) LoadSections(w *Wallet, sections []string) error {
	revisions, err := s.backend.ReadAll(s.stateKey(revisionSection))
	if err != nil {
		return fmt.Errorf("reading wallet revisions: %w", err)
	}
	w.mu.RLock()
	known := w.persisted
	knownSeqs := w.entitySeqs
	parsed := make(map[string]StoredCredential, len(w.Credentials))
	for _, cred := range w.Credentials {
		parsed[s.stateKey(credentialsSection, entityName(cred.ID))] = cred
	}
	w.mu.RUnlock()

	updated := maps.Clone(known)
	if updated == nil {
		updated = make(stateSnapshot)
	}
	for _, section := range sections {
		if err := s.refreshSection(section, known, updated); err != nil {
			return err
		}
	}
	loaded, seqs, err := s.parseSections(updated, sections, known, knownSeqs, parsed)
	if err != nil {
		return err
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	for _, section := range sections {
		switch section {
		case credentialsSection:
			w.Credentials = loaded.credentials
		case logSection:
			w.Log = s.filterLogEntries(loaded.log)
		case statusSection:
			w.StatusEntries = loaded.statusEntries
			w.StatusListCounter = loaded.statusListCounter
		case deferredSection:
			w.DeferredIssuances = loaded.deferred
		case attestationsSection:
			w.IssuedAttestations = dedupeIssuedAttestations(loaded.attestations)
		case settingsSection:
			w.BaseURL = loaded.settings.BaseURL
			w.IssuerURL = loaded.settings.IssuerURL
		}
	}
	w.persisted = updated
	maps.DeleteFunc(seqs, func(key string, _ int) bool { _, kept := updated[key]; return !kept })
	w.entitySeqs = seqs
	if slices.Contains(sections, credentialsSection) {
		w.savedCredentials = make(map[string]StoredCredential, len(loaded.credentials))
		for _, cred := range loaded.credentials {
			w.savedCredentials[cred.ID] = cred
		}
	}
	if w.revisions == nil {
		w.revisions = make(map[string]storage.Stamp)
	}
	for _, section := range sections {
		w.revisions[section] = revisions[s.revisionKey(section)].Stamp
	}
	w.allocateStatusIndex = s.allocateStatusIndex
	return nil
}

// refreshSection puts the store's current rows of a section into updated:
// rows whose stamp differs from known are read, rows that are gone are
// dropped. A section with many changed rows (a first load, a long absence
// from the log) is read in one query.
func (s *WalletStore) refreshSection(section string, known, updated stateSnapshot) error {
	stamps, err := s.sectionStamps(section)
	if err != nil {
		return err
	}
	for key := range known {
		if _, present := stamps[key]; !present && s.sectionOf(key) == section {
			delete(updated, key)
		}
	}
	var changed []string
	for key, stamp := range stamps {
		if blob, ok := known[key]; !ok || blob.Stamp != stamp {
			changed = append(changed, key)
		}
	}
	if len(changed) > readAllAbove {
		blobs, err := s.backend.ReadAll(s.stateKey(section))
		if err != nil {
			return fmt.Errorf("reading wallet state: %w", err)
		}
		maps.Copy(updated, blobs)
		if section == statusSection || section == settingsSection {
			changed = slices.DeleteFunc(changed, func(key string) bool { _, ok := blobs[key]; return ok })
		} else {
			changed = nil
		}
	}
	for _, key := range changed {
		data, err := s.backend.Read(key)
		if errors.Is(err, fs.ErrNotExist) {
			delete(updated, key)
			continue
		}
		if err != nil {
			return fmt.Errorf("reading wallet state: %w", err)
		}
		updated[key] = storage.Blob{Data: data, Stamp: stamps[key]}
	}
	return nil
}

// sectionStamps returns the stamps of a section's rows. The status counter
// and the settings are single rows outside a section prefix.
func (s *WalletStore) sectionStamps(section string) (map[string]storage.Stamp, error) {
	var stamps map[string]storage.Stamp
	var err error
	switch section {
	case settingsSection:
		stamps = make(map[string]storage.Stamp)
	default:
		stamps, err = s.backend.Stamps(s.stateKey(section))
		if err != nil {
			return nil, fmt.Errorf("reading wallet state: %w", err)
		}
	}
	single := map[string]string{statusSection: s.stateKey(statusCounterEntity), settingsSection: s.stateKey(settingsSection)}
	if key, ok := single[section]; ok {
		if stamp, ok := s.backend.Stat(key); ok {
			stamps[key] = stamp
		}
	}
	return stamps, nil
}

// loadedSections are the parsed entities of a load.
type loadedSections struct {
	credentials       []StoredCredential
	log               []LogEntry
	statusEntries     map[string]StatusEntry
	statusListCounter int
	deferred          []DeferredIssuance
	attestations      []IssuedAttestationSpec
	settings          walletSettings
}

// parseSections parses the rows of the given sections and returns them with
// the positions of the ordered rows by key. A credential whose row is the one
// already parsed keeps its parsed form and its position, so a reload parses
// only what changed.
func (s *WalletStore) parseSections(blobs stateSnapshot, sections []string, known stateSnapshot, knownSeqs map[string]int, parsed map[string]StoredCredential) (loadedSections, map[string]int, error) {
	var loaded loadedSections
	seqs := maps.Clone(knownSeqs)
	if seqs == nil {
		seqs = make(map[string]int)
	}
	type orderedCredential struct {
		seq  int
		cred StoredCredential
	}
	var credentials []orderedCredential
	var deferred []orderedEntity
	for _, key := range slices.Sorted(maps.Keys(blobs)) {
		section := s.sectionOf(key)
		if !slices.Contains(sections, section) {
			continue
		}
		data := blobs[key].Data
		var err error
		switch section {
		case credentialsSection:
			if before, ok := parsed[key]; ok && known[key].Stamp == blobs[key].Stamp {
				if seq, ok := seqs[key]; ok {
					credentials = append(credentials, orderedCredential{seq: seq, cred: before})
					break
				}
			}
			var entity orderedEntity
			var cred StoredCredential
			if err = json.Unmarshal(data, &entity); err == nil {
				if err = json.Unmarshal(entity.Value, &cred); err == nil {
					err = cred.Rehydrate()
				}
			}
			if err == nil {
				seqs[key] = entity.Seq
				credentials = append(credentials, orderedCredential{seq: entity.Seq, cred: cred})
			}
		case deferredSection:
			var entity orderedEntity
			if err = json.Unmarshal(data, &entity); err == nil {
				seqs[key] = entity.Seq
				deferred = append(deferred, entity)
			}
		case logSection:
			var entry LogEntry
			if err = json.Unmarshal(data, &entry); err == nil {
				loaded.log = append(loaded.log, entry)
			}
		case statusSection:
			if key == s.stateKey(statusCounterEntity) {
				loaded.statusListCounter, err = strconv.Atoi(string(data))
				break
			}
			var record statusRecord
			if err = json.Unmarshal(data, &record); err == nil {
				if loaded.statusEntries == nil {
					loaded.statusEntries = make(map[string]StatusEntry)
				}
				loaded.statusEntries[record.CredentialID] = record.StatusEntry
			}
		case attestationsSection:
			var spec IssuedAttestationSpec
			if err = json.Unmarshal(data, &spec); err == nil {
				loaded.attestations = append(loaded.attestations, spec)
			}
		case settingsSection:
			err = json.Unmarshal(data, &loaded.settings)
		}
		if err != nil {
			return loaded, nil, fmt.Errorf("parsing wallet state %s: %w", key, err)
		}
	}
	sort.SliceStable(credentials, func(i, j int) bool { return credentials[i].seq < credentials[j].seq })
	for _, c := range credentials {
		loaded.credentials = append(loaded.credentials, c.cred)
	}
	sort.SliceStable(deferred, func(i, j int) bool { return deferred[i].Seq < deferred[j].Seq })
	for _, entity := range deferred {
		var d DeferredIssuance
		if err := json.Unmarshal(entity.Value, &d); err != nil {
			return loaded, nil, fmt.Errorf("parsing a stored deferred issuance: %w", err)
		}
		loaded.deferred = append(loaded.deferred, d)
	}
	return loaded, seqs, nil
}

// saveEntities writes what changed since the snapshot and deletes what went
// away, then bumps the revision of every section it touched. The wallet
// state and the snapshot it is compared against are read under one lock, so
// a reload between them cannot pair an older state with a newer snapshot.
func (s *WalletStore) saveEntities(w *Wallet) error {
	w.mu.RLock()
	snapshot := w.persisted
	revisions := maps.Clone(w.revisions)
	current, saved, seqs, err := s.currentEntities(w, snapshot)
	w.mu.RUnlock()
	if err != nil {
		return err
	}
	if s.saveDelay != nil {
		s.saveDelay()
	}

	next := make(stateSnapshot, len(current))
	touched := make(map[string]bool)
	for key, data := range current {
		if blob, ok := snapshot[key]; ok && bytes.Equal(blob.Data, data) {
			next[key] = blob
			continue
		}
		stamp, err := s.backend.Write(key, data, 0o600)
		if err != nil {
			return fmt.Errorf("writing wallet state: %w", err)
		}
		next[key] = storage.Blob{Data: data, Stamp: stamp}
		touched[s.sectionOf(key)] = true
	}
	for key := range snapshot {
		if _, kept := current[key]; kept {
			continue
		}
		if err := s.backend.Delete(key); err != nil {
			return fmt.Errorf("deleting wallet state: %w", err)
		}
		touched[s.sectionOf(key)] = true
	}

	// A revision written with the stamp the wallet was loaded from proves
	// that nobody else changed the section in between, so the new stamp is
	// recorded and the server skips its own change on the next check. A
	// conflict means someone did, and the plain write leaves the old stamp
	// in place so the next check loads the section.
	own := make(map[string]storage.Stamp)
	for section := range touched {
		key := s.revisionKey(section)
		stamp, err := s.backend.WriteIf(key, revisionNonce(), 0o600, revisions[section].Version)
		if errors.Is(err, storage.ErrConflict) {
			_, err = s.backend.Write(key, revisionNonce(), 0o600)
		} else if err == nil {
			own[section] = stamp
		}
		if err != nil {
			return fmt.Errorf("writing wallet revision: %w", err)
		}
	}
	s.saves++
	if s.saves%logTrimEvery == 0 {
		if err := s.trimLogRows(); err != nil {
			return err
		}
	}

	// A reload during the save replaced the snapshot and the state together.
	// Its snapshot stands. At worst the next save writes again what was
	// written here.
	w.mu.Lock()
	if w.persisted.is(snapshot) {
		w.persisted = next
		w.savedCredentials = saved
		w.entitySeqs = seqs
		if w.revisions == nil {
			w.revisions = make(map[string]storage.Stamp)
		}
		maps.Copy(w.revisions, own)
	}
	w.mu.Unlock()
	return nil
}

// AppendLogEntry stores one activity log entry the wallet appended, without
// comparing the rest of the wallet. The log is the hot path under load, so a
// presentation costs one row and one revision write.
func (s *WalletStore) AppendLogEntry(w *Wallet, entry LogEntry) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if s.loadLogCleanMarker().After(entry.Time) {
		return nil
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encoding wallet state log: %w", err)
	}
	key := s.stateKey(logSection, logEntryName(entry))
	stamp, err := s.backend.Write(key, data, 0o600)
	if err != nil {
		return fmt.Errorf("writing wallet state: %w", err)
	}
	w.mu.RLock()
	expected := w.revisions[logSection].Version
	w.mu.RUnlock()
	revision, err := s.backend.WriteIf(s.revisionKey(logSection), revisionNonce(), 0o600, expected)
	own := err == nil
	if errors.Is(err, storage.ErrConflict) {
		_, err = s.backend.Write(s.revisionKey(logSection), revisionNonce(), 0o600)
	}
	if err != nil {
		return fmt.Errorf("writing wallet revision: %w", err)
	}
	s.saves++
	if s.saves%logTrimEvery == 0 {
		if err := s.trimLogRows(); err != nil {
			return err
		}
	}
	w.mu.Lock()
	w.persisted = w.persisted.with(key, storage.Blob{Data: data, Stamp: stamp})
	if own {
		if w.revisions == nil {
			w.revisions = make(map[string]storage.Stamp)
		}
		w.revisions[logSection] = revision
	}
	w.mu.Unlock()
	return nil
}

func revisionNonce() []byte {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return []byte(hex.EncodeToString(b[:]))
}

// trimLogRows deletes the oldest stored log rows beyond maxLogEntries. A
// server that only appends never loads the log, so the store bounds it.
func (s *WalletStore) trimLogRows() error {
	names, err := s.backend.List(s.stateKey(logSection))
	if err != nil {
		return fmt.Errorf("listing the wallet log: %w", err)
	}
	if len(names) <= maxLogEntries {
		return nil
	}
	for _, name := range names[:len(names)-maxLogEntries] {
		if err := s.backend.Delete(s.stateKey(logSection, name)); err != nil {
			return fmt.Errorf("trimming the wallet log: %w", err)
		}
	}
	_, err = s.backend.Write(s.revisionKey(logSection), revisionNonce(), 0o600)
	return err
}

// currentEntities marshals the wallet into entities. A credential equal to
// its stored form keeps its stored bytes, so a save marshals only what
// changed. It returns the entities, the credentials as they are now stored
// by id and the positions of the ordered rows by key. Caller holds w.mu.
func (s *WalletStore) currentEntities(w *Wallet, snapshot stateSnapshot) (map[string][]byte, map[string]StoredCredential, map[string]int, error) {
	current := make(map[string][]byte)
	put := func(key string, v any) error {
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("encoding wallet state %s: %w", key, err)
		}
		current[key] = data
		return nil
	}
	putOrdered := func(key string, seq int, v any) error {
		value, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("encoding wallet state %s: %w", key, err)
		}
		return put(key, orderedEntity{Seq: seq, Value: value})
	}

	seqs := make(map[string]int)
	creds := s.withStoredAssets(append([]StoredCredential(nil), w.Credentials...))
	saved := make(map[string]StoredCredential, len(creds))
	credentialSeqs := s.orderedSeqs(credentialsSection, snapshot, w.entitySeqs, len(creds), func(i int) string { return creds[i].ID })
	for i, cred := range creds {
		key := s.stateKey(credentialsSection, entityName(cred.ID))
		seqs[key] = credentialSeqs[i]
		saved[cred.ID] = cred
		if before, ok := w.savedCredentials[cred.ID]; ok && credentialUnchanged(before, cred) {
			if blob, stored := snapshot[key]; stored && w.entitySeqs[key] == credentialSeqs[i] {
				current[key] = blob.Data
				continue
			}
		}
		if err := putOrdered(key, credentialSeqs[i], cred); err != nil {
			return nil, nil, nil, err
		}
	}
	deferred := w.DeferredIssuances
	deferredSeqs := s.orderedSeqs(deferredSection, snapshot, w.entitySeqs, len(deferred), func(i int) string { return deferred[i].ID })
	for i, d := range deferred {
		key := s.stateKey(deferredSection, entityName(d.ID))
		seqs[key] = deferredSeqs[i]
		if err := putOrdered(key, deferredSeqs[i], d); err != nil {
			return nil, nil, nil, err
		}
	}
	for _, entry := range s.filterLogEntries(w.Log) {
		key := s.stateKey(logSection, logEntryName(entry))
		if blob, ok := snapshot[key]; ok {
			current[key] = blob.Data
			continue
		}
		data, err := json.Marshal(entry)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("encoding wallet state log: %w", err)
		}
		current[key] = data
	}
	for id, entry := range w.StatusEntries {
		if err := put(s.stateKey(statusSection, entityName(id)), statusRecord{CredentialID: id, StatusEntry: entry}); err != nil {
			return nil, nil, nil, err
		}
	}
	for _, spec := range dedupeIssuedAttestations(w.IssuedAttestations) {
		if err := put(s.stateKey(attestationsSection, shortHash(spec.Format+"|"+spec.VCT+"|"+spec.DocType)), spec); err != nil {
			return nil, nil, nil, err
		}
	}
	if err := put(s.stateKey(settingsSection), walletSettings{BaseURL: w.BaseURL, IssuerURL: w.IssuerURL}); err != nil {
		return nil, nil, nil, err
	}
	// The counter is created and moved by the allocator alone, so a save
	// with a counter behind the store's never sets it back. A reset to zero
	// of a stored counter is written.
	counterKey := s.stateKey(statusCounterEntity)
	if stored, ok := snapshot[counterKey]; ok {
		current[counterKey] = stored.Data
		if w.StatusListCounter == 0 {
			current[counterKey] = []byte("0")
		}
	}
	return current, saved, seqs, nil
}

// credentialUnchanged reports whether a credential is the one stored. The
// claims map is compared by identity first: a credential keeps its map for
// its whole life unless it was parsed again.
func credentialUnchanged(stored, cred StoredCredential) bool {
	if reflect.ValueOf(stored.Claims).Pointer() == reflect.ValueOf(cred.Claims).Pointer() {
		stored.Claims, cred.Claims = nil, nil
	}
	stored.issuedAt, cred.issuedAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(stored, cred)
}

// orderedSeqs returns the position of each item of an ordered section. An
// item keeps the position it was stored under, a new one gets the next, so
// a load returns the items in the order they were added. known holds the
// positions by key, and a row missing from it is read from the snapshot.
func (s *WalletStore) orderedSeqs(section string, snapshot stateSnapshot, known map[string]int, n int, idAt func(int) string) []int {
	prefix := s.sectionPrefix(section)
	existing := make(map[string]int)
	next := 0
	for key, blob := range snapshot {
		name, ok := strings.CutPrefix(key, prefix)
		if !ok {
			continue
		}
		seq, ok := known[key]
		if !ok {
			var entity orderedEntity
			if json.Unmarshal(blob.Data, &entity) != nil {
				continue
			}
			seq = entity.Seq
		}
		existing[name] = seq
		if seq >= next {
			next = seq + 1
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
// order, and by what it says, so two entries in one nanosecond stay apart.
func logEntryName(entry LogEntry) string {
	return fmt.Sprintf("%020d-%s", entry.Time.UnixNano(), shortHash(entry.Action+"\x00"+entry.Detail+"\x00"+entry.Severity+"\x00"+strconv.FormatBool(entry.Success)))
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
// the same status list index. The status revision moves with it, so the
// other servers pick up the counter their status list is sized by.
func (s *WalletStore) allocateStatusIndex(w *Wallet) (int, error) {
	key := s.stateKey(statusCounterEntity)
	for attempt := 0; attempt < 100; attempt++ {
		// The stamp is taken before the value. A value newer than the stamp
		// fails the write below, and the loop reads again.
		next, expected := 0, ""
		if stamp, ok := s.backend.Stat(key); ok {
			expected = stamp.Version
			data, err := s.backend.Read(key)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return 0, fmt.Errorf("reading the status counter: %w", err)
			}
			if next, err = strconv.Atoi(string(data)); err != nil {
				return 0, fmt.Errorf("parsing the status counter: %w", err)
			}
		}
		stored := []byte(strconv.Itoa(next + 1))
		stamp, err := s.backend.WriteIf(key, stored, 0o600, expected)
		if errors.Is(err, storage.ErrConflict) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if _, err := s.backend.Write(s.revisionKey(statusSection), revisionNonce(), 0o600); err != nil {
			return 0, fmt.Errorf("writing wallet revision: %w", err)
		}
		w.mu.Lock()
		w.StatusListCounter = next + 1
		w.persisted = w.persisted.with(key, storage.Blob{Data: stored, Stamp: stamp})
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
func (snap stateSnapshot) with(key string, blob storage.Blob) stateSnapshot {
	next := maps.Clone(snap)
	if next == nil {
		next = stateSnapshot{}
	}
	next[key] = blob
	return next
}

func (s *WalletStore) storedCredentialsFromEntities() ([]StoredCredential, error) {
	blobs, err := s.backend.ReadAll(s.stateKey(credentialsSection))
	if err != nil {
		return nil, err
	}
	creds := make([]StoredCredential, 0, len(blobs))
	for _, blob := range blobs {
		var entity orderedEntity
		var cred StoredCredential
		if json.Unmarshal(blob.Data, &entity) == nil && json.Unmarshal(entity.Value, &cred) == nil {
			creds = append(creds, cred)
		}
	}
	return creds, nil
}
