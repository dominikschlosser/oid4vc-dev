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
	"encoding/json"
	"io/fs"
	"net/http"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/storage"
)

// changedSections is store.changedSections with the error failing the test.
func changedSections(t *testing.T, store *WalletStore, w *Wallet, includeLog bool) []string {
	t.Helper()
	changed, err := store.changedSections(w, includeLog)
	if err != nil {
		t.Fatal(err)
	}
	return changed
}

func entityStore(t *testing.T) (*WalletStore, storage.Store) {
	t.Helper()
	backend := storage.NewMemory()
	return NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), backend), backend
}

func importTestCredential(t testing.TB, w *Wallet, vct string) string {
	t.Helper()
	key, _ := mock.GenerateKey()
	sdjwt, err := mock.GenerateSDJWT(mock.SDJWTConfig{Issuer: "https://test.example", VCT: vct, ExpiresIn: time.Hour, Claims: map[string]any{"a": 1}, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := w.ImportCredential(sdjwt)
	if err != nil {
		t.Fatal(err)
	}
	return cred.ID
}

// On an entity backend every part of the wallet survives a save and a load:
// credentials in the order they were added, the log in time order, status
// entries, deferred issuances, issued attestations and the serving URLs.
func TestEntities_RoundTrip(t *testing.T) {
	store, backend := entityStore(t)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	first := importTestCredential(t, w, "First")
	second := importTestCredential(t, w, "Second")
	w.RegisterStatusEntry(first, 7)
	w.DeferredIssuances = []DeferredIssuance{{ID: "d1", TransactionID: "tx", DeferredEndpoint: "https://issuer.example/deferred"}}
	w.BaseURL = "http://wallet.example"
	w.IssuerURL = "https://wallet.example:8086"
	for i := 0; i < 3; i++ {
		w.Log = append(w.Log, LogEntry{Time: time.Now().Add(time.Duration(i) * time.Millisecond), Action: "step", Detail: strings.Repeat("x", i)})
	}
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}

	keys, _ := backend.List(store.stateKey(credentialsSection))
	if len(keys) != 2 {
		t.Fatalf("credential entities = %v", keys)
	}

	reloaded, err := NewWalletStoreOn(store.Dir, backend).LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Credentials) != 2 || reloaded.Credentials[0].ID != first || reloaded.Credentials[1].ID != second {
		t.Fatalf("credentials = %+v", reloaded.Credentials)
	}
	if len(reloaded.Log) != 3 || !sort.SliceIsSorted(reloaded.Log, func(i, j int) bool { return reloaded.Log[i].Time.Before(reloaded.Log[j].Time) }) {
		t.Fatalf("log = %+v", reloaded.Log)
	}
	if reloaded.StatusEntries[first].Index != 7 {
		t.Fatalf("status entries = %+v", reloaded.StatusEntries)
	}
	if len(reloaded.DeferredIssuances) != 1 || reloaded.DeferredIssuances[0].ID != "d1" {
		t.Fatalf("deferred = %+v", reloaded.DeferredIssuances)
	}
	if len(reloaded.IssuedAttestations) != 2 {
		t.Fatalf("issued attestations = %+v", reloaded.IssuedAttestations)
	}
	if reloaded.BaseURL != w.BaseURL || reloaded.IssuerURL != w.IssuerURL {
		t.Fatalf("urls = %s %s", reloaded.BaseURL, reloaded.IssuerURL)
	}
}

// Two servers on one store keep each other's changes: a save writes the
// entities that changed in that server's wallet and leaves the rest alone.
func TestEntities_ConcurrentOpenersKeepEachOthersWrites(t *testing.T) {
	store, backend := entityStore(t)
	a, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(a); err != nil {
		t.Fatal(err)
	}
	second := NewWalletStoreOn(store.Dir, backend)
	b, err := second.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}

	fromA := importTestCredential(t, a, "FromA")
	b.Log = append(b.Log, LogEntry{Time: time.Now(), Action: "presentation", Success: true})
	var wg sync.WaitGroup
	for _, save := range []func() error{func() error { return store.Save(a) }, func() error { return second.Save(b) }} {
		wg.Add(1)
		go func(save func() error) {
			defer wg.Done()
			if err := save(); err != nil {
				t.Error(err)
			}
		}(save)
	}
	wg.Wait()

	merged, err := NewWalletStoreOn(store.Dir, backend).LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if len(merged.Credentials) != 1 || merged.Credentials[0].ID != fromA {
		t.Fatalf("credentials = %+v", merged.Credentials)
	}
	if len(merged.Log) != 1 || merged.Log[0].Action != "presentation" {
		t.Fatalf("log = %+v", merged.Log)
	}

	// A removal by one server reaches the store, and a second server that
	// reloads sees it gone while its own additions stay.
	a.RemoveCredential(fromA)
	if err := store.Save(a); err != nil {
		t.Fatal(err)
	}
	fromB := importTestCredential(t, b, "FromB")
	if err := second.Save(b); err != nil {
		t.Fatal(err)
	}
	final, err := NewWalletStoreOn(store.Dir, backend).LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Credentials) != 1 || final.Credentials[0].ID != fromB {
		t.Fatalf("credentials after removal = %+v", final.Credentials)
	}
}

// The status list index comes from a counter shared through the store, so
// two servers issuing at the same time never hand out the same index.
func TestEntities_StatusIndicesAreUniqueAcrossOpeners(t *testing.T) {
	store, backend := entityStore(t)
	a, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewWalletStoreOn(store.Dir, backend).LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	seen := make(map[int]bool)
	var wg sync.WaitGroup
	for _, w := range []*Wallet{a, b} {
		wg.Add(1)
		go func(w *Wallet) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				idx, err := w.NextStatusIndex()
				if err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				if seen[idx] {
					t.Errorf("index %d handed out twice", idx)
				}
				seen[idx] = true
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	if len(seen) != 50 {
		t.Fatalf("%d distinct indices, want 50", len(seen))
	}
	if reloaded, _ := NewWalletStoreOn(store.Dir, backend).LoadOrCreate(); reloaded.StatusListCounter != 50 {
		t.Fatalf("stored counter = %d", reloaded.StatusListCounter)
	}
}

// A reset to the baseline leaves no entity behind.
func TestEntities_ResetClearsTheStore(t *testing.T) {
	store, backend := entityStore(t)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	importTestCredential(t, w, "Gone")
	w.Log = append(w.Log, LogEntry{Time: time.Now(), Action: "gone"})
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}
	w.ResetToBaseline()
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}
	blobs, _ := backend.ReadAll(store.stateKey())
	for key := range blobs {
		for _, section := range []string{credentialsSection, logSection, statusSection, attestationsSection} {
			if strings.HasPrefix(key, store.stateKey(section)+"/") {
				t.Errorf("%s survived the reset", key)
			}
		}
	}
	reloaded, _ := NewWalletStoreOn(store.Dir, backend).LoadOrCreate()
	if len(reloaded.Credentials) != 0 || len(reloaded.Log) != 0 || reloaded.StatusListCounter != 0 {
		t.Fatalf("reloaded after reset: %d credentials, %d log entries, counter %d", len(reloaded.Credentials), len(reloaded.Log), reloaded.StatusListCounter)
	}
}

// A save whose snapshot a reload replaced in the meantime leaves the reload's
// snapshot in place. The reload also replaced the wallet's state, so that
// snapshot is the one that describes it, and nothing the reload dropped from
// memory is deleted by the next save.
func TestEntities_ReloadDuringSaveKeepsTheReloadedSnapshot(t *testing.T) {
	store, backend := entityStore(t)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}
	first := importTestCredential(t, w, "First")
	// The reload lands after the save read the wallet and before it
	// finished: the store's snapshot is what the reload put there.
	other, err := NewWalletStoreOn(store.Dir, backend).LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	reloadedSnapshot := other.persisted
	store.saveDelay = func() {
		w.mu.Lock()
		w.Credentials = nil
		w.persisted = reloadedSnapshot
		w.mu.Unlock()
	}
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}
	if !w.persisted.is(reloadedSnapshot) {
		t.Fatal("the save replaced the snapshot the reload put in place")
	}
	// The next save has nothing to delete, and the store still holds the
	// credential the save wrote.
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}
	if got, err := store.storedCredentialsFromEntities(); err != nil || len(got) != 1 || got[0].ID != first {
		t.Fatalf("stored credentials = %+v, %v", got, err)
	}
}

// The index the shared counter hands out is the one the issued credential's
// status claim carries, so two servers issuing at the same time produce
// distinct status claims.
func TestEntities_ServersIssueWithDistinctStatusIndices(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wallet")
	backend := storage.NewMemory()
	// The store is created once up front, as the first server of a
	// deployment does before the next one starts.
	if _, err := NewWalletStoreOn(dir, backend).LoadOrCreate(); err != nil {
		t.Fatal(err)
	}
	servers := []*Server{newTestServer(t, false), newTestServer(t, false)}
	for _, srv := range servers {
		srv.SetStore(NewWalletStoreOn(dir, backend))
		srv.wallet.IssuerURL = "https://wallet.example:8086"
	}
	var mu sync.Mutex
	seen := make(map[int]string)
	var wg sync.WaitGroup
	for _, srv := range servers {
		wg.Add(1)
		go func(srv *Server) {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				resp := serverRequest(t, srv, http.MethodPost, "/api/issue", `{"format":"sdjwt","template":"pid-sdjwt"}`)
				if resp.Code != http.StatusCreated {
					t.Errorf("issue: %d %s", resp.Code, resp.Body.String())
					return
				}
				doc := decodeJSON(t, resp)
				status, _ := doc["status"].(map[string]any)
				idx := int(status["idx"].(float64))
				mu.Lock()
				if other, dup := seen[idx]; dup {
					t.Errorf("index %d handed out to %s and %s", idx, other, doc["id"])
				}
				seen[idx] = doc["id"].(string)
				mu.Unlock()
			}
		}(srv)
	}
	wg.Wait()
	if len(seen) != 30 {
		t.Fatalf("%d distinct indices, want 30", len(seen))
	}
}

// A server sees which sections another opener changed, and none for its own
// saves, so a presentation on one server costs the others nothing and an
// issuance costs them the credential section once.
func TestEntities_ChangedSectionsNameWhatOthersChanged(t *testing.T) {
	store, backend := entityStore(t)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}
	if changed := changedSections(t, store, w, true); len(changed) != 0 {
		t.Fatalf("own save changed %v", changed)
	}
	importTestCredential(t, w, "Mine")
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}
	if changed := changedSections(t, store, w, true); len(changed) != 0 {
		t.Fatalf("own import changed %v", changed)
	}

	other := NewWalletStoreOn(store.Dir, backend)
	o, err := other.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	o.Log = append(o.Log, LogEntry{Time: time.Now(), Action: "presentation"})
	if err := other.Save(o); err != nil {
		t.Fatal(err)
	}
	if changed := changedSections(t, store, w, false); len(changed) != 0 {
		t.Fatalf("a log entry elsewhere changed %v for a request", changed)
	}
	if changed := changedSections(t, store, w, true); !slices.Equal(changed, []string{logSection}) {
		t.Fatalf("a log entry elsewhere changed %v for the log view", changed)
	}

	importTestCredential(t, o, "Elsewhere")
	if err := other.Save(o); err != nil {
		t.Fatal(err)
	}
	changed := changedSections(t, store, w, false)
	if !slices.Equal(changed, []string{credentialsSection, attestationsSection}) {
		t.Fatalf("an import elsewhere changed %v", changed)
	}
	if err := store.loadSections(w, changed); err != nil {
		t.Fatal(err)
	}
	if len(w.Credentials) != 2 || len(w.Log) != 0 {
		t.Fatalf("after loading %v: %d credentials, %d log entries", changed, len(w.Credentials), len(w.Log))
	}
	if changed := changedSections(t, store, w, false); len(changed) != 0 {
		t.Fatalf("still changed after loading: %v", changed)
	}
}

// A save never moves the shared status counter back: a server whose wallet
// still holds an older counter leaves the store's value in place.
func TestEntities_SaveLeavesTheSharedCounterAlone(t *testing.T) {
	store, backend := entityStore(t)
	a, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(a); err != nil {
		t.Fatal(err)
	}
	b, err := NewWalletStoreOn(store.Dir, backend).LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		if _, err := a.NextStatusIndex(); err != nil {
			t.Fatal(err)
		}
	}
	b.StatusListCounter = 10
	b.Log = append(b.Log, LogEntry{Time: time.Now(), Action: "presentation"})
	if err := NewWalletStoreOn(store.Dir, backend).Save(b); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewWalletStoreOn(store.Dir, backend).LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.StatusListCounter != 12 {
		t.Fatalf("stored counter = %d, want 12", reloaded.StatusListCounter)
	}
}

// A server whose snapshot is behind the store rewrites a credential another
// server added under the same key, so the store never lists it twice.
func TestEntities_StaleSnapshotRewritesTheSameRow(t *testing.T) {
	store, backend := entityStore(t)
	a, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(a); err != nil {
		t.Fatal(err)
	}
	second := NewWalletStoreOn(store.Dir, backend)
	b, err := second.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	importTestCredential(t, a, "FromA")
	if err := store.Save(a); err != nil {
		t.Fatal(err)
	}
	importTestCredential(t, b, "FromB")
	if err := second.Save(b); err != nil {
		t.Fatal(err)
	}
	// b's state is refreshed from the store while its snapshot stays behind.
	behind := b.persisted
	fresh, err := NewWalletStoreOn(store.Dir, backend).LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	b.Credentials = fresh.Credentials
	b.persisted = behind
	if err := second.Save(b); err != nil {
		t.Fatal(err)
	}
	rows, _ := backend.List(store.stateKey(credentialsSection))
	if len(rows) != 2 {
		t.Fatalf("credential rows = %v", rows)
	}
}

// countingStore counts the credential rows read and the rows written.
type countingStore struct {
	storage.Store
	reads, writes atomic.Int64
}

func (c *countingStore) Write(key string, data []byte, perm fs.FileMode) (storage.Stamp, error) {
	c.writes.Add(1)
	return c.Store.Write(key, data, perm)
}

func (c *countingStore) WriteIf(key string, data []byte, perm fs.FileMode, expected string) (storage.Stamp, error) {
	c.writes.Add(1)
	return c.Store.WriteIf(key, data, perm, expected)
}

func (c *countingStore) Read(key string) ([]byte, error) {
	if strings.Contains(key, "/"+credentialsSection+"/") {
		c.reads.Add(1)
	}
	return c.Store.Read(key)
}

func (c *countingStore) ReadAll(prefix string) (map[string]storage.Blob, error) {
	blobs, err := c.Store.ReadAll(prefix)
	for key := range blobs {
		if strings.Contains(key, "/"+credentialsSection+"/") {
			c.reads.Add(1)
		}
	}
	return blobs, err
}

// A credential another server added is loaded on its own: the rows already
// held keep their parsed form and are not read again, and a change made in
// memory to one of them is still saved afterwards.
func TestEntities_LoadReadsOnlyTheRowsThatChanged(t *testing.T) {
	backend := &countingStore{Store: storage.NewMemory()}
	dir := filepath.Join(t.TempDir(), "wallet")
	first := NewWalletStoreOn(dir, backend)
	w, err := first.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		importTestCredential(t, w, "Held")
	}
	if err := first.Save(w); err != nil {
		t.Fatal(err)
	}
	second := NewWalletStoreOn(dir, backend)
	o, err := second.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	added := importTestCredential(t, o, "Added")
	if err := second.Save(o); err != nil {
		t.Fatal(err)
	}

	held := reflect.ValueOf(w.Credentials[0].Claims).Pointer()
	w.Credentials[1].Uses = 5
	backend.reads.Store(0)
	if err := first.loadSections(w, []string{credentialsSection}); err != nil {
		t.Fatal(err)
	}
	if reads := backend.reads.Load(); reads != 1 {
		t.Fatalf("loading one added credential read %d rows", reads)
	}
	if len(w.Credentials) != 6 || w.Credentials[5].ID != added {
		t.Fatalf("credentials after the load = %d, last %s", len(w.Credentials), w.Credentials[len(w.Credentials)-1].ID)
	}
	if reflect.ValueOf(w.Credentials[0].Claims).Pointer() != held {
		t.Fatal("a held credential was parsed again")
	}
	if w.Credentials[1].Uses != 5 {
		t.Fatal("the load dropped a change made in memory")
	}
	if err := first.Save(w); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewWalletStoreOn(dir, backend).LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Credentials[1].Uses != 5 {
		t.Fatal("the change made in memory before the load was not saved")
	}
}

// Every logTrimEvery saves the store drops the oldest log rows beyond the
// cap and marks the log changed, so the other servers reload it.
func TestEntities_StoredLogIsTrimmed(t *testing.T) {
	store, backend := entityStore(t)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	entry := func(i int) LogEntry {
		return LogEntry{Time: start.Add(time.Duration(i) * time.Microsecond), Action: "step", Detail: strconv.Itoa(i)}
	}
	for i := 0; i < maxLogEntries+50; i++ {
		w.Log = append(w.Log, entry(i))
	}
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}
	last := maxLogEntries + 50
	for i := 1; i < logTrimEvery; i++ {
		if err := store.appendLogEntry(w, entry(last+i)); err != nil {
			t.Fatal(err)
		}
	}
	names, err := backend.List(store.stateKey(logSection))
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != maxLogEntries {
		t.Fatalf("stored log rows = %d, want %d", len(names), maxLogEntries)
	}
	if changed := changedSections(t, store, w, true); !slices.Equal(changed, []string{logSection}) {
		t.Fatalf("the trim changed %v", changed)
	}
	reloaded, err := NewWalletStoreOn(store.Dir, backend).LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Log) != maxLogEntries || reloaded.Log[len(reloaded.Log)-1].Detail != strconv.Itoa(last+logTrimEvery-1) {
		t.Fatalf("reloaded log: %d entries, last %q", len(reloaded.Log), reloaded.Log[len(reloaded.Log)-1].Detail)
	}
}

// A log entry a server appends is stored on its own and reaches another
// server's log view, and the server's next full save has nothing to write
// for it.
func TestEntities_AppendedLogEntryIsStoredOnItsOwn(t *testing.T) {
	backend := &countingStore{Store: storage.NewMemory()}
	store := NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), backend)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}
	other := NewWalletStoreOn(store.Dir, backend)
	o, err := other.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}

	w.AddLog("presentation", "sent", true)
	entry := w.GetLog()[len(w.GetLog())-1]
	backend.writes.Store(0)
	if err := store.appendLogEntry(w, entry); err != nil {
		t.Fatal(err)
	}
	if n := backend.writes.Load(); n != 2 {
		t.Fatalf("appending one entry wrote %d rows, want the row and the log revision", n)
	}
	if changed := changedSections(t, store, w, true); len(changed) != 0 {
		t.Fatalf("own log entry changed %v", changed)
	}
	changed := changedSections(t, other, o, true)
	if !slices.Equal(changed, []string{logSection}) {
		t.Fatalf("another server sees %v changed", changed)
	}
	if err := other.loadSections(o, changed); err != nil {
		t.Fatal(err)
	}
	if len(o.Log) != 1 || o.Log[0].Detail != "sent" {
		t.Fatalf("another server's log = %+v", o.Log)
	}

	backend.writes.Store(0)
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}
	if n := backend.writes.Load(); n != 0 {
		t.Fatalf("the next save wrote %d rows for the appended entry", n)
	}
}

// A credential whose raw form does not parse stays in the wallet, so one
// bad row never takes the whole wallet down.
func TestEntities_LoadKeepsACredentialItCannotRehydrate(t *testing.T) {
	store, backend := entityStore(t)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	id := importTestCredential(t, w, "Held")
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}
	key := store.credentialKey(id)
	data, err := backend.Read(key)
	if err != nil {
		t.Fatal(err)
	}
	var entity orderedEntity
	if err := json.Unmarshal(data, &entity); err != nil {
		t.Fatal(err)
	}
	var row map[string]any
	if err := json.Unmarshal(entity.Value, &row); err != nil {
		t.Fatal(err)
	}
	row["raw"] = "not a token"
	entity.Value, _ = json.Marshal(row)
	data, _ = json.Marshal(entity)
	if _, err := backend.Write(key, data, 0o600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewWalletStoreOn(store.Dir, backend).LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Credentials) != 1 || reloaded.Credentials[0].ID != id {
		t.Fatalf("credentials after the load = %+v", reloaded.Credentials)
	}
}

// A served wallet on an entity backend appends each log entry as one row
// through the log sink and loads the log only for the log views.
func TestEntities_ServerAppendsLogRowsAndLoadsTheLogOnDemand(t *testing.T) {
	srv := newTestServer(t, false)
	backend := &countingStore{Store: storage.NewMemory()}
	dir := filepath.Join(t.TempDir(), "wallet")
	store := NewWalletStoreOn(dir, backend)
	srv.SetStore(store)
	if err := store.Save(srv.wallet); err != nil {
		t.Fatal(err)
	}
	if resp := serverRequest(t, srv, "GET", "/api/credentials", ""); resp.Code != http.StatusOK {
		t.Fatalf("GET /api/credentials: %d", resp.Code)
	}
	other := NewWalletStoreOn(dir, backend)
	o, err := other.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}

	backend.writes.Store(0)
	srv.wallet.AddLog("presentation", "sent from the server", true)
	if n := backend.writes.Load(); n != 2 {
		t.Fatalf("a log entry on the server wrote %d rows, want the row and the log revision", n)
	}
	changed := changedSections(t, other, o, true)
	if err := other.loadSections(o, changed); err != nil {
		t.Fatal(err)
	}
	if len(o.Log) != 1 || o.Log[0].Detail != "sent from the server" {
		t.Fatalf("another server's log = %+v", o.Log)
	}

	o.AddLog("presentation", "sent elsewhere", true)
	if err := other.appendLogEntry(o, o.GetLog()[len(o.GetLog())-1]); err != nil {
		t.Fatal(err)
	}
	if resp := serverRequest(t, srv, "GET", "/api/credentials", ""); resp.Code != http.StatusOK {
		t.Fatalf("GET /api/credentials: %d", resp.Code)
	}
	if changed := changedSections(t, store, srv.wallet, true); !slices.Equal(changed, []string{logSection}) {
		t.Fatalf("a request without a log view loaded the log: changed %v", changed)
	}
	resp := serverRequest(t, srv, "GET", "/api/log", "")
	if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), "sent elsewhere") {
		t.Fatalf("GET /api/log: %d %s", resp.Code, resp.Body.String())
	}
	if changed := changedSections(t, store, srv.wallet, true); len(changed) != 0 {
		t.Fatalf("the log view left %v changed", changed)
	}
}
