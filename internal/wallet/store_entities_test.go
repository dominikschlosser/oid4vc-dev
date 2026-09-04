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
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/storage"
)

func entityStore(t *testing.T) (*WalletStore, storage.Store) {
	t.Helper()
	backend := storage.NewMemory()
	return NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), backend), backend
}

func importTestCredential(t *testing.T, w *Wallet, vct string) string {
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
				idx := w.NextStatusIndex()
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
			if strings.HasPrefix(key, store.sectionPrefix(section)) {
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
	if got := store.storedCredentialsFromEntities(); len(got) != 1 || got[0].ID != first {
		t.Fatalf("stored credentials = %+v", got)
	}
}

// Two servers on one store issuing at the same time never hand out the same
// status list index, since the counter moves through the store.
func TestEntities_ServersIssueWithDistinctStatusIndices(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wallet")
	backend := storage.NewMemory()
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

// The wallet's change stamp differs after every save, including saves by a
// second opener, so a server never mistakes a changed store for an unchanged
// one.
func TestEntities_StampChangesWithEverySave(t *testing.T) {
	store, backend := entityStore(t)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[storage.Stamp]bool)
	for i := 0; i < 3; i++ {
		if err := store.Save(w); err != nil {
			t.Fatal(err)
		}
		other, err := NewWalletStoreOn(store.Dir, backend).LoadOrCreate()
		if err != nil {
			t.Fatal(err)
		}
		other.Log = append(other.Log, LogEntry{Time: time.Now(), Action: "other"})
		if err := NewWalletStoreOn(store.Dir, backend).Save(other); err != nil {
			t.Fatal(err)
		}
		stamp, ok := store.WalletStamp()
		if !ok || seen[stamp] {
			t.Fatalf("stamp %+v seen again (ok=%t)", stamp, ok)
		}
		seen[stamp] = true
	}
}
