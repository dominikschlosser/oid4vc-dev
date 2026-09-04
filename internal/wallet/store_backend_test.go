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
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/storage"
)

// The same wallet directory is one wallet on every backend, so a
// second opener (another process on the file backend, another server on a
// shared database) sees what the first one saved, keys and CA included.
func TestWalletStore_SameNameSharesStateAcrossOpeners(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wallet")
	backend := storage.NewMemory()

	first := NewWalletStoreOn(dir, backend)
	w, err := first.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := mock.GenerateKey()
	sdjwt, err := mock.GenerateSDJWT(mock.SDJWTConfig{Issuer: "https://test.example", VCT: "Shared", ExpiresIn: time.Hour, Claims: map[string]any{"a": 1}, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ImportCredential(sdjwt); err != nil {
		t.Fatal(err)
	}
	if err := first.Save(w); err != nil {
		t.Fatal(err)
	}
	if _, err := credtemplate.Save(first.Templates(), credtemplate.Template{Name: "shared", Format: "sdjwt", Claims: map[string]any{"x": 1}}); err != nil {
		t.Fatal(err)
	}

	second := NewWalletStoreOn(dir, backend)
	reloaded, err := second.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Credentials) != 1 || reloaded.Credentials[0].VCT != "Shared" {
		t.Fatalf("second opener sees %d credentials", len(reloaded.Credentials))
	}
	if !reloaded.HolderKey.Equal(w.HolderKey) || !reloaded.CAKey.Equal(w.CAKey) {
		t.Fatal("second opener generated its own keys")
	}
	if _, err := credtemplate.Load("shared", second.Templates()); err != nil {
		t.Fatalf("second opener does not see the template: %v", err)
	}

	other := NewWalletStoreOn(filepath.Join(t.TempDir(), "wallet"), backend)
	if w, err := other.LoadOrCreate(); err != nil || len(w.Credentials) != 0 {
		t.Fatalf("a wallet under another directory shares state: %d credentials, %v", len(w.Credentials), err)
	}
}

// Every store opened without an explicit spec follows the environment, so
// one variable moves a whole test run, a served wallet and the CLI commands
// driving it onto the same backend.
func TestNewWalletStore_FollowsTheStorageEnvironment(t *testing.T) {
	t.Setenv(storage.EnvVar, storage.KindMemory)
	if kind := NewWalletStore(t.TempDir()).Backend().Kind(); kind != storage.KindMemory {
		t.Fatalf("backend = %s", kind)
	}

	t.Setenv(storage.EnvVar, "h2")
	if _, err := NewWalletStore(t.TempDir()).LoadOrCreate(); err == nil {
		t.Fatal("an unknown backend loaded a wallet")
	}
	if _, err := OpenWalletStore(t.TempDir(), "h2"); err == nil {
		t.Fatal("OpenWalletStore accepted an unknown backend")
	}
}

// The default wallet is keyed by its name alone on a backend without
// directories, so wallet servers in containers and a CLI on the host, whose
// home directories differ, address the same wallet in a shared database.
func TestWalletKeyPrefix(t *testing.T) {
	t.Setenv("EUDI_DEV_HOME", filepath.Join(t.TempDir(), "state"))
	if got := walletKeyPrefix(DefaultWalletDir()); got != "wallet" {
		t.Fatalf("default wallet prefix = %q", got)
	}
	if got := walletKeyPrefix(filepath.Join(filepath.Dir(DefaultWalletDir()), "second")); got != "second" {
		t.Fatalf("sibling wallet prefix = %q", got)
	}
	outside := filepath.Join(t.TempDir(), "elsewhere")
	if got := walletKeyPrefix(outside); got != filepath.ToSlash(outside)[1:] {
		t.Fatalf("outside wallet prefix = %q", got)
	}
}

// A server re-reads the store at the request boundary, so a change another
// opener of the same wallet saved (another server on a shared database) is
// visible on the next request.
func TestServerReloadSeesAnotherOpenersWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "wallet")
	backend := storage.NewMemory()
	srv := newTestServer(t, false)
	first := NewWalletStoreOn(dir, backend)
	if _, err := first.LoadOrCreate(); err != nil {
		t.Fatal(err)
	}
	srv.SetStore(first)
	if creds := decodeJSONArray(t, serverRequest(t, srv, http.MethodGet, "/api/credentials", "")); len(creds) != 0 {
		t.Fatalf("fresh wallet lists %d credentials", len(creds))
	}

	second := NewWalletStoreOn(dir, backend)
	w, err := second.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := mock.GenerateKey()
	sdjwt, err := mock.GenerateSDJWT(mock.SDJWTConfig{Issuer: "https://test.example", VCT: "Elsewhere", ExpiresIn: time.Hour, Claims: map[string]any{"a": 1}, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ImportCredential(sdjwt); err != nil {
		t.Fatal(err)
	}
	if err := second.Save(w); err != nil {
		t.Fatal(err)
	}

	creds := decodeJSONArray(t, serverRequest(t, srv, http.MethodGet, "/api/credentials", ""))
	if len(creds) != 1 || creds[0].(map[string]any)["vct"] != "Elsewhere" {
		t.Fatalf("server lists %v after another opener saved", creds)
	}
}

func TestConfigReportsTheStorageBackend(t *testing.T) {
	srv := newTestServer(t, false)
	srv.SetStore(NewWalletStoreOn(t.TempDir(), storage.NewMemory()))
	config := decodeJSON(t, serverRequest(t, srv, http.MethodGet, "/api/config", ""))
	if config["storage"] != storage.KindMemory {
		t.Fatalf("storage = %v", config["storage"])
	}
}
