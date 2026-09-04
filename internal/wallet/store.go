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
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dominikschlosser/eudi-dev/internal/config"
	"github.com/dominikschlosser/eudi-dev/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/internal/mock"
	"github.com/dominikschlosser/eudi-dev/internal/storage"
)

// WalletStore persists the wallet through the storage layer: wallet.json
// (one entity per blob under state/ on the memory and database backends, see
// store_entities.go), the key and certificate PEMs, assets/ and templates/
// under the wallet's prefix, and the shared CA one level up.
type WalletStore struct {
	// Dir is the wallet's directory. On the file backend it is where the
	// files are. On every backend it identifies the wallet: the instance
	// registry and the remote CLI find a served wallet by it.
	Dir string

	backend storage.Store
	// prefix is the wallet's key prefix (Dir's base name on the file backend,
	// Dir relative to the state directory elsewhere, see walletKeyPrefix).
	// sharedPrefix is the prefix one level up, where the CA lives.
	prefix       string
	sharedPrefix string

	// seed derives the keys this store generates. Empty generates at random.
	seed mock.Seed
	// seedSource says where the seed came from, for the startup summary: ""
	// for none, "seed" for a caller's, "built-in seed" for the one "auto"
	// applies on the memory backend.
	seedSource string

	// saveMu orders the writers of wallet.json. Save snapshots the wallet and
	// then writes the blob, and without the mutex a save that snapshotted
	// earlier can write later, so the blob silently loses whatever only the
	// newer snapshot had. The next reload then makes the loss permanent. The
	// server's own lock does not cover every writer: the log sink and the
	// demo issuer save through their own callbacks.
	saveMu sync.Mutex

	// saveDelay widens the snapshot-to-write window in tests. Nil otherwise.
	saveDelay func()

	// saves counts the entity saves, so the stored log is trimmed every
	// logTrimEvery of them.
	saves int
}

var walletRuntimeRegistry sync.Map

// walletJSON is the stored format of wallet.json.
type walletJSON struct {
	Credentials        []StoredCredential      `json:"credentials"`
	IssuedAttestations []IssuedAttestationSpec `json:"issued_attestations,omitempty"`
	Log                []LogEntry              `json:"log,omitempty"`
	DeferredIssuances  []DeferredIssuance      `json:"deferred_issuances,omitempty"`
	StatusEntries      map[string]StatusEntry  `json:"status_entries,omitempty"`
	StatusListCounter  int                     `json:"status_list_counter,omitempty"`
	BaseURL            string                  `json:"base_url,omitempty"`
	IssuerURL          string                  `json:"issuer_url,omitempty"`
	Port               int                     `json:"port,omitempty"`

	// LegacyPendingIssuances reads the field's earlier name, so deferred
	// credentials recorded under it are still collected. Only the current name
	// is written, so one save migrates the file.
	LegacyPendingIssuances []DeferredIssuance `json:"pending_issuances,omitempty"`
}

// DefaultWalletDir returns the default wallet storage directory inside the
// tool's state directory (~/.eudi-dev, with a legacy ~/.oid4vc-dev fallback).
func DefaultWalletDir() string {
	return filepath.Join(config.BaseDir(), "wallet")
}

// ResolveWalletDir returns the absolute wallet directory, the default when
// dir is empty.
func ResolveWalletDir(dir string) string {
	if dir == "" {
		dir = DefaultWalletDir()
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return dir
}

// NewWalletStore returns the store for a wallet directory (the default
// directory when dir is empty). The backend comes from EUDI_DEV_STORAGE,
// files when the variable is unset.
func NewWalletStore(dir string) *WalletStore {
	return NewWalletStoreOn(dir, storage.FromEnv(storageOptions(dir)))
}

// OpenWalletStore returns the store for a wallet directory on the backend
// given by spec (see storage.Open).
func OpenWalletStore(dir, spec string) (*WalletStore, error) {
	backend, err := storage.Open(spec, storageOptions(dir))
	if err != nil {
		return nil, err
	}
	return NewWalletStoreOn(dir, backend), nil
}

// storageOptions describes the wallet directory for storage.Open. An explicit
// dir, or a state directory set through the environment, counts as a
// requested location for "auto".
func storageOptions(dir string) storage.Options {
	requested := dir != "" || os.Getenv("EUDI_DEV_HOME") != "" || os.Getenv("OID4VC_DEV_HOME") != ""
	return storage.Options{Root: filepath.Dir(ResolveWalletDir(dir)), RootRequested: requested}
}

// NewWalletStoreOn returns the store for a wallet directory inside the given
// backend.
func NewWalletStoreOn(dir string, backend storage.Store) *WalletStore {
	dir = ResolveWalletDir(dir)
	prefix := filepath.Base(dir)
	if backend.Kind() != storage.KindFile {
		prefix = walletKeyPrefix(dir)
	}
	sharedPrefix := path.Dir(prefix)
	if sharedPrefix == "." {
		sharedPrefix = ""
	}
	store := &WalletStore{Dir: dir, backend: backend, prefix: prefix, sharedPrefix: sharedPrefix}
	store.SetSeed(os.Getenv(SeedEnvVar))
	return store
}

// SeedEnvVar is the environment variable with the key seed. "auto" means the
// built-in seed on the memory backend and random keys elsewhere.
const SeedEnvVar = "EUDI_DEV_SEED"

// defaultSeed is the seed "auto" uses. It is public, so it only serves a
// wallet whose state is lost on exit.
const defaultSeed = "eudi-dev"

// SetSeed derives the keys this store generates from seed (see SeedEnvVar).
// An empty seed generates at random.
func (s *WalletStore) SetSeed(seed string) {
	s.seed, s.seedSource = mock.Seed(seed), "seed"
	if seed == "auto" {
		s.seed, s.seedSource = nil, ""
		if s.backend.Kind() == storage.KindMemory {
			s.seed, s.seedSource = mock.Seed(defaultSeed), "built-in seed"
		}
	}
	if len(s.seed) == 0 {
		s.seedSource = ""
	}
}

// Seeded reports whether generated keys derive from a seed.
func (s *WalletStore) Seeded() bool {
	return len(s.seed) > 0
}

// SeedSource is "" without a seed, "seed" for a caller's seed and "built-in
// seed" for the public one "auto" applies on the memory backend.
func (s *WalletStore) SeedSource() string {
	return s.seedSource
}

// walletKeyPrefix is the key prefix of a wallet in a backend without
// directories: the wallet directory relative to the state directory when it
// lies inside it, else its absolute path in slash form without the leading
// separator. The default wallet is "wallet" on every machine.
func walletKeyPrefix(dir string) string {
	base := filepath.Dir(ResolveWalletDir(""))
	if rel, err := filepath.Rel(base, dir); err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, "../") {
		return filepath.ToSlash(rel)
	}
	slash := filepath.ToSlash(dir)
	if volume := filepath.VolumeName(dir); volume != "" {
		slash = strings.TrimPrefix(slash, filepath.ToSlash(volume))
	}
	return strings.TrimPrefix(slash, "/")
}

// Backend returns the storage layer this store writes through.
func (s *WalletStore) Backend() storage.Store {
	return s.backend
}

// Location describes where the wallet lives, for messages: the directory on
// the file backend, the backend and the prefix otherwise.
func (s *WalletStore) Location() string {
	return s.backend.Locate(s.prefix)
}

// Templates returns where this wallet's user templates live.
func (s *WalletStore) Templates() credtemplate.Location {
	return credtemplate.Location{Store: s.backend, Prefix: s.key("templates")}
}

// Exists reports whether the wallet has been saved at least once.
func (s *WalletStore) Exists() bool {
	if s.entityMode() {
		return s.hasEntities()
	}
	_, ok := s.WalletStamp()
	return ok
}

func (s *WalletStore) runtime() *WalletRuntime {
	runtime, _ := walletRuntimeRegistry.LoadOrStore(s.Dir, newWalletRuntime())
	return runtime.(*WalletRuntime)
}

// key returns the store key of a blob inside the wallet.
func (s *WalletStore) key(parts ...string) string {
	return path.Join(append([]string{s.prefix}, parts...)...)
}

func (s *WalletStore) walletKey() string { return s.key("wallet.json") }

// WalletStamp returns wallet.json's change stamp, or ok=false when the wallet
// has not been saved. The entity backends compare revisions per section
// instead (see ChangedSections).
func (s *WalletStore) WalletStamp() (storage.Stamp, bool) {
	return s.backend.Stat(s.walletKey())
}

// assetKey returns the key of a display image referenced from wallet.json,
// kept beside it so a credential's card art does not bloat the document the
// wallet reparses on every request.
func (s *WalletStore) assetKey(name string) string {
	return s.key("assets", name)
}

// storeDisplayAsset writes a data-URI display image as a content-addressed
// asset and returns a reference of the form "asset:<sha256>.<ext>". A value
// that is not a data URI (an already-stored reference, or an external URL) is
// returned unchanged with converted=false, so it can run on every save.
// Content addressing dedupes the baseline art a demo re-issues and makes an
// asset immutable, so a reference stays valid across a shared, reloaded store.
func (s *WalletStore) storeDisplayAsset(uri string) (ref string, converted bool) {
	contentType, data, ok := dataURIImage(uri)
	if !ok {
		return uri, false
	}
	sum := sha256.Sum256(data)
	name := hex.EncodeToString(sum[:]) + "." + assetExtension(contentType)
	key := s.assetKey(name)
	if _, exists := s.backend.Stat(key); exists {
		return "asset:" + name, true
	}
	if _, err := s.backend.Write(key, data, 0o600); err != nil {
		return uri, false
	}
	return "asset:" + name, true
}

// ReadDisplayAsset returns the bytes and content type of a stored display asset,
// or ok=false when the reference is not an asset reference or the asset is
// missing. The image-serving endpoint uses it.
func (s *WalletStore) ReadDisplayAsset(ref string) (contentType string, data []byte, ok bool) {
	name, found := strings.CutPrefix(ref, "asset:")
	// The name is a hash and an extension the store wrote, but the read is
	// guarded anyway so a reference can never reach outside the assets.
	if !found || name == "" || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return "", nil, false
	}
	data, err := s.backend.Read(s.assetKey(name))
	if err != nil {
		return "", nil, false
	}
	return assetContentType(name), data, true
}

// PruneUnreferencedAssets deletes display assets that no credential in
// wallet.json references. It reads the current wallet.json under saveMu, so it
// never races a save that is adding a reference (or an asset), and content
// addressing means a re-issued image rewrites the same asset. A leftover asset
// is harmless, so errors are ignored. The demo reset calls it, since clearing
// the baseline orphans the assets of whatever was issued since the last reset.
func (s *WalletStore) PruneUnreferencedAssets() {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	stored, err := s.storedCredentials()
	if err != nil {
		return
	}
	referenced := make(map[string]bool)
	for _, c := range stored {
		if c.Display == nil {
			continue
		}
		for _, uri := range []string{c.Display.LogoURI, c.Display.BackgroundURI} {
			if name, ok := strings.CutPrefix(uri, "asset:"); ok {
				referenced[name] = true
			}
		}
	}

	names, err := s.backend.List(s.key("assets"))
	if err != nil {
		return
	}
	for _, name := range names {
		if referenced[name] {
			continue
		}
		_ = s.backend.Delete(s.assetKey(name))
	}
}

func (s *WalletStore) storedCredentials() ([]StoredCredential, error) {
	if s.entityMode() {
		return s.storedCredentialsFromEntities()
	}
	var wj walletJSON
	data, err := s.backend.Read(s.walletKey())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return wj.Credentials, json.Unmarshal(data, &wj)
}

// assetExtension maps an image content type to a file extension.
func assetExtension(contentType string) string {
	switch contentType {
	case "image/png":
		return "png"
	case "image/jpeg":
		return "jpg"
	case "image/svg+xml":
		return "svg"
	case "image/webp":
		return "webp"
	case "image/gif":
		return "gif"
	default:
		return "bin"
	}
}

// assetContentType maps a stored asset name back to its content type.
func assetContentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".png"):
		return "image/png"
	case strings.HasSuffix(name, ".jpg"):
		return "image/jpeg"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(name, ".webp"):
		return "image/webp"
	case strings.HasSuffix(name, ".gif"):
		return "image/gif"
	default:
		return "application/octet-stream"
	}
}

// The shared CA sits one level above the wallet, so every wallet under the
// same state directory shares one CA.
func (s *WalletStore) sharedCAKeyPEM() string { return path.Join(s.sharedPrefix, "wallet-ca-key.pem") }

func (s *WalletStore) sharedCACertPEM() string {
	return path.Join(s.sharedPrefix, "wallet-ca-cert.pem")
}

func (s *WalletStore) tlsCertPEM() string { return s.key("wallet-tls-cert.pem") }

func (s *WalletStore) tlsKeyPEM() string { return s.key("wallet-tls-key.pem") }

func (s *WalletStore) legacyTLSCertPEM() string { return s.key("issuer-tls-cert.pem") }

func (s *WalletStore) legacyTLSKeyPEM() string { return s.key("issuer-tls-key.pem") }

func (s *WalletStore) logCleanMarkerKey() string { return s.key("wallet-log-cleaned-at") }

// LoadOrCreate loads the wallet, or creates a new empty wallet if none exists.
// Keys are loaded or auto-generated as needed.
func (s *WalletStore) LoadOrCreate() (*Wallet, error) {
	holderKey, issuerKey, err := s.LoadOrCreateKeys()
	if err != nil {
		return nil, err
	}
	caKey, caCert, err := s.LoadOrCreateSharedCA()
	if err != nil {
		return nil, err
	}

	w := New(holderKey, issuerKey, false)
	w.runtime = s.runtime()
	w.Templates = s.Templates()
	if err := w.SetCertificateAuthority(caKey, caCert); err != nil {
		return nil, fmt.Errorf("configuring shared wallet CA: %w", err)
	}

	if s.entityMode() {
		if err := s.loadEntities(w); err != nil {
			return nil, err
		}
		rehydrate(w)
		return w, nil
	}

	data, err := s.backend.Read(s.walletKey())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return w, nil
		}
		return nil, fmt.Errorf("reading wallet.json: %w", err)
	}

	var wj walletJSON
	if err := json.Unmarshal(data, &wj); err != nil {
		return nil, fmt.Errorf("parsing wallet.json: %w", err)
	}

	w.Credentials = wj.Credentials
	w.DeferredIssuances = wj.DeferredIssuances
	if len(w.DeferredIssuances) == 0 {
		w.DeferredIssuances = wj.LegacyPendingIssuances
	}
	w.IssuedAttestations = dedupeIssuedAttestations(wj.IssuedAttestations)
	w.Log = s.filterLogEntries(wj.Log)
	w.StatusEntries = wj.StatusEntries
	w.StatusListCounter = wj.StatusListCounter
	w.BaseURL = wj.BaseURL
	w.IssuerURL = wj.IssuerURL
	rehydrate(w)
	return w, nil
}

// rehydrate restores the credential fields that are not stored from Raw.
func rehydrate(w *Wallet) {
	for i := range w.Credentials {
		if err := w.Credentials[i].Rehydrate(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: rehydrating credential %s: %v\n", w.Credentials[i].ID, err)
		}
	}
}

// Save persists the wallet state.
func (s *WalletStore) Save(w *Wallet) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	if s.entityMode() {
		return s.saveEntities(w)
	}
	creds := s.withStoredAssets(w.GetCredentials())
	w.mu.RLock()
	issuedAttestations := dedupeIssuedAttestations(w.IssuedAttestations)
	deferredIssuances := append([]DeferredIssuance(nil), w.DeferredIssuances...)
	logEntries := s.filterLogEntries(w.Log)
	statusEntries := w.StatusEntries
	statusListCounter := w.StatusListCounter
	baseURL := w.BaseURL
	issuerURL := w.IssuerURL
	w.mu.RUnlock()
	wj := walletJSON{
		Credentials:        creds,
		DeferredIssuances:  deferredIssuances,
		IssuedAttestations: issuedAttestations,
		Log:                logEntries,
		StatusEntries:      statusEntries,
		StatusListCounter:  statusListCounter,
		BaseURL:            baseURL,
		IssuerURL:          issuerURL,
	}

	data, err := json.MarshalIndent(wj, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling wallet.json: %w", err)
	}
	if s.saveDelay != nil {
		s.saveDelay()
	}
	if _, err := s.backend.Write(s.walletKey(), data, 0o600); err != nil {
		return fmt.Errorf("writing wallet.json: %w", err)
	}
	return nil
}

// withStoredAssets moves any embedded display image out of the credentials
// into the assets, leaving a reference in its place. It works on the copy
// it is given, so the in-memory wallet is untouched until a reload picks up
// the references.
func (s *WalletStore) withStoredAssets(creds []StoredCredential) []StoredCredential {
	for i := range creds {
		if creds[i].Display == nil {
			continue
		}
		logo, logoConverted := s.storeDisplayAsset(creds[i].Display.LogoURI)
		background, backgroundConverted := s.storeDisplayAsset(creds[i].Display.BackgroundURI)
		if logoConverted || backgroundConverted {
			d := *creds[i].Display
			d.LogoURI = logo
			d.BackgroundURI = background
			creds[i].Display = &d
		}
	}
	return creds
}

// ClearLog removes all persisted wallet activity log entries.
func (s *WalletStore) ClearLog() error {
	w, err := s.LoadOrCreate()
	if err != nil {
		return err
	}
	if err := s.writeLogCleanMarker(time.Now()); err != nil {
		return err
	}
	w.mu.Lock()
	w.Log = nil
	w.mu.Unlock()
	return s.Save(w)
}

func (s *WalletStore) filterLogEntries(entries []LogEntry) []LogEntry {
	cleanedAt := s.loadLogCleanMarker()
	if cleanedAt.IsZero() {
		return append([]LogEntry(nil), entries...)
	}
	filtered := make([]LogEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Time.After(cleanedAt) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

func (s *WalletStore) loadLogCleanMarker() time.Time {
	data, err := s.backend.Read(s.logCleanMarkerKey())
	if err != nil {
		return time.Time{}
	}
	cleanedAt, err := time.Parse(time.RFC3339Nano, string(data))
	if err != nil {
		return time.Time{}
	}
	return cleanedAt
}

func (s *WalletStore) writeLogCleanMarker(cleanedAt time.Time) error {
	_, err := s.backend.Write(s.logCleanMarkerKey(), []byte(cleanedAt.Format(time.RFC3339Nano)), 0o600)
	return err
}

// LoadOrCreateKeys loads the holder and issuer keys, generating them if they don't exist.
func (s *WalletStore) LoadOrCreateKeys() (*ecdsa.PrivateKey, *ecdsa.PrivateKey, error) {
	holderKey, err := s.loadOrGenerateKey(s.key("holder.pem"), "holder")
	if err != nil {
		return nil, nil, err
	}

	issuerKey, err := s.loadOrGenerateKey(s.key("issuer.pem"), "issuer")
	if err != nil {
		return nil, nil, err
	}

	return holderKey, issuerKey, nil
}

// LoadOrCreateSharedCA loads the shared wallet CA or creates it.
func (s *WalletStore) LoadOrCreateSharedCA() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	keyData, keyErr := s.backend.Read(s.sharedCAKeyPEM())
	certData, certErr := s.backend.Read(s.sharedCACertPEM())
	if keyErr == nil && certErr == nil {
		key, err := parsePEMKey(keyData, "wallet CA")
		if err == nil {
			cert, err := parsePEMCertificate(certData, "wallet CA")
			if err == nil && cert.IsCA && cert.CheckSignatureFrom(cert) == nil {
				return key, cert, nil
			}
		}
	}
	if keyErr != nil && !errors.Is(keyErr, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("reading wallet CA key: %w", keyErr)
	}
	if certErr != nil && !errors.Is(certErr, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("reading wallet CA certificate: %w", certErr)
	}

	caKey, err := s.seed.Key("ca")
	if err != nil {
		return nil, nil, fmt.Errorf("generating wallet CA key: %w", err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("generating wallet CA certificate: %w", err)
	}
	if err := s.saveKeyPEM(s.sharedCAKeyPEM(), caKey); err != nil {
		return nil, nil, fmt.Errorf("saving wallet CA key: %w", err)
	}
	if err := s.saveCertPEM(s.sharedCACertPEM(), caCert); err != nil {
		return nil, nil, fmt.Errorf("saving wallet CA certificate: %w", err)
	}
	return caKey, caCert, nil
}

// LoadOrCreateSharedCACertificatePEM returns the shared wallet CA certificate PEM.
func (s *WalletStore) LoadOrCreateSharedCACertificatePEM() ([]byte, error) {
	if _, _, err := s.LoadOrCreateSharedCA(); err != nil {
		return nil, err
	}
	certPEM, err := s.backend.Read(s.sharedCACertPEM())
	if err != nil {
		return nil, fmt.Errorf("reading wallet CA certificate: %w", err)
	}
	return certPEM, nil
}

// LoadOrCreateIssuerTLSCertificate loads the issuer HTTPS certificate, or
// generates and persists a new one if none exists or it no longer matches the
// requested host.
func (s *WalletStore) LoadOrCreateIssuerTLSCertificate(serverName string) (tls.Certificate, error) {
	certPEM, keyPEM, err := s.loadIssuerTLSCertificatePEM(serverName)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("loading issuer TLS certificate: %w", err)
	}
	return cert, nil
}

// LoadOrCreateIssuerTLSCertificateForURL resolves the host from the issuer URL and
// loads or creates a matching issuer HTTPS certificate.
func (s *WalletStore) LoadOrCreateIssuerTLSCertificateForURL(issuerURL string) (tls.Certificate, error) {
	return s.LoadOrCreateIssuerTLSCertificate(parseIssuerHost(issuerURL))
}

// LoadOrCreateIssuerTLSCertificatePEM returns the persisted issuer HTTPS certificate PEM,
// generating it first if needed.
func (s *WalletStore) LoadOrCreateIssuerTLSCertificatePEM(serverName string) ([]byte, error) {
	certPEM, _, err := s.loadIssuerTLSCertificatePEM(serverName)
	if err != nil {
		return nil, err
	}
	return certPEM, nil
}

// LoadOrCreateIssuerTLSLeafCertificatePEM returns only the leaf PEM certificate
// for the wallet HTTPS server.
func (s *WalletStore) LoadOrCreateIssuerTLSLeafCertificatePEM(serverName string) ([]byte, error) {
	certPEM, err := s.LoadOrCreateIssuerTLSCertificatePEM(serverName)
	if err != nil {
		return nil, err
	}
	return firstCertificatePEM(certPEM)
}

// LoadOrCreateIssuerTLSCertificatePEMForURL resolves the host from the issuer URL and
// returns the matching persisted issuer HTTPS certificate PEM.
func (s *WalletStore) LoadOrCreateIssuerTLSCertificatePEMForURL(issuerURL string) ([]byte, error) {
	return s.LoadOrCreateIssuerTLSCertificatePEM(parseIssuerHost(issuerURL))
}

// LoadOrCreateIssuerTLSLeafCertificatePEMForURL resolves the host from the issuer URL and
// returns only the leaf PEM certificate for the wallet HTTPS server.
func (s *WalletStore) LoadOrCreateIssuerTLSLeafCertificatePEMForURL(issuerURL string) ([]byte, error) {
	return s.LoadOrCreateIssuerTLSLeafCertificatePEM(parseIssuerHost(issuerURL))
}

func (s *WalletStore) loadIssuerTLSCertificatePEM(serverName string) ([]byte, []byte, error) {
	if serverName == "" {
		serverName = "localhost"
	}
	caKey, caCert, err := s.LoadOrCreateSharedCA()
	if err != nil {
		return nil, nil, err
	}

	certPEM, certErr := s.backend.Read(s.tlsCertPEM())
	keyPEM, keyErr := s.backend.Read(s.tlsKeyPEM())
	if errors.Is(certErr, fs.ErrNotExist) && errors.Is(keyErr, fs.ErrNotExist) {
		certPEM, certErr = s.backend.Read(s.legacyTLSCertPEM())
		keyPEM, keyErr = s.backend.Read(s.legacyTLSKeyPEM())
	}
	if certErr == nil && keyErr == nil {
		if cert, err := tls.X509KeyPair(certPEM, keyPEM); err == nil && issuerTLSCertificateMatches(cert, serverName, caCert) {
			if err := s.saveIssuerTLSPEM(certPEM, keyPEM); err != nil {
				return nil, nil, err
			}
			return certPEM, keyPEM, nil
		}
	}

	if certErr != nil && !errors.Is(certErr, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("reading wallet TLS certificate: %w", certErr)
	}
	if keyErr != nil && !errors.Is(keyErr, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("reading wallet TLS key: %w", keyErr)
	}

	tlsKey, err := s.seed.Key("tls")
	if err != nil {
		return nil, nil, fmt.Errorf("generating TLS key: %w", err)
	}
	certPEM, keyPEM, err = issuerTLSCertificatePEM(serverName, tlsKey, caKey, caCert)
	if err != nil {
		return nil, nil, err
	}
	if err := s.saveIssuerTLSPEM(certPEM, keyPEM); err != nil {
		return nil, nil, err
	}

	return certPEM, keyPEM, nil
}

func (s *WalletStore) saveIssuerTLSPEM(certPEM, keyPEM []byte) error {
	if _, err := s.backend.Write(s.tlsKeyPEM(), keyPEM, 0o600); err != nil {
		return fmt.Errorf("saving wallet TLS key: %w", err)
	}
	if _, err := s.backend.Write(s.tlsCertPEM(), certPEM, 0o644); err != nil {
		return fmt.Errorf("saving wallet TLS certificate: %w", err)
	}
	return nil
}

func issuerTLSCertificateMatches(cert tls.Certificate, serverName string, caCert *x509.Certificate) bool {
	if len(cert.Certificate) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return false
	}
	if leaf.VerifyHostname(serverName) != nil {
		return false
	}
	if caCert == nil {
		return true
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	opts := x509.VerifyOptions{
		Roots:   roots,
		DNSName: serverName,
	}
	if _, err := leaf.Verify(opts); err != nil {
		return false
	}
	return true
}

// loadOrGenerateKey loads the PEM key stored at the given key, or generates and saves a new one.
func (s *WalletStore) loadOrGenerateKey(at, label string) (*ecdsa.PrivateKey, error) {
	data, err := s.backend.Read(at)
	if err == nil {
		return parsePEMKey(data, label)
	}

	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("reading %s key: %w", label, err)
	}

	key, err := s.seed.Key(label)
	if err != nil {
		return nil, fmt.Errorf("generating %s key: %w", label, err)
	}

	if err := s.saveKeyPEM(at, key); err != nil {
		return nil, fmt.Errorf("saving %s key: %w", label, err)
	}

	fmt.Fprintf(os.Stderr, "Generated %s key: %s\n", label, s.backend.Locate(at))
	return key, nil
}

// parsePEMKey parses an EC private key from PEM data.
func parsePEMKey(data []byte, label string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s key: no PEM block found", label)
	}

	// Try PKCS#8 first
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if ecKey, ok := key.(*ecdsa.PrivateKey); ok {
			return ecKey, nil
		}
		return nil, fmt.Errorf("%s key: not an EC key", label)
	}

	// Try EC key
	ecKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s key: unable to parse PEM: %w", label, err)
	}
	return ecKey, nil
}

func parsePEMCertificate(data []byte, label string) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("%s certificate: no PEM block found", label)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s certificate: unable to parse PEM: %w", label, err)
	}
	return cert, nil
}

// saveKeyPEM stores an EC private key as PEM.
func (s *WalletStore) saveKeyPEM(at string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling key: %w", err)
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}

	_, err = s.backend.Write(at, pem.EncodeToMemory(block), 0o600)
	return err
}

func (s *WalletStore) saveCertPEM(at string, cert *x509.Certificate) error {
	_, err := s.backend.Write(at, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644)
	return err
}

func firstCertificatePEM(data []byte) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no PEM CERTIFICATE block found")
	}
	return pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes}), nil
}
