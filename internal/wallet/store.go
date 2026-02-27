package wallet

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
)

// WalletStore handles file-based persistence for the wallet.
type WalletStore struct {
	Dir string
}

// walletJSON is the on-disk format of wallet.json.
type walletJSON struct {
	Credentials       []StoredCredential   `json:"credentials"`
	StatusEntries     map[string]StatusEntry `json:"status_entries,omitempty"`
	StatusListCounter int                    `json:"status_list_counter,omitempty"`
	Port              int                    `json:"port,omitempty"`
}

// DefaultWalletDir returns the default wallet storage directory.
func DefaultWalletDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".oid4vc-dev/wallet"
	}
	return filepath.Join(home, ".oid4vc-dev", "wallet")
}

// NewWalletStore creates a new WalletStore for the given directory.
func NewWalletStore(dir string) *WalletStore {
	if dir == "" {
		dir = DefaultWalletDir()
	}
	return &WalletStore{Dir: dir}
}

// ensureDir creates the wallet directory if it doesn't exist.
func (s *WalletStore) ensureDir() error {
	return os.MkdirAll(s.Dir, 0700)
}

// walletPath returns the path to wallet.json.
func (s *WalletStore) walletPath() string {
	return filepath.Join(s.Dir, "wallet.json")
}

// holderKeyPath returns the path to the holder private key.
func (s *WalletStore) holderKeyPath() string {
	return filepath.Join(s.Dir, "holder.pem")
}

// issuerKeyPath returns the path to the issuer private key.
func (s *WalletStore) issuerKeyPath() string {
	return filepath.Join(s.Dir, "issuer.pem")
}

// LoadOrCreate loads the wallet from disk, or creates a new empty wallet if none exists.
// Keys are loaded or auto-generated as needed.
func (s *WalletStore) LoadOrCreate() (*Wallet, error) {
	if err := s.ensureDir(); err != nil {
		return nil, fmt.Errorf("creating wallet directory: %w", err)
	}

	holderKey, issuerKey, err := s.LoadOrCreateKeys()
	if err != nil {
		return nil, err
	}

	w := New(holderKey, issuerKey, false)

	data, err := os.ReadFile(s.walletPath())
	if err != nil {
		if os.IsNotExist(err) {
			return w, nil
		}
		return nil, fmt.Errorf("reading wallet.json: %w", err)
	}

	var wj walletJSON
	if err := json.Unmarshal(data, &wj); err != nil {
		return nil, fmt.Errorf("parsing wallet.json: %w", err)
	}

	w.Credentials = wj.Credentials
	w.StatusEntries = wj.StatusEntries
	w.StatusListCounter = wj.StatusListCounter

	// Re-hydrate non-serializable fields from Raw
	for i := range w.Credentials {
		if err := w.Credentials[i].Rehydrate(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: rehydrating credential %s: %v\n", w.Credentials[i].ID, err)
		}
	}

	return w, nil
}

// Save persists the wallet state to disk.
func (s *WalletStore) Save(w *Wallet) error {
	if err := s.ensureDir(); err != nil {
		return fmt.Errorf("creating wallet directory: %w", err)
	}

	creds := w.GetCredentials()
	w.mu.RLock()
	statusEntries := w.StatusEntries
	statusListCounter := w.StatusListCounter
	w.mu.RUnlock()
	wj := walletJSON{
		Credentials:       creds,
		StatusEntries:     statusEntries,
		StatusListCounter: statusListCounter,
	}

	data, err := json.MarshalIndent(wj, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling wallet.json: %w", err)
	}

	return os.WriteFile(s.walletPath(), data, 0600)
}

// LoadOrCreateKeys loads holder and issuer keys from PEM files, generating them if they don't exist.
func (s *WalletStore) LoadOrCreateKeys() (*ecdsa.PrivateKey, *ecdsa.PrivateKey, error) {
	if err := s.ensureDir(); err != nil {
		return nil, nil, fmt.Errorf("creating wallet directory: %w", err)
	}

	holderKey, err := s.loadOrGenerateKey(s.holderKeyPath(), "holder")
	if err != nil {
		return nil, nil, err
	}

	issuerKey, err := s.loadOrGenerateKey(s.issuerKeyPath(), "issuer")
	if err != nil {
		return nil, nil, err
	}

	return holderKey, issuerKey, nil
}

// loadOrGenerateKey loads a PEM key from path, or generates and saves a new one.
func (s *WalletStore) loadOrGenerateKey(path, label string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return parsePEMKey(data, label)
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading %s key: %w", label, err)
	}

	// Generate new key
	key, err := mock.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating %s key: %w", label, err)
	}

	if err := saveKeyPEM(path, key); err != nil {
		return nil, fmt.Errorf("saving %s key: %w", label, err)
	}

	fmt.Fprintf(os.Stderr, "Generated %s key: %s\n", label, path)
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

// saveKeyPEM saves an EC private key as a PEM file.
func saveKeyPEM(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling key: %w", err)
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}

	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}
