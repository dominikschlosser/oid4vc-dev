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

// Package storage is the persistence layer. Everything the tool keeps between
// runs (the wallet document, keys, certificates, display assets, user
// templates) is a blob under a slash-separated key, and every backend stores
// the same keys. The file backend lays them out as the directory tree under
// the state directory, so an existing wallet directory is a file store.
package storage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync"
)

// EnvVar is the environment variable that selects the backend when no flag
// does.
const EnvVar = "EUDI_DEV_STORAGE"

// Backend names.
const (
	KindFile     = "file"
	KindMemory   = "memory"
	KindPostgres = "postgres"
)

// Store holds blobs under slash-separated keys relative to its root.
type Store interface {
	// Read returns the blob at key. A missing key returns an error that
	// satisfies errors.Is(err, fs.ErrNotExist).
	Read(key string) ([]byte, error)
	// Write replaces the blob at key atomically: a concurrent reader sees the
	// old or the new content, never a mix. perm is the file mode the file
	// backend applies. The others ignore it.
	Write(key string, data []byte, perm fs.FileMode) error
	// Delete removes the blob at key. A missing key is not an error.
	Delete(key string) error
	// Stat returns the blob's change stamp, or ok=false when it is missing.
	Stat(key string) (stamp Stamp, ok bool)
	// List returns the names of the blobs directly under prefix, sorted. A
	// missing prefix lists nothing.
	List(prefix string) ([]string, error)
	// Locate returns a readable location of key for messages (the file path
	// on the file backend). The root when key is "".
	Locate(key string) string
	// Kind is the backend name.
	Kind() string
}

// Stamp identifies a blob's current content. Two stamps of the same key are
// equal only while the blob is unchanged. A reader that cached a parse
// compares stamps to skip reparsing.
type Stamp struct {
	Version string
	Size    int64
}

// Options describe the state directory to Open.
type Options struct {
	// Root is the directory of the file backend, and what "auto" inspects.
	Root string
	// RootRequested reports that the caller named the state location (a flag
	// or an environment variable), which makes "auto" pick files.
	RootRequested bool
}

var (
	autoOnce sync.Once
	autoKind string
)

// Open returns the store for a spec. A spec is "file" (or empty), "memory",
// "auto", or a postgres:// connection URL. "auto" picks files when a state
// directory was named or holds state (a mounted volume, empty or not) and
// memory otherwise. It is decided once per process, so every opener lands on
// the same store.
func Open(spec string, opts Options) (Store, error) {
	spec = strings.TrimSpace(spec)
	switch {
	case spec == "" || spec == KindFile:
		return NewFile(opts.Root), nil
	case spec == KindMemory:
		return processMemory, nil
	case spec == "auto":
		autoOnce.Do(func() {
			autoKind = KindMemory
			if opts.RootRequested || rootHoldsState(opts.Root) {
				autoKind = KindFile
			}
		})
		return Open(autoKind, opts)
	case isPostgresSpec(spec):
		return openPostgres(spec)
	default:
		return nil, fmt.Errorf("unknown storage %q: use file, memory, auto or a postgres:// URL", spec)
	}
}

// rootHoldsState reports whether the state directory exists and holds more
// than the process bookkeeping a memory-backed server writes there (the
// instance registry and the remote target). Without that exception a
// memory-backed container would switch to files on its next start.
func rootHoldsState(root string) bool {
	entries, err := os.ReadDir(root)
	if err != nil {
		return false
	}
	if len(entries) == 0 {
		return true
	}
	for _, entry := range entries {
		if entry.Name() != "instances" && entry.Name() != "remote.json" {
			return true
		}
	}
	return false
}

// FromEnv opens the store set in EUDI_DEV_STORAGE, files when it is unset.
// A value Open refuses yields a store whose every operation returns that
// error, so the mistake surfaces on first use.
func FromEnv(opts Options) Store {
	store, err := Open(os.Getenv(EnvVar), opts)
	if err != nil {
		return failingStore{err: err}
	}
	return store
}

// failingStore stands in for a store that could not be opened.
type failingStore struct {
	err error
}

func (f failingStore) Read(string) ([]byte, error)             { return nil, f.err }
func (f failingStore) Write(string, []byte, fs.FileMode) error { return f.err }
func (f failingStore) Delete(string) error                     { return f.err }
func (f failingStore) Stat(string) (Stamp, bool)               { return Stamp{}, false }
func (f failingStore) List(string) ([]string, error)           { return nil, f.err }
func (f failingStore) Locate(string) string                    { return f.err.Error() }
func (f failingStore) Kind() string                            { return "" }

func isPostgresSpec(spec string) bool {
	return strings.HasPrefix(spec, "postgres://") || strings.HasPrefix(spec, "postgresql://")
}

// cleanKey validates a key: relative, slash-separated, no dot segments.
func cleanKey(key string) (string, error) {
	if key == "" {
		return "", errors.New("storage: empty key")
	}
	if strings.HasPrefix(key, "/") || path.Clean(key) != key || key == ".." || strings.HasPrefix(key, "../") {
		return "", fmt.Errorf("storage: invalid key %q", key)
	}
	return key, nil
}

// cleanPrefix validates a List prefix: a key, or "" for the root.
func cleanPrefix(prefix string) (string, error) {
	if prefix == "" {
		return "", nil
	}
	return cleanKey(prefix)
}

// notExist builds the error every backend returns for a missing key, so
// callers can test it with errors.Is and os.IsNotExist alike.
func notExist(op, key string) error {
	return &fs.PathError{Op: op, Path: key, Err: fs.ErrNotExist}
}
