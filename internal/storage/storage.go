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

// Package storage stores wallet state, keys, certificates, assets and templates as
// blobs under slash-separated keys. File storage preserves the existing directory
// layout.
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

const EnvVar = "EUDI_DEV_STORAGE"

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
	// backend applies. The others ignore it. It returns the blob's new stamp.
	Write(key string, data []byte, perm fs.FileMode) (Stamp, error)
	// Delete removes the blob at key. A missing key is not an error.
	Delete(key string) error
	// Stat returns the blob's change stamp, or ok=false when it is missing.
	Stat(key string) (stamp Stamp, ok bool)
	// List returns the names of the blobs directly under prefix, sorted. A
	// missing prefix lists nothing.
	List(prefix string) ([]string, error)
	// ReadAll returns every blob under prefix, at any depth, by key.
	ReadAll(prefix string) (map[string]Blob, error)
	// Stamps returns the stamp of every blob under prefix, at any depth, by
	// key.
	Stamps(prefix string) (map[string]Stamp, error)
	// WriteIf replaces the blob at key only while its stamp version is still
	// expected ("" for a blob that must not exist yet) and returns
	// ErrConflict otherwise. It returns the blob's new stamp.
	WriteIf(key string, data []byte, perm fs.FileMode, expected string) (Stamp, error)
	// Locate returns a readable location of key for messages (the file path
	// on the file backend). The root when key is "".
	Locate(key string) string
	Kind() string
}

// ErrConflict reports that a WriteIf found the blob changed by someone else.
var ErrConflict = errors.New("storage: blob changed concurrently")

type Blob struct {
	Data  []byte
	Stamp Stamp
}

// Stamp identifies a blob's current content. Two stamps of the same key are
// equal only while the blob is unchanged. A reader that cached a parse
// compares stamps to skip reparsing.
type Stamp struct {
	Version string
	Size    int64
}

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

// Open resolves auto once per process so all callers use the same backend. A named or
// existing state directory selects files. Otherwise use memory.
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

// Ignore the instance registry and remote target when detecting wallet state. Those
// local files also exist for memory storage and must not change the next backend
// selection.
func rootHoldsState(root string) bool {
	entries, err := os.ReadDir(root)
	if err != nil {
		return !errors.Is(err, fs.ErrNotExist)
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

// FromEnv returns a store that reports invalid backend configuration on first use.
func FromEnv(opts Options) Store {
	store, err := Open(os.Getenv(EnvVar), opts)
	if err != nil {
		return failingStore{err: err}
	}
	return store
}

type failingStore struct {
	err error
}

func (f failingStore) Read(string) ([]byte, error) { return nil, f.err }
func (f failingStore) Write(string, []byte, fs.FileMode) (Stamp, error) {
	return Stamp{}, f.err
}
func (f failingStore) Delete(string) error                     { return f.err }
func (f failingStore) Stat(string) (Stamp, bool)               { return Stamp{}, false }
func (f failingStore) List(string) ([]string, error)           { return nil, f.err }
func (f failingStore) ReadAll(string) (map[string]Blob, error) { return nil, f.err }
func (f failingStore) Stamps(string) (map[string]Stamp, error) { return nil, f.err }
func (f failingStore) WriteIf(string, []byte, fs.FileMode, string) (Stamp, error) {
	return Stamp{}, f.err
}
func (f failingStore) Locate(string) string { return f.err.Error() }
func (f failingStore) Kind() string         { return "" }

func isPostgresSpec(spec string) bool {
	return strings.HasPrefix(spec, "postgres://") || strings.HasPrefix(spec, "postgresql://")
}

func cleanKey(key string) (string, error) {
	if key == "" {
		return "", errors.New("storage: empty key")
	}
	if strings.HasPrefix(key, "/") || path.Clean(key) != key || key == ".." || strings.HasPrefix(key, "../") {
		return "", fmt.Errorf("storage: invalid key %q", key)
	}
	return key, nil
}

func cleanPrefix(prefix string) (string, error) {
	if prefix == "" {
		return "", nil
	}
	return cleanKey(prefix)
}

// Use errors.Is(err, fs.ErrNotExist) consistently across backends.
func notExist(op, key string) error {
	return &fs.PathError{Op: op, Path: key, Err: fs.ErrNotExist}
}
