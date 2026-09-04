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

package storage

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// tempPrefix marks an in-flight write. No key the wallet writes starts with
// it, so List can hide such files.
const tempPrefix = ".tmp-"

// fileStore keeps every key as a file under root.
type fileStore struct {
	root string
}

// NewFile returns a store rooted at dir. The directory is created on the
// first write.
func NewFile(dir string) Store {
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return &fileStore{root: dir}
}

func (s *fileStore) path(key string) string {
	return filepath.Join(s.root, filepath.FromSlash(key))
}

func (s *fileStore) Read(key string) ([]byte, error) {
	key, err := cleanKey(key)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(s.path(key))
}

// Write creates the file's directory when it is missing: 0755 for a
// world-readable blob, 0700 otherwise. The file is created with perm under
// the process umask, written beside the target and renamed into place, so a
// concurrent reader or a crash never sees a partial file.
func (s *fileStore) Write(key string, data []byte, perm fs.FileMode) (Stamp, error) {
	key, err := cleanKey(key)
	if err != nil {
		return Stamp{}, err
	}
	target := s.path(key)
	dir := filepath.Dir(target)
	dirPerm := fs.FileMode(0o700)
	if perm&0o004 != 0 {
		dirPerm = 0o755
	}
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return Stamp{}, fmt.Errorf("creating %s: %w", dir, err)
	}

	tmp, err := createTemp(dir, filepath.Base(target), perm)
	if err != nil {
		return Stamp{}, fmt.Errorf("creating temporary file for %s: %w", target, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return Stamp{}, fmt.Errorf("writing %s: %w", target, err)
	}
	if err := tmp.Close(); err != nil {
		return Stamp{}, fmt.Errorf("writing %s: %w", target, err)
	}
	if err := os.Rename(tmp.Name(), target); err != nil {
		return Stamp{}, err
	}
	stamp, _ := s.Stat(key)
	return stamp, nil
}

// createTemp opens a new file named tempPrefix + base + a random suffix in
// dir, created exclusively with perm.
func createTemp(dir, base string, perm fs.FileMode) (*os.File, error) {
	for {
		var suffix [4]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, err
		}
		name := filepath.Join(dir, tempPrefix+base+"-"+hex.EncodeToString(suffix[:]))
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return f, err
	}
}

func (s *fileStore) Delete(key string) error {
	key, err := cleanKey(key)
	if err != nil {
		return err
	}
	if err := os.Remove(s.path(key)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (s *fileStore) Stat(key string) (Stamp, bool) {
	key, err := cleanKey(key)
	if err != nil {
		return Stamp{}, false
	}
	info, err := os.Stat(s.path(key))
	if err != nil || info.IsDir() {
		return Stamp{}, false
	}
	return Stamp{Version: strconv.FormatInt(info.ModTime().UnixNano(), 10), Size: info.Size()}, true
}

func (s *fileStore) List(prefix string) ([]string, error) {
	prefix, err := cleanPrefix(prefix)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.path(prefix))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), tempPrefix) {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func (s *fileStore) ReadAll(prefix string) (map[string]Blob, error) {
	prefix, err := cleanPrefix(prefix)
	if err != nil {
		return nil, err
	}
	blobs := make(map[string]Blob)
	root, err := os.OpenRoot(s.root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return blobs, nil
		}
		return nil, err
	}
	defer func() { _ = root.Close() }()
	rootFS := root.FS()
	if prefix == "" {
		prefix = "."
	}
	err = fs.WalkDir(rootFS, prefix, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || strings.HasPrefix(d.Name(), tempPrefix) {
			return nil
		}
		data, err := fs.ReadFile(rootFS, p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		blobs[p] = Blob{Data: data, Stamp: Stamp{Version: strconv.FormatInt(info.ModTime().UnixNano(), 10), Size: info.Size()}}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return blobs, nil
}

func (s *fileStore) Stamps(prefix string) (map[string]Stamp, error) {
	prefix, err := cleanPrefix(prefix)
	if err != nil {
		return nil, err
	}
	stamps := make(map[string]Stamp)
	root, err := os.OpenRoot(s.root)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return stamps, nil
		}
		return nil, err
	}
	defer func() { _ = root.Close() }()
	if prefix == "" {
		prefix = "."
	}
	err = fs.WalkDir(root.FS(), prefix, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if d.IsDir() || strings.HasPrefix(d.Name(), tempPrefix) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		stamps[p] = Stamp{Version: strconv.FormatInt(info.ModTime().UnixNano(), 10), Size: info.Size()}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return stamps, nil
}

// WriteIf checks the stamp and writes without a lock, so two writers can
// both pass the check. The wallet keeps one document on this backend and
// shares no counter through it.
func (s *fileStore) WriteIf(key string, data []byte, perm fs.FileMode, expected string) (Stamp, error) {
	current, ok := s.Stat(key)
	if (ok && current.Version != expected) || (!ok && expected != "") {
		return Stamp{}, ErrConflict
	}
	return s.Write(key, data, perm)
}

func (s *fileStore) Locate(key string) string {
	if key == "" {
		return s.root
	}
	return s.path(key)
}

func (s *fileStore) Kind() string { return KindFile }
