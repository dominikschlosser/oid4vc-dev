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
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// memoryStore keeps every key in a map. State lives as long as the process.
type memoryStore struct {
	mu    sync.RWMutex
	blobs map[string]memoryBlob
	seq   uint64
}

type memoryBlob struct {
	data    []byte
	version uint64
}

// processMemory is the one memory store of the process, shared by every
// opener.
var processMemory = NewMemory()

// NewMemory returns an empty memory store of its own, for tests that need
// isolation from the process-wide one.
func NewMemory() Store {
	return &memoryStore{blobs: make(map[string]memoryBlob)}
}

func (s *memoryStore) Read(key string) ([]byte, error) {
	key, err := cleanKey(key)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	blob, ok := s.blobs[key]
	if !ok {
		return nil, notExist("read", key)
	}
	return append([]byte(nil), blob.data...), nil
}

func (s *memoryStore) Write(key string, data []byte, _ fs.FileMode) error {
	key, err := cleanKey(key)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	s.blobs[key] = memoryBlob{data: append([]byte(nil), data...), version: s.seq}
	return nil
}

func (s *memoryStore) Delete(key string) error {
	key, err := cleanKey(key)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.blobs, key)
	return nil
}

func (s *memoryStore) Stat(key string) (Stamp, bool) {
	key, err := cleanKey(key)
	if err != nil {
		return Stamp{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	blob, ok := s.blobs[key]
	if !ok {
		return Stamp{}, false
	}
	return Stamp{Version: strconv.FormatUint(blob.version, 10), Size: int64(len(blob.data))}, true
}

func (s *memoryStore) List(prefix string) ([]string, error) {
	prefix, err := cleanPrefix(prefix)
	if err != nil {
		return nil, err
	}
	if prefix != "" {
		prefix += "/"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var names []string
	for key := range s.blobs {
		name, ok := strings.CutPrefix(key, prefix)
		if !ok || strings.Contains(name, "/") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (s *memoryStore) ReadAll(prefix string) (map[string][]byte, error) {
	prefix, err := cleanPrefix(prefix)
	if err != nil {
		return nil, err
	}
	if prefix != "" {
		prefix += "/"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	blobs := make(map[string][]byte)
	for key, blob := range s.blobs {
		if strings.HasPrefix(key, prefix) {
			blobs[key] = append([]byte(nil), blob.data...)
		}
	}
	return blobs, nil
}

func (s *memoryStore) WriteIf(key string, data []byte, _ fs.FileMode, expected string) error {
	key, err := cleanKey(key)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	blob, ok := s.blobs[key]
	if (ok && strconv.FormatUint(blob.version, 10) != expected) || (!ok && expected != "") {
		return ErrConflict
	}
	s.seq++
	s.blobs[key] = memoryBlob{data: append([]byte(nil), data...), version: s.seq}
	return nil
}

func (s *memoryStore) Locate(key string) string {
	if key == "" {
		return KindMemory
	}
	return KindMemory + ":" + key
}

func (s *memoryStore) Kind() string { return KindMemory }
