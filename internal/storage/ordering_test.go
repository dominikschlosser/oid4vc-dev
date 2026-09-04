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
	"strconv"
	"sync"
	"testing"
)

// A reader that sees a revision written after a row also sees that row. The
// wallet's per-request reload relies on it: it checks the revision first and
// reads the state after.
func TestStore_ARowWrittenBeforeARevisionIsVisibleWithIt(t *testing.T) {
	for kind, store := range backends(t) {
		t.Run(kind, func(t *testing.T) {
			root := scope(t)
			revision := root + "/revision"
			defer store.Delete(revision)
			defer func() {
				rows, _ := store.ReadAll(root + "/rows")
				for key := range rows {
					_ = store.Delete(key)
				}
			}()
			var wg sync.WaitGroup
			done := make(chan struct{})
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer close(done)
				for n := 0; n < 300; n++ {
					key := root + "/rows/" + strconv.Itoa(n)
					if _, err := store.Write(key, []byte("x"), 0o600); err != nil {
						t.Error(err)
						return
					}
					if _, err := store.Write(revision, []byte(strconv.Itoa(n)), 0o600); err != nil {
						t.Error(err)
						return
					}
				}
			}()
			for i := 0; i < 4; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for {
						select {
						case <-done:
							return
						default:
						}
						data, err := store.Read(revision)
						if err != nil {
							continue
						}
						n, _ := strconv.Atoi(string(data))
						rows, err := store.ReadAll(root + "/rows")
						if err != nil {
							t.Error(err)
							return
						}
						for k := 0; k <= n; k++ {
							if _, ok := rows[root+"/rows/"+strconv.Itoa(k)]; !ok {
								t.Errorf("revision of row %d seen, row %d not", n, k)
								return
							}
						}
					}
				}()
			}
			wg.Wait()
		})
	}
}
