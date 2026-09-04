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
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the pgx database/sql driver
)

// postgresTable holds one row per key.
const postgresTable = "eudi_dev_state"

// postgresStore keeps every key as a row.
type postgresStore struct {
	db    *sql.DB
	label string

	// prepared records that the table exists. It is created on first use, so
	// a command routed to a running server never connects.
	prepareMu sync.Mutex
	prepared  bool
}

// postgresPools holds one store per connection URL, so every opener of a
// database in the process shares its connection pool.
var postgresPools sync.Map

// openPostgres returns the store for the database at a postgres:// URL.
// The connection is made, and the state table created, on first use.
func openPostgres(dsn string) (Store, error) {
	if store, ok := postgresPools.Load(dsn); ok {
		return store.(*postgresStore), nil
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening postgres storage: %w", err)
	}
	store, loaded := postgresPools.LoadOrStore(dsn, &postgresStore{db: db, label: postgresLabel(dsn)})
	if loaded {
		_ = db.Close()
	}
	return store.(*postgresStore), nil
}

// prepare creates the table unless it exists. A failure is not remembered,
// so a database that was still starting is retried on the next call. Two
// processes creating the table at the same moment race inside Postgres, and
// the loser's unique violation means the table is there.
func (s *postgresStore) prepare() error {
	s.prepareMu.Lock()
	defer s.prepareMu.Unlock()
	if s.prepared {
		return nil
	}
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS ` + postgresTable + ` (
		key        TEXT PRIMARY KEY,
		data       BYTEA NOT NULL,
		version    BIGINT NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL
	)`)
	var pgErr *pgconn.PgError
	if err != nil && !(errors.As(err, &pgErr) && pgErr.Code == "23505") {
		return fmt.Errorf("preparing postgres storage at %s: %w", s.label, err)
	}
	s.prepared = true
	return nil
}

// postgresLabel returns the URL without its credentials, for messages.
func postgresLabel(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return KindPostgres
	}
	u.User = nil
	u.RawQuery = ""
	return u.String()
}

func (s *postgresStore) Read(key string) ([]byte, error) {
	key, err := cleanKey(key)
	if err != nil {
		return nil, err
	}
	if err := s.prepare(); err != nil {
		return nil, err
	}
	var data []byte
	err = s.db.QueryRow(`SELECT data FROM `+postgresTable+` WHERE key = $1`, key).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, notExist("read", key)
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", key, err)
	}
	return data, nil
}

func (s *postgresStore) Write(key string, data []byte, _ fs.FileMode) error {
	key, err := cleanKey(key)
	if err != nil {
		return err
	}
	if err := s.prepare(); err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO `+postgresTable+` (key, data, version, updated_at)
		VALUES ($1, $2, 1, now())
		ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, version = `+postgresTable+`.version + 1, updated_at = now()`, key, data)
	if err != nil {
		return fmt.Errorf("writing %s: %w", key, err)
	}
	return nil
}

func (s *postgresStore) Delete(key string) error {
	key, err := cleanKey(key)
	if err != nil {
		return err
	}
	if err := s.prepare(); err != nil {
		return err
	}
	if _, err := s.db.Exec(`DELETE FROM `+postgresTable+` WHERE key = $1`, key); err != nil {
		return fmt.Errorf("deleting %s: %w", key, err)
	}
	return nil
}

func (s *postgresStore) Stat(key string) (Stamp, bool) {
	key, err := cleanKey(key)
	if err != nil {
		return Stamp{}, false
	}
	if err := s.prepare(); err != nil {
		return Stamp{}, false
	}
	var version, size int64
	err = s.db.QueryRow(`SELECT version, octet_length(data) FROM `+postgresTable+` WHERE key = $1`, key).Scan(&version, &size)
	if err != nil {
		return Stamp{}, false
	}
	return Stamp{Version: strconv.FormatInt(version, 10), Size: size}, true
}

func (s *postgresStore) List(prefix string) ([]string, error) {
	prefix, err := cleanPrefix(prefix)
	if err != nil {
		return nil, err
	}
	if err := s.prepare(); err != nil {
		return nil, err
	}
	if prefix != "" {
		prefix += "/"
	}
	escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(prefix)
	rows, err := s.db.Query(`SELECT key FROM `+postgresTable+` WHERE key LIKE $1 ESCAPE '\'`, escaped+"%")
	if err != nil {
		return nil, fmt.Errorf("listing %s: %w", prefix, err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		name := strings.TrimPrefix(key, prefix)
		if strings.Contains(name, "/") {
			continue
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

func (s *postgresStore) Locate(key string) string {
	if key == "" {
		return s.label
	}
	return s.label + "#" + key
}

func (s *postgresStore) Kind() string { return KindPostgres }
