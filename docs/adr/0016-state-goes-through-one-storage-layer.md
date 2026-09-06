# State goes through one storage layer

`internal/storage` stores the wallet's credentials, keys, certificates, display assets and user templates. Each value is a blob under a slash-separated key. Wallet data sits under the wallet's prefix. The shared CA sits one level above it.

Three backends implement `Store`: `file` writes the existing wallet directory layout, `memory` shares one store within a process, and `postgres` stores one row per key. Wallet servers using the same database and wallet prefix share persisted state.

Choose the backend with `--storage` or `EUDI_DEV_STORAGE`. Commands and tests that open a store without an explicit backend use the environment variable. The CLI defaults to `file`. The container image sets `memory`. Persistent deployments use `file` with a volume or a Postgres URL. `auto` selects files when a state directory was named, is empty, or contains wallet state. It selects memory when the directory is absent or contains only `instances/` and `remote.json`.

## What stays outside the layer

The instance registry (`instances/*.json`), active remote target and detached server log stay in local files. The CLI uses them to find processes on this machine. It identifies a running wallet by its directory on every backend. `/api/config` reports that directory.

Files the user points at by path (a credential, a template, a key PEM) are read from the filesystem. The layer holds only the tool's own state.

## Postgres schema

[ADR-0018](0018-postgres-stores-wallet-entities-as-keyed-blobs.md) explains why Postgres uses keyed blobs rather than a relational wallet schema.

`internal/storage/postgres.go` creates these objects on first use:

- `eudi_dev_state`: one table with `key TEXT PRIMARY KEY`, `data BYTEA NOT NULL`, `version BIGINT NOT NULL` and `updated_at TIMESTAMPTZ NOT NULL`.
- `eudi_dev_state_prefix`: an index on `key text_pattern_ops` for prefix lookups, in addition to the primary-key index.
- `eudi_dev_state_version`: a sequence that assigns write versions. Deleting and recreating a key gives it a new version.

Credentials, logs, keys, certificates and revision markers all use this table. There are no separate tables for these entities. The storage layer treats their contents as bytes. The wallet layer handles JSON and PEM encoding.

## Saving and reloading

The file backend stores the wallet as one `wallet.json`. Memory and Postgres store each credential, log entry, status entry, deferred issuance, issued attestation and settings record separately under `state/`. A save writes changed entities, deletes removed entities and updates a revision marker for each affected section. Adding a credential leaves unchanged credential rows alone, but also writes revision markers and any related status or log entries.

At request boundaries ([ADR-0005](0005-the-server-reloads-its-store-on-every-request.md)), the server compares section revisions and row versions with its cached values. It reads changed rows individually, or the whole section when more than 16 rows changed. Unchanged credentials keep their parsed form. The activity log loads on demand. Appending an entry writes the entry and its revision marker. The store trims old log entries every 64 saves or appends.

Postgres writes are atomic per row. A wallet save spans several statements and is not a transaction across all entities. Concurrent writes to the same entity can overwrite each other. Revision markers tell a server when to reload. They do not lock entity writes. The status-list counter uses compare-and-swap to allocate distinct indices across servers.

Use the file or memory backend for one wallet server. A file-backed server checks the wallet file's modification time and size, with a reload at least every two seconds while handling requests. Use Postgres to share persisted state across servers. Pending browser flows and demo issuer/verifier requests remain in memory, so requests in one flow must reach the same server.

The keys, the CA and every credential are stored in the clear on every backend (ADR-0003). Anyone with access to the stored CA key can sign certificates trusted by verifiers that use this CA.

Postgres is the only external backend. Another engine is another `Store` implementation behind the same keys.
