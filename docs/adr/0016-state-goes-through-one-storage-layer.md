# State goes through one storage layer

Everything the tool keeps between runs (the wallet document, the holder and issuer keys, the TLS leaf, the shared CA, display assets, user templates) is written and read through `internal/storage`. A `Store` holds blobs under slash-separated keys. The wallet is a named subtree, laid out as the wallet directory, and the CA sits one level above it. Only the process bookkeeping below stays outside the layer.

Three backends implement the store. `file` is the default and writes the wallet directory tree, so an existing wallet directory is a file store and the `--wallet-dir` contract holds. `memory` keeps the blobs in one store per process. Every opener in the process shares it. `postgres` keeps one row per key in one table, so several wallet servers pointed at the same database serve one wallet state.

The backend is chosen by `--storage` or `EUDI_DEV_STORAGE`, and every opener that takes no explicit spec follows the variable. That includes the test suites, so one variable moves a whole test run onto a backend. The container image sets `auto`: files when a state directory was named or holds state (a mounted volume, empty or not), memory otherwise. A container that mounts a volume keeps its state in files. One that mounts nothing holds its state in memory and runs on a read-only filesystem. The instance registry a memory-backed server writes does not count as state, so the next start of that container picks memory again.

## What stays outside the layer

The instance registry (`instances/*.json`), the active remote target and the detached server log describe processes on this machine. They stay files in the state directory, because older CLIs read the registry directly and route to a running server by its wallet directory. A served wallet therefore keeps its directory as its name on every backend, and reports it in `/api/config`.

Files the user points at by path (a credential, a template, a key PEM) are read from the filesystem. The layer holds only the tool's own state.

## Consequences

The file backend keeps the wallet as one `wallet.json`. The memory and database backends keep it as one blob per entity (a credential, a log entry, a status entry, a deferred issuance, an issued attestation, the settings) under `state/`, each keyed by the entity's identity. A save writes the entities that changed since the wallet was loaded and deletes the ones that went away, so two servers on one database only clash when they change the same entity. It keeps each credential as last stored and encodes only the ones that differ, so adding a credential costs one row however many the wallet holds. The status list counter moves with a compare-and-swap, so two servers issuing at once never hand out the same index.

The per-request reload (ADR-0005) compares one revision row per section with the ones the server loaded and refreshes only the sections that changed. Within a section it compares the stamps of the rows with the ones it holds and reads only the rows that are new or changed, keeping the parsed form of the rest. A server writes the revision of a section it changed with a compare-and-swap, so it recognises its own change and skips it. The activity log is append-only: a server stores each entry as one row without comparing the rest of the wallet, and the log views load it on demand, so a presentation costs one server one row and the others nothing. The store trims the log to its cap on its own, since a server that only appends never loads it.

The file and memory backends serve one wallet server. The CLI can work beside a file-backed server, which the reload picks up by the file's modification time. Several wallet servers on one wallet need the database backend.

The keys, the CA and every credential are stored in the clear on every backend (ADR-0003). A shared database holding the CA key is a trust anchor.

Postgres is the only external backend. Another engine is another `Store` implementation behind the same keys.

