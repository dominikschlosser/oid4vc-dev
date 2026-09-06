# Wallet

The wallet stores test credentials and presents them through OID4VP. It accepts OID4VCI offers from the CLI, QR codes and links. By default, credentials and keys persist in `~/.eudi-dev/wallet/`. Use `--wallet-dir` to choose another directory, or select [memory or Postgres storage](#storage-backends).

The wallet has two validation modes. Both run the same checks. The mode decides how validation violations are handled:

- `debug` (default) reports each finding and keeps processing the request. During DCQL evaluation it warns and keeps a credential match when some required claim paths are missing but other requested claims still match
- `strict` treats those violations as errors and refuses the request

Advisory findings remain warnings in either mode. `--haip` is a separate switch. See [HAIP 1.0 enforcement](wallet/presenting.md#haip-10-enforcement).

For OpenID Foundation conformance work, see [docs/conformance.md](./conformance.md).
For interaction diagrams of the implemented OID4VP and OID4VCI flows, see [docs/diagrams](./diagrams/README.md).

## Subcommands

| Subcommand     | Purpose                                                         |
|----------------|-----------------------------------------------------------------|
| `serve`        | Start wallet HTTP server with web UI, OID4VP endpoints, and optional URL scheme handling |
| `list`         | List stored credentials                                         |
| `show`         | Show a stored credential by ID (raw or decoded)                 |
| `import`       | Import a credential from file, stdin, or raw string (SD-JWT, JWT VC, mDoc) |
| `remove`       | Remove a credential by ID                                       |
| `generate-pid` | Deprecated. Generate default EUDI PID credentials (SD-JWT + mDoc) from the pre-defined PID templates, of the type `--vct` names. Use `issue ... --wallet --template pid-sdjwt|pid-mdoc` (or the `german-pid-*` ones) instead |
| `accept`       | Accept an OID4VP presentation request or OID4VCI credential offer (auto-detects) |
| `scan`         | Scan a QR code and auto-dispatch to accept/import               |
| `refresh`      | Ask a credential's issuer for a fresh copy over the refresh token grant |
| `deferred`     | Credentials an issuer deferred and the wallet is still collecting (`check`, `abandon`) |
| `logs`         | Show persisted wallet-side OID4VP/OID4VCI interaction logs      |
| `trust-list`   | Print the trust list JWT (`--list` for the profiles, `--url` for the URL) |
| `ca-cert`      | Print or export the shared wallet CA certificate                |
| `tls-cert`     | Print or export the HTTPS wallet certificate used by HTTPS wallet endpoints |
| `ps`           | List running wallet instances                                   |
| `use`          | Switch management to a remote instance (`use <url>`) or back to local (`use local`) |
| `kill`         | Stop a running wallet instance (`kill <pid|port|url>`, `kill --all`) |
| `info`         | Show the configuration of the managed wallet (local or remote)  |
| `register`     | Register OS URL scheme handlers on macOS. No-op elsewhere       |
| `unregister`   | Remove OS URL scheme handlers on macOS. No-op elsewhere         |

All of these are also available over HTTP on a running `wallet serve` instance. See [Wallet HTTP API](wallet/http-api.md).

## Quick start

```bash
# Issue PID credentials from the pre-defined templates and list them
eudi issue sdjwt --wallet --template pid-sdjwt
eudi issue mdoc --wallet --template pid-mdoc
eudi wallet list

# The German PID, which extends the country-independent one
eudi issue sdjwt --wallet --template german-pid-sdjwt
eudi issue mdoc --wallet --template german-pid-mdoc

# Deprecated equivalent (issues both PIDs at once, will be removed later)
eudi wallet generate-pid

# Show a credential (raw)
eudi wallet show <id>

# Show a credential (human-readable decoded)
eudi wallet show --decoded <id>

# Start the wallet web UI with stored credentials
eudi wallet serve

# Start the wallet and register URL scheme handlers
eudi wallet serve --register

# Export the shared wallet CA for verifier trust stores
eudi wallet ca-cert --out wallet-ca-cert.pem

# Export the HTTPS wallet certificate for verifier trust stores
eudi wallet tls-cert --out wallet-tls-cert.pem

# Process an OID4VP request from the CLI
eudi wallet accept 'openid4vp://authorize?client_id=...'

# Accept a credential offer (auto-detected from URI)
eudi wallet accept 'openid-credential-offer://...'

# Scan a QR code from screen and auto-detect the flow
eudi wallet scan --screen

# Show wallet-side interactions
eudi wallet logs
eudi wallet logs -f

# Import a credential from a file
eudi wallet import credential.txt

# Register URL scheme handlers so openid4vp:// links open the wallet on macOS
eudi wallet register
```

On Linux and Windows, `wallet register` and `wallet unregister` are no-ops, so shared scripts stay portable. Open copied `openid4vp://` or `openid-credential-offer://` links with `eudi wallet accept '<uri>'`.

The macOS URL handler sends links to the active remote wallet. While a remote target is set with `wallet use <url>`, clicked links go to that instance (useful when the wallet runs in a Docker container), and the handler then opens the remote consent UI in the browser. `wallet use local` routes links back to the local wallet server.

## Credential type inheritance

A domestic PID extends the country-independent one. ARF Annex 2 (v3.0.0) PID_14 requires the vct to be "`urn:eudi:pid:1` for the type defined in this document or a domestic type that extends it", so `urn:eudi:pid:de:1` carries every attribute `urn:eudi:pid:1` defines plus the German ones.

The wallet matches a DCQL `vct_values` entry against the credential's own type and every type it extends. A request for `urn:eudi:pid:1` is answered by any PID, a request for `urn:eudi:pid:de:1` by a German PID. The `[DCQL]` server log records the requested type whenever a credential matched under a type other than its own.

The relationship comes from two places:

- the PID type itself. A segment after `urn:eudi:pid:` that is a country or region code (`urn:eudi:pid:de:1`, `urn:eudi:pid:fr:1`) marks a domestic type, which extends `urn:eudi:pid:1`. A segment that is a version number (`urn:eudi:pid:1`, `urn:eudi:pid:2`) marks the country-independent type
- the `aka_vcts` claim ([SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) §2.2.2.2), which lists further types a credential is also of. It applies to every credential type, and the German PID this tool issues carries it

Inheritance only describes the credential type. The signature and trust list checks still decide whether the issuer is authorized (§6.6: "Verifiers and Holders MUST NOT assume that any issuer who issues a credential extending a known type is authorized to do so").

In mdoc every PID carries the doctype `eu.europa.ec.eudi.pid.1` (PID_05), and national elements are in a domestic namespace built by appending the country or region code to it (`eu.europa.ec.eudi.pid.de.1`, PID_06). A `doctype_value` request therefore matches every PID, and a claim query addresses a national element by its namespace: `"path": ["eu.europa.ec.eudi.pid.de.1", "birth_name"]`.

## Storage

Everything the wallet holds is stored unencrypted, including private keys and any access or refresh tokens an issuer returns. This is a development and test wallet. Point it at test issuers only and treat the wallet directory as disposable.

All wallet state is stored in `~/.eudi-dev/wallet/` by default:

```
~/.eudi-dev/
├── wallet-ca-cert.pem  # Shared CA certificate used across wallet instances
├── wallet-ca-key.pem   # Shared CA private key
├── remote.json         # Active remote wallet target set by wallet use
├── instances/          # Registry of running wallet servers (one file per pid)
└── wallet/
    ├── wallet.json       # Credentials + metadata
    ├── holder.pem        # Holder EC private key (auto-generated on first use)
    ├── issuer.pem        # Issuer EC private key (for self-issued credentials)
    ├── wallet-log-cleaned-at # Timestamp marker written by wallet logs clean
    ├── wallet-tls-cert.pem # HTTPS certificate for wallet endpoints on port+1
    ├── wallet-tls-key.pem  # HTTPS private key for wallet endpoints on port+1
    ├── assets/             # Display images (card art) referenced from wallet.json
    └── templates/          # User credential templates (see templates.md)
```

Display images are stored once under content-based names in `assets/`. Credentials refer to them as `asset:<hash>.<ext>` to keep wallet state small. Embedded `data:` URIs remain readable and move into asset storage on the next save.

On the file backend the activity log is the top-level `log` field of `wallet.json`. The other backends keep one entry per row (see [Storage backends](#storage-backends)). `wallet logs clean` clears those entries and writes `wallet-log-cleaned-at`. A running wallet server drops in-memory entries older than that marker when it saves. With `--wallet-dir`, both are in that directory.

Keys are P-256 EC keys, auto-generated on first use and reused across invocations. Wallets under the same wallet base directory share a persisted **CA key** and build certificate chains from it:

1. **CA certificate**: self-signed, used as trust anchor in the trust list (`/api/trustlist`)
2. **Leaf certificate**: signed by the CA, wraps the issuer key's public key

Generated credentials are signed with the **issuer key**. SD-JWT credentials include a deterministic `kid` header, expose the signing key through JWT VC issuer metadata, and include the leaf signing certificate in `x5c`. The shared CA is the anchor in the wallet trust list, so verifiers validate the signing key through that chain.

Each wallet keeps its own issuer key. Its credential-signing leaf certificate and HTTPS wallet certificate are generated from the shared CA.

Generated credentials expire in **30 days** by default. Use `--exp` to override (e.g. `--exp 720h` for 30 days, `--exp 24h` for 1 day). Use `--nbf` to set a not-before time (RFC3339 or duration, e.g. `--nbf 2025-01-15T00:00:00Z` or `--nbf -1h`).

![Wallet UI](./assets/wallet-ui.png)

## `wallet show <id>`

Shows a stored credential by its ID (as printed by `wallet list`). An unambiguous id prefix also resolves. By default it prints only the raw credential string, so it can be piped. `--decoded` prints human-readable output (the `--json` and `-v` global flags apply). Decoded output begins with a validity line, since the payload contains the expiry only as a Unix timestamp.

`wallet list` shows the same in its `VALID` column: the time left (`29d`, `5h`, `expired`) or `-` for a credential without an expiry.

```bash
eudi wallet show <id>                  # Raw credential string
eudi wallet show --decoded <id>        # Human-readable output
eudi wallet show --decoded --json <id> # JSON output
```

| Flag        | Default | Description                                          |
|-------------|---------|------------------------------------------------------|
| `--decoded` | `false` | Show human-readable decoded output instead of raw    |

## `wallet logs`

Shows saved OID4VP and OID4VCI activity, including requests, responses, credential imports, deferred issuance and notifications.

Each entry prints on one line with the event, direction, endpoint, status and other available request details. Use `-v` / `--verbose` to expand the payloads, including DCQL queries, credential requests, presented claims and issuer or verifier responses.

Use `-f` / `--follow` to print new entries as they are saved, like `kubectl logs -f`.

```bash
eudi wallet logs              # One line per persisted wallet interaction
eudi wallet logs -v           # Expand request/response details
eudi wallet logs -f           # Print existing logs, then follow new entries
eudi wallet logs clean        # Remove old persisted wallet logs
eudi wallet logs --json       # JSON array of log entries
```

| Flag       | Default | Description                                      |
|------------|---------|--------------------------------------------------|
| `-f, --follow` | `false` | Keep running and print new entries as they appear. Local wallets only (a remote wallet is refused) |
| `-v, --verbose` | `false` | Global flag. Expand structured log details        |
| `--json`   | `false` | Global flag. Output the persisted log entries as JSON. Cannot be combined with `--follow` |

## Serving the wallet

`wallet serve` runs the web UI, protocol endpoints, trust lists and management API. It loads credentials from the selected storage backend and handles consent for interactive requests. On macOS it can also register URL scheme handlers.

```bash
eudi wallet serve                      # web UI on http://localhost:8085
eudi wallet serve --auto-accept --pid  # headless, with default PIDs, for tests
```

See [serving the wallet](wallet/serve.md) for the endpoints, trust-list profiles, certificate export, URL scheme registration, runtime conformance settings, and every `wallet serve` flag.

## Presenting from the wallet

`wallet accept` answers an OID4VP presentation request (and dispatches a credential offer to issuance). `wallet scan` does the same from a QR code, and the same flows are reachable at the wallet's own `/authorize` and `/credential-offer` URLs without a custom scheme.

```bash
eudi wallet accept 'openid4vp://authorize?...'   # evaluate DCQL, consent, submit
eudi wallet scan --screen                        # scan a QR and dispatch
```

See [presenting from the wallet](wallet/presenting.md) for the full `wallet accept` and `wallet scan` reference, invoking the wallet by URL, and HAIP 1.0 enforcement.

## Issuing into the wallet

A credential offer is accepted with `wallet accept` (or the UI, a scanned QR, or the `/credential-offer` URL). The wallet handles sign-in at the issuer, deferred issuance, later renewal, and interactive (presentation-during-issuance) authorization.

```bash
eudi wallet accept 'openid-credential-offer://...'   # accept an offer
eudi wallet deferred                                 # what is still being collected
eudi wallet refresh <credential-id>                  # ask for a fresh copy
```

See [issuing into the wallet](wallet/issuing.md) for sign-in, renewal, deferred issuance, wallet attestation, the OpenID4VCI feature level (`--vci-version`), and interactive authorization.

## HTTP API

A running `wallet serve` exposes credential and template management, issuance, status changes, certificate exports and instance controls over HTTP. The API has no authentication by default and is intended for local development and isolated test networks.

```bash
curl http://localhost:8085/api/credentials
curl -X POST http://localhost:8085/api/issue -d '{"format":"sdjwt","pid":true}'
```

See [the wallet HTTP API](wallet/http-api.md) for every endpoint and for remote control (driving another instance from the CLI).

## Shared flags

All wallet subcommands accept `--wallet-dir` to override the storage directory, `--templates-dir` to override the credential template directory (see [templates](templates.md)) and `--storage` to choose the storage backend:

```bash
eudi wallet list --wallet-dir /tmp/test-wallet
eudi wallet serve --templates-dir ./my-templates
eudi wallet serve --storage memory
```

## Storage backends

Choose where to store credentials, keys, certificates, assets, templates and the activity log with `--storage` or `EUDI_DEV_STORAGE`:

| Value | State lives in |
|-------|----------------|
| `file` (default) | The wallet directory described above. One wallet server per directory. The CLI works beside it |
| `memory` | The process. One wallet server. It starts empty and forgets everything on exit (the [Docker image](docker.md#storage) default) |
| `auto` | Files when `--wallet-dir` or `EUDI_DEV_HOME` is given or the state directory holds state, memory otherwise |
| `postgres://user:pass@host:5432/db` | Rows in `eudi_dev_state`. Servers using the same database and wallet prefix share persisted state |

The file backend stores wallet state in `wallet.json`. Memory and Postgres store entities separately. Postgres uses one table, `eudi_dev_state`, for entities, keys, certificates and revision markers, plus a sequence for write versions. See [the storage design](adr/0016-state-goes-through-one-storage-layer.md) for the schema and concurrency limits.

The CLI finds running wallets by their wallet directory on every backend. `GET /api/config` reports the backend as `storage`. The default wallet uses the database prefix `wallet`, so host processes and containers using the same database share its persisted state. Browser flows and demo requests remain local to each server.

The flag and environment variable also apply to `issue --wallet` and `templates`. [ADR-0018](adr/0018-postgres-stores-wallet-entities-as-keyed-blobs.md) explains why Postgres uses keyed blobs, with example keys and performance tradeoffs.

## Seeded keys

`--seed <string>` or `EUDI_DEV_SEED` derives holder, issuer, CA and TLS keys from a string. With memory storage, this keeps the keys stable across restarts. Existing stored keys take precedence.

The [Docker image](docker.md#stateless-container) uses the public seed `eudi-dev`. The value `auto` uses that seed for memory storage and random keys for other backends. An empty value generates random keys. `GET /api/config` reports `seeded_keys`.
