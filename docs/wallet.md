# Wallet

A stateful testing wallet with file persistence, CLI-driven OID4VP/VCI flows, QR scanning, and OS URL scheme registration. Credentials and keys are stored in `~/.ssi-debugger/wallet/` (configurable via `--wallet-dir`) and persist across invocations.

## Subcommands

| Subcommand     | Purpose                                                         |
|----------------|-----------------------------------------------------------------|
| `serve`        | Start wallet HTTP server with web UI, OID4VP endpoints, and optional URL scheme handling |
| `list`         | List stored credentials                                         |
| `import`       | Import a credential from file, stdin, or raw string             |
| `remove`       | Remove a credential by ID                                       |
| `generate-pid` | Generate default EUDI PID credentials (SD-JWT + mDoc)           |
| `accept`       | Accept an OID4VP presentation request or OID4VCI credential offer (auto-detects) |
| `scan`         | Scan a QR code and auto-dispatch to accept/import               |
| `trust-list`   | Print the trust list JWT (or just the URL with `--url`)         |
| `register`     | Register OS URL scheme handlers (macOS only)                    |
| `unregister`   | Remove OS URL scheme handlers                                   |

## Quick start

```bash
# Generate PID credentials and list them (re-running replaces existing PIDs)
ssi-debugger wallet generate-pid
ssi-debugger wallet generate-pid --claims '{"given_name":"MAX","family_name":"POWER"}'
ssi-debugger wallet list

# Start the wallet web UI with stored credentials
ssi-debugger wallet serve

# Start the wallet and register URL scheme handlers
ssi-debugger wallet serve --register

# Process an OID4VP request from the CLI
ssi-debugger wallet accept 'openid4vp://authorize?client_id=...'

# Accept a credential offer (auto-detected from URI)
ssi-debugger wallet accept 'openid-credential-offer://...'

# Scan a QR code from screen and auto-detect the flow
ssi-debugger wallet scan --screen

# Import a credential from a file
ssi-debugger wallet import credential.txt

# Register URL scheme handlers so openid4vp:// links open the wallet
ssi-debugger wallet register
```

## Storage

All wallet state is stored in `~/.ssi-debugger/wallet/` by default:

```
~/.ssi-debugger/wallet/
├── wallet.json       # Credentials + metadata
├── holder.pem        # Holder EC private key (auto-generated on first use)
└── issuer.pem        # Issuer EC private key (for self-issued credentials)
```

Keys are P-256 EC keys, auto-generated on first use and reused across invocations.

![Wallet UI](./wallet-ui.png)

## `wallet serve`

Starts a persistent wallet HTTP server with a web UI for managing credentials and handling OID4VP/OID4VCI flows. Loads credentials from disk and saves state on credential changes. Includes request logging with timestamps and a browser-based consent UI for incoming requests.

The server exposes:
- Web UI for credential management and consent
- OID4VP authorization endpoint (`/authorize`)
- ETSI trust list endpoint (`/api/trustlist`) — use this URL as `--trust-list` when validating credentials issued by the wallet

Use `--register` to also register OS URL scheme handlers so that `openid4vp://` and `openid-credential-offer://` links automatically open the wallet.

```bash
ssi-debugger wallet serve
ssi-debugger wallet serve --port 9000 --auto-accept
ssi-debugger wallet serve --pid --credential extra.txt
ssi-debugger wallet serve --register           # also register URL scheme handlers
ssi-debugger wallet serve --register --port 9000
```

| Flag                    | Default  | Description                                      |
|-------------------------|----------|--------------------------------------------------|
| `--port`                | `8085`   | Server port                                      |
| `--auto-accept`         | `false`  | Auto-approve all presentations (headless mode)   |
| `--credential`          | —        | Import credential from file (repeatable)         |
| `--pid`                 | `false`  | Generate default EUDI PID credentials on start   |
| `--key`                 | —        | Override holder key (PEM/JWK)                    |
| `--issuer-key`          | —        | Override issuer key (PEM/JWK)                    |
| `--session-transcript`  | `oid4vp` | mDoc session transcript mode: `oid4vp` or `iso`  |
| `--register`            | `false`  | Register OS URL scheme handlers                  |
| `--no-register`         | `false`  | Skip URL scheme registration (overrides --register) |

## `wallet accept <uri>`

Auto-detects the URI type and dispatches to the appropriate flow:

- `openid4vp://`, `haip://`, `eudi-openid4vp://` → OID4VP presentation (evaluates DCQL, shows consent UI, submits VP token)
- `openid-credential-offer://` → OID4VCI credential issuance (fetches credential from issuer)

In interactive mode (default), OID4VP requests start a temporary consent UI server and auto-open it in the browser. With `--auto-accept`, auto-selects and submits the first matching credentials.

```bash
ssi-debugger wallet accept 'openid4vp://authorize?...' --auto-accept
ssi-debugger wallet accept 'openid-credential-offer://...'
```

## `wallet scan`

Scans a QR code from an image file or screen capture and auto-detects the content:

- `openid4vp://` → delegates to `accept` (OID4VP presentation)
- `openid-credential-offer://` → delegates to `accept` (OID4VCI issuance)
- SD-JWT / mDoc raw credential → delegates to `import`

```bash
ssi-debugger wallet scan qr-image.png
ssi-debugger wallet scan --screen              # macOS interactive screen capture
ssi-debugger wallet scan --screen --auto-accept # auto-approve if it's a presentation
```

## `wallet trust-list`

Generates and prints the ETSI trust list JWT containing the wallet's issuer certificate. The output can be piped to a file or used directly with `--trust-list` in the `validate` command. Use `--url` to print only the URL for a running wallet server instead.

```bash
ssi-debugger wallet trust-list                          # Print the trust list JWT
ssi-debugger wallet trust-list > trustlist.jwt          # Save to file
ssi-debugger wallet trust-list --url                    # http://localhost:8085/api/trustlist
ssi-debugger wallet trust-list --url --port 9000        # http://localhost:9000/api/trustlist
ssi-debugger wallet trust-list --url --docker           # http://host.docker.internal:8085/api/trustlist
```

| Flag       | Default | Description                                        |
|------------|---------|----------------------------------------------------|
| `--url`    | `false` | Print only the trust list URL (for a running server) |
| `--port`   | `8085`  | Wallet server port (used with --url)                |
| `--docker` | `false` | Use `host.docker.internal` instead of `localhost` (used with --url) |

## `wallet register` / `wallet unregister`

Registers (or removes) OS-level URL scheme handlers so that `openid4vp://`, `eudi-openid4vp://`, `haip://`, and `openid-credential-offer://` links automatically open the wallet.

The handler script first tries to POST to a running `wallet serve` instance. If the server is not running, it falls back to invoking the CLI directly (`wallet accept`).

- **macOS**: Creates an AppleScript `.app` bundle in `~/Applications/` and registers via Launch Services
- **Other platforms**: Not supported — use `wallet accept <uri>` instead

```bash
ssi-debugger wallet register               # Register URL handlers (default listener port 8085)
ssi-debugger wallet register --port 9000   # Use custom listener port
ssi-debugger wallet unregister             # Remove URL handlers
```

| Flag     | Default | Description                                                    |
|----------|---------|----------------------------------------------------------------|
| `--port` | `8085`  | Listener port for handler script to try before falling back to CLI |

## Shared flag

All wallet subcommands accept `--wallet-dir` to override the storage directory:

```bash
ssi-debugger wallet list --wallet-dir /tmp/test-wallet
```
