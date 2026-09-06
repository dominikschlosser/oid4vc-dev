# Hosting a Public Demo

Run a shared public wallet with the `--demo` profile, as at `https://eudi-test.dev`. Visitors can issue, present, decode and delete test credentials. Process controls and host filesystem endpoints are disabled. See [`examples/public-demo/`](../examples/public-demo/) for a deployment example.

## Demo profile

```bash
eudi wallet serve --demo --base-url https://eudi-test.dev \
  --vci-client-id https://eudi-test.dev --vci-redirect-uri https://eudi-test.dev/callback \
  --status-list --imprint-file imprint.html
```

`--demo` enables the defaults described below. Explicit flags can override `--pid`, `--mode debug`, `--haip` and `--vci-version 1.1`. For example, `--demo --vci-version 1.0` selects the published OpenID4VCI feature level.

### Baseline and consent

The server starts headlessly with protected PID credentials from the bundled templates. User templates with the same names, including those in `--templates-dir`, override the baseline used at startup and reset.

Browser flows ask for consent. API submissions provide consent directly. Browser sessions keep dialogs associated with the visitor who started the flow. Requests without a browser ID appear in a shared banner where any visitor can answer them.

### Administrative operations

Demo mode returns `403` for shutdown, template writes, error injection, log clearing and changes to format, consent or conformance settings. The issue endpoint also rejects template saving and visitor-supplied images. Template images still apply. Configuration responses omit host paths and the process ID.

### Outbound connections

Visitor URLs are restricted to public network addresses. The wallet checks resolved addresses when connecting and rejects loopback, private, link local, CGNAT and unique local ranges, including cloud metadata endpoints. Its own advertised origins are exempt at their exact address and port so the bundled issuer and verifier can communicate with the wallet.

### Validation

Demo mode checks OpenID4VP and issuance against HAIP 1.0. Violations appear as activity log warnings while debug mode continues the flow. The UI shows the active settings under **Conformance**.

Presentation checks cover request delivery, client identification, response encryption, credential formats and algorithms. Unsigned Digital Credentials API requests use the platform origin to identify the caller. Issuance checks cover the grant, PAR, PKCE, DPoP and client authentication. See [specification support](spec-compliance.md) for individual requirements.

Use `--mode strict` to reject violations or `--haip=false` to disable HAIP checks. Some interoperability advisories remain warnings in strict mode.

### Periodic reset

`--demo-reset` accepts an interval such as `24h`, a daily time such as `00:00`, or a time with a zone such as `"00:00 Europe/Berlin"`. `0` disables resets. Daily schedules follow local time, including daylight saving changes, and retain their schedule across restarts.

A reset replaces the PID baseline and clears the activity log. Keys, certificates and URLs remain stable. The footer shows the reset schedule.

## Browser hardening

A shared wallet renders one visitor's data in another visitor's browser. The server therefore sends `Content-Security-Policy` (scripts from this origin only, no inline script, no framing, no `<base>` rewriting), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: no-referrer` on every response. The UI escapes values in attribute contexts as well as text, so a credential cannot inject markup through a status list URI, a `vct`, a claim name or a credential configuration id. The consent event stream is same-origin only.

## robots.txt and security.txt

The server serves `/robots.txt` (pages allowed, the API and the protocol endpoints excluded) and `/.well-known/security.txt` (RFC 9116, contact and policy of the project, expiry six months from the request). Every page has a meta description.

## What stays open (accepted risk)

Every wallet server includes an issuer at `/issuer` and a verifier at `/verifier`. The issuer offers a Demo Event Ticket through pre-authorized and authorization code flows. The verifier requests the ticket or a PID through OpenID4VP.

The verifier signs requests delivered from `/verifier/request/{id}`, identifies itself with `x509_hash:` and receives encrypted `direct_post.jwt` responses. Each request has its own encryption key and accepts one response. Offers and requests expire after ten minutes and are kept only in memory.

The verifier page has a PID format toggle. By default a PID request asks for the SD-JWT VC or the mdoc and the wallet presents whichever it has. Picking one format asks for that one alone, so a format mismatch becomes visible. The ticket is always an SD-JWT VC.

The issuer page has a status list toggle. With it on, the ticket carries a reference to the wallet's own status list (one reserved index per ticket). The wallet imports the ticket as revocable and the demo verifier rejects the next presentation once it is revoked.

The wallet UI pages the credential list (ten per page), so a demo with hundreds of credentials between resets stays usable.

The demo starts with four PID credentials: the country-independent EUDI PID (`urn:eudi:pid:1`) and the German PID that extends it (`urn:eudi:pid:de:1`), each as an SD-JWT VC and an mdoc. The two carry different attributes, each following its own rulebook.

The verifier page offers both through its credential toggle. The PID request names `urn:eudi:pid:1`, which both credentials match, and the wallet presents one of them. The German PID request names `urn:eudi:pid:de:1`, which only the German credential matches. See [credential type inheritance](wallet.md#credential-type-inheritance).

`POST /verifier/api/requests` takes the type as `vct` and accepts any type in `urn:eudi:pid:` (`urn:eudi:pid:fr:1` works the same). A request naming a domestic type is SD-JWT VC only, since every PID shares the mdoc doctype `eu.europa.ec.eudi.pid.1`. A PID request can also ask for the demo ticket with `"ticket": "combined"` (one DCQL option contains PID and ticket, next to a PID-only option) or `"ticket": "optional"` (a second credential set with `required: false`). Both show the set choices in the consent dialog.

All four are marked protected. The UI, the API and the CLI refuse to delete or revoke them, so the demo always keeps its baseline. Everything a visitor issues afterwards behaves normally and can be deleted. Clearing the flag needs direct access to `wallet.json`.

State is shared between all visitors. Anyone can issue credentials, delete them and watch the activity log. The periodic reset cleans up.

The compose example rate limits per client address in Caddy, the component that sees the real address (the wallet behind it sees the proxy). The Caddy image is built from the `Dockerfile` next to the compose file because the rate-limit plugin is not in the standard image. Three zones apply, each answering `429` with `Retry-After`:

| Zone | Requests | What it covers |
|---|---|---|
| `flows_burst` | 120 per minute | The endpoints that make the wallet fetch a visitor-supplied URL or grow its state until the next reset: presentations, offers, issuance, imports, refreshes, deferred collection, demo issuer offers, verification requests |
| `flows_hour` | 2000 per hour | The same endpoints, so a script left running is capped between resets |
| `site` | 1200 per minute | Everything else, including the UI and the stats report |

The limits allow interactive use while bounding automated traffic. An idle page makes about 14 initial requests, then receives updates through an event stream. Clients behind the same public address share the allowance. Apply equivalent limits if using another reverse proxy.

## Base URL and issuer URL

With an https base URL the issuer URL equals the base URL. Status list URIs, `iss`, the `.well-known` metadata and trust list URLs all use the public origin. The reverse proxy terminates TLS, so the built-in self-signed HTTPS listener stays off. With an http base URL the wallet keeps its second self-signed HTTPS listener on port+1.

## Client identity for authorization-code issuance

HAIP issuance runs the authorization code flow, which needs a client id and a redirect URI. Both default to the wallet's own origin (`--base-url`) and its `/callback` endpoint. The example deployment sets them explicitly:

```
--vci-client-id https://eudi-test.dev --vci-redirect-uri https://eudi-test.dev/callback
```

Issuers that require registration register exactly those two values. Pass different ones when an issuer registered you under another client id. Pre-authorized code offers work without either flag (an attestation is still sent where the issuer's metadata asks for one).

## The demo issuer as an authorization server

The demo issuer is also its own authorization server. Its metadata at `/.well-known/oauth-authorization-server/issuer` advertises PAR, PKCE S256, DPoP and ABCA draft-10 methods `attest_jwt_client_auth` and `attest_jwt_client_auth_dpop`. Its endpoints are `/issuer/par`, `/issuer/authorize` and `/issuer/token`.

It accepts the attestation claims defined by ABCA draft-07, draft-08 and draft-10. A valid attestation for a supported draft other than the configured version produces a warning ([ADR-0014](adr/0014-pinned-draft-versions-stay-supported-alongside-the-latest.md)).

Client authentication is required on the token endpoint for both grants (HAIP 1.0 §4.4.1). `--demo-issuer-client-auth optional` also permits clients without an attestation.

The key-proof challenge comes from the Nonce Endpoint defined in OpenID4VCI 1.0 §7. The issuer serves it at `POST /issuer/nonce` and advertises it as `nonce_endpoint` in its Credential Issuer metadata. A proof signed over a stale nonce is answered with `invalid_nonce`, which tells the wallet to fetch a fresh nonce and retry.

Authentication is one hardcoded account, **alice / alice**, printed on the login page. The issuer stores no user data and a session ends with its flow.

The sign-in happens during redemption. The **Authorization code offer** button creates an offer with nobody signed in. The wallet then runs the pushed authorization request, and the authorization endpoint asks the user to authenticate. The credential is bound to the account that completed that login.

On a hosted wallet the user's browser is on another machine, so the wallet returns the authorization URL to the caller. The tab that started the flow receives an `authorize` event on `/api/requests/stream` and navigates. An API caller gets `202 authorization_required` with the URL and an `offer_id`. The flow stays open either way until the issuer redirects back to the wallet's `/callback`, which resumes it and returns the visitor to the wallet UI.

The callback is matched by `state` alone, so the sign-in can happen in any browser that can reach the wallet. This lets `eudi wallet accept` complete an authorization code offer against the hosted demo. The CLI opens the URL locally and follows the flow at `GET /api/offers/{offer_id}` until it reports `completed` or `failed`.

The pushed authorization request and the token request must both carry a wallet attestation, and the demo issuer verifies it. The PoP must be signed by the attested key, and `sub`, `aud`, `jti` and the expiry must match. Possession of the attested key can be proven in both ways the draft allows: a dedicated `OAuth-Client-Attestation-PoP` JWT, or the DPoP proof the request already carries (`attest_jwt_client_auth_dpop`), where the issuer checks that the DPoP key is the attested key. The access token is bound to the DPoP key and the credential request must prove that key again. The ticket carries the name of the account that signed in, so a flow that skipped the login is visible in the result.

### Wallets from other providers

The demo issuer trusts the shared wallet CA. It also accepts attestations from other providers when their signature verifies against the included leaf certificate. This permits interoperability testing without treating the provider as trusted.

The ticket records the result in `wallet_attestation`: `trusted` for a chain reaching the wallet CA, `untrusted` for another signer, or `none` when authentication was optional and omitted. The wallet provider's trust list is available at `/api/trustlists/wallet-provider`.

A wallet with no attestation is refused. HAIP 1.0 §4.4.1 requires it: "Wallets MUST use, and Issuers MUST require, an OAuth2 Client authentication mechanism at OAuth2 Endpoints that support client authentication". To test such a wallet, start the server with `--demo-issuer-client-auth optional`. The authorization server then also advertises and accepts `none`. An attestation is still verified wherever one is sent, and the ticket records the outcome.

## What an issuer needs to verify the wallet

The wallet authenticates PAR and token requests with a wallet attestation. With a separate possession proof, it sends both headers below. When the server advertises combined DPoP proof, the DPoP header replaces the separate attestation PoP header.

- `OAuth-Client-Attestation`, signed by the wallet's issuer key (`sub` is the client id, `cnf.jwk` is the wallet's holder key, and `iss` is the wallet origin, which draft 10 permits). Its `x5c` header carries only the leaf certificate (the self-signed root is stripped).
- `OAuth-Client-Attestation-PoP`, signed by that holder key. If the authorization server metadata advertises a `challenge_endpoint`, the wallet fetches a challenge first and includes it.

When the configuration requires key attestations, the credential proof includes `key-attestation+jwt`. It appears in the JWT proof header or as an attestation proof, depending on the offered format. The reported storage and user authentication levels are test claims. The wallet stores keys unencrypted ([SECURITY.md](../SECURITY.md)).

The leaf certificate is included in the attestation. The trust anchor is fetched once:

| Source | URL |
| --- | --- |
| CA certificate (the anchor to pin) | `/api/certificates/ca`, JWKS form with `?format=jwks` |
| Signing key by `kid` | `/.well-known/jwt-vc-issuer` |
| ETSI trust list with the same CA | `/api/trustlists` for the index, `/api/trustlists/{id}` for a list |

Pin the CA. It is kept across restarts and the periodic reset, while a leaf is reissued whenever the wallet regenerates its signing key. The trust lists are grouped by trust profile (`pid`, `local`), but every one contains the same CA, so any of them works as the anchor for the attestations too. The CA is self-signed, so trust in it is established out of band.

## Imprint

Pass `--imprint-file` with an HTML snippet containing the operator's name, address and contact details. The wallet serves it at `/imprint` and `/decoder/imprint`, adds the EU non-affiliation notice and links it from the footer. The standalone decoder accepts the same flag.

The demo uses the `eudi_session` cookie to associate consent requests with a browser. It is an opaque session value with `HttpOnly`, `SameSite=Lax` and, for HTTPS connections, `Secure`. The activity log remains shared.

Pages opened by the CLI or URL handler keep the supplied browser ID in `sessionStorage`. Theme preferences and dismissed banner state use `localStorage`. These values provide UI behavior without third-party tracking. Describe this storage in the deployment's privacy notice.

## Deploying and updating

[`examples/public-demo/deploy.sh`](../examples/public-demo/deploy.sh) manages a host over ssh. Point `DEMO_HOST` at any ssh destination (a `~/.ssh/config` alias, `user@host`, or a bare host), optionally with `DEMO_DIR` and `DEMO_URL`. Put them in the environment or in a `deploy.env` next to the script (gitignored).

```bash
cd examples/public-demo
cat > deploy.env <<'ENV'
DEMO_HOST=root@demo.example
DEMO_URL=https://demo.example
ENV

./deploy.sh setup     # first deployment: Docker, stack, volume ownership, start
./deploy.sh push      # after editing Caddyfile, compose file or imprint
./deploy.sh update    # pull the released image and restart
./deploy.sh rollback  # put the release that was live before that back
./deploy.sh status    # container status plus the version the site reports
./deploy.sh verify    # check that every public endpoint answers
./deploy.sh logs      # follow the wallet log
```

`push` and `update` record the release they replace, so `rollback` on its own puts that one back. `rollback v2.0.0` selects any release directly. The choice is pinned as `WALLET_TAG` in the host's `.env` (where the compose file reads the image tag), so it is kept across a restart. The image is pulled before anything is switched, so naming a release that was never published leaves the running demo unchanged. A later `update` clears the pin and returns to the newest release.

`setup` also fixes the wallet data volume's ownership. Docker creates named volumes owned by root while the image runs as uid 1000, which would put the wallet into a crash loop on a fresh host.

### Preview host

Use the preview host to try a release before deploying it to the main site. It runs a second wallet with its own volume and release, behind the same Caddy at a separate subdomain (`preview.eudi-test.dev` in the example). Point the subdomain at the same host and add its URL to `deploy.env`.

```bash
# in deploy.env, alongside DEMO_HOST and DEMO_URL:
PREVIEW_URL=https://preview.demo.example

./deploy.sh preview v2.1.0   # run v2.1.0 on the preview host, main site untouched
./deploy.sh verify           # checks the main site and the preview host
./deploy.sh promote          # move the main site to the release the preview runs
./deploy.sh logs preview     # follow the preview wallet log
```

`preview` copies the stack (the Caddy preview block and the `wallet-preview` service), prepares the preview data volume, pins its release as `PREVIEW_TAG` in the host's `.env`, starts the preview wallet, and reloads Caddy gracefully so the main site stays up. Without a tag it runs `latest`, so the preview mirrors the newest release until a change is pinned. `promote` reads the version the preview reports and moves the main site to exactly that image, recording the release it replaces so `rollback` still works.

### Strict conformance host

The strict conformance target runs as a third wallet on a separate subdomain, `strict.eudi-test.dev` in the example. It uses strict validation, HAIP, auto-accept and the default PID baseline.

Caddy permits only GET and HEAD from the public internet. This exposes protocol documents and GET `/authorize` requests. The latter can still start presentation flows. The harness accesses other management operations through an SSH tunnel to `127.0.0.1:18086` on the host.

`STRICT_TAG` pins its release independently. Its issuance redirect URI uses the `oid4vc-dev-vci-strict` alias on the production conformance service.

```bash
# in deploy.env, alongside DEMO_HOST and DEMO_URL:
STRICT_URL=https://strict.demo.example

./deploy.sh strict v2.3.0    # run v2.3.0 on the strict host, main site untouched
./deploy.sh logs strict      # follow the strict wallet log
```

[The conformance runbook](./conformance-run.md) describes the run against it.

## Usage statistics

The compose example includes an optional usage report. Caddy writes an access log with the client address anonymized at write time (`ip_mask` zeroes the last IPv4 octet and the last 80 bits of IPv6, for both `remote_ip` and `client_ip`). [GoAccess](https://goaccess.io) turns that log into a static HTML report every two minutes, and Caddy serves it at `/stats` behind basic auth. The pages get no extra JavaScript, the report sets no cookies, and no third party is involved.

```bash
./deploy.sh stats-password   # writes stats.env with a bcrypt hash (gitignored)
./deploy.sh push             # applies it
./deploy.sh stats            # quick summary in the terminal
./deploy.sh stats-reset      # discard the log and start counting from zero
```

Then open `https://your-domain/stats/`. To turn it off, remove the `handle_path /stats*` block from the Caddyfile and the `stats` service. The anonymized log still counts as processed access data, so word your imprint accordingly.

Your own tests count in the statistics. One page load produces several requests for assets, wallet state and the event stream. `deploy.sh stats` separates page views from API calls and lists writes separately. Writes include issuance, presentation, imports and deletion from both people and automated tests.

Visitor counts are approximate because addresses are masked. Everyone sharing an IPv4 `/24` is counted together.

### Log bounds

- the access log rotates at 10 MiB, keeps three files and drops anything older than 30 days (about 40 MiB worst case)
- every container caps its own log at 10 MB with three files, through the `logging` anchor in the compose file (Docker's default is unlimited)
- the report only reads the current access log file, so a rotation also caps how far back the statistics reach

## Deployment notes

- Terminate TLS in a reverse proxy (the example uses Caddy with automatic Let's Encrypt) and forward to the wallet's HTTP port. The wallet derives all advertised URLs from `--base-url`.
- Persist a volume at `/home/app/.eudi-dev` (the parent of `wallet/`) and set `EUDI_DEV_STORAGE=file` and `EUDI_DEV_SEED=` (the image's default is memory with a public seed). The shared CA is stored one level above the wallet directory, and issuer keys must persist across restarts, otherwise verifiers holding the old trust list fail.
- Run one replica for this file-backed deployment.
- Leave `HTTP_PROXY` and `HTTPS_PROXY` unset in the container. A proxy would bypass the dial time network checks.
- Self-fetches of the public origin (for example a pasted offer pointing at the demo itself) resolve through public DNS. On typical cloud hosts hairpin NAT makes this work. A compose network alias for the public hostname would resolve to a private address and be blocked.
- Keep the rate limiting in the proxy. The compose example's Caddyfile ships active `rate_limit` zones (described above).

## Pointing the CLI at the demo

```bash
eudi wallet use https://eudi-test.dev
```

Management commands (list, issue, delete) then run against the hosted instance. `serve`, `scan` and `register` stay local.
