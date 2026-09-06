# Load test target: two wallet servers, one database, one ingress

Two `eudi-dev` wallet servers share one Postgres database and sit behind an nginx ingress. Every request through the ingress lands on either server, and both serve the same wallet (the same keys, CA, credentials and activity log). This is the target for load and performance tests of verifiers, issuers and the wallet itself.

## Layout

| Service | Role | Host port |
|---------|------|-----------|
| `ingress` | nginx. HTTP round robin over both servers, TLS passthrough for the issuer endpoints | 8080 (HTTP), 8086 (HTTPS issuer endpoints) |
| `wallet-1`, `wallet-2` | `eudi wallet serve --auto-accept --pid` on the `postgres` storage backend | none |
| `db` | Postgres 16 | none |

The wallets advertise `http://localhost:8080` as their base URL and `https://localhost:8086` as their issuer URL, so the status list, issuer metadata and trust list URLs embedded in credentials point at the ingress.

## Run

```bash
cd examples/load-test
docker compose up -d
curl -s localhost:8080/api/config | jq '{storage, credential_count}'
docker compose logs ingress | grep upstream=
```

The ingress log shows `upstream=` alternating between the two server addresses. `storage` is `postgres` and `credential_count` is the same on each. `WALLET_TAG=2.4.0 docker compose up -d` pins a release. `docker compose build` builds the image from the working tree. `INGRESS_PORT=18080 docker compose up -d` moves the HTTP host port (the base URL follows it).

## Drive it

The [wallet HTTP API](../../docs/wallet/http-api.md) is the load surface. A presentation, an import and an issuance are each one request:

```bash
# Present: your verifier sends an OID4VP authorization request, the wallet answers it
curl -s "localhost:8080/authorize?client_id=...&response_type=vp_token&response_mode=direct_post&response_uri=...&nonce=...&dcql_query=..."

# Import a credential
curl -s -X POST localhost:8080/api/credentials --data-binary @credential.txt

# Issue a credential into the shared wallet
curl -s -X POST localhost:8080/api/issue -H 'Content-Type: application/json' -d '{"format":"sdjwt","template":"pid-sdjwt"}'
```

The CLI drives it as a remote wallet:

```bash
eudi wallet use http://localhost:8080
eudi wallet list
eudi wallet logs
```

A browser session stays on one server (the ingress hashes the `eudi_session` cookie), so the wallet UI at `http://localhost:8080` works as usual once it has been opened. A flow that starts with a verifier's or issuer's redirect in a fresh browser lands on either server, so open the UI first.

## Check correctness under load

`loadtest` drives the target with concurrent issuances, presentations and listings, then checks that nothing was lost: every issued credential is listed once, no two credentials share a status list index, every presentation reached the verifier callback, and every server reports the same credential count. It runs a verifier callback on this machine, which the containers reach as `host.docker.internal`.

```bash
go run ./examples/load-test/loadtest -url http://localhost:8080
```

`-issuers`, `-issues`, `-presenters`, `-presentations` and `-readers` set the load. `-callback-port` moves the callback (default 9090) and `-callback-host` names this machine as the containers reach it (default `host.docker.internal`). `-url` also takes several comma separated server URLs, used in turn, to run without the ingress. `-servers` names the servers behind the ingress, which are asked directly when a listing misses a credential. A credential that is missing from a listing begun after its issuance was acknowledged counts as a problem even when the next listing has it.

## Scale

Add a `wallet-3` service to the compose file with the same anchor and add it to both upstreams in `nginx.conf`. Each server re-reads the shared state at the request boundary and writes only the rows it changed, so servers issuing and presenting at the same time keep each other's changes.

## Clean up

```bash
docker compose down -v
```

`-v` removes the database volume and with it the wallet, its keys and its CA.
