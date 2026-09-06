# Running OIDF Conformance Against the Demo Issuer and Verifier

This runbook runs the official OIDF issuer and verifier plans against the demo issuer and demo verifier that `wallet serve` mounts under `/issuer` and `/verifier`. It is the counterpart of [Running OIDF Wallet Conformance](./conformance-run.md): here the suite acts as the wallet and the demo issuer and verifier are under test.

Only the wallet goes through certification. These issuer and verifier plans run locally (or on the hosted demo service) as quality checks, and the wrapper refuses the production certification service.

## What Runs

The wrapper starts one wallet server and drives these plans through the official `run-test-plan.py`:

- `oid4vci-1_0-issuer-test-plan` against the demo issuer, three times (authorization code wallet initiated, authorization code issuer initiated, pre-authorized code)
- `oid4vci-1_0-issuer-haip-test-plan` against the demo issuer (SD-JWT VC, authorization code, issuer initiated). Only the VCI modules run. The demo issuer implements the minimal HAIP profile a wallet needs (PAR, PKCE S256, DPoP, attestation-based client authentication), and the plan's appended FAPI2 Security Profile server modules need a full OAuth authorization server
- `oid4vp-1final-verifier-test-plan` against the demo verifier, three times (SD-JWT VC signed request, SD-JWT VC unsigned request under the `redirect_uri` prefix, mdoc signed request)
- `oid4vp-1final-verifier-haip-test-plan` against the demo verifier (SD-JWT VC and mdoc, both `direct_post.jwt`)

The wrapper excludes modules for features the demo services do not offer. The official runner counts skips as failures.

Excluded issuer checks cover signed metadata, required key attestations and credential encryption. Batch checks run only in scenarios that supply a batch offer. Signed verifier scenarios exclude `request-uri-method-post` because the demo verifier serves requests through GET.

The pre-authorized code scenario also leaves out the six client attestation negative modules. Suite release-v5.2.4 breaks them under that grant: after the expected token refusal the module continues into the credential request and the suite interrupts the module with "Condition called when test status is 'WAITING'. This is a bug in the test module". The same modules complete under both authorization code scenarios, where the refusal happens at the PAR endpoint.

The harness replaces the human tester the plans expect:

- it pushes a fresh demo credential offer to the suite's exposed `credential_offer` endpoint whenever an issuer-initiated module waits for one (by value, since a `credential_offer_uri` must be https)
- it signs in at the demo issuer's authorization page as the demo account (alice) and follows the redirect to the suite's callback
- it creates a demo verifier request per verifier module and delivers its query string to the suite's authorization endpoint, in place of the wallet an `openid4vp://` link would invoke
- it uploads the screenshot placeholders the verifier plans require at the end

Verifier modules end in `REVIEW` because the suite cannot observe the verifier's decision. The harness also checks the demo verifier's recorded result. Tampered presentations must be `failed` and valid presentations must be `verified`. A mismatch exits with code 3.

## Prerequisites

The same as [Running OIDF Wallet Conformance](./conformance-run.md): a local conformance-suite checkout at the documented baseline, and the suite server running on the host behind its nginx.

## Run

```bash
OIDF_SUITE_DIR="$PWD/../conformance-suite" \
OIDF_SUITE_TAG=release-v5.2.4 \
OIDF_RUN_DIR=/tmp/oidf-demorp-conformance \
  scripts/oidf-demorp-conformance.sh
```

Selected scenarios only (substring match on the scenario slug):

```bash
ONLY_SCENARIOS=vp-verifier-final-sdjwt,vci-issuer-preauth \
  scripts/oidf-demorp-conformance.sh
```

The `--rerun` selector passes through to the official runner exactly as in the wallet runbook.

## How the Demo Pair Is Served

The verifier plans require the `request_uri` and the `response_uri` to be https, and the HAIP issuer metadata checks require an https credential issuer. The wrapper starts the wallet with an https base URL and `--serve-tls`, so the wallet binds that origin itself with its own TLS certificate (the suite skips certificate verification on outbound calls).

The suite signs the credentials it presents to the demo verifier under its own CAs (the `vp-signing` CA from `scripts/certs-keys` for SD-JWT VCs, a built-in mdoc IACA root for mdocs). The wrapper passes both to the wallet as `--demo-verifier-trust-anchor` files, so the demo verifier accepts those chains next to the wallet CA it always trusts. The IACA root is published by the suite server at `/mdoc-iaca-root.pem`. When that endpoint is unavailable the wrapper extracts the same certificate from the suite source.

The generated configs also give the suite the wallet CA: as `credential.trust_anchor_pem` in the issuer configs, so the suite validates the demo ticket's certificate chain, and as `client.request_object_trust_anchor_pem` in the verifier configs, so it validates the demo verifier's signed request objects.

## Environment Overrides

The wallet runbook's suite and server overrides apply unchanged (`CONFORMANCE_MODE`, `CONFORMANCE_SERVER`, `OIDF_SUITE_DIR`, `OIDF_SUITE_TAG`, `OIDF_SUITE_URL`, `OIDF_RUN_DIR`, `OIDF_MODULE_IDLE_TIMEOUT`, `OIDF_KEEP_SUITE_DB`, `OIDF_REQUEST_TIMEOUT`, `PORT`, `EUDI_DEV_STORAGE`). Set `OIDF_REQUEST_TIMEOUT=60` on a loaded machine, and leave `OIDF_KEEP_SUITE_DB` off for repeated runs (a suite database that holds several runs answers so slowly that modules stall). Specific to this wrapper:

- `OIDF_DEMO_BASE_URL`: the https origin the demo issuer and verifier advertise. Defaults to `https://localhost:<port+1>`
- `ONLY_SCENARIOS`: comma separated scenario slug substrings to run a subset

`CONFORMANCE_MODE=hosted` needs a publicly reachable `OIDF_DEMO_BASE_URL` (a tunnel with its own TLS terminator), because the hosted suite fetches the demo endpoints itself. Local mode is the supported setup.

## Result Artifacts

The wrapper prints the run directory and leaves the same artifacts as the wallet wrapper (`wallet.log`, `runner.log`, `results/` with the exported archives and the generated configs). The runner log also contains the `[verdicts]` block with the demo verifier's outcome per verifier module.
