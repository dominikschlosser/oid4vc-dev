# OIDF Conformance

This repository can be used against the OpenID Foundation wallet conformance tests in **strict** mode, but not all official test plans are supported yet.

## What is included here

- `scripts/oidf-wallet-conformance.sh` starts the built-in wallet in a conformance-friendly mode:
  - `wallet serve`
  - `--mode strict`
  - `--auto-accept`
  - `--pid`
- The wallet now uses final-spec request precedence and final OID4VCI credential request payloads.

## Current scope

The current strict-mode wallet is suitable for the OID4VP subset that matches the features implemented in this repository:

- `openid4vp://`, `haip-vp://`, `eudi-openid4vp://`
- `direct_post` and `direct_post.jwt`
- signed Request Objects with `x5c`
- `request_uri` and `request_uri_method=post`
- SD-JWT and mDoc presentation
- DCQL-based matching

## Known gaps

These areas still prevent claiming full OIDF wallet-suite coverage:

- no Presentation Exchange / `presentation_definition` support
- no `dc_api` / `dc_api.jwt` response modes
- no full verifier trust-anchor management for Request Object chains beyond the supplied `x5c`
- HAIP support is currently an **OID4VP subset**, not the full HAIP 1.0 profile
- no integrated runner for the external OIDF certification service; the official tests still need to be configured and launched there

## Running against the OIDF service

1. Start the wallet:

```bash
scripts/oidf-wallet-conformance.sh
```

2. Use the running wallet endpoint in the OIDF conformance service as the wallet under test.

3. Select only plans that match the current implementation scope above.

## References

- [OpenID4VP 1.0 Final](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
- [OpenID4VCI 1.0 Final](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html)
- [HAIP 1.0 Final](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html)
- [OIDF Conformance Service](https://www.certification.openid.net/)
