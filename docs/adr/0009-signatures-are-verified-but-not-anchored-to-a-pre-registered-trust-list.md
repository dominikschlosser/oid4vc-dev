# Signatures are verified but not anchored to a pre-registered trust list

When a verifier sends a signed request object, the wallet verifies the JWS against the leaf certificate in the `x5c` header and checks that the supplied chain is internally consistent. When an issuer serves signed Credential Issuer Metadata, the wallet verifies the signature over its `x5c` leaf and checks `typ`, `alg` and a `sub` matching the issuer identifier. The wallet has no configured trust anchors for either check.

## Why there is nothing to anchor to

This test wallet is not provisioned with trusted verifier or issuer CAs. It can check signature validity and chain consistency, but cannot establish who controls the root certificate.

`verifySuppliedX5CChain` builds a root pool from the top certificate of the supplied chain and verifies the leaf against that. This proves the chain is consistent. It says nothing about who issued its root. `verifyIssuerMetadataChainTrust` logs "signed but unplaced" when it cannot anchor the signer, so the gap is visible.

An attacker can generate a certificate, sign a request object or issuer metadata, and supply a matching `x509_hash` or `sub`. The signature and chain checks will pass. They prove that the data is internally consistent, not that the signer is trusted.

## What is still enforced

A request object for a signing-required `client_id` prefix must be signed (an `alg` of `none` is a finding, fatal in strict mode). The `x509_hash` value must be the SHA-256 of the certificate that signed the request. Under HAIP the signing certificate must not be self-signed, and the trust anchor must not be in the `x5c` header. These checks work without a configured CA, but do not establish trust in the signer.

## Consequences

Request object and issuer metadata verification use no configured CA or trust list.

Documentation and findings describe these results as signature and chain-consistency checks. They do not establish the signer's identity. `SECURITY.md` and `docs/spec-compliance.md` state this limit. Strict mode ([ADR-0001](0001-debug-by-default-validation-with-opt-in-strict-mode.md)) makes findings fatal only for checks the wallet can perform.
