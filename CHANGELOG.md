# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - 2026-03-04

### Added

- Display version in `wallet serve` and `proxy` startup banners

## [1.0.2] - 2026-03-04

### Fixed

- DCQL `trusted_authorities` now reads `values` (array) per OID4VP 1.0 spec instead of `value` (string)
- Codecov ignore patterns use regex syntax to match Go coverage paths

## [1.0.1] - 2026-03-04

### Added

- Version auto-detection from Go module info for `go install` builds (falls back to ldflags, then `dev`)

## [1.0.0] - 2026-03-04

First stable release of oid4vc-dev, a developer toolkit for debugging and testing
OID4VP, OID4VCI, SD-JWT, mDoc, and related SSI/eIDAS 2.0 protocols.

### Features

- **Credential Decoding** - Auto-detect and decode SD-JWT VC, JWT VC, and mDoc/mdoc credentials with selective disclosure resolution
- **Credential Validation** - Signature verification (ES256/384/512, RS256/384/512, PS256), certificate chain validation against ETSI trust lists, token status list (RFC 9596) checking
- **Credential Issuance** - Generate test SD-JWT, JWT VC, and mDoc credentials with configurable claims, key types, and certificate chains
- **DCQL Evaluation** - Parse and evaluate Digital Credentials Query Language queries with credential matching, claim_sets, and credential_sets support
- **Wallet** - Full OID4VP 1.0 wallet with consent UI, supporting:
  - All client_id schemes (x509_san_dns, x509_hash, redirect_uri, verifier_attestation, decentralized_identifier)
  - Response modes: direct_post, direct_post.jwt (JARM), fragment
  - Encrypted request objects (JWE with ECDH-ES)
  - HAIP 1.0 enforcement mode
  - SIOPv2 self-issued ID token (response_type "vp_token id_token")
  - OID4VCI pre-authorized code flow with tx_code support
  - DCQL `trusted_authorities` (`etsi_tl`) filtering
  - Session transcript generation (OID4VP and ISO 18013-7 modes)
- **Proxy** - Debugging reverse proxy that intercepts, classifies, and decodes OID4VP/VCI traffic with:
  - Live web dashboard with SSE streaming
  - HAR export
  - Automatic JWE decryption (key extraction from subprocess stdout)
  - Subprocess management for proxied services
- **Web UI** - Browser-based credential decoder and validator
- **QR Code** - Screen capture and decode support (macOS)
- **Docker** - Multi-arch Docker image with HTTP API for integration testing (Testcontainers support)
### Spec Compliance

- OID4VP 1.0 (Draft 28) - Authorization request parsing, DCQL, JAR, all response modes
- OID4VCI 1.0 - Pre-authorized code grant, credential endpoint, proof of possession
- HAIP 1.0 - Full enforcement of mandatory parameters and algorithms
- SD-JWT (RFC 9809) - Parsing, disclosure resolution, key binding JWT, SHA-256/384/512
- mDoc (ISO 18013-5) - CBOR parsing, COSE_Sign1 verification, MSO validation
- ETSI TS 119 612 - Trust list generation and certificate chain validation
- RFC 9596 - Token status list generation and checking
- SIOPv2 - Self-issued ID token with JWK thumbprint subject

[1.0.3]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.3
[1.0.2]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.2
[1.0.1]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.1
[1.0.0]: https://github.com/dominikschlosser/oid4vc-dev/releases/tag/v1.0.0
