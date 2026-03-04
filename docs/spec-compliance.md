# Spec Compliance

Status of implemented features against the relevant specifications.

## OID4VP 1.0 (OpenID for Verifiable Presentations)

| Feature | Status | Notes |
|---------|--------|-------|
| Authorization request parsing | Implemented | `openid4vp://`, `haip://`, `eudi-openid4vp://` schemes |
| `request_uri` (GET) | Implemented | Fetches and parses signed request objects |
| `request_uri_method=post` | Implemented | Sends `wallet_metadata` and `wallet_nonce` |
| Encrypted request objects (JWE) | Implemented | `--require-encrypted-request` flag |
| DCQL query evaluation | Implemented | Including `credential_sets` constraints |
| `direct_post` response mode | Implemented | |
| `direct_post.jwt` response mode | Implemented | JARM-encrypted responses |
| JAR (signed request objects) | Implemented | Signature verification with x5c chain |
| `x509_san_dns:` client_id | Implemented | Verified against leaf cert SAN |
| `x509_hash:` client_id | Implemented | SHA-256 thumbprint matching |
| `redirect_uri:` client_id | Implemented | Parsed, no additional validation |
| `verifier_attestation:` client_id | Validated | Checks JWT structure in header, verifies `sub` claim matches client_id |
| `decentralized_identifier:` client_id | Validated | DID format validation, `kid` cross-check (full DID resolution not implemented) |
| VP Token as JSON array | Implemented | Multiple credentials in a single response |
| `fragment` response mode | Implemented | Builds redirect URL with vp_token/state as fragment params; not the default |
| SIOPv2 self-issued `id_token` | Implemented | `response_type=vp_token id_token` or `id_token` alone |
| `transaction_data` | Not implemented | Optional for verifiers to send; wallets MUST reject if unsupported |

## OID4VCI 1.0 (OpenID for Verifiable Credential Issuance)

| Feature | Status | Notes |
|---------|--------|-------|
| Credential offer parsing | Implemented | `openid-credential-offer://` scheme |
| Pre-authorized code grant | Implemented | With optional `tx_code` |
| Authorization code grant | Not implemented | Optional per spec; offers with only `authorization_code` are rejected |
| Token endpoint | Implemented | Exchanges pre-authorized code for access token |
| Credential endpoint | Implemented | Proof of possession via JWT |
| Batch credential issuance | Not implemented | Optional per spec |
| Deferred credential issuance | Not implemented | Optional per spec |

## HAIP 1.0 (High Assurance Interoperability Profile)

| Feature | Status | Notes |
|---------|--------|-------|
| `response_mode` must be `direct_post.jwt` | Enforced | With `--haip` flag |
| `client_id` must use `x509_hash:` | Enforced | With `--haip` flag |
| Signed request object (JAR) required | Enforced | With `--haip` flag |
| DCQL query required | Enforced | With `--haip` flag |
| Request object `alg` must be ES256 | Enforced | With `--haip` flag |

## SD-JWT (Selective Disclosure JWT)

| Feature | Status | Notes |
|---------|--------|-------|
| Parsing (header, payload, disclosures) | Implemented | |
| `_sd` claim resolution | Implemented | Recursive |
| Array disclosures | Implemented | `...` sentinel values |
| Key Binding JWT | Implemented | Generated during presentation |
| Signature verification (ES256/384/512) | Implemented | |
| Signature verification (RS256/384/512, PS256) | Implemented | |
| SHA-256/384/512 disclosure digests | Implemented | |

## mDOC / ISO 18013-5

| Feature | Status | Notes |
|---------|--------|-------|
| IssuerSigned CBOR parsing | Implemented | |
| DeviceResponse generation | Implemented | |
| COSE_Sign1 verification | Implemented | ES256 |
| MSO (Mobile Security Object) parsing | Implemented | |
| Validity info (validFrom, validUntil) | Implemented | |
| IssuerSignedItem digest verification | Implemented | |
| Session transcript (OID4VP mode) | Implemented | Default |
| Session transcript (ISO 18013-7 mode) | Implemented | `--session-transcript iso` |
| DeviceSigned generation | Implemented | Wallet generates DeviceAuth in DeviceResponse |

## ETSI TS 119 612 Trust Lists

| Feature | Status | Notes |
|---------|--------|-------|
| Trust list JWT generation | Implemented | Wallet generates its own |
| Trust list JWT parsing | Implemented | |
| Certificate chain validation against trust list | Implemented | In `validate` command |

## Token Status List (RFC 9596)

| Feature | Status | Notes |
|---------|--------|-------|
| Status list JWT generation | Implemented | `--status-list` flag |
| Status list JWT parsing | Implemented | |
| Revocation status check | Implemented | In `validate --status-list` |
| Runtime status changes via API | Implemented | `POST /api/credentials/<id>/status` |
