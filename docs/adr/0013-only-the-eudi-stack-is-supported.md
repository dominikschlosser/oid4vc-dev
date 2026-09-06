# Only what the EUDI stack references is supported

The specifications this toolkit implements are the ones the EUDI Architecture and Reference Framework builds on: OpenID4VP 1.0, OpenID4VCI 1.0, HAIP 1.0, SD-JWT and SD-JWT VC, ISO 18013-5, ETSI TS 119 602, and the Token Status List draft. `docs/spec-compliance.md` lists them and says what is implemented from each.

The toolkit recognises and reports mechanisms outside that set, but does not implement them.

## Why recognising is not supporting

Silently ignoring an unsupported mechanism can make a request appear verified. A finding must identify which mechanism was skipped and what remains unchecked.

When a request, credential or token uses an unsupported mechanism, the toolkit identifies it in a finding. It leaves the affected key or signature unresolved.

## What this looks like in the code

`openid_federation:` as a Client Identifier Prefix is refused with "not supported by this wallet". OID4VP 1.0 §5.9.3 defers its processing rules to OpenID Federation, and the wallet resolves no trust chain (`internal/wallet/clientid.go`).

A key named by a DID is reported as unresolved: in the credential import warning, in the HAIP findings, in the skipped-signature note of `validate`, and in the failure of a status list check (`keys.DIDReference`). An issuer key is resolved through the `x5c` chain HAIP 1.0 §6.1.1 requires or the issuer metadata SD-JWT VC defines. `did:key` carries its key in the identifier and could be decoded in a few lines. It is left out on purpose.

The Status List Token check accepts ES256 and ES384 only (`internal/statuslist/checker.go`).

## Deviations are still processed

Debug mode continues when the toolkit can process a request despite a profile violation. It collects findings ([ADR-0001](0001-debug-by-default-validation-with-opt-in-strict-mode.md)), so developers can inspect the exchange. For example, it can send `direct_post` where HAIP requires `direct_post.jwt`, or use a supported credential format outside the profile. A mechanism with no implementation cannot complete the flow. The wallet reports it as unsupported.

Support means the mechanism is checked. It does not mean the result is trusted: signatures are verified without being tied to a pre-registered trust list ([ADR-0009](0009-signatures-are-verified-but-not-anchored-to-a-pre-registered-trust-list.md)).

## Consequences

Add support when the EUDI ARF or a referenced specification defines the mechanism. Until then, report its use clearly. Revisit this decision when the supported specification set changes.

Findings must distinguish unsupported key resolution from a missing key or failed fetch. `SECURITY.md` and `docs/spec-compliance.md` describe the supported mechanisms.

A Request Object under a `decentralized_identifier:` or `verifier_attestation:` client identifier has its key in a place this wallet does not resolve. A request passed with no finding would look verified. So `VerifyRequestObjectSignature` reports which key it would have needed and where it would come from. It does the same for a bare `client_id`, whose key would have to be pre-registered, and this wallet registers nothing.
