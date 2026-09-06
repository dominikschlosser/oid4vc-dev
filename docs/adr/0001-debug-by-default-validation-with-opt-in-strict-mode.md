# Debug-by-default validation with an opt-in strict mode

Validation has two modes (`internal/wallet/mode.go`). In `debug`, the default, normative findings are logged as warnings and the flow continues. This lets developers see how a malformed request affects the exchange. In `strict`, the same findings stop the flow.

`validatePresentationRequestCore` collects findings and applies the selected mode. DCQL matching, request object signature verification and `wallet_nonce` checks follow it too. See `docs/spec-compliance.md` for behavior by feature.

`--haip` is a separate switch. It adds the HAIP 1.0 checks on top of the base specifications. Debug mode logs HAIP violations and continues. Strict mode rejects requests that violate the profile.

## Consequences

In debug mode, the wallet can present credentials even when the request object signature is invalid. It records the failed check in the activity log. Conformance runs and anything checking spec behaviour must pass `--mode strict`.
