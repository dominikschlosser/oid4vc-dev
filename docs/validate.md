# Validate

Validate a credential by checking signatures, expiry, and revocation status. Unlike `decode` (which only parses and displays), `validate` actively checks correctness.

If neither `--key` nor `--trust-list` is provided, signature verification is skipped and only expiry and status checks are performed. This is useful for quick revocation checks without needing the issuer's key.

```bash
# Full validation with signature verification
ssi-debugger validate --key issuer-key.pem credential.txt
ssi-debugger validate --trust-list trust-list.jwt credential.txt
ssi-debugger validate --key key.pem --status-list credential.txt
ssi-debugger validate --key key.pem --allow-expired credential.txt

# Expiry + revocation check without signature verification
ssi-debugger validate --status-list credential.txt
ssi-debugger validate credential.txt
```

## Flags

| Flag              | Description                                       |
|-------------------|---------------------------------------------------|
| `--key`           | Public key file (PEM or JWK) — optional            |
| `--trust-list`    | ETSI trust list JWT (file path or URL) — optional   |
| `--status-list`   | Check revocation via status list (network call)    |
| `--allow-expired` | Don't fail on expired credentials                  |

When a trust list is provided and the credential contains an x5c (SD-JWT) or x5chain (mDOC) certificate chain, the chain is validated against the trust list before verifying the signature.
