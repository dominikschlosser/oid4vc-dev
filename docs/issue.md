# Issue

Generate test SD-JWT or mDOC credentials for development and testing. Produces valid, signed credentials using an ephemeral P-256 key by default (prints the public JWK to stderr).

```bash
ssi-debugger issue sdjwt
ssi-debugger issue sdjwt --pid
ssi-debugger issue sdjwt --pid --omit resident_address,birth_place,administrative_number
ssi-debugger issue sdjwt --claims '{"name":"Test","age":30}'
ssi-debugger issue sdjwt --iss https://my-issuer.example --vct my-type --exp 48h
ssi-debugger issue sdjwt --key signing-key.pem
ssi-debugger issue sdjwt --wallet                # Issue and import into wallet
ssi-debugger issue mdoc
ssi-debugger issue mdoc --pid
ssi-debugger issue mdoc --claims '{"name":"Test"}' --doc-type com.example.test
ssi-debugger issue mdoc --pid --wallet           # Issue mDoc and import into wallet
```

Round-trip with decode:

```bash
ssi-debugger issue sdjwt | ssi-debugger decode
ssi-debugger issue mdoc  | ssi-debugger decode
```

## Flags

### `issue sdjwt`

| Flag       | Default                   | Description                                    |
|------------|---------------------------|------------------------------------------------|
| `--claims` | —                         | Claims as JSON string or `@filepath`           |
| `--key`    | —                         | Private key file (PEM or JWK); ephemeral if omitted |
| `--iss`    | `https://issuer.example`  | Issuer URL                                     |
| `--vct`    | `urn:eudi:pid:de:1`       | Verifiable Credential Type                     |
| `--exp`    | `24h`                     | Expiration duration                            |
| `--pid`    | `false`                   | Use full EUDI PID Rulebook claims              |
| `--omit`   | —                         | Comma-separated claim names to exclude         |
| `--wallet` | `false`                   | Import the issued credential into the wallet   |

### `issue mdoc`

| Flag          | Default                        | Description                                    |
|---------------|--------------------------------|------------------------------------------------|
| `--claims`    | —                              | Claims as JSON string or `@filepath`           |
| `--key`       | —                              | Private key file (PEM or JWK); ephemeral if omitted |
| `--doc-type`  | `eu.europa.ec.eudi.pid.1`      | Document type                                  |
| `--namespace` | `eu.europa.ec.eudi.pid.1`      | Namespace                                      |
| `--pid`       | `false`                        | Use full EUDI PID Rulebook claims              |
| `--omit`      | —                              | Comma-separated claim names to exclude         |
| `--wallet`    | `false`                        | Import the issued credential into the wallet   |

When no `--claims` are provided, a minimal set of PID-like claims is used (given_name, family_name, birth_date). With `--pid`, the full EUDI PID Rulebook claim set is generated (27 claims including address, nationality, age attributes, document metadata, etc.).
