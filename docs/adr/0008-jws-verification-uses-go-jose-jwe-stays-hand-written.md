# JWS verification uses go-jose, JWE uses local code

All JWS verification uses `jws.Verify`, a wrapper around go-jose. Each caller supplies the allowed algorithms when parsing. The token cannot choose which algorithms the verifier accepts. This gives `sdjwt`, `statuslist`, `wallet` and `demorp` the same signature checks.

## Why go-jose cannot do the JWE

go-jose derives the ECDH-ES key with empty `apu` and `apv` on the encrypt path (`DeriveECDHES(algID, []byte{}, []byte{}, ...)` in its key generator) and exposes no way to set them. ISO 18013-7 Annex B requires the mdoc generated nonce in `apu` and the request nonce in `apv`, and this wallet sends both for mdoc presentations. Encrypting through go-jose would derive a key from empty values while the header advertised the nonces, and every such presentation would fail to decrypt at the verifier.

go-jose reads `apu` and `apv` correctly when decrypting. Using the library for decryption alone would leave two implementations of the Concat KDF to maintain and compare. Both directions therefore use the same local implementation.

The proxy also decrypts captured JWEs using content encryption keys from a key log, without the private key.

## Consequences

Before moving JWE onto any library, check that it can set `apu` and `apv` when encrypting. Run the mdoc presentation tests to check this. The JWE tests alone do not cover it.

Comments in the JWE code explain the key derivation and the AES-CBC-HS256 path, including PKCS#7 padding. A library that supports the required nonce handling could replace this code.
