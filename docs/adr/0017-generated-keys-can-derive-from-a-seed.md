# Generated keys can derive from a seed

The wallet can derive generated holder, issuer, CA and TLS keys from `--seed` or `EUDI_DEV_SEED` using HKDF-SHA256 with a separate label per key. A wallet using memory storage then keeps the same keys across restarts without a volume or database. Verifiers can keep using the same CA trust anchor.

Existing keys take precedence. The seed is used only when generating a missing key.

With memory storage, the wallet creates new CA and TLS certificates on each start, using random serial numbers. Go's ECDSA signing draws its nonce from the system's random source, so the certificate bytes differ between starts while their keys and subjects stay the same. A verifier matches the CA by subject and key, so the chain still verifies. The credential-signing leaf keeps one serial per trust-list profile, derived from the profile name.

## The image default

The image sets `EUDI_DEV_SEED=eudi-dev` with the memory backend, so every container serves the same keys and CA without any state. The seed is public, so anyone can derive these keys. For persistent storage, set an empty seed to generate random keys, as the public demo does. `wallet serve` warns when the public seed is used with `--demo` or persistent storage. `auto` applies the same seed on the memory backend only.

## Consequences

Anyone who knows or guesses a seed can derive every key generated from it (see SECURITY.md). Test environments can choose a private seed or leave it empty.

The seed travels in the environment. The detached server inherits `EUDI_DEV_SEED` and never sees the seed on its command line. The URL handler script carries no seed, so a wallet it starts generates random keys unless the handler's environment sets `EUDI_DEV_SEED`.

The default container combines memory storage and a fixed public seed, and can run on a read-only filesystem.
