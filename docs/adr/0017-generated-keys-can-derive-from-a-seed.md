# Generated keys can derive from a seed

The keys a wallet generates on first use (holder, issuer, the shared CA, the TLS leaf) can derive from a seed string (`--seed`, `EUDI_DEV_SEED`) through HKDF-SHA256, one label per key. A wallet that stores nothing, such as a container on the memory backend or one on a read-only filesystem, then serves the same keys and the same CA on every start. A verifier keeps trusting the trust list it fetched before a restart, and nothing has to be mounted, backed up or shared.

Keys already in the store are used as they are. The seed only decides what a missing key becomes, so it changes nothing for a wallet that has state.

A wallet that stores nothing signs its CA and TLS certificates anew on each start, each with a random serial. Go's ECDSA signing draws its nonce from the system's random source, so the certificate bytes differ between starts while their keys and subjects stay the same. A verifier matches the CA by subject and key, so the chain still verifies. The credential-signing leaf keeps one serial per trust-list profile, derived from the profile name.

## The image default

The image sets `EUDI_DEV_SEED=eudi-dev` with the memory backend, so every container serves the same keys and CA without any state. A seed that ships with a public image is public, so it must not become a CA that persists anywhere. A deployment that persists sets an empty seed for random keys, as the public demo does. `wallet serve` warns when the public seed meets `--demo` or a persisting backend. `auto` applies the same seed on the memory backend only.

## Consequences

Anyone who knows or guesses a seed holds every key derived from it (see SECURITY.md). A test bench picks a seed of its own, or none.

The seed travels in the environment. The detached server inherits `EUDI_DEV_SEED` and never sees the seed on its command line. The URL handler script carries no seed, so a wallet it starts generates random keys unless the handler's environment sets `EUDI_DEV_SEED`.

The memory backend, the default seed and the read-only filesystem together make a container that needs no state at all. That is the container the verifier and issuer test setups start and throw away.
