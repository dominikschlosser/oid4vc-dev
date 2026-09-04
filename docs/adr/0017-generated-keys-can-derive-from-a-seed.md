# Generated keys can derive from a seed

The keys a wallet generates on first use (holder, issuer, the shared CA, the TLS leaf) can derive from a seed string (`--seed`, `EUDI_DEV_SEED`) through HKDF-SHA256, one label per key. A wallet that stores nothing, such as a container on the memory backend or one on a read-only filesystem, then serves the same keys and the same CA on every start. A verifier keeps trusting the trust list it fetched before a restart, and nothing has to be mounted, backed up or shared.

Keys already in the store are used as they are. The seed only decides what a missing key becomes, so it changes nothing for a wallet that has state.

A wallet that stores nothing signs its certificates anew on each start, with a fresh serial. Go's ECDSA signing draws its nonce from the system's random source, so the certificate bytes differ between starts while their keys and subjects stay the same. A verifier matches the CA by subject and key, so the chain still verifies. A serial is never reused, which RFC 5280 requires and browsers enforce.

## The image default

The image sets `EUDI_DEV_SEED=auto`: the built-in seed applies when the state lives in memory and random keys are generated when a volume or a database holds the state. A seed that ships with a public image is public, so it must never become a CA that persists anywhere. The memory backend loses its state on exit, so nothing derived from the public seed outlives the container.

## Consequences

Anyone who knows or guesses a seed holds every key derived from it (see SECURITY.md). A test bench picks a seed of its own, or none.

The seed travels in the environment. The detached server and the URL handler script get it from `EUDI_DEV_SEED`, never from a command line.

The memory backend, the default seed and the read-only filesystem together make a container that needs no state at all. That is the container the verifier and issuer test setups start and throw away.
