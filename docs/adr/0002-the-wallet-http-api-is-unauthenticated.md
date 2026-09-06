# The wallet HTTP API is unauthenticated

The wallet HTTP API has no authentication. CI jobs, Testcontainers tests, curl and the remote CLI can manage a wallet without setting up credentials first. Anyone who can reach the port controls the wallet and its credentials.

Run the wallet on localhost or an isolated test network, with test credentials only (see `SECURITY.md`).

For public hosting, use `--demo`. It closes the process and filesystem endpoints (`demoBlockedRoute` in `internal/wallet/demo.go`), blocks server-side fetches into private networks and resets state on a schedule. All remaining endpoints and data are public.

## Consequences

A malicious web page can send requests to localhost. To block those requests, `/api/` rejects an `Origin` from another site (`internal/httpsec/origin.go`). CLI tools and curl usually send no `Origin` header and can still use the API.
 `/api/dc-api` is exempt, because a verifier's page invokes the Digital Credentials API from its own origin. For an unsigned Digital Credentials API request, the wallet identifies the caller from the request origin and asks the user for consent.

The protocol endpoints (`/authorize`, `/credential-offer`, `/callback`) stay open to any origin.
