# Docker Verifier Testing Guide

The primary use case for the Docker image is **automated integration testing of OID4VP verifiers**. The container acts as a fully functional EUDI wallet that your verifier can send presentation requests to.

## Quick start

```bash
docker pull ghcr.io/dominikschlosser/ssi-debugger:latest
docker run -p 8085:8085 ghcr.io/dominikschlosser/ssi-debugger
```

The default CMD starts the wallet server with pre-loaded PID credentials in headless mode — ready for automated verifier testing out of the box.

You can override the command to use any CLI feature:

```bash
echo "eyJhbGci..." | docker run -i ghcr.io/dominikschlosser/ssi-debugger decode
docker run -i ghcr.io/dominikschlosser/ssi-debugger validate --trust-list https://example.com/trustlist.jwt < credential.txt
```

## How it works

1. The container starts with `--pid` (two pre-loaded EUDI PID credentials: one SD-JWT, one mDoc) and `--auto-accept` (automatically presents matching credentials without user consent)
2. Your verifier sends an OID4VP authorization request to the wallet's `/authorize` endpoint
3. The wallet evaluates the DCQL query, finds matching credentials, creates a VP token, and POSTs it back to your verifier's `response_uri`

## Wallet endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/authorize` | GET/POST | OID4VP authorization endpoint — accepts standard OID4VP query parameters (`client_id`, `response_type`, `dcql_query`, `nonce`, `state`, `response_uri`, `response_mode`, `request_uri`) |
| `/api/trustlist` | GET | Returns the wallet's ETSI trust list JWT — use this to validate the signatures of credentials issued by the wallet |
| `/api/credentials` | GET | Lists all credentials currently held by the wallet |

## Typical verifier integration test flow

1. Start the wallet container
2. Your verifier constructs an OID4VP authorization request with a DCQL query requesting PID attributes
3. Redirect/send the request to `http://<wallet>/authorize?client_id=...&response_type=vp_token&response_mode=direct_post&response_uri=http://<your-verifier>/callback&nonce=...&dcql_query=...`
4. The wallet auto-selects matching credentials and POSTs `vp_token` + `state` to your `response_uri`
5. Your verifier receives the VP token and can validate it using the wallet's trust list from `/api/trustlist`

## Docker Compose example

```yaml
services:
  wallet:
    image: ghcr.io/dominikschlosser/ssi-debugger:latest
    ports:
      - "8085:8085"
  verifier:
    build: .
    environment:
      WALLET_URL: http://wallet:8085
      # Use the wallet's trust list to validate received VP tokens
      TRUST_LIST_URL: http://wallet:8085/api/trustlist
```

## Testcontainers (Java)

```java
GenericContainer<?> wallet = new GenericContainer<>("ghcr.io/dominikschlosser/ssi-debugger:latest")
    .withExposedPorts(8085)
    .waitingFor(Wait.forHttp("/api/trustlist").forStatusCode(200));
wallet.start();

String walletUrl = "http://" + wallet.getHost() + ":" + wallet.getMappedPort(8085);

// Send an OID4VP request to the wallet
String authorizeUrl = walletUrl + "/authorize"
    + "?client_id=" + URLEncoder.encode(verifierClientId, UTF_8)
    + "&response_type=vp_token"
    + "&response_mode=direct_post"
    + "&response_uri=" + URLEncoder.encode(callbackUrl, UTF_8)
    + "&nonce=" + nonce
    + "&dcql_query=" + URLEncoder.encode(dcqlQuery, UTF_8);

// The wallet will auto-accept and POST the VP token to your callbackUrl
httpClient.send(HttpRequest.newBuilder(URI.create(authorizeUrl)).GET().build(),
    HttpResponse.BodyHandlers.ofString());

// Validate received credentials using the wallet's trust list
String trustListUrl = walletUrl + "/api/trustlist";
```

## Testcontainers (Go)

```go
ctx := context.Background()
wallet, _ := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
    ContainerRequest: testcontainers.ContainerRequest{
        Image:        "ghcr.io/dominikschlosser/ssi-debugger:latest",
        ExposedPorts: []string{"8085/tcp"},
        WaitingFor:   wait.ForHTTP("/api/trustlist").WithPort("8085"),
    },
    Started: true,
})

walletURL, _ := wallet.Endpoint(ctx, "http")
// Send OID4VP request to walletURL + "/authorize?..."
// Wallet POSTs VP token back to your response_uri
// Validate with trust list from walletURL + "/api/trustlist"
```

## Custom PID claims

The default CMD starts the wallet with two EUDI PID credentials (SD-JWT + mDoc) containing standard attributes (`given_name`, `family_name`, `birth_date`, `age_over_18`, etc.). To customize the PID claims, generate them first and mount the wallet directory:

```bash
# Generate custom PIDs into a local directory, then start the wallet with them
docker run --rm -v wallet-data:/root/.ssi-debugger/wallet ghcr.io/dominikschlosser/ssi-debugger \
  wallet generate-pid --claims '{"given_name":"MAX","family_name":"POWER"}'

docker run -p 8085:8085 -v wallet-data:/root/.ssi-debugger/wallet ghcr.io/dominikschlosser/ssi-debugger \
  wallet serve --auto-accept --port 8085
```

## Supported response modes

`direct_post` (default) and `direct_post.jwt` (JARM — the wallet encrypts the response using the verifier's ephemeral key from the request object).
