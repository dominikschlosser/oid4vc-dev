# Build Caddy with https://github.com/mholt/caddy-ratelimit because the standard image
# cannot read the rate_limit directive.
FROM caddy:2-builder AS builder

RUN xcaddy build --with github.com/mholt/caddy-ratelimit

FROM caddy:2

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
