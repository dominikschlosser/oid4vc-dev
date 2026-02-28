FROM golang:1.26-alpine AS build
ARG VERSION=dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -ldflags "-s -w -X github.com/dominikschlosser/oid4vc-dev/cmd.Version=${VERSION}" -o oid4vc-dev .

FROM alpine:3.21
RUN adduser -D -h /home/app app
COPY --from=build /app/oid4vc-dev /usr/local/bin/
USER app
ENV PORT=8085
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -q --spider http://localhost:${PORT}/ || exit 1
ENTRYPOINT ["oid4vc-dev"]
CMD ["wallet", "serve", "--auto-accept", "--pid", "--port", "8085"]
