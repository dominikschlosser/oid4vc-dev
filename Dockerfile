FROM golang:1.25-alpine AS build
ARG VERSION=dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -ldflags "-s -w -X github.com/dominikschlosser/ssi-debugger/cmd.Version=${VERSION}" -o ssi-debugger .

FROM alpine:latest
COPY --from=build /app/ssi-debugger /usr/local/bin/
ENTRYPOINT ["ssi-debugger"]
CMD ["wallet", "serve", "--auto-accept", "--pid", "--port", "8085"]
