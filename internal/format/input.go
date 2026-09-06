// Copyright 2026 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package format

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// DefaultRemoteTimeout keeps unresponsive issuers and verifiers from delaying flows
// indefinitely.
const DefaultRemoteTimeout = 15 * time.Second

// Allow longer waits for slow counterparties, such as a conformance suite sharing the
// host.
const remoteTimeoutEnv = "EUDI_REMOTE_TIMEOUT"

var remoteTimeout = resolveRemoteTimeout(os.Getenv(remoteTimeoutEnv))

// Invalid or nonpositive durations keep the default. They must not disable timeouts.
func resolveRemoteTimeout(raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return DefaultRemoteTimeout
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value <= 0 {
		log.Printf("[HTTP] ignoring %s=%q (%v), using %s", remoteTimeoutEnv, raw, err, DefaultRemoteTimeout)
		return DefaultRemoteTimeout
	}
	return value
}

var httpClient = &http.Client{
	Timeout:   remoteTimeout,
	Transport: newPolicyTransport(),
}

// Reuse connections to avoid exhausting local ports during rapid fetches. Local
// endpoints bypass proxies and accept self-signed certificates.
var localHTTPClient = &http.Client{
	Timeout:   remoteTimeout,
	Transport: newLocalPolicyTransport(),
}

func newPolicyTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   dialControl,
	}).DialContext
	return transport
}

func newLocalPolicyTransport() *http.Transport {
	transport := newPolicyTransport()
	transport.Proxy = nil
	//nolint:gosec // Local dev endpoints use self-signed certificates on localhost/host.docker.internal.
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	// On the host, host.docker.internal may not resolve. Fall back to localhost so
	// URLs issued for Docker clients also work locally.
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: dialControl}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			if port, ok := strings.CutPrefix(addr, "host.docker.internal:"); ok {
				if conn2, err2 := dialer.DialContext(ctx, network, "localhost:"+port); err2 == nil {
					return conn2, nil
				}
			}
		}
		return conn, err
	}
	return transport
}

// HTTPClientForURL returns a shared fetch client configured for the target URL.
// Local developer endpoints bypass proxies and accept self-signed HTTPS certs.
// The clients are reused so connections pool instead of a new socket per fetch.
func HTTPClientForURL(rawURL string) *http.Client {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return httpClient
	}
	if isLocalFetchHost(u.Hostname()) {
		return localHTTPClient
	}
	return httpClient
}

func isLocalFetchHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost", "127.0.0.1", "::1", "host.docker.internal":
		return true
	default:
		return false
	}
}

func readStdin() (string, error) {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return "", fmt.Errorf("cannot read stdin: %w", err)
	}
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return "", fmt.Errorf("no input provided (use a file path, URL, raw string, or pipe to stdin)")
	}
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("reading stdin: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading file %s: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// ReadInput reads credential input from: URL, file path, "-" for stdin, or raw string.
func ReadInput(input string) (string, error) {
	input = strings.TrimSpace(input)

	if input == "-" || input == "" {
		return readStdin()
	}

	if strings.HasPrefix(input, "https://") || strings.HasPrefix(input, "http://") {
		return FetchURL(input)
	}

	// Try as file path. Inputs with a URI scheme (openid-credential-offer://,
	// file://, ...) are never file paths. Without this guard they could name
	// files on unusual filesystems.
	if !strings.Contains(input, "://") {
		if _, err := os.Stat(input); err == nil {
			return readFile(input)
		}
	}

	return input, nil
}

// ReadRemoteInput reads credential input in server context: http(s) URLs are
// fetched, everything else is returned verbatim. Unlike ReadInput it never
// touches stdin or the local filesystem, so visitor-supplied values cannot
// name files on the server.
func ReadRemoteInput(input string) (string, error) {
	input = strings.TrimSpace(input)
	if strings.HasPrefix(input, "https://") || strings.HasPrefix(input, "http://") {
		return FetchURL(input)
	}
	return input, nil
}

// ReadInputRaw reads input from stdin, a file, or returns the raw string.
// Unlike ReadInput, it does NOT HTTP-fetch URLs. Useful when the caller
// needs to detect the format before deciding whether to fetch.
func ReadInputRaw(input string) (string, error) {
	input = strings.TrimSpace(input)

	if input == "-" || input == "" {
		return readStdin()
	}

	if strings.Contains(input, "://") {
		return input, nil
	}

	if !strings.HasPrefix(input, "{") {
		if _, err := os.Stat(input); err == nil {
			return readFile(input)
		}
	}

	return input, nil
}

// MaxRemoteBytes limits credential, metadata and status list responses consistently.
const MaxRemoteBytes = maxFetchBytes

// ReadRemoteBody limits response size so peers cannot exhaust process memory.
func ReadRemoteBody(r io.Reader, what string) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxRemoteBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxRemoteBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", what, MaxRemoteBytes)
	}
	return b, nil
}

const maxFetchBytes = 10 << 20

// fetchAttempts is how many times a remote read is tried when the server does
// not answer at all. Only a request that got no response is repeated: OpenID4VP
// 1.0 §5.10.2 says "If the Verifier responds with any HTTP error response, the
// Wallet MUST terminate the process", and a timeout is not a response.
const fetchAttempts = 3

var fetchRetryDelay = 500 * time.Millisecond

func FetchURL(url string) (string, error) {
	var resp *http.Response
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return "", fmt.Errorf("fetching %s: %w", url, err)
		}
		// Go sends no Accept header by default. Some servers reject that.
		req.Header.Set("Accept", "*/*")

		var doErr error
		resp, doErr = HTTPClientForURL(url).Do(req)
		if doErr == nil {
			break
		}
		if attempt >= fetchAttempts {
			return "", fmt.Errorf("fetching %s: %w", url, doErr)
		}
		time.Sleep(fetchRetryDelay)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if msg := strings.TrimSpace(string(body)); msg != "" {
			return "", fmt.Errorf("fetching %s: HTTP %d: %s", url, resp.StatusCode, msg)
		}
		return "", fmt.Errorf("fetching %s: HTTP %d", url, resp.StatusCode)
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes+1))
	if err != nil {
		return "", fmt.Errorf("reading response from %s: %w", url, err)
	}
	if len(b) > maxFetchBytes {
		return "", fmt.Errorf("fetching %s: response exceeds %d bytes", url, maxFetchBytes)
	}

	return strings.TrimSpace(string(b)), nil
}
