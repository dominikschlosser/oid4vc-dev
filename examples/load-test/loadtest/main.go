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

// Command loadtest drives the wallet behind the ingress with concurrent
// issuances, presentations and listings, then checks that nothing was lost:
// every issued credential is listed once, no two credentials share a status
// list index, every presentation reached the verifier callback, and every
// server reports the same credential count.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type options struct {
	walletURL     string
	callbackHost  string
	callbackPort  int
	issuers       int
	issues        int
	presenters    int
	presentations int
	readers       int
	servers       []string
}

func main() {
	var opts options
	flag.StringVar(&opts.walletURL, "url", "http://localhost:8080", "wallet URL (the ingress), or several comma separated URLs used in turn")
	flag.StringVar(&opts.callbackHost, "callback-host", "host.docker.internal", "host name the wallet containers reach this machine by")
	flag.IntVar(&opts.callbackPort, "callback-port", 9090, "port the verifier callback listens on")
	flag.IntVar(&opts.issuers, "issuers", 8, "concurrent issuing clients")
	flag.IntVar(&opts.issues, "issues", 20, "issuances per issuing client")
	flag.IntVar(&opts.presenters, "presenters", 8, "concurrent presenting verifiers")
	flag.IntVar(&opts.presentations, "presentations", 30, "presentations per verifier")
	flag.IntVar(&opts.readers, "readers", 4, "concurrent clients listing credentials while the others write")
	direct := flag.String("servers", "", "comma separated URLs of the servers behind the ingress, asked directly when a listing misses a credential")
	flag.Parse()
	if *direct != "" {
		opts.servers = strings.Split(*direct, ",")
	}
	targets = strings.Split(opts.walletURL, ",")
	opts.walletURL = "{target}"

	if err := run(opts); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	fmt.Println("PASS")
}

var client = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 64}}

// targets are the URLs requests go to in turn. One entry is the ingress.
var (
	targets   []string
	targetSeq atomic.Uint64
)

// at returns the URL of the next request, the placeholder replaced by the
// next target.
func at(walletURL, path string) string {
	if walletURL == "{target}" {
		walletURL = targets[targetSeq.Add(1)%uint64(len(targets))]
	}
	return walletURL + path
}

// timings collects request durations per operation.
type timings struct {
	mu   sync.Mutex
	data map[string][]time.Duration
}

func (t *timings) add(op string, d time.Duration) {
	t.mu.Lock()
	t.data[op] = append(t.data[op], d)
	t.mu.Unlock()
}

func (t *timings) report(elapsed time.Duration) {
	ops := make([]string, 0, len(t.data))
	for op := range t.data {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	fmt.Printf("%-14s %6s %9s %9s %9s %9s\n", "operation", "count", "rate/s", "p50", "p95", "max")
	for _, op := range ops {
		ds := t.data[op]
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		fmt.Printf("%-14s %6d %9.1f %9s %9s %9s\n", op, len(ds), float64(len(ds))/elapsed.Seconds(),
			ds[len(ds)/2].Round(time.Millisecond), ds[len(ds)*95/100].Round(time.Millisecond), ds[len(ds)-1].Round(time.Millisecond))
	}
}

type issued struct {
	id    string
	idx   int
	acked time.Time
}

func run(opts options) error {
	baseline, err := config(opts.walletURL)
	if err != nil {
		return err
	}
	fmt.Printf("target %s: storage=%v credentials=%v\n", strings.Join(targets, ", "), baseline["storage"], baseline["credential_count"])
	baseCount := int(baseline["credential_count"].(float64))

	callbacks := &callbackServer{received: make(map[string]string)}
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", opts.callbackPort))
	if err != nil {
		return fmt.Errorf("listening for verifier callbacks: %w", err)
	}
	srv := &http.Server{Handler: callbacks, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(listener) }()
	defer func() { _ = srv.Shutdown(context.Background()) }()
	callbackURL := fmt.Sprintf("http://%s:%d/callback", opts.callbackHost, opts.callbackPort)

	t := &timings{data: make(map[string][]time.Duration)}
	var (
		mu           sync.Mutex
		issuedCreds  []issued
		expected     = make(map[string]bool)
		firstErr     error
		wg           sync.WaitGroup
		readerErrors []string
	)
	fail := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}
	start := time.Now()

	for i := 0; i < opts.issuers; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for n := 0; n < opts.issues; n++ {
				began := time.Now()
				cred, err := issue(opts.walletURL, fmt.Sprintf("LOAD-%d-%d", worker, n))
				t.add("issue", time.Since(began))
				if err != nil {
					fail(err)
					return
				}
				mu.Lock()
				issuedCreds = append(issuedCreds, cred)
				mu.Unlock()
			}
		}(i)
	}
	for i := 0; i < opts.presenters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < opts.presentations; n++ {
				state := randomHex()
				mu.Lock()
				expected[state] = true
				mu.Unlock()
				began := time.Now()
				err := present(opts.walletURL, callbackURL, state)
				t.add("present", time.Since(began))
				if err != nil {
					fail(err)
					return
				}
			}
		}()
	}
	// Readers check that a credential acknowledged before a listing began is
	// in that listing, whichever server answers it.
	stopReaders := make(chan struct{})
	var readersWG sync.WaitGroup
	for i := 0; i < opts.readers; i++ {
		readersWG.Add(1)
		go func() {
			defer readersWG.Done()
			for {
				select {
				case <-stopReaders:
					return
				default:
				}
				mu.Lock()
				known := append([]issued(nil), issuedCreds...)
				mu.Unlock()
				began := time.Now()
				listed, err := list(opts.walletURL)
				t.add("list", time.Since(began))
				if err != nil {
					fail(err)
					return
				}
				for _, cred := range known {
					if listed.ids[cred.id] {
						continue
					}
					// Read again at once: a gap that closes is a delay, one
					// that stays is a loss.
					again, err := list(opts.walletURL)
					if err != nil {
						fail(err)
						return
					}
					detail := fmt.Sprintf("credential %s acked %s, listing began %s, missing from it (server %s), present on the next read from %s: %t",
						cred.id, cred.acked.Format("15:04:05.000"), began.Format("15:04:05.000"), listed.upstream, again.upstream, again.ids[cred.id])
					for _, server := range opts.servers {
						if l, err := list(server); err == nil {
							detail += fmt.Sprintf(", %s directly: %t (%d listed)", server, l.ids[cred.id], len(l.ids))
						}
					}
					mu.Lock()
					readerErrors = append(readerErrors, detail)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	close(stopReaders)
	readersWG.Wait()
	elapsed := time.Since(start)
	if firstErr != nil {
		return firstErr
	}

	// Presentations are answered asynchronously, so give the last callbacks
	// a moment to arrive.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && callbacks.count() < len(expected) {
		time.Sleep(200 * time.Millisecond)
	}

	t.report(elapsed)
	fmt.Printf("issued %d credentials, %d presentations requested, %d callbacks received in %s\n", len(issuedCreds), len(expected), callbacks.count(), elapsed.Round(time.Millisecond))

	var problems []string
	problems = append(problems, readerErrors...)

	final, err := list(opts.walletURL)
	if err != nil {
		return err
	}
	listed := final.ids
	if want := baseCount + len(issuedCreds); len(listed) != want {
		problems = append(problems, fmt.Sprintf("the wallet lists %d credentials, want %d (baseline %d plus %d issued)", len(listed), want, baseCount, len(issuedCreds)))
	}
	indices := make(map[int]string)
	for _, cred := range issuedCreds {
		if _, ok := listed[cred.id]; !ok {
			problems = append(problems, fmt.Sprintf("issued credential %s is not listed", cred.id))
		}
		if other, dup := indices[cred.idx]; dup {
			problems = append(problems, fmt.Sprintf("credentials %s and %s share status list index %d", other, cred.id, cred.idx))
		}
		indices[cred.idx] = cred.id
	}
	for state := range expected {
		token, ok := callbacks.get(state)
		if !ok {
			problems = append(problems, fmt.Sprintf("presentation %s never reached the verifier", state))
		} else if !strings.Contains(token, "~") {
			problems = append(problems, fmt.Sprintf("presentation %s carried no SD-JWT presentation", state))
		}
	}
	for i := 0; i < 6; i++ {
		cfg, err := config(opts.walletURL)
		if err != nil {
			return err
		}
		if got := int(cfg["credential_count"].(float64)); got != len(listed) {
			problems = append(problems, fmt.Sprintf("a server reports %d credentials while the listing has %d", got, len(listed)))
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		for _, p := range problems {
			fmt.Println("  -", p)
		}
		return fmt.Errorf("%d correctness problems", len(problems))
	}
	fmt.Printf("checks: %d credentials listed once, %d distinct status indices, %d presentations delivered, %d servers agree\n", len(issuedCreds), len(indices), len(expected), 6)
	return nil
}

func config(walletURL string) (map[string]any, error) {
	resp, err := client.Get(at(walletURL, "/api/config"))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var cfg map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("reading /api/config: %w", err)
	}
	return cfg, nil
}

func issue(walletURL, givenName string) (issued, error) {
	body, _ := json.Marshal(map[string]any{"format": "sdjwt", "template": "pid-sdjwt", "claims": map[string]any{"given_name": givenName}})
	resp, err := client.Post(at(walletURL, "/api/issue"), "application/json", bytes.NewReader(body))
	if err != nil {
		return issued{}, err
	}
	defer resp.Body.Close()
	var doc struct {
		ID     string `json:"id"`
		Status struct {
			Idx int `json:"idx"`
		} `json:"status"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil || resp.StatusCode != http.StatusCreated || doc.ID == "" {
		return issued{}, fmt.Errorf("issue: status %d, id %q, error %q: %w", resp.StatusCode, doc.ID, doc.Error, err)
	}
	return issued{id: doc.ID, idx: doc.Status.Idx, acked: time.Now()}, nil
}

const dcqlQuery = `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["given_name"]}]}]}`

func present(walletURL, callbackURL, state string) error {
	query := url.Values{
		"client_id":     {"redirect_uri:" + callbackURL},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"response_uri":  {callbackURL},
		"nonce":         {randomHex()},
		"state":         {state},
		"dcql_query":    {dcqlQuery},
	}
	resp, err := client.Get(at(walletURL, "/authorize?"+query.Encode()))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("authorize: status %d", resp.StatusCode)
	}
	return nil
}

// listing is one GET /api/credentials: the ids and the server that answered.
type listing struct {
	ids      map[string]bool
	upstream string
}

func list(walletURL string) (listing, error) {
	resp, err := client.Get(at(walletURL, "/api/credentials"))
	if err != nil {
		return listing{}, err
	}
	defer resp.Body.Close()
	var creds []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		return listing{}, fmt.Errorf("listing credentials: %w", err)
	}
	ids := make(map[string]bool, len(creds))
	for _, c := range creds {
		if ids[c.ID] {
			return listing{}, errors.New("credential " + c.ID + " is listed twice")
		}
		ids[c.ID] = true
	}
	return listing{ids: ids, upstream: resp.Header.Get("X-Upstream")}, nil
}

// callbackServer is the verifier: it receives the direct_post responses.
type callbackServer struct {
	mu       sync.Mutex
	received map[string]string
}

func (c *callbackServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.received[r.PostForm.Get("state")] = r.PostForm.Get("vp_token")
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte("{}"))
}

func (c *callbackServer) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.received)
}

func (c *callbackServer) get(state string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	token, ok := c.received[state]
	return token, ok
}

func randomHex() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
