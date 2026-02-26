package proxy

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"

	"github.com/dominikschlosser/ssi-debugger/internal/web"
)

// Dashboard serves the web dashboard for live traffic inspection.
type Dashboard struct {
	store *Store
	port  int
}

// NewDashboard creates a new dashboard server.
func NewDashboard(store *Store, port int) *Dashboard {
	return &Dashboard{store: store, port: port}
}

// ListenAndServe starts the dashboard HTTP server.
func (d *Dashboard) ListenAndServe() error {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/entries", d.handleEntries)
	mux.HandleFunc("GET /api/har", d.handleHAR)
	mux.HandleFunc("GET /api/stream", d.handleStream)

	// Mount the credential decoder web UI under /decode/
	decodeMux := web.NewMux("")
	mux.Handle("/decode/", http.StripPrefix("/decode", decodeMux))

	sub, _ := fs.Sub(staticFiles, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	return http.ListenAndServe(fmt.Sprintf(":%d", d.port), mux)
}

func (d *Dashboard) handleEntries(w http.ResponseWriter, r *http.Request) {
	entries := d.store.Entries()
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(entries)
}

func (d *Dashboard) handleHAR(w http.ResponseWriter, r *http.Request) {
	entries := d.store.Entries()
	har := GenerateHAR(entries)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ssi-debugger.har\"")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(har)
}

func (d *Dashboard) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	flusher.Flush()

	ch, unsub := d.store.Subscribe()
	defer unsub()

	for {
		select {
		case entry := <-ch:
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
