// Package wallet implements a stateful testing wallet for OID4VP presentations and OID4VCI issuance flows.
package wallet

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/keys"
	"github.com/dominikschlosser/oid4vc-dev/internal/mdoc"
	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
	"github.com/dominikschlosser/oid4vc-dev/internal/sdjwt"
	"github.com/google/uuid"
)

// SessionTranscriptMode controls how the mDoc session transcript is constructed.
type SessionTranscriptMode string

const (
	// SessionTranscriptISO uses ISO 18013-7 Annex B.4.4 format (EUDI wallet default).
	// Hash inputs are CBOR-encoded [value, mdocGeneratedNonce] arrays, and the
	// handover is wrapped in CBOR Tag 24.
	SessionTranscriptISO SessionTranscriptMode = "iso"

	// SessionTranscriptOID4VP uses the OID4VP Appendix B.2.6 format.
	// Hash inputs are plain string bytes, and the handover is a plain array.
	SessionTranscriptOID4VP SessionTranscriptMode = "oid4vp"
)

// StatusEntry tracks the status list index and current status for a credential.
type StatusEntry struct {
	Index  int `json:"index"`
	Status int `json:"status"` // 0=valid, 1=revoked
}

// Wallet holds credentials, keys, and manages presentation consent flows.
type Wallet struct {
	HolderKey            *ecdsa.PrivateKey
	IssuerKey            *ecdsa.PrivateKey
	AutoAccept           bool
	SessionTranscript    SessionTranscriptMode // "oid4vp" (default) or "iso"
	Credentials          []StoredCredential
	StatusEntries        map[string]StatusEntry // credential ID → status entry
	StatusListCounter    int                    // next available status list index
	BaseURL              string                 // base URL for status list endpoint
	Requests             map[string]*ConsentRequest
	Log                  []LogEntry
	mu                   sync.RWMutex
	subscribers          map[int64]chan *ConsentRequest
	subID                int64
	errSubscribers       map[int64]chan WalletError
	errSubID             int64
	lastError            *WalletError
}

// WalletError is an error event that can be displayed in the UI.
type WalletError struct {
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

// StoredCredential is a credential stored in the wallet.
type StoredCredential struct {
	ID          string         `json:"id"`
	Format      string         `json:"format"`       // "dc+sd-jwt" or "mso_mdoc"
	Raw         string         `json:"raw"`           // original credential string
	Claims      map[string]any `json:"claims"`        // decoded claims for display/matching
	VCT         string         `json:"vct,omitempty"` // SD-JWT vct
	DocType     string         `json:"doctype,omitempty"`
	Disclosures []sdjwt.Disclosure `json:"-"`
	NameSpaces  map[string][]mdoc.IssuerSignedItem `json:"-"`
}

// ConsentRequest represents a pending presentation or issuance consent.
type ConsentRequest struct {
	ID            string            `json:"id"`
	Type          string            `json:"type"` // "presentation" or "issuance"
	AuthRequest   *oid4vc.AuthorizationRequest `json:"-"`
	MatchedCreds  []CredentialMatch `json:"matched_credentials"`
	Status        string            `json:"status"` // "pending", "approved", "denied"
	ResultCh      chan ConsentResult    `json:"-"`
	SubmissionCh  chan SubmissionResult `json:"-"` // result of VP submission after approval
	CreatedAt     time.Time         `json:"created_at"`
	ClientID      string            `json:"client_id"`
	Nonce         string            `json:"nonce,omitempty"`
	ResponseURI   string            `json:"response_uri,omitempty"`
	DCQLQuery     map[string]any    `json:"dcql_query,omitempty"`
}

// CredentialMatch links a credential to a DCQL query credential ID.
type CredentialMatch struct {
	QueryID      string         `json:"query_id"`
	CredentialID string         `json:"credential_id"`
	Format       string         `json:"format"`
	VCT          string         `json:"vct,omitempty"`
	DocType      string         `json:"doctype,omitempty"`
	Claims       map[string]any `json:"claims"`
	SelectedKeys []string       `json:"selected_keys"` // claim names to disclose
}

// ConsentResult is returned by the consent flow.
type ConsentResult struct {
	Approved       bool
	SelectedClaims map[string][]string // credential ID → claim names
}

// SubmissionResult is the outcome of VP token submission after consent approval.
type SubmissionResult struct {
	RedirectURI string `json:"redirect_uri,omitempty"`
	Error       string `json:"error,omitempty"`
	StatusCode  int    `json:"status_code,omitempty"`
}

// LogEntry records a wallet action.
type LogEntry struct {
	Time    time.Time `json:"time"`
	Action  string    `json:"action"`
	Detail  string    `json:"detail"`
	Success bool      `json:"success"`
}

// New creates a new wallet with the given options.
func New(holderKey, issuerKey *ecdsa.PrivateKey, autoAccept bool) *Wallet {
	return &Wallet{
		HolderKey:   holderKey,
		IssuerKey:   issuerKey,
		AutoAccept:  autoAccept,
		Requests:    make(map[string]*ConsentRequest),
		subscribers: make(map[int64]chan *ConsentRequest),
	}
}

// GenerateDefaultCredentials generates SD-JWT and mDoc PID credentials.
// If PID credentials already exist, they are replaced. Optional claimOverrides
// are merged on top of the default PID claims. vct specifies the SD-JWT VCT;
// if empty, mock.DefaultPIDVCT is used.
func (w *Wallet) GenerateDefaultCredentials(claimOverrides map[string]any, vct string) error {
	if vct == "" {
		vct = mock.DefaultPIDVCT
	}
	log.Printf("[Wallet] Generating default PID credentials: vct=%s overrides=%d", vct, len(claimOverrides))
	issuerKey := w.IssuerKey

	sdClaims := make(map[string]any, len(mock.SDJWTPIDClaims))
	for k, v := range mock.SDJWTPIDClaims {
		sdClaims[k] = v
	}
	for k, v := range claimOverrides {
		sdClaims[k] = v
	}

	mdocClaims := make(map[string]any, len(mock.MDOCPIDClaims))
	for k, v := range mock.MDOCPIDClaims {
		mdocClaims[k] = v
	}
	for k, v := range claimOverrides {
		mdocClaims[k] = v
	}

	// Remove existing PID credentials before generating new ones
	w.removeByType("dc+sd-jwt", vct, "")
	w.removeByType("mso_mdoc", "", "eu.europa.ec.eudi.pid.1")

	// Generate SD-JWT PID
	var holderPubKey *ecdsa.PublicKey
	if w.HolderKey != nil {
		holderPubKey = &w.HolderKey.PublicKey
	}

	sdConfig := mock.SDJWTConfig{
		Issuer:    "https://issuer.example",
		VCT:       vct,
		ExpiresIn: 365 * 24 * time.Hour,
		Claims:    sdClaims,
		Key:       issuerKey,
		HolderKey: holderPubKey,
	}

	// Assign status list indices if enabled
	var sdStatusIdx, mdocStatusIdx int
	if w.BaseURL != "" {
		sdStatusIdx = w.nextStatusIndex()
		sdConfig.StatusListURI = w.BaseURL + "/api/statuslist"
		sdConfig.StatusListIdx = sdStatusIdx
	}

	sdResult, err := mock.GenerateSDJWT(sdConfig)
	if err != nil {
		return fmt.Errorf("generating SD-JWT PID: %w", err)
	}
	if err := w.ImportCredential(sdResult); err != nil {
		return fmt.Errorf("importing SD-JWT PID: %w", err)
	}

	// Register status entry for SD-JWT credential
	if w.BaseURL != "" {
		sdCred := w.Credentials[len(w.Credentials)-1]
		w.registerStatusEntry(sdCred.ID, sdStatusIdx)
	}

	mdocConfig := mock.MDOCConfig{
		DocType:   "eu.europa.ec.eudi.pid.1",
		Namespace: "eu.europa.ec.eudi.pid.1",
		Claims:    mdocClaims,
		Key:       issuerKey,
		HolderKey: holderPubKey,
	}

	if w.BaseURL != "" {
		mdocStatusIdx = w.nextStatusIndex()
		mdocConfig.StatusListURI = w.BaseURL + "/api/statuslist"
		mdocConfig.StatusListIdx = mdocStatusIdx
	}

	// Generate mDoc PID
	mdocResult, err := mock.GenerateMDOC(mdocConfig)
	if err != nil {
		return fmt.Errorf("generating mDoc PID: %w", err)
	}
	if err := w.ImportCredential(mdocResult); err != nil {
		return fmt.Errorf("importing mDoc PID: %w", err)
	}

	// Register status entry for mDoc credential
	if w.BaseURL != "" {
		mdocCred := w.Credentials[len(w.Credentials)-1]
		w.registerStatusEntry(mdocCred.ID, mdocStatusIdx)
	}

	return nil
}

// nextStatusIndex returns the next status list index and increments the counter.
func (w *Wallet) nextStatusIndex() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	idx := w.StatusListCounter
	w.StatusListCounter++
	return idx
}

// registerStatusEntry records a status entry for a credential.
func (w *Wallet) registerStatusEntry(credID string, idx int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.StatusEntries == nil {
		w.StatusEntries = make(map[string]StatusEntry)
	}
	w.StatusEntries[credID] = StatusEntry{Index: idx, Status: 0}
}

// removeByType removes credentials matching the given format and vct/doctype.
func (w *Wallet) removeByType(format, vct, docType string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	filtered := w.Credentials[:0]
	for _, c := range w.Credentials {
		if c.Format == format && (vct == "" || c.VCT == vct) && (docType == "" || c.DocType == docType) {
			continue
		}
		filtered = append(filtered, c)
	}
	w.Credentials = filtered
}

// ImportCredential auto-detects and imports a credential string.
func (w *Wallet) ImportCredential(raw string) error {
	raw = strings.TrimSpace(raw)

	// Try SD-JWT first (contains ~)
	if strings.Contains(raw, "~") {
		if err := w.importSDJWT(raw); err != nil {
			return err
		}
		cred := w.Credentials[len(w.Credentials)-1]
		log.Printf("[Wallet] Imported SD-JWT credential: vct=%s claims=%d disclosures=%d", cred.VCT, len(cred.Claims), len(cred.Disclosures))
		return nil
	}

	// Try mDoc (base64url or hex encoded CBOR)
	detected := format.Detect(raw)
	if detected == format.FormatMDOC {
		if err := w.importMDoc(raw); err != nil {
			return err
		}
		cred := w.Credentials[len(w.Credentials)-1]
		log.Printf("[Wallet] Imported mDoc credential: docType=%s claims=%d", cred.DocType, len(cred.Claims))
		return nil
	}

	// Try as SD-JWT without disclosures (just a JWT)
	if strings.Count(raw, ".") == 2 {
		if err := w.importSDJWT(raw + "~"); err != nil {
			return err
		}
		cred := w.Credentials[len(w.Credentials)-1]
		log.Printf("[Wallet] Imported SD-JWT credential (no disclosures): vct=%s claims=%d", cred.VCT, len(cred.Claims))
		return nil
	}

	return fmt.Errorf("unable to detect credential format (expected SD-JWT or mDoc)")
}

func (w *Wallet) importSDJWT(raw string) error {
	token, err := sdjwt.Parse(raw)
	if err != nil {
		return fmt.Errorf("parsing SD-JWT: %w", err)
	}

	cred := StoredCredential{
		ID:          uuid.New().String(),
		Format:      "dc+sd-jwt",
		Raw:         raw,
		Claims:      token.ResolvedClaims,
		Disclosures: token.Disclosures,
	}

	if vct, ok := token.Payload["vct"].(string); ok {
		cred.VCT = vct
	}

	w.mu.Lock()
	w.Credentials = append(w.Credentials, cred)
	w.mu.Unlock()
	return nil
}

func (w *Wallet) importMDoc(raw string) error {
	doc, err := mdoc.Parse(raw)
	if err != nil {
		return fmt.Errorf("parsing mDoc: %w", err)
	}

	claims := make(map[string]any)
	for ns, items := range doc.NameSpaces {
		for _, item := range items {
			claims[ns+":"+item.ElementIdentifier] = item.ElementValue
		}
	}

	cred := StoredCredential{
		ID:         uuid.New().String(),
		Format:     "mso_mdoc",
		Raw:        raw,
		Claims:     claims,
		DocType:    doc.DocType,
		NameSpaces: doc.NameSpaces,
	}

	w.mu.Lock()
	w.Credentials = append(w.Credentials, cred)
	w.mu.Unlock()
	return nil
}

// RemoveCredential removes a credential by ID.
func (w *Wallet) RemoveCredential(id string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, c := range w.Credentials {
		if c.ID == id {
			w.Credentials = append(w.Credentials[:i], w.Credentials[i+1:]...)
			return true
		}
	}
	return false
}

// GetCredentials returns a snapshot of all credentials.
func (w *Wallet) GetCredentials() []StoredCredential {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]StoredCredential, len(w.Credentials))
	copy(out, w.Credentials)
	return out
}

// GetCredential returns a credential by ID.
func (w *Wallet) GetCredential(id string) (StoredCredential, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, c := range w.Credentials {
		if c.ID == id {
			return c, true
		}
	}
	return StoredCredential{}, false
}

// AddLog records a log entry.
func (w *Wallet) AddLog(action, detail string, success bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.Log = append(w.Log, LogEntry{
		Time:    time.Now(),
		Action:  action,
		Detail:  detail,
		Success: success,
	})
}

// GetLog returns a snapshot of log entries.
func (w *Wallet) GetLog() []LogEntry {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]LogEntry, len(w.Log))
	copy(out, w.Log)
	return out
}

// CreateConsentRequest creates a new consent request and notifies subscribers.
func (w *Wallet) CreateConsentRequest(req *ConsentRequest) {
	w.mu.Lock()
	w.Requests[req.ID] = req
	subs := make([]chan *ConsentRequest, 0, len(w.subscribers))
	for _, ch := range w.subscribers {
		subs = append(subs, ch)
	}
	w.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- req:
		default:
		}
	}
}

// GetRequest returns a consent request by ID.
func (w *Wallet) GetRequest(id string) (*ConsentRequest, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	req, ok := w.Requests[id]
	return req, ok
}

// GetPendingRequests returns all pending consent requests.
func (w *Wallet) GetPendingRequests() []*ConsentRequest {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var out []*ConsentRequest
	for _, r := range w.Requests {
		if r.Status == "pending" {
			out = append(out, r)
		}
	}
	return out
}

// Subscribe returns a channel for new consent requests and an unsubscribe function.
func (w *Wallet) Subscribe() (<-chan *ConsentRequest, func()) {
	ch := make(chan *ConsentRequest, 16)
	w.mu.Lock()
	w.subID++
	id := w.subID
	w.subscribers[id] = ch
	w.mu.Unlock()

	return ch, func() {
		w.mu.Lock()
		delete(w.subscribers, id)
		w.mu.Unlock()
		for {
			select {
			case <-ch:
			default:
				return
			}
		}
	}
}

// SubscribeErrors returns a channel for error events and an unsubscribe function.
func (w *Wallet) SubscribeErrors() (<-chan WalletError, func()) {
	ch := make(chan WalletError, 16)
	w.mu.Lock()
	w.errSubID++
	id := w.errSubID
	if w.errSubscribers == nil {
		w.errSubscribers = make(map[int64]chan WalletError)
	}
	w.errSubscribers[id] = ch
	w.mu.Unlock()

	return ch, func() {
		w.mu.Lock()
		delete(w.errSubscribers, id)
		w.mu.Unlock()
		for {
			select {
			case <-ch:
			default:
				return
			}
		}
	}
}

// NotifyError sends an error event to all subscribers and stores it for polling.
func (w *Wallet) NotifyError(err WalletError) {
	w.mu.Lock()
	w.lastError = &err
	subs := make([]chan WalletError, 0, len(w.errSubscribers))
	for _, ch := range w.errSubscribers {
		subs = append(subs, ch)
	}
	w.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- err:
		default:
		}
	}
}

// PopLastError returns and clears the last error, if any.
func (w *Wallet) PopLastError() *WalletError {
	w.mu.Lock()
	defer w.mu.Unlock()
	err := w.lastError
	w.lastError = nil
	return err
}

// Rehydrate re-populates non-serializable fields (Disclosures, NameSpaces) from Raw.
func (c *StoredCredential) Rehydrate() error {
	if c.Raw == "" {
		return nil
	}

	switch c.Format {
	case "dc+sd-jwt":
		token, err := sdjwt.Parse(c.Raw)
		if err != nil {
			return fmt.Errorf("parsing SD-JWT: %w", err)
		}
		c.Disclosures = token.Disclosures
		if c.Claims == nil {
			c.Claims = token.ResolvedClaims
		}

	case "mso_mdoc":
		doc, err := mdoc.Parse(c.Raw)
		if err != nil {
			return fmt.Errorf("parsing mDoc: %w", err)
		}
		c.NameSpaces = doc.NameSpaces
		if c.Claims == nil {
			claims := make(map[string]any)
			for ns, items := range doc.NameSpaces {
				for _, item := range items {
					claims[ns+":"+item.ElementIdentifier] = item.ElementValue
				}
			}
			c.Claims = claims
		}
	}

	return nil
}

// LoadKeyFromFile loads a private key from a file path.
func LoadKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	privKey, err := keys.LoadPrivateKey(path)
	if err != nil {
		return nil, err
	}
	ecKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key must be an EC private key (P-256)")
	}
	return ecKey, nil
}

// CredentialSummary returns a JSON-serializable summary of a credential.
func CredentialSummary(c StoredCredential) map[string]any {
	summary := map[string]any{
		"id":     c.ID,
		"format": c.Format,
		"claims": c.Claims,
	}
	if c.VCT != "" {
		summary["vct"] = c.VCT
	}
	if c.DocType != "" {
		summary["doctype"] = c.DocType
	}
	return summary
}

// MarshalConsentRequest returns a JSON-serializable view of a consent request.
func MarshalConsentRequest(r *ConsentRequest) map[string]any {
	m := map[string]any{
		"id":         r.ID,
		"type":       r.Type,
		"status":     r.Status,
		"client_id":  r.ClientID,
		"created_at": r.CreatedAt.Format(time.RFC3339),
		"matched_credentials": r.MatchedCreds,
	}
	if r.Nonce != "" {
		m["nonce"] = r.Nonce
	}
	if r.ResponseURI != "" {
		m["response_uri"] = r.ResponseURI
	}
	if r.DCQLQuery != nil {
		m["dcql_query"] = r.DCQLQuery
	}
	return m
}

// ImportCredentialFromFile reads a file and imports the credential.
func (w *Wallet) ImportCredentialFromFile(path string) error {
	raw, err := format.ReadInput(path)
	if err != nil {
		return fmt.Errorf("reading credential file: %w", err)
	}
	return w.ImportCredential(raw)
}

// SetCredentialStatus sets the status value for a credential.
func (w *Wallet) SetCredentialStatus(credID string, status int) (StatusEntry, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	entry, ok := w.StatusEntries[credID]
	if !ok {
		return StatusEntry{}, false
	}
	entry.Status = status
	w.StatusEntries[credID] = entry
	return entry, true
}

// BuildStatusBitstring builds a bitstring from status entries (1 bit per entry).
func (w *Wallet) BuildStatusBitstring() []byte {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if w.StatusListCounter == 0 {
		// Minimum 1 byte
		return make([]byte, 1)
	}

	// Calculate number of bytes needed
	numBytes := (w.StatusListCounter + 7) / 8
	// Minimum 16 bytes as per RFC 9596
	if numBytes < 16 {
		numBytes = 16
	}
	bitstring := make([]byte, numBytes)

	for _, entry := range w.StatusEntries {
		if entry.Status != 0 {
			byteIdx := entry.Index / 8
			bitOffset := entry.Index % 8
			if byteIdx < len(bitstring) {
				bitstring[byteIdx] |= byte(1 << bitOffset)
			}
		}
	}

	return bitstring
}

// CredentialsJSON returns all credentials as JSON bytes.
func (w *Wallet) CredentialsJSON() ([]byte, error) {
	creds := w.GetCredentials()
	summaries := make([]map[string]any, len(creds))
	for i, c := range creds {
		summaries[i] = CredentialSummary(c)
	}
	return json.Marshal(summaries)
}
