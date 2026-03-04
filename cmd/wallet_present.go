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

package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"

	"github.com/dominikschlosser/oid4vc-dev/internal/config"
	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
	"github.com/dominikschlosser/oid4vc-dev/internal/wallet"
)

// dispatchOID4Opts holds options for dispatching an OID4VP/VCI URI.
type dispatchOID4Opts struct {
	port              int
	autoAccept        bool
	sessionTranscript string
	txCode            string
	haip              bool
}

// dispatchURI detects the URI type and dispatches to the appropriate wallet flow.
func dispatchURI(uri string, opts dispatchOID4Opts) error {
	detected := format.Detect(uri)

	switch detected {
	case format.FormatOID4VP:
		w, store, err := loadWallet()
		if err != nil {
			return err
		}
		if opts.autoAccept {
			w.AutoAccept = true
		}
		if opts.haip {
			w.RequireHAIP = true
		}
		if err := applySessionTranscriptMode(w, opts.sessionTranscript); err != nil {
			return err
		}
		return runPresent(w, store, uri, opts.port)

	case format.FormatOID4VCI:
		return processCredentialOffer(uri, opts.txCode)

	default:
		return fmt.Errorf("unable to detect URI type (expected openid4vp://, openid-credential-offer://, or similar): %s", format.Truncate(uri, 80))
	}
}

// runPresent handles an OID4VP authorization request: evaluates credentials,
// optionally shows a consent UI, creates VP tokens, and submits the response.
func runPresent(w *wallet.Wallet, store *wallet.WalletStore, uri string, port int) error {
	parsed, err := wallet.ParseAuthorizationRequest(uri)
	if err != nil {
		return fmt.Errorf("parsing authorization request: %w", err)
	}

	if warning := wallet.VerifyClientID(parsed.ClientID, parsed.RequestObject, wallet.GetResponseURI(parsed)); warning != "" {
		yellow := color.New(color.FgYellow)
		yellow.Printf("  WARNING: %s\n", warning)
		w.AddLog("presentation", fmt.Sprintf("client_id warning: %s", warning), false)
	}

	// Evaluate DCQL
	var matches []wallet.CredentialMatch
	if parsed.DCQLQuery != nil {
		matches = w.EvaluateDCQL(parsed.DCQLQuery)
	}

	if len(matches) == 0 {
		return fmt.Errorf("no matching credentials found for the DCQL query")
	}

	responseURI := parsed.ResponseURI
	if responseURI == "" {
		responseURI = parsed.RedirectURI
	}

	dim := color.New(color.Faint)

	// Start server so the trust list is available during verification
	srv := wallet.NewServer(w, port, nil)
	addr, err := srv.ListenAndServeBackground()
	if err != nil {
		return fmt.Errorf("starting server: %w", err)
	}
	defer srv.Shutdown()

	dim.Println("───────────────────────────────────────")
	yellow := color.New(color.FgYellow)
	yellow.Printf("  Verifier: %s\n", parsed.ClientID)
	fmt.Printf("  Trust List:  %s/api/trustlist\n", addr)
	dim.Printf("               http://host.docker.internal:%d/api/trustlist\n", port)
	for _, m := range matches {
		fmt.Printf("  Credential: %s (%s)\n", m.Format, typeLabel(m.VCT, m.DocType, m.Format))
		fmt.Printf("  Disclosing: %v\n", m.SelectedKeys)
	}

	// Wait for consent if not auto-accepting
	matches, submissionCh, denied := waitForConsent(w, matches, parsed, responseURI, addr, dim)
	if denied {
		return nil
	}

	dim.Println("───────────────────────────────────────")

	// Create and submit VP tokens
	err = submitPresentation(w, store, matches, parsed, responseURI, submissionCh, dim)
	if err != nil {
		return err
	}

	return nil
}

// waitForConsent shows a consent UI and waits for the user's decision.
// Returns the (potentially updated) matches, a submission channel for UI feedback,
// and whether the presentation was denied or timed out.
func waitForConsent(w *wallet.Wallet, matches []wallet.CredentialMatch, parsed *oid4vc.AuthorizationRequest, responseURI, addr string, dim *color.Color) ([]wallet.CredentialMatch, chan wallet.SubmissionResult, bool) {
	if w.AutoAccept {
		return matches, nil, false
	}

	consentReq := &wallet.ConsentRequest{
		ID:           uuid.New().String(),
		Type:         "presentation",
		MatchedCreds: matches,
		Status:       "pending",
		ResultCh:     make(chan wallet.ConsentResult, 1),
		SubmissionCh: make(chan wallet.SubmissionResult, 1),
		CreatedAt:    time.Now(),
		ClientID:     parsed.ClientID,
		Nonce:        parsed.Nonce,
		ResponseURI:  responseURI,
		DCQLQuery:    parsed.DCQLQuery,
	}

	w.CreateConsentRequest(consentReq)

	fmt.Printf("  Consent UI: %s\n", addr)
	dim.Println("───────────────────────────────────────")
	fmt.Println("Waiting for consent decision...")

	openBrowser(addr)

	select {
	case result := <-consentReq.ResultCh:
		if !result.Approved {
			fmt.Println("Presentation denied.")
			return nil, nil, true
		}
		if result.SelectedClaims != nil {
			for i, m := range matches {
				if selectedKeys, ok := result.SelectedClaims[m.CredentialID]; ok {
					matches[i].SelectedKeys = selectedKeys
				}
			}
		}
	case <-time.After(config.ConsentTimeout):
		fmt.Println("Consent timeout.")
		return nil, nil, true
	}

	return matches, consentReq.SubmissionCh, false
}

// submitPresentation creates VP tokens, submits them to the verifier, and prints the result.
func submitPresentation(w *wallet.Wallet, store *wallet.WalletStore, matches []wallet.CredentialMatch, parsed *oid4vc.AuthorizationRequest, responseURI string, submissionCh chan wallet.SubmissionResult, dim *color.Color) error {
	params := wallet.PresentationParams{
		Nonce:         parsed.Nonce,
		ClientID:      parsed.ClientID,
		ResponseURI:   responseURI,
		ResponseMode:  parsed.ResponseMode,
		RequestObject: parsed.RequestObject,
	}
	vpResult, err := w.CreateVPTokenMap(matches, params)
	if err != nil {
		w.AddLog("presentation", fmt.Sprintf("VP token creation failed: %v", err), false)
		if submissionCh != nil {
			submissionCh <- wallet.SubmissionResult{Error: err.Error()}
		}
		return fmt.Errorf("creating VP tokens: %w", err)
	}

	// Submit to verifier (encrypts if direct_post.jwt with encryption key)
	// Create self-issued id_token if requested
	var idToken string
	if wallet.ResponseTypeContains(parsed.ResponseType, "id_token") {
		idToken, err = w.CreateSelfIssuedIDToken(parsed.Nonce, parsed.ClientID)
		if err != nil {
			return fmt.Errorf("creating self-issued id_token: %w", err)
		}
	}

	result, err := w.SubmitPresentation(vpResult, idToken, parsed.State, responseURI, params)
	if err != nil {
		w.AddLog("presentation", fmt.Sprintf("Submission failed: %v", err), false)
		if submissionCh != nil {
			submissionCh <- wallet.SubmissionResult{Error: err.Error()}
		}
		return fmt.Errorf("submitting presentation: %w", err)
	}

	// Print result and notify UI
	submission := wallet.SubmissionResult{
		RedirectURI: result.RedirectURI,
		StatusCode:  result.StatusCode,
	}

	if result.StatusCode >= 400 {
		red := color.New(color.FgRed)
		red.Printf("  Error: %s\n", wallet.FormatDirectPostResult(result))
		fmt.Printf("  Body:  %s\n", result.Body)
		submission.Error = result.Body
		w.AddLog("presentation", fmt.Sprintf("Verifier %s rejected: %s", parsed.ClientID, result.Body), false)
	} else {
		green := color.New(color.FgGreen)
		green.Printf("  Submitted: %s\n", wallet.FormatDirectPostResult(result))
		w.AddLog("presentation", fmt.Sprintf("Presented to %s: %s", parsed.ClientID, wallet.FormatDirectPostResult(result)), true)
	}
	dim.Println("───────────────────────────────────────")

	if submissionCh != nil {
		submissionCh <- submission
	}

	if err := store.Save(w); err != nil {
		fmt.Fprintf(os.Stderr, "warning: saving wallet: %v\n", err)
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	}

	return nil
}

// processCredentialOffer fetches and stores a credential from an OID4VCI offer URI.
func processCredentialOffer(uri string, txCode string) error {
	w, store, err := loadWallet()
	if err != nil {
		return err
	}

	if txCode != "" {
		w.TxCode = txCode
	}

	result, err := w.ProcessCredentialOffer(uri)
	if err != nil {
		return fmt.Errorf("processing credential offer: %w", err)
	}

	if err := store.Save(w); err != nil {
		return fmt.Errorf("saving wallet: %w", err)
	}

	fmt.Printf("Received %s credential from %s (ID: %s)\n", result.Format, result.Issuer, result.CredentialID)

	if jsonOutput {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))
	}

	return nil
}
