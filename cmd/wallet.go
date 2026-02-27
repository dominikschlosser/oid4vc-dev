package cmd

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"text/tabwriter"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/keys"
	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
	"github.com/dominikschlosser/oid4vc-dev/internal/qr"
	"github.com/dominikschlosser/oid4vc-dev/internal/wallet"
	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var walletDir string

var walletCmd = &cobra.Command{
	Use:   "wallet",
	Short: "Manage a local testing wallet for OID4VP/OID4VCI flows",
	Long:  "Stateful wallet with file persistence. Supports credential management, OID4VP presentations, OID4VCI issuance, QR scanning, and URL scheme registration.",
}

func init() {
	walletCmd.PersistentFlags().StringVar(&walletDir, "wallet-dir", "", "Wallet storage directory (default ~/.oid4vc-dev/wallet/)")
	walletCmd.AddCommand(walletServeCmd())
	walletCmd.AddCommand(walletListCmd())
	walletCmd.AddCommand(walletImportCmd())
	walletCmd.AddCommand(walletRemoveCmd())
	walletCmd.AddCommand(walletGeneratePIDCmd())
	walletCmd.AddCommand(walletAcceptCmd())
	walletCmd.AddCommand(walletScanCmd())
	walletCmd.AddCommand(walletRegisterCmd())
	walletCmd.AddCommand(walletUnregisterCmd())
	walletCmd.AddCommand(walletTrustListCmd())

	// Deprecated aliases (hidden from help)
	presentAlias := &cobra.Command{
		Use:        "present <uri>",
		Short:      "Deprecated: use 'wallet accept' instead",
		Hidden:     true,
		Deprecated: "use 'wallet accept' instead",
		Args:       cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Delegate to accept
			acceptCmd, _, _ := walletCmd.Find([]string{"accept"})
			acceptCmd.SetArgs(args)
			return acceptCmd.RunE(acceptCmd, args)
		},
	}
	walletCmd.AddCommand(presentAlias)

	listenAlias := &cobra.Command{
		Use:        "listen",
		Short:      "Deprecated: use 'wallet serve --register' instead",
		Hidden:     true,
		Deprecated: "use 'wallet serve --register' instead",
		RunE: func(cmd *cobra.Command, args []string) error {
			serveCmd, _, _ := walletCmd.Find([]string{"serve"})
			serveCmd.Flags().Set("register", "true")
			return serveCmd.RunE(serveCmd, args)
		},
	}
	walletCmd.AddCommand(listenAlias)

	rootCmd.AddCommand(walletCmd)
}

// loadStore creates a WalletStore from the --wallet-dir flag.
func loadStore() *wallet.WalletStore {
	return wallet.NewWalletStore(walletDir)
}

// loadWallet loads the wallet from the store, creating it if needed.
func loadWallet() (*wallet.Wallet, *wallet.WalletStore, error) {
	store := loadStore()
	w, err := store.LoadOrCreate()
	if err != nil {
		return nil, nil, fmt.Errorf("loading wallet: %w", err)
	}
	return w, store, nil
}

// --- wallet serve ---

func walletServeCmd() *cobra.Command {
	var (
		port              int
		autoAccept        bool
		credFiles         []string
		pid               bool
		keyPath           string
		issuerKey         string
		sessionTranscript string
		register          bool
		noRegister        bool
		statusList        bool
		baseURL           string
		preferredFormat   string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start wallet HTTP server with web UI, OID4VP endpoints, and optional URL scheme handling",
		Long: `Start a persistent wallet server with a web UI for managing credentials and handling OID4VP/OID4VCI flows.

Capabilities:
  - Web UI for credential management and consent
  - OID4VP authorization endpoint (/authorize)
  - Trust list endpoint (/api/trustlist)
  - Request logging with timestamps
  - Browser-based consent UI for incoming requests

Use --register to also register OS URL scheme handlers (openid4vp://, openid-credential-offer://)
so the wallet automatically receives incoming protocol requests.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store := loadStore()
			w, err := store.LoadOrCreate()
			if err != nil {
				return fmt.Errorf("loading wallet: %w", err)
			}

			// Override keys if explicitly provided
			if keyPath != "" {
				holderKey, err := loadWalletECKey(keyPath, "holder")
				if err != nil {
					return err
				}
				w.HolderKey = holderKey
			}
			if issuerKey != "" {
				ik, err := loadWalletECKey(issuerKey, "issuer")
				if err != nil {
					return err
				}
				w.IssuerKey = ik
			}

			if autoAccept {
				w.AutoAccept = true
			}

			if err := applySessionTranscriptMode(w, sessionTranscript); err != nil {
				return err
			}

			if preferredFormat != "" {
				w.PreferredFormat = preferredFormat
			}

			if statusList {
				if baseURL == "" {
					baseURL = fmt.Sprintf("http://localhost:%d", port)
				}
				w.BaseURL = baseURL
			}

			if pid {
				if err := w.GenerateDefaultCredentials(nil, ""); err != nil {
					return fmt.Errorf("generating PID credentials: %w", err)
				}
				if err := store.Save(w); err != nil {
					return fmt.Errorf("saving wallet: %w", err)
				}
			}

			for _, path := range credFiles {
				if err := w.ImportCredentialFromFile(path); err != nil {
					return fmt.Errorf("importing credential %s: %w", path, err)
				}
			}
			if len(credFiles) > 0 {
				if err := store.Save(w); err != nil {
					return fmt.Errorf("saving wallet: %w", err)
				}
			}

			// Print startup banner
			cyan := color.New(color.FgCyan, color.Bold)
			dim := color.New(color.Faint)
			yellow := color.New(color.FgYellow)

			cyan.Printf("OID4VC Dev Wallet\n")
			dim.Println("───────────────────────────────────────")
			fmt.Printf("  Server:      http://localhost:%d\n", port)
			fmt.Printf("  Authorize:   http://localhost:%d/authorize\n", port)
			fmt.Printf("  Trust List:  http://localhost:%d/api/trustlist\n", port)
			dim.Printf("               http://host.docker.internal:%d/api/trustlist\n", port)
			fmt.Printf("  Credentials: %d loaded\n", len(w.GetCredentials()))
			fmt.Printf("  Storage:     %s\n", store.Dir)
			if w.AutoAccept {
				fmt.Printf("  Mode:        auto-accept\n")
			} else {
				fmt.Printf("  Mode:        interactive (consent UI)\n")
			}
			fmt.Printf("  Transcript:  %s\n", w.SessionTranscript)
			if w.PreferredFormat != "" {
				fmt.Printf("  Preferred:   %s\n", w.PreferredFormat)
			}
			if w.BaseURL != "" {
				fmt.Printf("  Status List: %s/api/statuslist\n", w.BaseURL)
			}

			// Register URL scheme handlers if requested
			if register && !noRegister {
				if err := wallet.RegisterURLSchemes(port); err != nil {
					yellow.Printf("  Register:    skipped (%s)\n", err)
				} else {
					fmt.Printf("  Register:    URL scheme handlers registered\n")
				}
			}

			dim.Println("───────────────────────────────────────")
			fmt.Println()

			if len(w.GetCredentials()) > 0 {
				for _, c := range w.GetCredentials() {
					fmt.Printf("  [%s] %s (%d claims)\n", c.Format, credLabel(c), len(c.Claims))
				}
				fmt.Println()
			}

			srv := wallet.NewServer(w, port, func() {
				if err := store.Save(w); err != nil {
					fmt.Fprintf(os.Stderr, "warning: saving wallet: %v\n", err)
				}
			})

			// Always enable request logging
			srv.SetLogger(func(format string, args ...any) {
				timestamp := time.Now().Format("15:04:05")
				dim.Printf("[%s] ", timestamp)
				fmt.Printf(format+"\n", args...)
			})

			// Open browser consent UI for incoming requests when not in auto-accept mode
			if !w.AutoAccept {
				srv.SetOnConsentRequest(func(req *wallet.ConsentRequest) {
					url := fmt.Sprintf("http://localhost:%d", port)
					fmt.Printf("  Opening consent UI: %s\n", url)
					openBrowser(url)
				})
			}

			if register && !noRegister {
				fmt.Println("Listening for URL scheme dispatches...")
				fmt.Println()
			}

			return srv.ListenAndServe()
		},
	}

	cmd.Flags().IntVar(&port, "port", 8085, "Wallet server port")
	cmd.Flags().BoolVar(&autoAccept, "auto-accept", false, "Headless mode: auto-approve all presentations")
	cmd.Flags().StringSliceVar(&credFiles, "credential", nil, "Import credential from file (repeatable)")
	cmd.Flags().BoolVar(&pid, "pid", false, "Auto-generate default EUDI PID credentials (SD-JWT + mDoc)")
	cmd.Flags().StringVar(&keyPath, "key", "", "Holder private key file (PEM/JWK); uses stored key or auto-generates")
	cmd.Flags().StringVar(&issuerKey, "issuer-key", "", "Issuer key for generated credentials (PEM/JWK)")
	cmd.Flags().StringVar(&sessionTranscript, "session-transcript", "oid4vp", "mDoc session transcript mode: 'oid4vp' (OID4VP 1.0, default) or 'iso' (ISO 18013-7)")
	cmd.Flags().BoolVar(&register, "register", false, "Register OS URL scheme handlers (openid4vp://, openid-credential-offer://)")
	cmd.Flags().BoolVar(&noRegister, "no-register", false, "Skip URL scheme registration (overrides --register)")
	cmd.Flags().BoolVar(&statusList, "status-list", false, "Embed status list references in generated credentials")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Base URL for status list endpoint (default: http://localhost:<port>)")
	cmd.Flags().StringVar(&preferredFormat, "preferred-format", "", "Preferred credential format when multiple match: 'dc+sd-jwt' or 'mso_mdoc'")
	return cmd
}

// --- wallet list ---

func walletListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List stored credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			w, _, err := loadWallet()
			if err != nil {
				return err
			}

			creds := w.GetCredentials()
			if len(creds) == 0 {
				fmt.Println("No credentials stored.")
				return nil
			}

			if jsonOutput {
				data, err := w.CredentialsJSON()
				if err != nil {
					return err
				}
				fmt.Println(string(data))
				return nil
			}

			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tFORMAT\tTYPE\tCLAIMS")
			for _, c := range creds {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", c.ID, c.Format, credLabel(c), len(c.Claims))
			}
			tw.Flush()
			return nil
		},
	}
}

// --- wallet import ---

func walletImportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "import [file-or-raw]",
		Short: "Import credential to store",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			w, store, err := loadWallet()
			if err != nil {
				return err
			}

			input := "-" // stdin by default
			if len(args) > 0 {
				input = args[0]
			}

			raw, err := format.ReadInputRaw(input)
			if err != nil {
				return fmt.Errorf("reading input: %w", err)
			}

			if err := w.ImportCredential(raw); err != nil {
				return fmt.Errorf("importing credential: %w", err)
			}

			if err := store.Save(w); err != nil {
				return fmt.Errorf("saving wallet: %w", err)
			}

			creds := w.GetCredentials()
			last := creds[len(creds)-1]
			fmt.Printf("Imported %s credential (%s) with %d claims\n", last.Format, credLabel(last), len(last.Claims))
			return nil
		},
	}
}

// --- wallet remove ---

func walletRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <id>",
		Short: "Remove credential by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			w, store, err := loadWallet()
			if err != nil {
				return err
			}

			if !w.RemoveCredential(args[0]) {
				return fmt.Errorf("credential %s not found", args[0])
			}

			if err := store.Save(w); err != nil {
				return fmt.Errorf("saving wallet: %w", err)
			}

			fmt.Printf("Removed credential %s\n", args[0])
			return nil
		},
	}
}

// --- wallet generate-pid ---

func walletGeneratePIDCmd() *cobra.Command {
	var (
		claimsFlag string
		keyPath    string
		vctFlag    string
		statusList bool
		baseURL    string
	)

	cmd := &cobra.Command{
		Use:   "generate-pid",
		Short: "Generate default EUDI PID credentials (SD-JWT + mDoc)",
		Long:  "Generate EUDI PID credentials with default claims. If PID credentials already exist, they are replaced. Use --claims to override specific claim values.",
		RunE: func(cmd *cobra.Command, args []string) error {
			w, store, err := loadWallet()
			if err != nil {
				return err
			}

			if keyPath != "" {
				issuerKey, err := loadWalletECKey(keyPath, "issuer")
				if err != nil {
					return err
				}
				w.IssuerKey = issuerKey
			}

			if statusList {
				if baseURL == "" {
					baseURL = "http://localhost:8085"
				}
				w.BaseURL = baseURL
			}

			overrides, err := parseClaimsOverrides(claimsFlag)
			if err != nil {
				return err
			}

			if err := w.GenerateDefaultCredentials(overrides, vctFlag); err != nil {
				return fmt.Errorf("generating PID credentials: %w", err)
			}

			if err := store.Save(w); err != nil {
				return fmt.Errorf("saving wallet: %w", err)
			}

			fmt.Println("Generated default EUDI PID credentials (SD-JWT + mDoc)")
			return nil
		},
	}

	cmd.Flags().StringVar(&claimsFlag, "claims", "", "Claim overrides as JSON (e.g. '{\"given_name\":\"Max\"}')")
	cmd.Flags().StringVar(&keyPath, "key", "", "Path to PEM-encoded EC private key for signing (default: auto-generated)")
	cmd.Flags().StringVar(&vctFlag, "vct", mock.DefaultPIDVCT, "Verifiable Credential Type for SD-JWT PID")
	cmd.Flags().BoolVar(&statusList, "status-list", false, "Embed status list references in generated credentials")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Base URL for status list endpoint (default: http://localhost:8085)")
	return cmd
}

// --- presentation flow ---

// runPresent handles an OID4VP authorization request: evaluates credentials,
// optionally shows a consent UI, creates VP tokens, and submits the response.
func runPresent(w *wallet.Wallet, store *wallet.WalletStore, uri string, port int) error {
	parsed, err := wallet.ParseAuthorizationRequest(uri)
	if err != nil {
		return fmt.Errorf("parsing authorization request: %w", err)
	}

	if warning := wallet.VerifyClientID(parsed.ClientID, parsed.RequestObject); warning != "" {
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
		fmt.Println("No matching credentials found.")
		return nil
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
	case <-time.After(5 * time.Minute):
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

	// Determine vp_token
	var vpToken any
	if len(vpResult.TokenMap) == 1 {
		for _, v := range vpResult.TokenMap {
			vpToken = v
		}
	} else {
		vpToken = vpResult.TokenMap
	}

	// Submit — encrypt if direct_post.jwt with encryption key
	var result *wallet.DirectPostResult
	if parsed.ResponseMode == "direct_post.jwt" && wallet.HasEncryptionKey(parsed.RequestObject) {
		jwe, encErr := w.EncryptResponse(vpToken, parsed.State, vpResult.MDocNonce, params)
		if encErr != nil {
			w.AddLog("presentation", fmt.Sprintf("JWE encryption failed: %v", encErr), false)
			if submissionCh != nil {
				submissionCh <- wallet.SubmissionResult{Error: encErr.Error()}
			}
			return fmt.Errorf("encrypting response: %w", encErr)
		}
		result, err = wallet.SubmitDirectPostJWT(responseURI, parsed.State, vpToken, jwe)
	} else {
		result, err = wallet.SubmitDirectPost(responseURI, parsed.State, vpToken)
	}
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

// --- dispatch helpers ---

// dispatchOID4Opts holds options for dispatching an OID4VP/VCI URI.
type dispatchOID4Opts struct {
	port              int
	autoAccept        bool
	sessionTranscript string
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
		if err := applySessionTranscriptMode(w, opts.sessionTranscript); err != nil {
			return err
		}
		return runPresent(w, store, uri, opts.port)

	case format.FormatOID4VCI:
		return processCredentialOffer(uri)

	default:
		return fmt.Errorf("unable to detect URI type (expected openid4vp://, openid-credential-offer://, or similar): %s", truncate(uri, 80))
	}
}

// processCredentialOffer fetches and stores a credential from an OID4VCI offer URI.
func processCredentialOffer(uri string) error {
	w, store, err := loadWallet()
	if err != nil {
		return err
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

// --- wallet accept ---

func walletAcceptCmd() *cobra.Command {
	var (
		port              int
		autoAccept        bool
		sessionTranscript string
	)

	cmd := &cobra.Command{
		Use:   "accept <uri>",
		Short: "Accept and process an OID4VP presentation request or OID4VCI credential offer",
		Long: `Auto-detects the URI type and dispatches to the appropriate flow:

  - openid4vp://, haip://, eudi-openid4vp://  →  OID4VP presentation
  - openid-credential-offer://                 →  OID4VCI credential issuance

For OID4VP requests, the wallet evaluates the DCQL query, shows a consent UI
(unless --auto-accept), and submits a VP token to the verifier.

For OID4VCI offers, the wallet fetches the credential from the issuer and
stores it locally. The --port, --auto-accept, and --session-transcript flags
only apply to OID4VP flows.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return dispatchURI(args[0], dispatchOID4Opts{
				port:              port,
				autoAccept:        autoAccept,
				sessionTranscript: sessionTranscript,
			})
		},
	}

	cmd.Flags().IntVar(&port, "port", 8085, "Server port for OID4VP (serves trust list and consent UI)")
	cmd.Flags().BoolVar(&autoAccept, "auto-accept", false, "Auto-approve OID4VP presentations")
	cmd.Flags().StringVar(&sessionTranscript, "session-transcript", "oid4vp", "mDoc session transcript mode: 'oid4vp' (OID4VP 1.0, default) or 'iso' (ISO 18013-7)")
	return cmd
}

// --- wallet scan ---

func walletScanCmd() *cobra.Command {
	var (
		port              int
		screen            bool
		autoAccept        bool
		sessionTranscript string
	)

	cmd := &cobra.Command{
		Use:   "scan [image-file]",
		Short: "Scan QR code and auto-detect flow (accept/import)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var content string
			var err error

			if screen {
				content, err = qr.ScanScreen()
			} else if len(args) > 0 {
				content, err = qr.ScanFile(args[0])
			} else {
				return fmt.Errorf("provide an image file or use --screen")
			}

			if err != nil {
				return fmt.Errorf("scanning QR: %w", err)
			}

			fmt.Printf("Scanned: %s\n\n", content)

			detected := format.Detect(content)

			// For credential formats, import directly
			if detected == format.FormatSDJWT || detected == format.FormatMDOC || detected == format.FormatJWT {
				w, store, err := loadWallet()
				if err != nil {
					return err
				}
				if err := w.ImportCredential(content); err != nil {
					return fmt.Errorf("importing credential: %w", err)
				}
				if err := store.Save(w); err != nil {
					return fmt.Errorf("saving wallet: %w", err)
				}
				creds := w.GetCredentials()
				last := creds[len(creds)-1]
				fmt.Printf("Imported %s credential (%s)\n", last.Format, credLabel(last))
				return nil
			}

			// For OID4 URIs, use the shared dispatch
			return dispatchURI(content, dispatchOID4Opts{
				port:              port,
				autoAccept:        autoAccept,
				sessionTranscript: sessionTranscript,
			})
		},
	}

	cmd.Flags().IntVar(&port, "port", 8085, "Server port (serves trust list and consent UI)")
	cmd.Flags().BoolVar(&screen, "screen", false, "Interactive screen capture (macOS)")
	cmd.Flags().BoolVar(&autoAccept, "auto-accept", false, "Auto-approve presentations")
	cmd.Flags().StringVar(&sessionTranscript, "session-transcript", "oid4vp", "mDoc session transcript mode: 'oid4vp' (OID4VP 1.0, default) or 'iso' (ISO 18013-7)")
	return cmd
}

// --- wallet register ---

func walletRegisterCmd() *cobra.Command {
	var port int

	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register OS URL scheme handlers (openid4vp://, openid-credential-offer://)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return wallet.RegisterURLSchemes(port)
		},
	}

	cmd.Flags().IntVar(&port, "port", 8085, "Listener port for handler script to try before falling back to CLI")
	return cmd
}

// --- wallet unregister ---

func walletUnregisterCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unregister",
		Short: "Remove OS URL scheme handlers",
		RunE: func(cmd *cobra.Command, args []string) error {
			return wallet.UnregisterURLSchemes()
		},
	}
}

// --- wallet trust-list ---

func walletTrustListCmd() *cobra.Command {
	var (
		port    int
		docker  bool
		urlOnly bool
	)

	cmd := &cobra.Command{
		Use:   "trust-list",
		Short: "Print the trust list JWT for this wallet (or just the URL)",
		Long: `Generates and prints the ETSI trust list JWT containing the wallet's issuer certificate.
The output can be piped to a file or used directly with --trust-list in the validate command.

Use --url to print only the trust list URL for a running wallet server instead.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if urlOnly {
				if docker {
					fmt.Printf("http://host.docker.internal:%d/api/trustlist\n", port)
				} else {
					fmt.Printf("http://localhost:%d/api/trustlist\n", port)
				}
				return nil
			}

			w, _, err := loadWallet()
			if err != nil {
				return err
			}

			jwt, err := wallet.GenerateTrustListJWT(w.IssuerKey)
			if err != nil {
				return fmt.Errorf("generating trust list: %w", err)
			}

			fmt.Println(jwt)
			return nil
		},
	}

	cmd.Flags().BoolVar(&urlOnly, "url", false, "Print only the trust list URL (for a running wallet server)")
	cmd.Flags().IntVar(&port, "port", 8085, "Wallet server port (used with --url)")
	cmd.Flags().BoolVar(&docker, "docker", false, "Use host.docker.internal instead of localhost (used with --url)")
	return cmd
}

// --- helpers ---

// typeLabel returns the best human-readable type label from a VCT or DocType,
// falling back to the format string if both are empty.
func typeLabel(vct, docType, fmt_ string) string {
	if vct != "" {
		return vct
	}
	if docType != "" {
		return docType
	}
	return fmt_
}

func credLabel(c wallet.StoredCredential) string {
	return typeLabel(c.VCT, c.DocType, c.Format)
}

func parseClaimsOverrides(flag string) (map[string]any, error) {
	if flag == "" {
		return nil, nil
	}
	var overrides map[string]any
	if err := json.Unmarshal([]byte(flag), &overrides); err != nil {
		return nil, fmt.Errorf("parsing --claims JSON: %w", err)
	}
	return overrides, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func applySessionTranscriptMode(w *wallet.Wallet, mode string) error {
	switch mode {
	case "oid4vp", "":
		w.SessionTranscript = wallet.SessionTranscriptOID4VP
	case "iso":
		w.SessionTranscript = wallet.SessionTranscriptISO
	default:
		return fmt.Errorf("invalid --session-transcript value %q (must be 'iso' or 'oid4vp')", mode)
	}
	return nil
}

func openBrowser(url string) {
	switch runtime.GOOS {
	case "darwin":
		exec.Command("open", url).Start()
	case "linux":
		exec.Command("xdg-open", url).Start()
	}
}

func loadWalletECKey(path, label string) (*ecdsa.PrivateKey, error) {
	if path != "" {
		privKey, err := keys.LoadPrivateKey(path)
		if err != nil {
			return nil, fmt.Errorf("loading %s key: %w", label, err)
		}
		ecKey, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("--%s key must be an EC private key (P-256)", label)
		}
		return ecKey, nil
	}

	key, err := mock.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating %s key: %w", label, err)
	}

	fmt.Fprintf(os.Stderr, "Generated ephemeral %s key\n", label)
	return key, nil
}
