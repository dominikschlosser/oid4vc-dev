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
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/dominikschlosser/oid4vc-dev/internal/config"
	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
	"github.com/dominikschlosser/oid4vc-dev/internal/wallet"
)

func walletServeCmd() *cobra.Command {
	var (
		port                    int
		autoAccept              bool
		credFiles               []string
		pid                     bool
		keyPath                 string
		issuerKey               string
		sessionTranscript       string
		register                bool
		noRegister              bool
		statusList              bool
		baseURL                 string
		docker                  bool
		preferredFormat         string
		requireEncryptedRequest bool
		haip                    bool
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
			if err := applyValidationMode(w, walletValidationMode); err != nil {
				return err
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

			if requireEncryptedRequest {
				encKey, err := mock.GenerateKey()
				if err != nil {
					return fmt.Errorf("generating request encryption key: %w", err)
				}
				w.RequireEncryptedRequest = true
				w.RequestEncryptionKey = encKey
			}

			if haip {
				w.RequireHAIP = true
			}

			if statusList {
				if baseURL == "" {
					if docker {
						baseURL = fmt.Sprintf("http://host.docker.internal:%d", port)
					} else {
						baseURL = fmt.Sprintf("http://localhost:%d", port)
					}
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

			cyan.Printf("OID4VC Dev Wallet %s\n", Version)
			dim.Println("───────────────────────────────────────")
			fmt.Printf("  Server:      http://localhost:%d\n", port)
			fmt.Printf("  Authorize:   http://localhost:%d/authorize\n", port)
			fmt.Printf("  Trust List:  http://localhost:%d/api/trustlist\n", port)
			dim.Printf("               http://host.docker.internal:%d/api/trustlist\n", port)
			fmt.Printf("  Credentials: %d loaded\n", len(w.GetCredentials()))
			fmt.Printf("  Storage:     %s\n", store.Dir)
			fmt.Printf("  Validation:  %s\n", w.ValidationMode)
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
			if w.RequireEncryptedRequest {
				fmt.Printf("  Encrypted:   request object encryption required\n")
			}
			if w.RequireHAIP {
				fmt.Printf("  HAIP:        enforced (x509_hash, direct_post.jwt, DCQL, JAR, ES256)\n")
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

	cmd.Flags().IntVar(&port, "port", config.DefaultWalletPort, "Wallet server port")
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
	cmd.Flags().BoolVar(&docker, "docker", false, "Use host.docker.internal instead of localhost for --base-url")
	cmd.Flags().StringVar(&preferredFormat, "preferred-format", "", "Preferred credential format when multiple match: 'dc+sd-jwt', 'mso_mdoc', or 'jwt_vc_json'")
	cmd.Flags().BoolVar(&requireEncryptedRequest, "require-encrypted-request", false, "Require verifiers to encrypt request objects (sends encryption key in wallet_metadata)")
	cmd.Flags().BoolVar(&haip, "haip", false, "Enforce HAIP 1.0 compliance (x509_hash, direct_post.jwt, DCQL, JAR, ES256)")
	return cmd
}
