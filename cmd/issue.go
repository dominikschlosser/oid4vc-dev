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
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dominikschlosser/oid4vc-dev/internal/keys"
	"github.com/dominikschlosser/oid4vc-dev/internal/mock"
	"github.com/dominikschlosser/oid4vc-dev/internal/wallet"
	"github.com/spf13/cobra"
)

var (
	issueClaims        string
	issueKeyPath       string
	issueIssuer        string
	issueVCT           string
	issueExpires       string
	issueNBF           string
	issueDocType       string
	issueNamespace     string
	issuePID           bool
	issueOmit          []string
	issueToWallet      bool
	issueStatusListURI string
	issueStatusListIdx int
)

var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Generate test SD-JWT, JWT, or mDOC credentials",
	Long:  "Generate test credentials for development and testing. Produces valid, signed credentials using ephemeral keys by default.",
}

var issueSDJWTCmd = &cobra.Command{
	Use:   "sdjwt",
	Short: "Generate a test SD-JWT credential",
	Long:  "Generate a signed SD-JWT credential with selectively disclosable claims. Uses an ephemeral P-256 key by default.",
	RunE:  runIssueSDJWT,
}

var issueJWTCmd = &cobra.Command{
	Use:   "jwt",
	Short: "Generate a test JWT VC credential",
	Long:  "Generate a signed JWT VC credential with claims directly in the payload (no selective disclosure). Uses an ephemeral P-256 key by default.",
	RunE:  runIssueJWT,
}

var issueMDOCCmd = &cobra.Command{
	Use:   "mdoc",
	Short: "Generate a test mDOC credential",
	Long:  "Generate a signed mDOC (IssuerSigned) credential. Uses an ephemeral P-256 key by default.",
	RunE:  runIssueMDOC,
}

func init() {
	rootCmd.AddCommand(issueCmd)
	issueCmd.AddCommand(issueSDJWTCmd)
	issueCmd.AddCommand(issueJWTCmd)
	issueCmd.AddCommand(issueMDOCCmd)

	// SD-JWT flags
	issueSDJWTCmd.Flags().StringVar(&issueClaims, "claims", "", "Claims as JSON string or @filepath")
	issueSDJWTCmd.Flags().StringVar(&issueKeyPath, "key", "", "Private key file (PEM or JWK); ephemeral P-256 if omitted")
	issueSDJWTCmd.Flags().StringVar(&issueIssuer, "iss", "https://issuer.example", "Issuer URL")
	issueSDJWTCmd.Flags().StringVar(&issueVCT, "vct", mock.DefaultPIDVCT, "Verifiable Credential Type")
	issueSDJWTCmd.Flags().StringVar(&issueExpires, "exp", "720h", "Expiration duration (e.g. 720h, 24h)")
	issueSDJWTCmd.Flags().StringVar(&issueNBF, "nbf", "", "Not-before time (RFC3339 e.g. 2025-01-15T00:00:00Z, or duration e.g. -1h)")
	issueSDJWTCmd.Flags().BoolVar(&issuePID, "pid", false, "Use full EUDI PID Rulebook claims")
	issueSDJWTCmd.Flags().StringSliceVar(&issueOmit, "omit", nil, "Comma-separated claim names to omit from --pid (e.g. resident_address,birth_place)")
	issueSDJWTCmd.Flags().BoolVar(&issueToWallet, "wallet", false, "Import the issued credential into the wallet")
	issueSDJWTCmd.Flags().StringVar(&issueStatusListURI, "status-list-uri", "", "Status list URI to embed in credential")
	issueSDJWTCmd.Flags().IntVar(&issueStatusListIdx, "status-list-idx", 0, "Status list index to embed in credential")

	// JWT flags
	issueJWTCmd.Flags().StringVar(&issueClaims, "claims", "", "Claims as JSON string or @filepath")
	issueJWTCmd.Flags().StringVar(&issueKeyPath, "key", "", "Private key file (PEM or JWK); ephemeral P-256 if omitted")
	issueJWTCmd.Flags().StringVar(&issueIssuer, "iss", "https://issuer.example", "Issuer URL")
	issueJWTCmd.Flags().StringVar(&issueVCT, "vct", mock.DefaultPIDVCT, "Verifiable Credential Type")
	issueJWTCmd.Flags().StringVar(&issueExpires, "exp", "720h", "Expiration duration (e.g. 720h, 24h)")
	issueJWTCmd.Flags().StringVar(&issueNBF, "nbf", "", "Not-before time (RFC3339 e.g. 2025-01-15T00:00:00Z, or duration e.g. -1h)")
	issueJWTCmd.Flags().BoolVar(&issuePID, "pid", false, "Use full EUDI PID Rulebook claims")
	issueJWTCmd.Flags().StringSliceVar(&issueOmit, "omit", nil, "Comma-separated claim names to omit from --pid (e.g. resident_address,birth_place)")
	issueJWTCmd.Flags().BoolVar(&issueToWallet, "wallet", false, "Import the issued credential into the wallet")
	issueJWTCmd.Flags().StringVar(&issueStatusListURI, "status-list-uri", "", "Status list URI to embed in credential")
	issueJWTCmd.Flags().IntVar(&issueStatusListIdx, "status-list-idx", 0, "Status list index to embed in credential")

	// mDOC flags
	issueMDOCCmd.Flags().StringVar(&issueClaims, "claims", "", "Claims as JSON string or @filepath")
	issueMDOCCmd.Flags().StringVar(&issueKeyPath, "key", "", "Private key file (PEM or JWK); ephemeral P-256 if omitted")
	issueMDOCCmd.Flags().StringVar(&issueDocType, "doc-type", "eu.europa.ec.eudi.pid.1", "Document type")
	issueMDOCCmd.Flags().StringVar(&issueNamespace, "namespace", "eu.europa.ec.eudi.pid.1", "Namespace")
	issueMDOCCmd.Flags().StringVar(&issueExpires, "exp", "720h", "Expiration duration (e.g. 720h, 24h)")
	issueMDOCCmd.Flags().StringVar(&issueNBF, "nbf", "", "Not-before time (RFC3339 e.g. 2025-01-15T00:00:00Z, or duration e.g. -1h)")
	issueMDOCCmd.Flags().BoolVar(&issuePID, "pid", false, "Use full EUDI PID Rulebook claims")
	issueMDOCCmd.Flags().StringSliceVar(&issueOmit, "omit", nil, "Comma-separated claim names to omit from --pid (e.g. resident_address,birth_place)")
	issueMDOCCmd.Flags().BoolVar(&issueToWallet, "wallet", false, "Import the issued credential into the wallet")
	issueMDOCCmd.Flags().StringVar(&issueStatusListURI, "status-list-uri", "", "Status list URI to embed in credential")
	issueMDOCCmd.Flags().IntVar(&issueStatusListIdx, "status-list-idx", 0, "Status list index to embed in credential")
}

func runIssueSDJWT(cmd *cobra.Command, args []string) error {
	key, err := loadOrGenerateIssueKey()
	if err != nil {
		return err
	}

	claims, err := resolveIssueClaimsForFormat("sdjwt")
	if err != nil {
		return err
	}

	expDuration, err := time.ParseDuration(issueExpires)
	if err != nil {
		return fmt.Errorf("invalid --exp duration: %w", err)
	}

	nbf, err := parseNBF(issueNBF)
	if err != nil {
		return err
	}

	cfg := mock.SDJWTConfig{
		Issuer:        issueIssuer,
		VCT:           issueVCT,
		ExpiresIn:     expDuration,
		NotBefore:     nbf,
		Claims:        claims,
		Key:           key,
		StatusListURI: issueStatusListURI,
		StatusListIdx: issueStatusListIdx,
	}

	result, err := mock.GenerateSDJWT(cfg)
	if err != nil {
		return fmt.Errorf("generating SD-JWT: %w", err)
	}

	fmt.Println(result)

	if issueToWallet {
		return importToWallet(result)
	}
	return nil
}

func runIssueJWT(cmd *cobra.Command, args []string) error {
	key, err := loadOrGenerateIssueKey()
	if err != nil {
		return err
	}

	claims, err := resolveIssueClaimsForFormat("jwt")
	if err != nil {
		return err
	}

	expDuration, err := time.ParseDuration(issueExpires)
	if err != nil {
		return fmt.Errorf("invalid --exp duration: %w", err)
	}

	nbf, err := parseNBF(issueNBF)
	if err != nil {
		return err
	}

	cfg := mock.JWTConfig{
		Issuer:        issueIssuer,
		VCT:           issueVCT,
		ExpiresIn:     expDuration,
		NotBefore:     nbf,
		Claims:        claims,
		Key:           key,
		StatusListURI: issueStatusListURI,
		StatusListIdx: issueStatusListIdx,
	}

	result, err := mock.GenerateJWT(cfg)
	if err != nil {
		return fmt.Errorf("generating JWT: %w", err)
	}

	fmt.Println(result)

	if issueToWallet {
		return importToWallet(result)
	}
	return nil
}

func runIssueMDOC(cmd *cobra.Command, args []string) error {
	key, err := loadOrGenerateIssueKey()
	if err != nil {
		return err
	}

	claims, err := resolveIssueClaimsForFormat("mdoc")
	if err != nil {
		return err
	}

	expDuration, err := time.ParseDuration(issueExpires)
	if err != nil {
		return fmt.Errorf("invalid --exp duration: %w", err)
	}

	nbf, err := parseNBF(issueNBF)
	if err != nil {
		return err
	}

	cfg := mock.MDOCConfig{
		DocType:       issueDocType,
		Namespace:     issueNamespace,
		Claims:        claims,
		Key:           key,
		ExpiresIn:     expDuration,
		ValidFrom:     nbf,
		StatusListURI: issueStatusListURI,
		StatusListIdx: issueStatusListIdx,
	}

	result, err := mock.GenerateMDOC(cfg)
	if err != nil {
		return fmt.Errorf("generating mDOC: %w", err)
	}

	fmt.Println(result)

	if issueToWallet {
		return importToWallet(result)
	}
	return nil
}

func loadOrGenerateIssueKey() (*ecdsa.PrivateKey, error) {
	if issueKeyPath != "" {
		privKey, err := keys.LoadPrivateKey(issueKeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading key: %w", err)
		}
		ecKey, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("--key must be an EC private key (P-256)")
		}
		return ecKey, nil
	}

	key, err := mock.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral key: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Ephemeral signing key (public JWK):")
	fmt.Fprintln(os.Stderr, mock.PublicKeyJWK(&key.PublicKey))
	return key, nil
}

func resolveIssueClaimsForFormat(format string) (map[string]any, error) {
	if issuePID && issueClaims == "" {
		switch format {
		case "mdoc":
			return omitClaims(mock.MDOCPIDClaims, issueOmit), nil
		default:
			return omitClaims(mock.SDJWTPIDClaims, issueOmit), nil
		}
	}

	if issueClaims == "" {
		return omitClaims(mock.DefaultClaims, issueOmit), nil
	}

	var data []byte
	if strings.HasPrefix(issueClaims, "@") {
		var err error
		data, err = os.ReadFile(issueClaims[1:])
		if err != nil {
			return nil, fmt.Errorf("reading claims file: %w", err)
		}
	} else {
		data = []byte(issueClaims)
	}

	var claims map[string]any
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("parsing claims JSON: %w", err)
	}
	return omitClaims(claims, issueOmit), nil
}

func importToWallet(raw string) error {
	store := wallet.NewWalletStore(walletDir)
	w, err := store.LoadOrCreate()
	if err != nil {
		return fmt.Errorf("loading wallet: %w", err)
	}

	imported, err := w.ImportCredential(raw)
	if err != nil {
		return fmt.Errorf("importing to wallet: %w", err)
	}

	if err := store.Save(w); err != nil {
		return fmt.Errorf("saving wallet: %w", err)
	}

	label := imported.VCT
	if label == "" {
		label = imported.DocType
	}
	fmt.Fprintf(os.Stderr, "Imported %s credential (%s) into wallet\n", imported.Format, label)
	return nil
}

func parseNBF(val string) (*time.Time, error) {
	if val == "" {
		return nil, nil
	}
	// Try as duration first (e.g. "-1h")
	if d, err := time.ParseDuration(val); err == nil {
		t := time.Now().Add(d)
		return &t, nil
	}
	// Try as RFC3339
	t, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return nil, fmt.Errorf("invalid --nbf value %q: expected RFC3339 (e.g. 2025-01-15T00:00:00Z) or duration (e.g. -1h)", val)
	}
	return &t, nil
}

func omitClaims(claims map[string]any, omit []string) map[string]any {
	if len(omit) == 0 {
		return claims
	}
	exclude := make(map[string]bool, len(omit))
	for _, name := range omit {
		exclude[strings.TrimSpace(name)] = true
	}
	result := make(map[string]any, len(claims))
	for k, v := range claims {
		if !exclude[k] {
			result[k] = v
		}
	}
	return result
}
