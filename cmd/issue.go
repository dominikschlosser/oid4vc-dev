// Copyright 2025 Dominik Schlosser
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

	"github.com/dominikschlosser/ssi-debugger/internal/keys"
	"github.com/dominikschlosser/ssi-debugger/internal/mock"
	"github.com/spf13/cobra"
)

var (
	issueClaims    string
	issueKeyPath   string
	issueIssuer    string
	issueVCT       string
	issueExpires   string
	issueDocType   string
	issueNamespace string
	issuePID       bool
	issueOmit      []string
)

var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Generate test SD-JWT or mDOC credentials",
	Long:  "Generate test credentials for development and testing. Produces valid, signed credentials using ephemeral keys by default.",
}

var issueSDJWTCmd = &cobra.Command{
	Use:   "sdjwt",
	Short: "Generate a test SD-JWT credential",
	Long:  "Generate a signed SD-JWT credential with selectively disclosable claims. Uses an ephemeral P-256 key by default.",
	RunE:  runIssueSDJWT,
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
	issueCmd.AddCommand(issueMDOCCmd)

	// SD-JWT flags
	issueSDJWTCmd.Flags().StringVar(&issueClaims, "claims", "", "Claims as JSON string or @filepath")
	issueSDJWTCmd.Flags().StringVar(&issueKeyPath, "key", "", "Private key file (PEM or JWK); ephemeral P-256 if omitted")
	issueSDJWTCmd.Flags().StringVar(&issueIssuer, "iss", "https://issuer.example", "Issuer URL")
	issueSDJWTCmd.Flags().StringVar(&issueVCT, "vct", "urn:eudi:pid:1", "Verifiable Credential Type")
	issueSDJWTCmd.Flags().StringVar(&issueExpires, "exp", "24h", "Expiration duration (e.g. 24h, 30m)")
	issueSDJWTCmd.Flags().BoolVar(&issuePID, "pid", false, "Use full EUDI PID Rulebook claims")
	issueSDJWTCmd.Flags().StringSliceVar(&issueOmit, "omit", nil, "Comma-separated claim names to omit from --pid (e.g. resident_address,birth_place)")

	// mDOC flags
	issueMDOCCmd.Flags().StringVar(&issueClaims, "claims", "", "Claims as JSON string or @filepath")
	issueMDOCCmd.Flags().StringVar(&issueKeyPath, "key", "", "Private key file (PEM or JWK); ephemeral P-256 if omitted")
	issueMDOCCmd.Flags().StringVar(&issueDocType, "doc-type", "eu.europa.ec.eudi.pid.1", "Document type")
	issueMDOCCmd.Flags().StringVar(&issueNamespace, "namespace", "eu.europa.ec.eudi.pid.1", "Namespace")
	issueMDOCCmd.Flags().BoolVar(&issuePID, "pid", false, "Use full EUDI PID Rulebook claims")
	issueMDOCCmd.Flags().StringSliceVar(&issueOmit, "omit", nil, "Comma-separated claim names to omit from --pid (e.g. resident_address,birth_place)")
}

func runIssueSDJWT(cmd *cobra.Command, args []string) error {
	key, err := loadOrGenerateIssueKey()
	if err != nil {
		return err
	}

	claims, err := resolveIssueClaims()
	if err != nil {
		return err
	}

	expDuration, err := time.ParseDuration(issueExpires)
	if err != nil {
		return fmt.Errorf("invalid --exp duration: %w", err)
	}

	cfg := mock.SDJWTConfig{
		Issuer:    issueIssuer,
		VCT:       issueVCT,
		ExpiresIn: expDuration,
		Claims:    claims,
		Key:       key,
	}

	result, err := mock.GenerateSDJWT(cfg)
	if err != nil {
		return fmt.Errorf("generating SD-JWT: %w", err)
	}

	fmt.Println(result)
	return nil
}

func runIssueMDOC(cmd *cobra.Command, args []string) error {
	key, err := loadOrGenerateIssueKey()
	if err != nil {
		return err
	}

	claims, err := resolveIssueClaims()
	if err != nil {
		return err
	}

	cfg := mock.MDOCConfig{
		DocType:   issueDocType,
		Namespace: issueNamespace,
		Claims:    claims,
		Key:       key,
	}

	result, err := mock.GenerateMDOC(cfg)
	if err != nil {
		return fmt.Errorf("generating mDOC: %w", err)
	}

	fmt.Println(result)
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

func resolveIssueClaims() (map[string]any, error) {
	if issuePID && issueClaims == "" {
		return omitClaims(mock.PIDClaims, issueOmit), nil
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
