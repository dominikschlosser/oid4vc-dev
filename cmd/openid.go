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
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/dominikschlosser/ssi-debugger/internal/openid4"
	"github.com/dominikschlosser/ssi-debugger/internal/output"
	"github.com/dominikschlosser/ssi-debugger/internal/qr"
	"github.com/spf13/cobra"
)

var (
	qrSource  string
	qrScreen  bool
)

var openidCmd = &cobra.Command{
	Use:   "openid [input]",
	Short: "Decode an OID4VCI credential offer or OID4VP authorization request",
	Long: `Decode and inspect OpenID for Verifiable Credential Issuance (OID4VCI) credential offers
and OpenID for Verifiable Presentations (OID4VP) authorization requests.

Accepts:
  - URI schemes: openid-credential-offer://, openid4vp://, haip://, eudi-openid4vp://
  - HTTPS URLs with query parameters
  - JWT request objects
  - Raw JSON
  - File paths
  - Stdin (pipe or use -)
  - QR code from image file (--qr) or screen capture (--screen)

Auto-detects VCI vs VP based on content.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runOpenID,
}

func init() {
	openidCmd.Flags().StringVar(&qrSource, "qr", "", "scan QR code from image file")
	openidCmd.Flags().BoolVar(&qrScreen, "screen", false, "scan QR code from screen capture")
	rootCmd.AddCommand(openidCmd)
}

func runOpenID(cmd *cobra.Command, args []string) error {
	if qrSource != "" && qrScreen {
		return fmt.Errorf("cannot use --qr and --screen together")
	}
	if (qrSource != "" || qrScreen) && len(args) > 0 {
		return fmt.Errorf("cannot use --qr/--screen together with a positional argument")
	}

	var raw string
	var err error

	if qrScreen {
		raw, err = qr.ScanScreen()
	} else if qrSource != "" {
		raw, err = qr.ScanFile(qrSource)
	} else {
		input := ""
		if len(args) > 0 {
			input = args[0]
		}
		raw, err = readOID4Input(input)
	}
	if err != nil {
		return err
	}

	opts := output.Options{
		JSON:    jsonOutput,
		NoColor: noColor,
		Verbose: verbose,
	}

	reqType, result, err := openid4.Parse(raw)
	if err != nil {
		return fmt.Errorf("parsing OpenID request: %w", err)
	}

	switch reqType {
	case openid4.TypeVCI:
		offer, ok := result.(*openid4.CredentialOffer)
		if !ok {
			return fmt.Errorf("unexpected result type for VCI: %T", result)
		}
		output.PrintCredentialOffer(offer, opts)
	case openid4.TypeVP:
		req, ok := result.(*openid4.AuthorizationRequest)
		if !ok {
			return fmt.Errorf("unexpected result type for VP: %T", result)
		}
		output.PrintAuthorizationRequest(req, opts)
	}

	return nil
}

// readOID4Input reads OpenID input from stdin, a file, or returns the raw string.
// Unlike format.ReadInput, it does NOT HTTP-fetch URLs — the parser handles
// selective fetching for request_uri and credential_offer_uri.
func readOID4Input(input string) (string, error) {
	input = strings.TrimSpace(input)

	if input == "-" || input == "" {
		stat, err := os.Stdin.Stat()
		if err != nil {
			return "", fmt.Errorf("cannot read stdin: %w", err)
		}
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			return "", fmt.Errorf("no input provided (use a URI, URL, JWT, JSON, file path, or pipe to stdin)")
		}
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("reading stdin: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}

	// Try as file path (but not if it looks like a URI/URL/JWT/JSON)
	if !strings.Contains(input, "://") && !strings.HasPrefix(input, "{") && !strings.Contains(input, ".") || strings.Count(input, ".") != 2 {
		if _, err := os.Stat(input); err == nil {
			b, err := os.ReadFile(input)
			if err != nil {
				return "", fmt.Errorf("reading file %s: %w", input, err)
			}
			return strings.TrimSpace(string(b)), nil
		}
	}

	return input, nil
}

