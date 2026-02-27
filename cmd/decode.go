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
	"strings"

	"github.com/dominikschlosser/ssi-debugger/internal/format"
	"github.com/dominikschlosser/ssi-debugger/internal/mdoc"
	"github.com/dominikschlosser/ssi-debugger/internal/openid4"
	"github.com/dominikschlosser/ssi-debugger/internal/output"
	"github.com/dominikschlosser/ssi-debugger/internal/qr"
	"github.com/dominikschlosser/ssi-debugger/internal/sdjwt"
	"github.com/spf13/cobra"
)

var (
	decodeQRSource string
	decodeQRScreen bool
	decodeFormat   string
)

var decodeCmd = &cobra.Command{
	Use:   "decode [input]",
	Short: "Auto-detect and decode credentials and OpenID4VCI/VP requests",
	Long: `Decode and inspect SSI credentials (JWT, SD-JWT, mDOC) and OpenID4VCI/VP requests.

Accepts:
  - Credential strings: SD-JWT, JWT, mDOC (hex or base64url)
  - URI schemes: openid-credential-offer://, openid4vp://, haip://, eudi-openid4vp://
  - HTTPS URLs with OID4 query parameters
  - JWT request objects
  - Raw JSON
  - File paths
  - Stdin (pipe or use -)
  - QR code from image file (--qr) or screen capture (--screen)

Auto-detects the format. Use --format to override detection.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runDecode,
}

func init() {
	decodeCmd.Flags().StringVar(&decodeQRSource, "qr", "", "scan QR code from image file")
	decodeCmd.Flags().BoolVar(&decodeQRScreen, "screen", false, "scan QR code from screen capture")
	decodeCmd.Flags().StringVarP(&decodeFormat, "format", "f", "", "pin format: sdjwt, jwt, mdoc, vci, vp")
	rootCmd.AddCommand(decodeCmd)
}

var formatAliases = map[string]format.CredentialFormat{
	"sdjwt":   format.FormatSDJWT,
	"sd-jwt":  format.FormatSDJWT,
	"jwt":     format.FormatJWT,
	"mdoc":    format.FormatMDOC,
	"mso_mdoc": format.FormatMDOC,
	"vci":     format.FormatOID4VCI,
	"oid4vci": format.FormatOID4VCI,
	"vp":      format.FormatOID4VP,
	"oid4vp":  format.FormatOID4VP,
}

func runDecode(cmd *cobra.Command, args []string) error {
	if decodeQRSource != "" && decodeQRScreen {
		return fmt.Errorf("cannot use --qr and --screen together")
	}
	if (decodeQRSource != "" || decodeQRScreen) && len(args) > 0 {
		return fmt.Errorf("cannot use --qr/--screen together with a positional argument")
	}

	var raw string
	var err error

	if decodeQRScreen {
		raw, err = qr.ScanScreen()
	} else if decodeQRSource != "" {
		raw, err = qr.ScanFile(decodeQRSource)
	} else {
		input := ""
		if len(args) > 0 {
			input = args[0]
		}
		raw, err = format.ReadInputRaw(input)
	}
	if err != nil {
		return err
	}

	opts := output.Options{
		JSON:    jsonOutput,
		NoColor: noColor,
		Verbose: verbose,
	}

	// Determine format: pinned or auto-detected
	var detected format.CredentialFormat
	if decodeFormat != "" {
		f, ok := formatAliases[strings.ToLower(decodeFormat)]
		if !ok {
			return fmt.Errorf("unknown format %q (valid: sdjwt, jwt, mdoc, vci, vp)", decodeFormat)
		}
		detected = f
	} else {
		detected = format.Detect(raw)
	}

	// For credential formats where input is an HTTP URL, fetch first then re-detect
	if isCredentialFormat(detected) && isHTTPURL(raw) {
		raw, err = format.FetchURL(raw)
		if err != nil {
			return err
		}
		if decodeFormat == "" {
			detected = format.Detect(raw)
		}
	}

	switch detected {
	case format.FormatSDJWT:
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing SD-JWT: %w", err)
		}
		output.PrintSDJWT(token, opts)

	case format.FormatJWT:
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing JWT: %w", err)
		}
		output.PrintJWT(token, opts)

	case format.FormatMDOC:
		doc, err := mdoc.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing mDOC: %w", err)
		}
		output.PrintMDOC(doc, opts)

	case format.FormatOID4VCI, format.FormatOID4VP:
		return decodeOID4(raw, opts)

	default:
		return fmt.Errorf("unable to auto-detect format (not a credential or OpenID4VCI/VP request)")
	}

	return nil
}

func decodeOID4(raw string, opts output.Options) error {
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

func isCredentialFormat(f format.CredentialFormat) bool {
	return f == format.FormatSDJWT || f == format.FormatJWT || f == format.FormatMDOC
}

func isHTTPURL(s string) bool {
	lower := strings.ToLower(s)
	return strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://")
}
