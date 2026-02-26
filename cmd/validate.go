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
	"crypto"
	"fmt"

	"github.com/dominikschlosser/ssi-debugger/internal/format"
	"github.com/dominikschlosser/ssi-debugger/internal/keys"
	"github.com/dominikschlosser/ssi-debugger/internal/mdoc"
	"github.com/dominikschlosser/ssi-debugger/internal/output"
	"github.com/dominikschlosser/ssi-debugger/internal/sdjwt"
	"github.com/dominikschlosser/ssi-debugger/internal/statuslist"
	"github.com/dominikschlosser/ssi-debugger/internal/trustlist"
	"github.com/dominikschlosser/ssi-debugger/internal/validate"
	"github.com/spf13/cobra"
)

var (
	keyFile        string
	trustListFile  string
	statusListFlag bool
	allowExpired   bool
)

var validateCmd = &cobra.Command{
	Use:   "validate [input]",
	Short: "Decode and verify a credential's signature",
	Long:  "Decodes and validates a credential. Verifies signatures with --key (PEM or JWK file) or --trust-list. Optionally checks revocation status.",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runValidate,
}

func init() {
	validateCmd.Flags().StringVar(&keyFile, "key", "", "Public key file (PEM or JWK)")
	validateCmd.Flags().StringVar(&trustListFile, "trust-list", "", "ETSI trust list JWT (file path or URL)")
	validateCmd.Flags().BoolVar(&statusListFlag, "status-list", false, "Check revocation via status list (network call)")
	validateCmd.Flags().BoolVar(&allowExpired, "allow-expired", false, "Don't fail on expired credentials")
	rootCmd.AddCommand(validateCmd)
}

func runValidate(cmd *cobra.Command, args []string) error {
	input := ""
	if len(args) > 0 {
		input = args[0]
	}

	raw, err := format.ReadInput(input)
	if err != nil {
		return err
	}

	opts := output.Options{
		JSON:    jsonOutput,
		NoColor: noColor,
		Verbose: verbose,
	}

	// Load public key(s)
	var pubKeys []crypto.PublicKey

	if keyFile != "" {
		key, err := keys.LoadPublicKey(keyFile)
		if err != nil {
			return fmt.Errorf("loading key: %w", err)
		}
		pubKeys = append(pubKeys, key)
	}

	var tlCerts []trustlist.CertInfo
	if trustListFile != "" {
		tlRaw, err := format.ReadInput(trustListFile)
		if err != nil {
			return fmt.Errorf("reading trust list: %w", err)
		}
		tl, err := trustlist.Parse(tlRaw)
		if err != nil {
			return fmt.Errorf("parsing trust list: %w", err)
		}
		tlCerts = trustlist.ExtractPublicKeys(tl)
		for _, ci := range tlCerts {
			pubKeys = append(pubKeys, ci.PublicKey)
		}
	}

	if len(pubKeys) == 0 {
		return fmt.Errorf("provide --key or --trust-list for signature verification")
	}

	detected := format.Detect(raw)

	switch detected {
	case format.FormatSDJWT:
		token, err := sdjwt.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing SD-JWT: %w", err)
		}
		output.PrintSDJWT(token, opts)

		// If the token has an x5c header and we have a trust list, extract the
		// leaf certificate's public key and validate the chain against the trust list.
		var bestResult *sdjwt.VerifyResult
		if x5cKey, err := validate.ExtractAndValidateX5C(token.Header, tlCerts); err == nil && x5cKey != nil {
			bestResult = sdjwt.Verify(token, x5cKey)
		} else {
			// Fall back to trying each key directly
			for _, key := range pubKeys {
				result := sdjwt.Verify(token, key)
				if result.SignatureValid {
					bestResult = result
					break
				}
				bestResult = result
			}
		}
		output.PrintVerifyResultSDJWT(bestResult, opts)

		if !bestResult.SignatureValid {
			return fmt.Errorf("signature verification failed")
		}
		if bestResult.Expired && !allowExpired {
			return fmt.Errorf("credential expired")
		}

		// Status list check
		if statusListFlag {
			checkStatus(token.ResolvedClaims, opts)
		}

	case format.FormatMDOC:
		doc, err := mdoc.Parse(raw)
		if err != nil {
			return fmt.Errorf("parsing mDOC: %w", err)
		}
		output.PrintMDOC(doc, opts)

		var bestResult *mdoc.VerifyResult
		if x5cKey, err := validate.ExtractAndValidateMDOCX5Chain(doc, tlCerts); err == nil && x5cKey != nil {
			bestResult = mdoc.Verify(doc, x5cKey)
		} else {
			for _, key := range pubKeys {
				result := mdoc.Verify(doc, key)
				if result.SignatureValid {
					bestResult = result
					break
				}
				bestResult = result
			}
		}
		output.PrintVerifyResultMDOC(bestResult, opts)

		if !bestResult.SignatureValid {
			return fmt.Errorf("signature verification failed")
		}
		if bestResult.Expired && !allowExpired {
			return fmt.Errorf("credential expired")
		}

		// Status list check for mDOC — wrap in "status" key since ExtractStatusRef
		// expects {"status": {"status_list": ...}} but MSO.Status is the inner map.
		if statusListFlag && doc.IssuerAuth != nil && doc.IssuerAuth.MSO != nil && doc.IssuerAuth.MSO.Status != nil {
			checkStatus(map[string]any{"status": doc.IssuerAuth.MSO.Status}, opts)
		}

	default:
		return fmt.Errorf("unable to auto-detect credential format")
	}

	return nil
}

func checkStatus(claims map[string]any, opts output.Options) {
	ref := statuslist.ExtractStatusRef(claims)
	if ref == nil {
		if !opts.JSON {
			fmt.Println("\n  No status list reference found in credential")
		}
		return
	}
	result, err := statuslist.Check(ref)
	if err != nil {
		output.PrintError(fmt.Sprintf("status check: %v", err))
		return
	}
	if opts.JSON {
		output.PrintJSON(result)
	} else {
		if result.IsValid {
			fmt.Printf("\n  ✓ Status: valid (index %d, status=%d)\n", result.Index, result.Status)
		} else {
			fmt.Printf("\n  ✗ Status: revoked (index %d, status=%d)\n", result.Index, result.Status)
		}
	}
}
