package cmd

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/dominikschlosser/ssi-debugger/internal/format"
	"github.com/dominikschlosser/ssi-debugger/internal/keys"
	"github.com/dominikschlosser/ssi-debugger/internal/mdoc"
	"github.com/dominikschlosser/ssi-debugger/internal/output"
	"github.com/dominikschlosser/ssi-debugger/internal/sdjwt"
	"github.com/dominikschlosser/ssi-debugger/internal/statuslist"
	"github.com/dominikschlosser/ssi-debugger/internal/trustlist"
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
		if x5cKey, err := extractAndValidateX5C(token.Header, tlCerts); err == nil && x5cKey != nil {
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
		if x5cKey, err := extractAndValidateMDOCX5Chain(doc, tlCerts); err == nil && x5cKey != nil {
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

		// Status list check for mDOC
		if statusListFlag && doc.IssuerAuth != nil && doc.IssuerAuth.MSO != nil && doc.IssuerAuth.MSO.Status != nil {
			checkStatus(doc.IssuerAuth.MSO.Status, opts)
		}

	default:
		return fmt.Errorf("unable to auto-detect credential format")
	}

	return nil
}

// extractAndValidateX5C extracts the leaf certificate public key from a JWT x5c header
// and validates that the certificate chain is anchored in the trust list.
// Returns nil, nil if no x5c header is present.
func extractAndValidateX5C(header map[string]any, tlCerts []trustlist.CertInfo) (crypto.PublicKey, error) {
	x5cRaw, ok := header["x5c"].([]any)
	if !ok || len(x5cRaw) == 0 || len(tlCerts) == 0 {
		return nil, nil
	}

	var certs []*x509.Certificate
	for _, entry := range x5cRaw {
		b64, ok := entry.(string)
		if !ok {
			return nil, fmt.Errorf("x5c entry is not a string")
		}
		der, err := format.DecodeBase64Std(b64)
		if err != nil {
			return nil, fmt.Errorf("decoding x5c certificate: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing x5c certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	return validateCertChain(certs, tlCerts)
}

// extractAndValidateMDOCX5Chain extracts the leaf certificate public key from a COSE
// x5chain (label 33) in the unprotected header and validates the chain against the trust list.
// Returns nil, nil if no x5chain is present.
func extractAndValidateMDOCX5Chain(doc *mdoc.Document, tlCerts []trustlist.CertInfo) (crypto.PublicKey, error) {
	if doc.IssuerAuth == nil || doc.IssuerAuth.UnprotectedHeader == nil || len(tlCerts) == 0 {
		return nil, nil
	}

	// COSE x5chain label is 33
	x5chainRaw, ok := doc.IssuerAuth.UnprotectedHeader[int64(33)]
	if !ok {
		// Try uint64 key variant
		x5chainRaw, ok = doc.IssuerAuth.UnprotectedHeader[uint64(33)]
		if !ok {
			return nil, nil
		}
	}

	// x5chain can be a single cert ([]byte) or an array of certs ([]any containing []byte)
	var certDERs [][]byte
	switch v := x5chainRaw.(type) {
	case []byte:
		certDERs = append(certDERs, v)
	case []any:
		for _, entry := range v {
			if b, ok := entry.([]byte); ok {
				certDERs = append(certDERs, b)
			}
		}
	default:
		return nil, nil
	}

	if len(certDERs) == 0 {
		return nil, nil
	}

	var certs []*x509.Certificate
	for _, der := range certDERs {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing x5chain certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	return validateCertChain(certs, tlCerts)
}

// validateCertChain verifies that the leaf certificate chains up to a trust list certificate.
func validateCertChain(certs []*x509.Certificate, tlCerts []trustlist.CertInfo) (crypto.PublicKey, error) {
	leaf := certs[0]

	roots := x509.NewCertPool()
	for _, ci := range tlCerts {
		tlCert, err := x509.ParseCertificate(ci.Raw)
		if err != nil {
			continue
		}
		roots.AddCert(tlCert)
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("certificate chain not trusted: %w", err)
	}

	return leaf.PublicKey, nil
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
