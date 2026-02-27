package wallet

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/dominikschlosser/oid4vc-dev/internal/format"
	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
)

// VerifyClientID checks if client_id with x509_san_dns: or x509_san_uri: prefix
// matches the leaf certificate SAN from the request object's x5c header.
// Returns a warning string if there's a mismatch, or "" if OK / not applicable.
func VerifyClientID(clientID string, reqObj *oid4vc.RequestObjectJWT) string {
	var scheme, expected string
	switch {
	case strings.HasPrefix(clientID, "x509_san_dns:"):
		scheme = "dns"
		expected = strings.TrimPrefix(clientID, "x509_san_dns:")
	case strings.HasPrefix(clientID, "x509_san_uri:"):
		scheme = "uri"
		expected = strings.TrimPrefix(clientID, "x509_san_uri:")
	default:
		return ""
	}

	if reqObj == nil || reqObj.Header == nil {
		return "client_id uses x509 scheme but request object has no x5c header"
	}

	x5cRaw, ok := reqObj.Header["x5c"]
	if !ok {
		return "client_id uses x509 scheme but request object has no x5c header"
	}

	x5cArr, ok := x5cRaw.([]any)
	if !ok || len(x5cArr) == 0 {
		return "client_id uses x509 scheme but x5c header is empty"
	}

	leafB64, ok := x5cArr[0].(string)
	if !ok {
		return "client_id uses x509 scheme but x5c[0] is not a string"
	}

	der, err := format.DecodeBase64Std(leafB64)
	if err != nil {
		return fmt.Sprintf("client_id uses x509 scheme but failed to decode x5c[0]: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Sprintf("client_id uses x509 scheme but failed to parse leaf certificate: %v", err)
	}

	switch scheme {
	case "dns":
		for _, name := range cert.DNSNames {
			if name == expected {
				return ""
			}
		}
		return fmt.Sprintf("client_id expects DNS SAN %q but leaf certificate has DNSNames=%v", expected, cert.DNSNames)
	case "uri":
		for _, u := range cert.URIs {
			if u.String() == expected {
				return ""
			}
		}
		uris := make([]string, len(cert.URIs))
		for i, u := range cert.URIs {
			uris[i] = u.String()
		}
		return fmt.Sprintf("client_id expects URI SAN %q but leaf certificate has URIs=%v", expected, uris)
	}

	return ""
}
