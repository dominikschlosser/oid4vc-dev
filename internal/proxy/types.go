package proxy

import (
	"net/http"
	"time"
)

// TrafficClass categorizes intercepted HTTP traffic by OID4VP/VCI protocol step.
type TrafficClass int

const (
	ClassUnknown             TrafficClass = iota
	ClassVPAuthRequest                    // GET with client_id, response_type=vp_token
	ClassVPRequestObject                  // GET request_uri → JWT response
	ClassVPAuthResponse                   // POST with vp_token to response_uri
	ClassVCICredentialOffer               // credential_offer / credential_offer_uri
	ClassVCIMetadata                      // .well-known/openid-credential-issuer
	ClassVCITokenRequest                  // POST to token endpoint
	ClassVCICredentialRequest             // POST to credential endpoint
)

var classLabels = map[TrafficClass]string{
	ClassUnknown:              "Unknown",
	ClassVPAuthRequest:        "VP Auth Request",
	ClassVPRequestObject:      "VP Request Object",
	ClassVPAuthResponse:       "VP Auth Response",
	ClassVCICredentialOffer:   "VCI Credential Offer",
	ClassVCIMetadata:          "VCI Metadata",
	ClassVCITokenRequest:      "VCI Token Request",
	ClassVCICredentialRequest: "VCI Credential Request",
}

// Label returns a human-readable label for the traffic class.
func (c TrafficClass) Label() string {
	if l, ok := classLabels[c]; ok {
		return l
	}
	return "Unknown"
}

// TrafficEntry represents a single intercepted HTTP request/response pair.
type TrafficEntry struct {
	ID              int64          `json:"id"`
	Timestamp       time.Time      `json:"timestamp"`
	Method          string         `json:"method"`
	URL             string         `json:"url"`
	RequestHeaders  http.Header    `json:"requestHeaders"`
	RequestBody     string         `json:"requestBody,omitempty"`
	StatusCode      int            `json:"statusCode"`
	ResponseHeaders http.Header    `json:"responseHeaders"`
	ResponseBody    string         `json:"responseBody,omitempty"`
	Class           TrafficClass   `json:"class"`
	ClassLabel      string         `json:"classLabel"`
	Decoded         map[string]any `json:"decoded,omitempty"`
	Credentials     []string       `json:"credentials,omitempty"` // raw credential strings found in this entry
	Duration        time.Duration  `json:"duration"`
	DurationMS      int64          `json:"durationMs"`
}
