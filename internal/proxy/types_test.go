package proxy

import "testing"

func TestTrafficClassLabel(t *testing.T) {
	tests := []struct {
		class TrafficClass
		want  string
	}{
		{ClassUnknown, "Unknown"},
		{ClassVPAuthRequest, "VP Auth Request"},
		{ClassVPRequestObject, "VP Request Object"},
		{ClassVPAuthResponse, "VP Auth Response"},
		{ClassVCICredentialOffer, "VCI Credential Offer"},
		{ClassVCIMetadata, "VCI Metadata"},
		{ClassVCITokenRequest, "VCI Token Request"},
		{ClassVCICredentialRequest, "VCI Credential Request"},
	}

	for _, tt := range tests {
		if got := tt.class.Label(); got != tt.want {
			t.Errorf("TrafficClass(%d).Label() = %q, want %q", tt.class, got, tt.want)
		}
	}
}

func TestTrafficClassLabelUnmapped(t *testing.T) {
	unmapped := TrafficClass(999)
	if got := unmapped.Label(); got != "Unknown" {
		t.Errorf("unmapped TrafficClass.Label() = %q, want 'Unknown'", got)
	}
}
