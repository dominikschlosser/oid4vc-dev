package wallet

import (
	"net/url"
	"testing"

	"github.com/dominikschlosser/oid4vc-dev/internal/oid4vc"
)

func TestGetResponseURI_PreferResponseURI(t *testing.T) {
	req := &oid4vc.AuthorizationRequest{
		ResponseURI: "https://verifier.example/response",
		RedirectURI: "https://verifier.example/redirect",
	}
	got := GetResponseURI(req)
	if got != "https://verifier.example/response" {
		t.Errorf("expected response_uri, got %s", got)
	}
}

func TestGetResponseURI_FallbackToRedirect(t *testing.T) {
	req := &oid4vc.AuthorizationRequest{
		RedirectURI: "https://verifier.example/redirect",
	}
	got := GetResponseURI(req)
	if got != "https://verifier.example/redirect" {
		t.Errorf("expected redirect_uri, got %s", got)
	}
}

func TestGetResponseMode_Explicit(t *testing.T) {
	req := &oid4vc.AuthorizationRequest{
		ResponseMode: "direct_post.jwt",
	}
	got := GetResponseMode(req)
	if got != "direct_post.jwt" {
		t.Errorf("expected direct_post.jwt, got %s", got)
	}
}

func TestGetResponseMode_Default(t *testing.T) {
	req := &oid4vc.AuthorizationRequest{}
	got := GetResponseMode(req)
	if got != "direct_post" {
		t.Errorf("expected default direct_post, got %s", got)
	}
}

func TestParseAuthorizationRequestFromParams(t *testing.T) {
	params := url.Values{}
	params.Set("client_id", "https://verifier.example")
	params.Set("response_uri", "https://verifier.example/callback")
	params.Set("response_type", "vp_token")
	params.Set("nonce", "test-nonce")
	params.Set("dcql_query", `{"credentials":[{"id":"pid","format":"dc+sd-jwt"}]}`)

	authReq, err := ParseAuthorizationRequestFromParams(params)
	if err != nil {
		t.Fatalf("ParseAuthorizationRequestFromParams: %v", err)
	}

	if authReq.ClientID != "https://verifier.example" {
		t.Errorf("expected client_id https://verifier.example, got %s", authReq.ClientID)
	}
	if authReq.Nonce != "test-nonce" {
		t.Errorf("expected nonce test-nonce, got %s", authReq.Nonce)
	}
	if authReq.DCQLQuery == nil {
		t.Error("expected non-nil dcql_query")
	}
}
