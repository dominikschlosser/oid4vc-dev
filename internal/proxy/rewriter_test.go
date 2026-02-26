package proxy

import (
	"net/http"
	"testing"
)

func TestRewriteBodyReplacesHost(t *testing.T) {
	rw := NewRewriter("target.example.com", "localhost:9090")

	body := `{"redirect_uri":"http://target.example.com/callback","other":"value"}`
	got := rw.RewriteBody(body, "application/json")
	want := `{"redirect_uri":"http://localhost:9090/callback","other":"value"}`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRewriteBodySkipsJWT(t *testing.T) {
	rw := NewRewriter("target.example.com", "localhost:9090")

	jwt := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0YXJnZXQuZXhhbXBsZS5jb20ifQ.signature"
	got := rw.RewriteBody(jwt, "application/jwt")
	if got != jwt {
		t.Errorf("expected JWT to be unchanged, got %q", got)
	}
}

func TestRewriteBodyNoMatch(t *testing.T) {
	rw := NewRewriter("target.example.com", "localhost:9090")

	body := `{"key":"value"}`
	got := rw.RewriteBody(body, "application/json")
	if got != body {
		t.Errorf("expected body unchanged, got %q", got)
	}
}

func TestRewriteBodyMultipleOccurrences(t *testing.T) {
	rw := NewRewriter("target.example.com", "localhost:9090")

	body := "http://target.example.com/a and http://target.example.com/b"
	got := rw.RewriteBody(body, "text/html")
	want := "http://localhost:9090/a and http://localhost:9090/b"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRewriteHeadersLocation(t *testing.T) {
	rw := NewRewriter("target.example.com", "localhost:9090")

	h := http.Header{}
	h.Set("Location", "http://target.example.com/callback?code=123")
	rw.RewriteHeaders(h)

	want := "http://localhost:9090/callback?code=123"
	if got := h.Get("Location"); got != want {
		t.Errorf("Location: got %q, want %q", got, want)
	}
}

func TestRewriteHeadersContentLocation(t *testing.T) {
	rw := NewRewriter("target.example.com", "localhost:9090")

	h := http.Header{}
	h.Set("Content-Location", "http://target.example.com/resource")
	rw.RewriteHeaders(h)

	want := "http://localhost:9090/resource"
	if got := h.Get("Content-Location"); got != want {
		t.Errorf("Content-Location: got %q, want %q", got, want)
	}
}

func TestRewriteHeadersNoOp(t *testing.T) {
	rw := NewRewriter("target.example.com", "localhost:9090")

	h := http.Header{}
	h.Set("Content-Type", "application/json")
	rw.RewriteHeaders(h)

	if got := h.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type should be unchanged, got %q", got)
	}
}
