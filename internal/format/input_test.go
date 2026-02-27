package format

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadInputRaw_RawString(t *testing.T) {
	raw, err := ReadInputRaw("eyJhbGciOiJFUzI1NiJ9.test.sig")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != "eyJhbGciOiJFUzI1NiJ9.test.sig" {
		t.Errorf("expected raw string back, got %q", raw)
	}
}

func TestReadInputRaw_URIPassthrough(t *testing.T) {
	uri := "openid4vp://authorize?client_id=test"
	raw, err := ReadInputRaw(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != uri {
		t.Errorf("expected URI passthrough, got %q", raw)
	}
}

func TestReadInputRaw_HTTPURLPassthrough(t *testing.T) {
	url := "https://example.com/credential"
	raw, err := ReadInputRaw(url)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != url {
		t.Errorf("expected URL passthrough, got %q", raw)
	}
}

func TestReadInputRaw_FileRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cred.txt")
	if err := os.WriteFile(path, []byte("  test-credential-data  \n"), 0644); err != nil {
		t.Fatal(err)
	}

	raw, err := ReadInputRaw(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != "test-credential-data" {
		t.Errorf("expected trimmed file content, got %q", raw)
	}
}

func TestReadInputRaw_JSONNotTreatedAsFile(t *testing.T) {
	// JSON strings starting with { should not be treated as file paths
	raw, err := ReadInputRaw(`{"credential_issuer":"https://example.com"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != `{"credential_issuer":"https://example.com"}` {
		t.Errorf("expected JSON passthrough, got %q", raw)
	}
}

func TestReadInputRaw_Whitespace(t *testing.T) {
	raw, err := ReadInputRaw("  some-token  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != "some-token" {
		t.Errorf("expected trimmed input, got %q", raw)
	}
}

func TestReadInput_RawString(t *testing.T) {
	raw, err := ReadInput("eyJhbGciOiJFUzI1NiJ9.test.sig")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != "eyJhbGciOiJFUzI1NiJ9.test.sig" {
		t.Errorf("expected raw string back, got %q", raw)
	}
}

func TestReadInput_FileRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cred.txt")
	if err := os.WriteFile(path, []byte("  file-content  \n"), 0644); err != nil {
		t.Fatal(err)
	}

	raw, err := ReadInput(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != "file-content" {
		t.Errorf("expected trimmed file content, got %q", raw)
	}
}

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("  content  \n"), 0644); err != nil {
		t.Fatal(err)
	}

	content, err := readFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content != "content" {
		t.Errorf("expected trimmed content, got %q", content)
	}
}

func TestReadFile_NotFound(t *testing.T) {
	_, err := readFile("/nonexistent/path/file.txt")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}
