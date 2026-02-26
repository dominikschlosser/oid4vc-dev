package qr

import (
	"image"
	"runtime"
	"strings"
	"testing"
)

const testQRContent = "openid4vp://authorize?client_id=test&response_type=vp_token"

func TestScanFile_ValidQR(t *testing.T) {
	got, err := ScanFile("testdata/test_qr.png")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != testQRContent {
		t.Errorf("got %q, want %q", got, testQRContent)
	}
}

func TestScanFile_NoQR(t *testing.T) {
	// Create a blank image file to test with
	_, err := ScanFile("testdata/no_qr.png")
	if err == nil {
		t.Fatal("expected error for image without QR code")
	}
}

func TestScanFile_InvalidPath(t *testing.T) {
	_, err := ScanFile("testdata/nonexistent.png")
	if err == nil {
		t.Fatal("expected error for non-existent file")
	}
}

func TestDecodeQR_BlankImage(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 100, 100))
	_, err := decodeQR(img)
	if err == nil {
		t.Fatal("expected error for blank image")
	}
}

func TestScanFile_InvalidImage(t *testing.T) {
	// A file that exists but isn't a valid image
	_, err := ScanFile("scan.go")
	if err == nil {
		t.Fatal("expected error for non-image file")
	}
}

func TestScanScreen_NonDarwin(t *testing.T) {
	// ScanScreen is only supported on macOS. On other platforms it returns
	// an error immediately. We can't test the interactive screencapture in
	// an automated test, so we only verify the platform guard here.
	if runtime.GOOS == "darwin" {
		t.Skip("skipping: ScanScreen launches interactive screencapture on macOS")
	}
	_, err := ScanScreen()
	if err == nil {
		t.Fatal("expected error on non-darwin platform")
	}
	if !strings.Contains(err.Error(), "only supported on macOS") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestScanFile_ErrorMessages(t *testing.T) {
	_, err := ScanFile("testdata/nonexistent.png")
	if err == nil || !strings.Contains(err.Error(), "opening image file") {
		t.Errorf("expected 'opening image file' error, got: %v", err)
	}

	_, err = ScanFile("testdata/no_qr.png")
	if err == nil || !strings.Contains(err.Error(), "no QR code found") {
		t.Errorf("expected 'no QR code found' error, got: %v", err)
	}
}
