package qr

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ScanScreen opens the macOS interactive screen region selector, captures the
// selected area, and decodes a QR code from it.
func ScanScreen() (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("--screen is only supported on macOS; use --qr with an image file instead")
	}

	tmpDir, err := os.MkdirTemp("", "ssi-debugger-qr-*")
	if err != nil {
		return "", fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	tmpFile := filepath.Join(tmpDir, "capture.png")

	// screencapture -i: interactive selection mode (crosshair)
	var stderr bytes.Buffer
	cmd := exec.Command("screencapture", "-i", tmpFile)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if strings.Contains(errMsg, "cannot capture") || strings.Contains(errMsg, "image from rect") {
			// Permission denied — open System Settings to the right pane
			_ = exec.Command("open", "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture").Run()
			return "", fmt.Errorf("screen recording permission denied\n\nSystem Settings has been opened to the Screen Recording pane.\nGrant access to your terminal app, then re-run the command.")
		}
		return "", fmt.Errorf("screencapture failed: %s", errMsg)
	}

	// User may press Escape to cancel — file won't exist
	if _, err := os.Stat(tmpFile); err != nil {
		return "", fmt.Errorf("screen capture cancelled")
	}

	return ScanFile(tmpFile)
}
