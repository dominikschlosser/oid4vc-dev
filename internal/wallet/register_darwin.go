//go:build darwin

package wallet

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const appBundleName = "OID4VC-Dev-Wallet.app"

func appBundlePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Applications", appBundleName)
}

func handlerScriptPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".oid4vc-dev", "url-handler.sh")
}

// RegisterURLSchemes creates a macOS .app bundle via osacompile and registers URL scheme handlers.
// macOS delivers URLs via Apple Events, so we use an AppleScript with "on open location"
// that calls a bash handler script.
func RegisterURLSchemes(listenerPort int) error {
	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding executable path: %w", err)
	}
	binaryPath, err = filepath.EvalSymlinks(binaryPath)
	if err != nil {
		return fmt.Errorf("resolving executable path: %w", err)
	}

	// Write the bash handler script
	handlerPath := handlerScriptPath()
	if err := os.MkdirAll(filepath.Dir(handlerPath), 0755); err != nil {
		return fmt.Errorf("creating handler directory: %w", err)
	}

	handler := strings.ReplaceAll(strings.ReplaceAll(`#!/bin/bash
BINARY="{{BINARY_PATH}}"
URI="$1"
LISTENER="http://localhost:{{PORT}}"

case "$URI" in
  openid-credential-offer://*)
    curl -sf -X POST "$LISTENER/api/offers" \
      -H "Content-Type: application/json" \
      -d "{\"uri\":\"$URI\"}" 2>/dev/null \
      || "$BINARY" wallet accept "$URI" 2>&1 | tee /tmp/oid4vc-dev-wallet.log
    ;;
  *)
    curl -sf -X POST "$LISTENER/api/presentations" \
      -H "Content-Type: application/json" \
      -d "{\"uri\":\"$URI\"}" 2>/dev/null \
      || "$BINARY" wallet accept "$URI" 2>&1 | tee /tmp/oid4vc-dev-wallet.log
    ;;
esac
`, "{{BINARY_PATH}}", binaryPath), "{{PORT}}", fmt.Sprintf("%d", listenerPort))

	if err := os.WriteFile(handlerPath, []byte(handler), 0755); err != nil {
		return fmt.Errorf("writing handler script: %w", err)
	}

	// Remove existing bundle so osacompile can create a fresh one
	bundlePath := appBundlePath()
	os.RemoveAll(bundlePath)
	if err := os.MkdirAll(filepath.Dir(bundlePath), 0755); err != nil {
		return fmt.Errorf("creating Applications directory: %w", err)
	}

	// Write AppleScript source — "on open location" receives the URL from macOS Apple Events
	appleScript := fmt.Sprintf(`on open location theURL
	do shell script quoted form of "%s" & " " & quoted form of theURL & " >> /tmp/oid4vc-dev-wallet.log 2>&1 &"
end open location
`, handlerPath)

	tmpScript, err := os.CreateTemp("", "oid4vc-dev-*.applescript")
	if err != nil {
		return fmt.Errorf("creating temp AppleScript: %w", err)
	}
	defer os.Remove(tmpScript.Name())

	if _, err := tmpScript.WriteString(appleScript); err != nil {
		tmpScript.Close()
		return fmt.Errorf("writing AppleScript: %w", err)
	}
	tmpScript.Close()

	// Compile AppleScript into .app bundle
	cmd := exec.Command("osacompile", "-o", bundlePath, tmpScript.Name())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("osacompile failed: %s: %w", string(out), err)
	}

	// Patch Info.plist to add URL schemes and LSUIElement (no Dock icon)
	plistPath := filepath.Join(bundlePath, "Contents", "Info.plist")
	plistBuddy := "/usr/libexec/PlistBuddy"

	plistCmds := [][]string{
		{"-c", "Add :CFBundleIdentifier string com.oid4vc-dev.wallet", plistPath},
		{"-c", "Add :LSUIElement bool true", plistPath},
		{"-c", "Add :CFBundleURLTypes array", plistPath},
		// OID4VP schemes
		{"-c", "Add :CFBundleURLTypes:0 dict", plistPath},
		{"-c", "Add :CFBundleURLTypes:0:CFBundleURLName string OID4VP", plistPath},
		{"-c", "Add :CFBundleURLTypes:0:CFBundleURLSchemes array", plistPath},
		{"-c", "Add :CFBundleURLTypes:0:CFBundleURLSchemes:0 string openid4vp", plistPath},
		{"-c", "Add :CFBundleURLTypes:0:CFBundleURLSchemes:1 string eudi-openid4vp", plistPath},
		{"-c", "Add :CFBundleURLTypes:0:CFBundleURLSchemes:2 string haip", plistPath},
		// OID4VCI scheme
		{"-c", "Add :CFBundleURLTypes:1 dict", plistPath},
		{"-c", "Add :CFBundleURLTypes:1:CFBundleURLName string OID4VCI", plistPath},
		{"-c", "Add :CFBundleURLTypes:1:CFBundleURLSchemes array", plistPath},
		{"-c", "Add :CFBundleURLTypes:1:CFBundleURLSchemes:0 string openid-credential-offer", plistPath},
	}

	for _, args := range plistCmds {
		cmd := exec.Command(plistBuddy, args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("PlistBuddy %v failed: %s: %w", args, string(out), err)
		}
	}

	// Re-sign the bundle (osacompile signs it, but PlistBuddy modifications invalidate the signature)
	cmd = exec.Command("codesign", "--force", "--sign", "-", bundlePath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("codesign failed: %s: %w", string(out), err)
	}

	// Register with Launch Services
	lsregister := "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
	cmd = exec.Command(lsregister, "-R", bundlePath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("lsregister failed: %s: %w", string(out), err)
	}

	fmt.Printf("Registered URL scheme handlers:\n")
	fmt.Printf("  App bundle: %s\n", bundlePath)
	fmt.Printf("  Handler:    %s\n", handlerPath)
	fmt.Printf("  Binary:     %s\n", binaryPath)
	fmt.Printf("  Schemes:    openid4vp://, eudi-openid4vp://, haip://, openid-credential-offer://\n")
	return nil
}

// UnregisterURLSchemes removes the macOS .app bundle and handler script.
func UnregisterURLSchemes() error {
	bundlePath := appBundlePath()

	// Unregister from Launch Services
	lsregister := "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
	cmd := exec.Command(lsregister, "-u", bundlePath)
	cmd.CombinedOutput() // ignore errors if not registered

	// Remove the app bundle
	if err := os.RemoveAll(bundlePath); err != nil {
		return fmt.Errorf("removing app bundle: %w", err)
	}

	// Remove handler script
	os.Remove(handlerScriptPath()) // ignore errors if not present

	fmt.Printf("Unregistered URL scheme handlers and removed %s\n", bundlePath)
	return nil
}
