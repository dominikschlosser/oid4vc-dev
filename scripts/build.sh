#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

VERSION="${1:-dev}"
LDFLAGS="-s -w -X github.com/dominikschlosser/oid4vc-dev/cmd.Version=${VERSION}"

echo "Formatting..."
go run golang.org/x/tools/cmd/goimports@latest -w -local github.com/dominikschlosser/oid4vc-dev .
gofmt -w .

echo "Building oid4vc-dev ${VERSION}..."
go build -ldflags "$LDFLAGS" -o oid4vc-dev .
echo "Done: ./oid4vc-dev"

# Detect current shell and install completions
CURRENT_SHELL="$(basename "$SHELL")"
BINARY="${PROJECT_DIR}/oid4vc-dev"

case "$CURRENT_SHELL" in
  zsh)
    COMP_DIR="${HOME}/.zsh/completions"
    mkdir -p "$COMP_DIR"
    "$BINARY" completion zsh > "$COMP_DIR/_oid4vc-dev"
    echo "Installed zsh completions to $COMP_DIR/_oid4vc-dev"
    echo "Run 'source $COMP_DIR/_oid4vc-dev' or add $COMP_DIR to your fpath and restart your shell."
    ;;
  bash)
    COMP_DIR="${HOME}/.local/share/bash-completion/completions"
    mkdir -p "$COMP_DIR"
    "$BINARY" completion bash > "$COMP_DIR/oid4vc-dev"
    echo "Installed bash completions to $COMP_DIR/oid4vc-dev"
    echo "Run 'source $COMP_DIR/oid4vc-dev' or restart your shell."
    ;;
  fish)
    COMP_DIR="${HOME}/.config/fish/completions"
    mkdir -p "$COMP_DIR"
    "$BINARY" completion fish > "$COMP_DIR/oid4vc-dev.fish"
    echo "Installed fish completions to $COMP_DIR/oid4vc-dev.fish"
    ;;
  *)
    echo "Unknown shell '$CURRENT_SHELL', skipping completion installation."
    ;;
esac
