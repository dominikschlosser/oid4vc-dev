#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PORT=${PORT:-8085}

cd "$ROOT_DIR"

exec go run . wallet serve \
  --mode strict \
  --auto-accept \
  --pid \
  --port "$PORT" \
  "$@"
