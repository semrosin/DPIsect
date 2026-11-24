#!/usr/bin/env bash
set -euo pipefail

# Run from the repository root, where the default binary and artifact paths live.
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."
exec go run ./experiments/batch "$@"
