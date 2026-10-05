#!/usr/bin/env bash
# Fast local gate: the flake's own formatting and eval-fixtures checks,
# the same two that gate CI.
set -euo pipefail

if ! command -v nix >/dev/null 2>&1; then
  echo "pre-commit: nix not found on PATH, skipping flake checks" >&2
  exit 0
fi

sys=$(nix eval --raw --impure --expr 'builtins.currentSystem')
exec nix build --no-link --accept-flake-config \
  ".#checks.$sys.formatting" ".#checks.$sys.eval-fixtures"
