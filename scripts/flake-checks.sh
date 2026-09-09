#!/usr/bin/env bash
# Build the two flake checks the CI flake-checks job gates on, resolving the
# current system so this runs on both linux and darwin. Kept fast by treefmt's
# excludes of the hash-bound evidence trees; nix evaluation is the slow step.
set -euo pipefail
sys=$(nix eval --raw --impure --expr builtins.currentSystem)
exec nix build --print-build-logs \
  ".#checks.${sys}.formatting" \
  ".#checks.${sys}.eval-fixtures"
