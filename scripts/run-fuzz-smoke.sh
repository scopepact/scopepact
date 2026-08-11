#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

command -v cargo-fuzz >/dev/null 2>&1 || {
  echo "cargo-fuzz is required; install it with: cargo install cargo-fuzz --locked" >&2
  exit 1
}

for target in mcp_message signed_inputs state_recovery guard_effect; do
  cargo +nightly fuzz run \
    --fuzz-dir "$project_root/fuzz" \
    "$target" \
    -- -runs=10000
done
