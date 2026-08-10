#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
guard_tmp=$(mktemp -d "${TMPDIR:-/tmp}/scopepact-guard.XXXXXX")
trap 'rm -rf "$guard_tmp"' EXIT HUP INT TERM

cd "$project_root"
cargo run --quiet -p scopepact-guard -- keygen --out "$guard_tmp/key.json" >/dev/null

echo "Allowed in-scope call:"
cargo run --quiet -p scopepact-guard -- check \
    --policy examples/mcp-guard-policy.json \
    --key "$guard_tmp/key.json" \
    < examples/mcp-allowed.json \
    > "$guard_tmp/allowed-receipt.json"
sed -n '1,120p' "$guard_tmp/allowed-receipt.json"

echo
echo "Independent receipt verification:"
cargo run --quiet -p scopepact-guard -- verify \
    < "$guard_tmp/allowed-receipt.json"

echo
echo "Blocked out-of-scope call:"
if cargo run --quiet -p scopepact-guard -- check \
    --policy examples/mcp-guard-policy.json \
    --key "$guard_tmp/key.json" \
    < examples/mcp-blocked.json \
    > "$guard_tmp/blocked-receipt.json"; then
    echo "Out-of-scope call was accepted." >&2
    exit 1
else
    status=$?
    if [ "$status" -ne 3 ]; then
        exit "$status"
    fi
fi
sed -n '1,120p' "$guard_tmp/blocked-receipt.json"

echo
echo "ScopePact Guard demo passed."
