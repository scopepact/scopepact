#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
guard_tmp=$(mktemp -d "${TMPDIR:-/tmp}/scopepact-proxy.XXXXXX")
trap 'rm -rf "$guard_tmp"' EXIT HUP INT TERM

cd "$project_root"
cargo build --quiet -p scopepact-guard
target/debug/scopepact-guard keygen --out "$guard_tmp/key.json" >/dev/null

{
    echo '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}'
    echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/workspace/project/README.md","content":"allowed"}}}'
    echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/hosts","content":"blocked"}}}'
} | target/debug/scopepact-guard mcp \
    --policy examples/mcp-guard-policy.json \
    --key "$guard_tmp/key.json" \
    --audit "$guard_tmp/audit.jsonl" \
    -- node conformance/javascript/mock_mcp_server.mjs \
    > "$guard_tmp/output.jsonl"

node conformance/javascript/verify_guard_proxy.mjs \
    "$guard_tmp/output.jsonl" \
    "$guard_tmp/audit.jsonl"
