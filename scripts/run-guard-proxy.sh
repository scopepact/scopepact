#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
guard_tmp=$(mktemp -d "${TMPDIR:-/tmp}/scopepact-proxy.XXXXXX")
trap 'rm -rf "$guard_tmp"' EXIT HUP INT TERM

cd "$project_root"
cargo build --quiet -p scopepact-guard
umask 077
printf '%s\n' 'scopepact-local-demo-passphrase' > "$guard_tmp/passphrase"
target/debug/scopepact-guard keygen \
    --out "$guard_tmp/key.json" \
    --passphrase-file "$guard_tmp/passphrase" \
    > /dev/null
printf '%s\n' 'scopepact-policy-demo-passphrase' > "$guard_tmp/policy-passphrase"
target/debug/scopepact-guard keygen \
    --out "$guard_tmp/policy-key.json" \
    --passphrase-file "$guard_tmp/policy-passphrase" \
    > /dev/null
target/debug/scopepact-guard policy trust-init \
    --issuer scopepact-demo-policy-issuer \
    --audience guard:local-development \
    --key "$guard_tmp/policy-key.json" \
    --key-passphrase-file "$guard_tmp/policy-passphrase" \
    --out "$guard_tmp/policy-trust.json" \
    > /dev/null
target/debug/scopepact-guard policy sign \
    --policy examples/mcp-guard-policy.json \
    --issuer scopepact-demo-policy-issuer \
    --audience guard:local-development \
    --key "$guard_tmp/policy-key.json" \
    --key-passphrase-file "$guard_tmp/policy-passphrase" \
    --out "$guard_tmp/policy-bundle.json" \
    > /dev/null
target/debug/scopepact-guard policy verify \
    --policy-bundle "$guard_tmp/policy-bundle.json" \
    --policy-trust "$guard_tmp/policy-trust.json" \
    --policy-audience guard:local-development \
    > /dev/null

SCOPEPACT_TEST_UNMEDIATED_MARKER="$guard_tmp/unmediated-effect" \
node conformance/javascript/drive_guard_proxy.mjs \
    target/debug/scopepact-guard mcp \
    --policy-bundle "$guard_tmp/policy-bundle.json" \
    --policy-trust "$guard_tmp/policy-trust.json" \
    --policy-audience guard:local-development \
    --key "$guard_tmp/key.json" \
    --key-passphrase-file "$guard_tmp/passphrase" \
    --state "$guard_tmp/state.jsonl" \
    --audit "$guard_tmp/audit.jsonl" \
    -- node conformance/javascript/mock_mcp_server.mjs \
    > "$guard_tmp/output.jsonl" \
    2> "$guard_tmp/events.jsonl"
test -f "$guard_tmp/unmediated-effect"

mv "$guard_tmp/policy-bundle.json" "$guard_tmp/policy-bundle.unavailable"
echo '{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"scopepact-demo","version":"0.1.0"}}}' | \
    target/debug/scopepact-guard mcp \
    --policy-bundle "$guard_tmp/policy-bundle.json" \
    --policy-trust "$guard_tmp/policy-trust.json" \
    --policy-audience guard:local-development \
    --key "$guard_tmp/key.json" \
    --key-passphrase-file "$guard_tmp/passphrase" \
    --state "$guard_tmp/state.jsonl" \
    -- node conformance/javascript/mock_mcp_server.mjs \
    > /dev/null
mv "$guard_tmp/policy-bundle.unavailable" "$guard_tmp/policy-bundle.json"

mv "$guard_tmp/state.jsonl.policy-cache.json" \
    "$guard_tmp/state.jsonl.policy-cache.real"
ln -s "$guard_tmp/state.jsonl.policy-cache.real" \
    "$guard_tmp/state.jsonl.policy-cache.json"
mv "$guard_tmp/policy-bundle.json" "$guard_tmp/policy-bundle.unavailable"
if printf '%s\n' '{"jsonrpc":"2.0","id":4,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"scopepact-demo","version":"0.1.0"}}}' | \
    target/debug/scopepact-guard mcp \
    --policy-bundle "$guard_tmp/policy-bundle.json" \
    --policy-trust "$guard_tmp/policy-trust.json" \
    --policy-audience guard:local-development \
    --key "$guard_tmp/key.json" \
    --key-passphrase-file "$guard_tmp/passphrase" \
    --state "$guard_tmp/state.jsonl" \
    -- node conformance/javascript/mock_mcp_server.mjs \
    > /dev/null 2> /dev/null
then
    echo "Guard unexpectedly followed a symlinked policy cache" >&2
    exit 1
fi
rm "$guard_tmp/state.jsonl.policy-cache.json"
mv "$guard_tmp/state.jsonl.policy-cache.real" \
    "$guard_tmp/state.jsonl.policy-cache.json"
mv "$guard_tmp/policy-bundle.unavailable" "$guard_tmp/policy-bundle.json"

target/debug/scopepact-guard state inspect \
    --policy-bundle "$guard_tmp/policy-bundle.json" \
    --policy-trust "$guard_tmp/policy-trust.json" \
    --policy-audience guard:local-development \
    --key "$guard_tmp/key.json" \
    --key-passphrase-file "$guard_tmp/passphrase" \
    --state "$guard_tmp/state.jsonl" \
    > /dev/null

target/debug/scopepact-guard state export-audit \
    --policy-bundle "$guard_tmp/policy-bundle.json" \
    --policy-trust "$guard_tmp/policy-trust.json" \
    --policy-audience guard:local-development \
    --key "$guard_tmp/key.json" \
    --key-passphrase-file "$guard_tmp/passphrase" \
    --state "$guard_tmp/state.jsonl" \
    --out "$guard_tmp/recovered-audit.jsonl"

cmp "$guard_tmp/audit.jsonl" "$guard_tmp/recovered-audit.jsonl"

printf '%s\n' 'scopepact-rotated-demo-passphrase' > "$guard_tmp/new-passphrase"
target/debug/scopepact-guard keygen \
    --out "$guard_tmp/new-key.json" \
    --passphrase-file "$guard_tmp/new-passphrase" \
    > /dev/null
target/debug/scopepact-guard state rotate-signer \
    --policy-bundle "$guard_tmp/policy-bundle.json" \
    --policy-trust "$guard_tmp/policy-trust.json" \
    --policy-audience guard:local-development \
    --key "$guard_tmp/key.json" \
    --key-passphrase-file "$guard_tmp/passphrase" \
    --new-key "$guard_tmp/new-key.json" \
    --new-key-passphrase-file "$guard_tmp/new-passphrase" \
    --state "$guard_tmp/state.jsonl" \
    > /dev/null
node conformance/javascript/verify_guard_proxy.mjs \
    "$guard_tmp/output.jsonl" \
    "$guard_tmp/audit.jsonl" \
    "$guard_tmp/events.jsonl"

run_child_failure() {
    failure_mode=$1
    expected_event=$2
    failure_state="$guard_tmp/state-$failure_mode.jsonl"
    failure_events="$guard_tmp/events-$failure_mode.log"
    if printf '%s\n' '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"scopepact-failure-test","version":"0.1.0"}}}' | \
        SCOPEPACT_TEST_SERVER_MODE="$failure_mode" \
        target/debug/scopepact-guard mcp \
        --policy-bundle "$guard_tmp/policy-bundle.json" \
        --policy-trust "$guard_tmp/policy-trust.json" \
        --policy-audience guard:local-development \
        --key "$guard_tmp/new-key.json" \
        --key-passphrase-file "$guard_tmp/new-passphrase" \
        --state "$failure_state" \
        -- node conformance/javascript/mock_mcp_server.mjs \
        > /dev/null 2> "$failure_events"
    then
        echo "Guard unexpectedly accepted child failure mode $failure_mode" >&2
        exit 1
    fi
    node conformance/javascript/verify_guard_failure.mjs \
        "$failure_events" "$expected_event"
}

run_child_failure invalid_output worker_failure
run_child_failure oversized_output worker_failure
run_child_failure exit_nonzero child_exit

node -e 'const fs=require("fs"); const p=JSON.parse(fs.readFileSync(process.argv[1])); p.policy_epoch=2; fs.writeFileSync(process.argv[2], JSON.stringify(p, null, 2)+"\n");' \
    examples/mcp-guard-policy.json \
    "$guard_tmp/next-policy.json"
target/debug/scopepact-guard policy sign \
    --policy "$guard_tmp/next-policy.json" \
    --issuer scopepact-demo-policy-issuer \
    --audience guard:local-development \
    --key "$guard_tmp/policy-key.json" \
    --key-passphrase-file "$guard_tmp/policy-passphrase" \
    --out "$guard_tmp/next-policy-bundle.json" \
    > /dev/null
target/debug/scopepact-guard state activate-policy \
    --policy-bundle "$guard_tmp/policy-bundle.json" \
    --policy-trust "$guard_tmp/policy-trust.json" \
    --policy-audience guard:local-development \
    --new-policy-bundle "$guard_tmp/next-policy-bundle.json" \
    --new-policy-trust "$guard_tmp/policy-trust.json" \
    --new-policy-audience guard:local-development \
    --key "$guard_tmp/new-key.json" \
    --key-passphrase-file "$guard_tmp/new-passphrase" \
    --state "$guard_tmp/state.jsonl" \
    > /dev/null
target/debug/scopepact-guard state inspect \
    --policy-bundle "$guard_tmp/next-policy-bundle.json" \
    --policy-trust "$guard_tmp/policy-trust.json" \
    --policy-audience guard:local-development \
    --key "$guard_tmp/new-key.json" \
    --key-passphrase-file "$guard_tmp/new-passphrase" \
    --state "$guard_tmp/state.jsonl" \
    > /dev/null
target/debug/scopepact-guard state export-trust \
    --policy-bundle "$guard_tmp/next-policy-bundle.json" \
    --policy-trust "$guard_tmp/policy-trust.json" \
    --policy-audience guard:local-development \
    --key "$guard_tmp/new-key.json" \
    --key-passphrase-file "$guard_tmp/new-passphrase" \
    --state "$guard_tmp/state.jsonl" \
    --out "$guard_tmp/signer-trust.json"
sed -n '1p' "$guard_tmp/audit.jsonl" | \
    target/debug/scopepact-guard verify --trust-bundle "$guard_tmp/signer-trust.json" \
    > /dev/null
