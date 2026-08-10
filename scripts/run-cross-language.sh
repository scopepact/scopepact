#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
conformance_root="$project_root/conformance"
demo_tmp=$(mktemp -d "${TMPDIR:-/tmp}/scopepact-demo.XXXXXX")
trap 'rm -rf "$demo_tmp"' EXIT HUP INT TERM

python3 "$conformance_root/python/agent_a.py" offer "$demo_tmp/offer.json"
node "$conformance_root/javascript/agent_b.mjs" "$demo_tmp/offer.json" "$demo_tmp/reply.json"
python3 "$conformance_root/python/agent_a.py" verify-reply "$demo_tmp/reply.json"
python3 "$conformance_root/python/agent_a.py" tamper "$demo_tmp/offer.json" "$demo_tmp/tampered.json"

if node "$conformance_root/javascript/agent_b.mjs" \
    "$demo_tmp/tampered.json" "$demo_tmp/invalid-reply.json" >/dev/null 2>&1; then
    echo "Tampered payload was accepted." >&2
    exit 1
fi

echo "JavaScript Agent B: rejected tampered payload"
echo "ScopePact cross-language exchange passed."
