#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$project_root"

cargo fmt --all -- --check
cargo check --workspace --all-targets --no-default-features
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --doc --all-features
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s conformance/python -p 'test_*.py'
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s conformance -p 'test_server.py'
node --test conformance/javascript/agent_b.test.mjs
node --test conformance/javascript/guard_receipt.test.mjs
node --check conformance/javascript/scenario_runner.mjs
node --check conformance/javascript/drive_guard_proxy.mjs
node --check conformance/javascript/guard_receipt.mjs
node --check conformance/javascript/mock_mcp_server.mjs
node --check conformance/javascript/verify_guard_proxy.mjs
node --check conformance/javascript/verify_guard_failure.mjs
node --check conformance/web/app.js
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s website -p 'test_*.py'
node --check website/public/app.js
./scripts/run-cross-language.sh
./scripts/run-guard.sh
./scripts/run-guard-proxy.sh
