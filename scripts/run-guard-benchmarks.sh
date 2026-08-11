#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
iterations=${SCOPEPACT_BENCH_ITERATIONS:-10000}
state_records=${SCOPEPACT_BENCH_STATE_RECORDS:-100}

cd "$project_root"
cargo run --release --locked -p scopepact-guard --example benchmark_guard -- \
  --iterations "$iterations" \
  --state-records "$state_records"
