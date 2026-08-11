# ScopePact Guard Performance Evidence

Status: initial reproducible harness. No production service objective is
claimed yet.

Run the optimized benchmark from a clean checkout with:

```sh
SCOPEPACT_BENCH_ITERATIONS=10000 \
SCOPEPACT_BENCH_STATE_RECORDS=100 \
./scripts/run-guard-benchmarks.sh > guard-benchmark.json
```

The harness emits `scopepact-guard-benchmark-v1` JSON containing the Guard
version, build profile, operating system, architecture, logical CPU count,
workload sizes, elapsed nanoseconds, per-operation latency, throughput, durable
append latency, recovery latency, and journal/head byte growth.

The four in-memory workloads are:

- unique allowed calls with Ed25519 receipt signing;
- unique calls to an ungranted tool, including blocked receipt signing;
- repeated calls with the same effect ID and digest after the first reservation;
- unique allowed calls carrying a one-unit typed payment.

The durable workload commits and synchronizes each allowed effect separately,
closes the state, reopens it, validates the complete hash/signature chain, and
reports recovered commitments and file sizes. It intentionally measures real
filesystem synchronization, so results are meaningful only with the filesystem
and storage hardware recorded alongside the JSON.

For peak resident memory, wrap the script in the platform measurement tool and
retain its output beside the JSON. On Linux use `/usr/bin/time -v`; on macOS use
`/usr/bin/time -l`. Do not compare debug builds, virtualized and bare-metal
storage, or runs with different iteration counts as regressions.

The current state compatibility ceilings are 50,000 records, 64 MiB for the
journal, 16 MiB for the head log, and 8 MiB per journal record. These are hard
rejection limits, not demonstrated performance targets. A release candidate
must benchmark startup/recovery near the supported ceiling, publish its runner
hardware and filesystem, and establish CI budgets from repeated clean-runner
measurements before the performance roadmap gate can be checked.
