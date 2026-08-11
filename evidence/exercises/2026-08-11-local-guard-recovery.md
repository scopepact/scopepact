# Local Guard Recovery Exercise: 2026-08-11

Result: PASS with limitations. This is pre-release local evidence, not a
production certification or external review.

## Environment

- Time: `2026-08-11T07:26:42Z`
- Repository base revision: `62e48bd174b6c1a8254fe60a2518a64b0f383af3`
- Change set: uncommitted production-roadmap implementation under review
- Host: macOS 26.5.1 (25F80), arm64
- Rust: 1.91.1 (ed61e7d7e 2025-11-07)
- Operator: automated local exercise through
  `scripts/run-guard-recovery-exercise.sh`

No passphrases, private keys, credentials, prompts, request arguments, or
sensitive resource paths are retained in this report.

## Scenarios

| Scenario | Expected result | Actual result |
| --- | --- | --- |
| Receipt signer compromise status | An otherwise valid receipt signed by a locally revoked key is rejected | PASS |
| Policy rollback | A lower policy epoch and the prior signed bundle are rejected after authenticated activation | PASS |
| Corrupt state | A partial journal tail fails closed; explicit tail recovery validates the complete prefix | PASS |
| Journal rollback | A head log ahead of the journal fails closed | PASS |
| Interrupted initialization | A valid genesis journal with no head entry is reopened and its authenticated head is rebuilt | PASS |
| Lagging head repair | Multiple missing head entries are rebuilt only after journal and existing-prefix validation | PASS |
| Partial head write | A partial head tail fails closed; explicit recovery removes only the incomplete bytes and preserves duplicate suppression | PASS |
| Unavailable journal | The live writer is poisoned, no effect is forwarded, and restart finds no durable reservation | PASS |
| Uncertain append | A head-write failure poisons the live writer; restart repairs journal-ahead state and preserves duplicate suppression | PASS |
| Stopped backup and restore | Copying the stopped journal/head pair and reopening it preserves the committed effect and blocks its replay | PASS |
| Live operational continuity | MCP proxy, last-known-good policy fallback, audit reconstruction, signer rotation, policy activation, and historical receipt verification complete | PASS |
| Operational event redaction | Start, decision, and stop JSONL events contain no request ID, tool, arguments, resource, reason, signature, public key, or raw receipt | PASS |
| Private cache substitution | A symlink substituted for the last-known-good policy cache is rejected on Unix | PASS |
| Host-effect boundary | The wrapped server creates an out-of-band marker, proving Guard is not an OS sandbox | PASS |
| Invalid child output | Malformed and oversized child messages stop the proxy with a redacted worker-failure event | PASS |
| Abrupt child failure | A child exiting with status 23 stops Guard nonzero and preserves the child status in a redacted event | PASS |

The strict Rust lint gate also passed before the exercise. The Guard effect
fuzzer completed 10,000 ASAN runs separately in the same change set without a
crash.

## Commands

```sh
cargo clippy --workspace --all-targets --all-features -- -D warnings
./scripts/run-guard-recovery-exercise.sh
cargo test -p scopepact-guard --test durable_state \
  stopped_backup_and_restore_preserve_duplicate_suppression
```

The exercise script runs named regression tests for signer revocation, policy
rollback, corrupt state, head-ahead rollback, stopped backup/restore, missing
and partial head recovery, unavailable journal handling, and uncertain append
recovery. It then runs the healthy and hostile-child MCP proxy scenarios.

## Limitations And Follow-Up

- The exercise ran on one local macOS arm64 host. Linux, Windows, minimum-Rust,
  CI, slow-I/O, and storage-exhaustion results remain outstanding.
- Signer revocation was applied to a copied consumer trust bundle. Guard does
  not yet ship an authenticated historical signer-revocation journal command.
- The backup/restore test used a clean stopped local copy. It did not exercise a
  remote backup product, lost host, ownership restoration, or external manifest
  signer.
- Coordinated rollback of both local files was not exercised against a real
  external anchor; the repository does not yet provide an anchor integration.
- No real key, host, policy issuer, downstream server, HSM, or KMS was
  compromised. The scenarios validate response mechanics, not forensic
  completeness.
- Near-limit recovery time, real disk-full behavior, permission loss after
  open, process termination at every durable write boundary, slow stdio, and a
  documented soak period remain release-candidate gates.

Owners: Guard maintainers. These limitations remain open in `ROADMAP.md`; this
report must not be used to remove the evaluation-aid warning.
