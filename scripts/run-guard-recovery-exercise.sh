#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"

cargo test -p scopepact-guard --test durable_state \
  revoked_signer_status_rejects_an_otherwise_valid_receipt
cargo test -p scopepact-guard --test durable_state \
  signed_policy_activation_is_monotonic_and_preserves_history
cargo test -p scopepact-guard --test durable_state \
  corrupted_journal_fails_closed
cargo test -p scopepact-guard --test durable_state \
  head_ahead_of_journal_fails_closed_after_commit_crash
cargo test -p scopepact-guard --test durable_state \
  journal_genesis_with_empty_head_recovers_initialization_crash
cargo test -p scopepact-guard --test durable_state \
  multiple_missing_head_records_are_rebuilt_from_validated_journal
cargo test -p scopepact-guard --test durable_state \
  partial_head_tail_recovery_preserves_committed_effect
cargo test -p scopepact-guard --test durable_state \
  stopped_backup_and_restore_preserve_duplicate_suppression
cargo test -p scopepact-guard \
  state::tests::append_failure_poisons_writer_and_recovery_preserves_commitment
cargo test -p scopepact-guard \
  state::tests::unavailable_journal_poisons_writer_without_durable_commitment
./scripts/run-guard-proxy.sh

echo "ScopePact Guard recovery exercise passed."
