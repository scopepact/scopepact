# ScopePact Guard Migration Guide

Status: experimental v0.1. There is no production-supported upgrade path yet.

This guide describes the state that current Guard builds accept and the checks
required before changing binaries, policies, or receipt signers. It does not
turn an experimental release into a supported production deployment.

## Current Compatibility Contract

The current Guard accepts state journal version 3 only. A v3 deployment consists
of security-related files that must be treated as one operational set:

- the append-only `STATE.jsonl` journal;
- the sibling `STATE.jsonl.head` rollback-detection log;
- the signed policy bundle, pinned policy-issuer trust, and last-known-good
  `STATE.jsonl.policy-cache.json` when present;
- the active encrypted receipt key and its separately provisioned passphrase;
- exported signer trust and reconstructed audit files used by receipt consumers.

The journal binds the exact principal, agent, policy epoch, policy digest,
bundle digest, revocation set, and active receipt signer. Reopening with a
different value fails closed. A policy or signer transition must use the
authenticated `state activate-policy` or `state rotate-signer` command; replacing
configuration files is not a migration.

State v2 was experimental and is not accepted by v3. No automatic v2-to-v3
migration is currently shipped. This remains a release blocker in
[`ROADMAP.md`](../ROADMAP.md).

## Pre-Upgrade Procedure

1. Stop the Guard and its wrapped MCP server. Confirm no Guard process holds the
   state lock.
2. Run `state inspect` with the currently active signed bundle and receipt key.
3. Run `state export-audit` and `state export-trust`, then verify representative
   old receipts against the exported trust bundle.
4. Copy the complete operational set above to protected backup storage. Preserve
   file permissions, ownership, and the relationship between the journal and
   head log.
5. Record cryptographic checksums and the Guard source revision used for the
   inspection. Protect that manifest outside the state directory if rollback
   detection matters.
6. Test the candidate binary against a copy of the state in an isolated
   environment. Never let two Guard processes open the live state concurrently.
7. Start the candidate with the unchanged active bundle and signer, then repeat
   inspection and receipt verification before admitting tool traffic.

Current inspection mutates only one crash-recovery condition: if the journal
contains fully synchronized records missing from the tail of the head log,
opening validates the complete journal and existing head prefix, then repairs
every missing head entry. This includes an initialization crash after genesis
was synchronized but before the first head entry. Corrupt records, a head log
ahead of the journal, and partial trailing bytes fail closed.

## Failed Upgrade And Rollback

Do not restore an older copy of `STATE.jsonl` or its head log over newer live
state. Doing so can remove committed effect IDs and budget usage, enabling a
duplicate effect. The local two-file hash chain detects independent truncation,
but coordinated rollback of both files requires an external anchor to detect.

A binary rollback is acceptable only when that binary understands state v3 and
the active policy, key, and receipt contracts. Stop the candidate, inspect the
current state with a compatible tool, and start the previous binary against the
same current files. Do not downgrade the policy epoch or signer history.

If the only available backup predates committed effects, treat restoration as a
security incident. Keep the deployment offline, reconcile downstream effects,
rotate exposed trust where appropriate, and create a new policy epoch. The
project does not yet ship a disaster-recovery command that can prove an old
backup is safe to resume.

## Migrating Experimental V2 State

There is currently no supported in-place conversion. Keep v2 state read-only
with the exact historical binary needed to inspect it. Starting a new v3 state
is a deliberate authority reset: prior effect IDs, call counts, and spend totals
will not be present. It must use a new deployment audience or otherwise ensure
that old requests cannot be replayed, and downstream effects must be reconciled
before traffic resumes.

Do not hand-edit v2 records into v3. V3 record hashes, policy bindings, signer
history, and receipt commitments have different authenticated semantics.

## Support Window

ScopePact is pre-release. Only the current default branch receives security
fixes, and no historical state format has a guaranteed support window. A stable
Guard release must publish explicit upgrade, downgrade, migration, and
security-fix windows before this restriction can change.
