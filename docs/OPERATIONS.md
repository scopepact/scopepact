# ScopePact Guard Operations Runbook

Status: experimental v0.1. Exercise this runbook in an isolated environment
before relying on it. ScopePact Guard is not yet approved for production use.

This runbook covers the single-host local MCP Guard profile. It assumes the
host, filesystem synchronization, policy trust provisioning, and external
backup location behave as claimed. It does not recover from a fully compromised
host or prove coordinated rollback of both local state files.

## Deployment Inventory

Record these values for every deployment without storing passphrases or private
key plaintext in the inventory:

- Guard binary version, source revision, checksum, operating system, and
  architecture;
- wrapped MCP server binary, arguments, version, and checksum;
- policy audience, issuer, epoch, bundle digest, expiration, and trust-file
  checksum;
- active receipt signer key ID and encrypted-key-file checksum;
- absolute state, head-log, policy-cache, audit, and external-anchor locations;
- owner, incident contact, maintenance window, and last recovery exercise.

Run `state inspect` after provisioning and retain its output with the inventory.
Export signer trust and verify representative receipts before admitting tool
traffic.

## Backup

1. Stop the Guard and wrapped server. Confirm no process holds the state lock.
2. Run `state inspect`, `state export-audit`, and `state export-trust` with the
   active signed policy and receipt key.
3. Copy `STATE.jsonl`, `STATE.jsonl.head`, the signed policy bundle, issuer trust
   file, optional policy cache, encrypted receipt key, reconstructed audit, and
   exported receipt trust as one backup set.
4. Preserve restrictive ownership and permissions. Store the passphrase in the
   secret manager, not in the backup manifest.
5. Generate SHA-256 checksums for every file and protect the signed or otherwise
   authenticated manifest outside the state directory.
6. Verify the copied journal from an isolated location before declaring the
   backup complete.

The journal and head log are a pair. A copy made while Guard is running can
capture mismatched commit points and is not an accepted backup procedure.

## Restore

1. Keep the target deployment offline. Never overwrite newer live state with a
   backup in place.
2. Restore into a new protected directory and verify the backup manifest,
   ownership, permissions, policy issuer trust, and encrypted key provenance.
   Keep the state, head, policy cache, protected key, and passphrase as regular
   files with no group/other permissions; Unix Guard opens security-sensitive
   local files with `O_NOFOLLOW`.
3. Compare the restored journal head with the newest external anchor. If the
   restored state is older, stop and follow the rollback incident procedure.
4. Run `state inspect`, export audit and trust again, and compare them with the
   retained backup evidence.
5. Reconcile downstream effects after the backup timestamp. Missing commitments
   can permit duplicate execution and must not be dismissed as an audit issue.
6. Start Guard only after the accountable operator accepts that reconciliation.

Current Guard has no command that proves an old backup is safe to resume. A
restore that may omit committed effects is a security incident.

## Routine Policy Rotation And Revocation

Create and offline-verify a new bundle before the active bundle expires. Use a
strictly greater policy epoch and `state activate-policy` while Guard is
stopped. The transition cannot change the principal or agent identity and is
authenticated by the active receipt signer.

Use explicit revoked rule IDs in the new signed bundle to disable authority.
After activation, inspect the state, replace the policy cache, restart Guard,
and confirm the old bundle fails to reopen the journal. Never delete rules from
an unsigned file and treat that as revocation.

If a policy issuer key may be compromised, stop Guard, mark the issuer revoked
in the authenticated local trust configuration, provision a new issuer through
the configuration trust channel, and issue a greater policy epoch. Do not use
last-known-good fallback to extend the affected issuer or an expired bundle.

## Routine Receipt Signer Rotation

Generate and protect a replacement key, then run `state rotate-signer` while the
old provider is still available. The journal records a transcript cross-signed
by both keys. Export the new signer trust, distribute it through an authenticated
channel, and verify receipts from before and after rotation.

Retain the old encrypted key only for the approved evidence-retention need. It
must not reopen the active journal after rotation.

## Receipt Signer Compromise

1. Stop Guard and isolate the host and key-provider credentials.
2. Preserve state, logs, trust files, binaries, and downstream effect evidence.
3. Determine the earliest possible compromise time and identify every receipt
   signed by the affected key after that point.
4. Reconcile downstream effects against durable commitments and receipts.
5. Provision a new deployment trust root and policy epoch before resuming.

A cross-signed rotation authorized only after a key is compromised does not
prove that the legitimate operator approved the replacement. Current Guard can
represent revoked signer status in trust data but does not ship an authenticated
historical signer-revocation command. Treat that as a production blocker; do not
hand-edit the journal.

## Corrupt Or Partially Written State

Stop Guard and copy both state files before changing anything. `state inspect`
must fail closed on invalid hashes, signatures, sequence, policy/signer binding,
head-ahead rollback, oversized state, or partial tails.

Use `state recover-tail` only when bytes exist after the final complete newline.
It validates every complete journal/head record and removes only incomplete
trailing bytes. It cannot repair a changed complete record, a missing committed
journal record, or a head log ahead of the journal. Do not edit JSON, recalculate
hashes, or start with empty state as an expedient recovery.

## Suspected Rollback

Keep the deployment offline. Preserve the suspect state and compare both local
logs with the newest external anchor and downstream effects. A journal behind
its head log fails locally; coordinated rollback of both files requires the
external anchor to detect.

Assume effect IDs and budgets after the restored point are missing. Reconcile
all such effects, rotate affected trust, create a greater policy epoch, and
retain a sanitized incident report. Never fix rollback by copying an older head
log over a newer one.

## Wrapped Server Or Host Compromise

Guard authorizes MCP messages; it does not sandbox the wrapped process or undo
effects created outside an admitted call. On suspected compromise, stop both
processes, revoke policy authority through a greater signed epoch, isolate
credentials, preserve operational events and state, and investigate all host
and downstream effects independently of Guard receipts.

## Disaster-Recovery Exercise

At minimum, an exercise must demonstrate:

- clean backup and isolated restore with manifest verification;
- journal inspection, audit reconstruction, and historical receipt trust;
- duplicate suppression and monotonic budgets after restart;
- receipt signer rotation and policy activation;
- partial-tail recovery and rejection of a changed complete record;
- detection of head-ahead and externally anchored coordinated rollback;
- policy issuer, receipt signer, and wrapped-server compromise decisions;
- measured recovery time and state size on the deployment hardware.

Record the source revision, sanitized commands, expected and actual result,
participants, timestamps, gaps, owners, and remediation deadlines. Do not record
passphrases, private keys, credentials, prompts, tool arguments, or sensitive
resource paths in the published report.

Sanitized exercise reports are retained under
[`evidence/exercises/`](../evidence/exercises/). The initial local report is
not a substitute for release-platform or external exercises.
