# ScopePact Production Roadmap

This roadmap defines engineering order and release gates, not calendar promises.
Completion requires checked-in evidence such as tests, benchmarks, review reports,
release manifests, or operational exercises. A feature is not complete because it
has been demonstrated once.

## Release Tracks

ScopePact has two release tracks with independent status:

1. **Community Guard** is the deployable local MCP enforcement runtime. It can
   reach production readiness before the broader protocol is stable.
2. **ScopePact Protocol** is the cross-runtime authority and proof contract. A
   stable protocol release additionally requires frozen encodings, multiple
   independent implementations, and deployment-profile interoperability.

Status claims must name the component. "Guard 1.0" does not mean "ScopePact
Protocol v1," and passing wire vectors does not make an SDK a production
enforcement runtime.

## Current Baseline: Research Alpha

The following alpha evidence exists today:

- [x] Rust authority kernel with identity, replay, capability attenuation,
  revocation, payment limits, and per-effect decisions.
- [x] Local MCP stdio Guard for `tools/call`, fail-closed policy enforcement,
  duplicate suppression, and Ed25519-signed decision receipts.
- [x] Cross-language envelope and receipt verification with negative cases.
- [x] Shared transcript vectors across Rust, Python, JavaScript, Flutter, Swift,
  Go, C++, and C#.
- [x] Public threat model, security invariants, governance, licensing, and
  vulnerability-reporting process.

The current release remains an evaluation aid. Durable local state, encrypted
receipt keys, authenticated policies, transactional receipt commitments, and a
strict MCP message boundary now exist. State migration, symlink-safe resource
enforcement, operating-system sandbox evidence, hostile-failure/load testing,
external review, reproducible releases, and frozen public interfaces still
prevent a production claim.

## Phase 1: Community Guard Beta

**Objective:** survive restart, reject unsafe configuration, and enforce a
trusted policy without depending on a hosted service.

### Durable decisions and budgets

- [x] Define a versioned storage contract independent of the policy engine.
- [x] Atomically persist effect reservations, effect digests, call counts,
  cumulative spend, active policy epoch, and receipt-chain position.
- [x] Recover without re-authorizing an already committed effect after a clean
  restart, process crash, or interrupted write.
- [x] Fail closed on corrupt, rolled-back, incompatible, or partially written
  state; provide an explicit operator recovery command rather than silently
  resetting security state.
- [x] Make receipt retention and budget/effect commitment one transaction, then
  derive or repair the human-readable audit stream from committed records.
- [ ] Test process contention, storage exhaustion, restart, crash points,
  rollback detection, and migration from every supported state version.

### Key custody and rotation

- [x] Replace direct raw-seed use in the decision path with a signer interface
  that accepts typed transcript bytes and never exposes key material.
- [x] Support a protected local provider first, with restrictive file creation,
  encrypted-at-rest key material, and non-interactive secret injection.
- [x] Define provider hooks for operating-system keystores, PKCS#11, and cloud
  KMS/HSM services without making any one vendor normative.
- [x] Publish signer trust bundles containing key IDs, public keys, validity
  windows, status, and replacement relationships.
- [x] Support overlapping key rotation and verify old receipts after rotation;
  reject unknown, expired, or revoked signers according to local policy.

### Authenticated policy lifecycle

- [x] Publish a strict, versioned JSON Schema for Guard policy and examples.
- [x] Define a signed policy-bundle transcript covering issuer, audience,
  policy epoch, validity window, rules, revocations, and content digest.
- [x] Pin trusted policy issuers locally and reject rollback, stale epochs,
  future activation outside clock tolerance, unknown fields, and invalid
  signatures.
- [x] Activate policy and revocation changes atomically with durable state.
- [x] Keep a last-known-good policy for availability while ensuring an expired
  or revoked policy cannot be extended implicitly.
- [x] Add an offline validation command that explains policy errors without
  activating the bundle.

### MCP enforcement boundary

- [x] Parse and classify every MCP client-to-server and server-to-client
  JSON-RPC message type supported by the declared MCP version.
- [x] Define explicit pass, inspect, transform, and reject behavior for each
  message class, including notifications, cancellation, progress, and errors.
- [x] Bound line size, nesting, string size, batch size, pending requests,
  concurrency, child-process output, and decision latency before expensive work.
- [x] Preserve valid JSON-RPC request IDs exactly and document the correlation
  rule across reconnects.
- [ ] Add adapter-specific resource canonicalization. Filesystem enforcement
  must resolve symlinks and canonical roots in the same trust boundary as the
  effect, or reject policies that claim it does.
- [x] Document and test the operating-system sandbox boundary separately from
  protocol authorization.

### Beta exit evidence

- [ ] Restart and injected-crash suites demonstrate at-most-once effects and
  monotonic budgets across all durable commit points.
- [x] Corrupt state, untrusted policy, signer mismatch, and unsafe resource
  interpretation fail closed with actionable diagnostics.
- [ ] The full repository and portable SDK verification suites pass in CI on
  every supported operating system and minimum toolchain.
- [x] `SECURITY.md`, the Guard guide, examples, and migration guide describe the
  implemented boundary without a production claim.

## Phase 2: Community Guard Release Candidate

**Objective:** demonstrate that the beta design remains secure under hostile
inputs, realistic load, operational failure, and software-supply-chain review.

### Adversarial and reliability engineering

- [ ] Add coverage-guided fuzz targets for JSON-RPC framing, policy parsing,
  path/resource canonicalization, receipt decoding, signed bundles, state
  recovery, and every domain-separated transcript.
- [x] Add property tests for capability attenuation, budget monotonicity,
  idempotence, serialization round trips, and policy-epoch ordering.
- [ ] Model concurrent effect reservation and policy activation; test the model
  against the storage implementation with deterministic fault injection.
- [ ] Test disk-full, permission loss, clock skew, key-provider outage, child
  process failure, broken pipes, oversized traffic, slow readers/writers, and
  abrupt termination.
- [ ] Run dependency, license, secret, and unsafe-code checks on every release.

### Performance and denial-of-service limits

- [ ] Publish reproducible latency, throughput, memory, and state-growth
  benchmarks for allowed, blocked, duplicate, and payment-bearing calls.
- [x] Define supported maximums and hard rejection behavior for every untrusted
  input and resource dimension.
- [ ] Establish performance regression budgets in CI and document the hardware
  and workload used for release measurements.
- [ ] Verify bounded startup and recovery time at the documented state limit.

### Evidence and operations

- [x] Link receipts into a tamper-evident chain anchored by durable state and
  support offline continuity verification and audit reconstruction.
- [x] Emit structured, redaction-safe operational events and health signals
  without recording prompts, private reasoning, credentials, or raw secrets.
- [x] Publish backup, restore, rotation, revocation, incident, compromise,
  rollback, and disaster-recovery runbooks.
- [x] Exercise key compromise, policy rollback, corrupt state, and disaster
  recovery; retain sanitized exercise reports as release evidence.
- [x] Define version support, security-fix, and migration windows.

### Reproducible release pipeline

- [ ] Build pinned, reproducible artifacts for supported targets from a clean
  environment.
- [ ] Generate checksums, an SBOM, source provenance, license notices, and
  machine-readable release metadata.
- [ ] Sign tags, artifacts, checksums, and provenance with documented offline
  verification steps and a rotation/revocation process for release keys.
- [ ] Publish installation, upgrade, downgrade, migration, and rollback tests.
- [ ] Prove the release contains the same source revision and test vectors that
  passed the release gate.

### Release-candidate exit evidence

- [ ] No open critical or high-severity issue within the claimed Guard boundary.
- [ ] Fuzzing, fault injection, load, recovery, and platform matrices pass for a
  documented soak period with no unexplained crash, state loss, or duplicate
  execution.
- [ ] A release candidate can be installed, upgraded, backed up, restored, and
  independently verified using only public documentation and artifacts.
- [ ] The threat model and every known limitation have an owner, mitigation,
  explicit deployment assumption, or removal from the production claim.

## Phase 3: Community Guard 1.0

**Objective:** make a narrow, evidence-backed production claim for the documented
local MCP Guard deployment profile.

- [ ] Obtain external cryptographic, authorization, and implementation review;
  publish the scope, findings, fixes, and residual risks.
- [ ] Resolve every blocking external finding and add regression coverage.
- [ ] Complete at least one production-like pilot operated from the public
  runbooks, including recovery and signer/policy rotation.
- [ ] Freeze the Guard 1.x CLI, policy, state, and receipt compatibility rules;
  publish a deprecation and migration policy.
- [ ] Publish the supported deployment matrix, service objectives, resource
  limits, and incident-response contacts.
- [ ] Cut and verify the signed `scopepact-guard` 1.0 release from an approved
  release candidate.

Only after every item above is evidenced may Guard documentation remove the
"evaluation aid" warning for the supported deployment profile. ScopePact still
must not be described as a sandbox or as protection against a compromised host
or a downstream server that creates unmediated effects.

## Phase 4: ScopePact Protocol v1 Candidate

**Objective:** turn the implemented security kernel into a stable,
cross-organization interoperability contract.

### Normative protocol and profiles

- [ ] Freeze the mandatory v1 state machines, envelope, handshake, capability,
  effect, revocation, and extension semantics.
- [ ] Specify deterministic CBOR/COSE encodings for grants, mandates, receipts,
  and trust bundles with canonical positive and negative vectors.
- [ ] Specify secure transport profiles with exporter binding, clock-skew rules,
  resource limits, trust-anchor provisioning, and reconnect behavior.
- [ ] Complete remote MCP identity/authorization, A2A task/artifact, and typed
  payment mandate profiles without weakening the core invariants.
- [ ] Define compatibility negotiation, extension registration, deprecation,
  migration, and unknown-critical-extension behavior.

### Independent interoperability

- [ ] Publish generated data-model bindings separately from enforcement-runtime
  maturity claims.
- [ ] Complete an independent full-kernel implementation maintained outside the
  Rust reference implementation's code path.
- [ ] Require at least two independent implementations to pass wire, kernel,
  deployment, negative, and cross-version suites.
- [ ] Run public interoperability events and retain signed, reproducible reports.
- [ ] Obtain external review of the frozen cryptographic transcripts and
  authorization semantics before the final compatibility freeze.

### Protocol v1 exit evidence

- [ ] All normative documents use testable MUST/SHOULD language and map each
  security requirement to vectors or deployment tests.
- [ ] Every supported profile has a deployment threat model, operations guide,
  and explicit certification scope.
- [ ] Protocol v1 artifacts are reproducible, signed, versioned, and governed by
  the public compatibility and vulnerability-response processes.
- [ ] Two independent implementations interoperate across every mandatory
  profile without private test fixtures or undocumented behavior.

## Phase 5: ScopePact Protocol v1

- [ ] Resolve all blocking candidate and external-review findings.
- [ ] Freeze v1 transcripts, schemas, vectors, and compatibility rules.
- [ ] Publish signed normative specifications, conformance assets, migration
  guidance, and the independent interoperability report.
- [ ] Cut stable runtime and SDK releases only for surfaces that independently
  meet their documented maturity gates.

## Cross-Cutting Rules

- Security fixes and reusable enforcement features remain in the public
  repository. Enterprise orchestration may consume public interfaces but cannot
  privately redefine conformance or protocol behavior.
- New dependencies require maintenance, provenance, license, and compromise-
  recovery review proportional to their role in the trusted computing base.
- Natural-language prompts and model output never become authority-bearing
  inputs merely to improve compatibility or convenience.
- Unknown or ambiguous security state fails closed. Recovery is an explicit,
  audited operator action.
- Marketing, website, README, SDK, and security-policy status claims are updated
  only after the matching exit evidence is checked in.
