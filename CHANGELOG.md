# Changelog

ScopePact follows Keep a Changelog structure while the project is pre-release.

## Unreleased

### Added

- deterministic authenticated handshake and identity proof transcript;
- capability attenuation and per-effect authority kernel;
- optional sender-constrained JWT federation profile;
- Python and JavaScript cross-language frame implementations;
- Flutter and Swift alpha envelope SDKs backed by a shared runtime vector;
- Go, C++20/OpenSSL, and C#/.NET alpha envelope SDKs backed by the same vector;
- 15-case local conformance workbench;
- `scopepact-guard` MCP stdio proxy with policy enforcement;
- Ed25519-signed decision receipts with a language-neutral transcript;
- cross-language proxy and receipt verification demonstration;
- contributor, governance, security, and roadmap documentation;
- public introduction site at [scopepact.org](https://scopepact.org), including
  the motivation, trust boundary, architecture, runtime status, and evidence.
- community-first governance commitments, public maintainer path, support
  guidance, and structured GitHub contribution templates.
- phased, evidence-gated production roadmap separating Community Guard and
  cross-protocol stability claims;
- crash-safe, single-writer Guard decision journal with durable budget and
  effect replay, hash-linked records, truncation detection, and policy/signer
  binding;
- Guard state inspection, audit reconstruction, and explicit partial-tail
  recovery commands.
- typed receipt-signer provider boundary and an authenticated encrypted local
  key format using Argon2id and XChaCha20-Poly1305;
- non-interactive passphrase-file loading with restrictive file checks and
  wrong-passphrase/tamper regression coverage.
- cross-signed receipt-signer rotation records, journal-derived historical
  signer trust bundles, and trust-aware offline receipt verification.
- strict Draft 2020-12 Guard policy schema with validator-backed drift and
  rejection tests;
- audience-bound signed policy bundles, pinned issuer trust, explicit rule
  revocations, and offline policy verification.
- authenticated, monotonic policy-epoch activation in Guard state v3 with exact
  bundle/revocation binding and multi-epoch receipt trust history.
- atomically replaced last-known-good policy caching with signature, issuer,
  audience, revocation, and hard-expiration revalidation on fallback.
- bidirectional MCP 2025-06-18 JSON-RPC classification, lifecycle enforcement,
  exact request correlation, progress/cancellation checks, and bounded traffic;
- fail-closed child-output inspection and explicit rejection of server-initiated
  requests other than `ping`.
- deterministic Guard receipt vector reproduced by Rust and independently
  verified, including negative cases, by JavaScript and Python.
- property-based coverage for capability attenuation, monotonic policy epochs,
  Guard budgets, duplicate effects, and receipt serialization round trips;
- deterministic durable-state fault tests for journal-ahead recovery and
  fail-closed head-ahead rollback detection;
- poisoned-writer handling after uncertain durable appends, with deterministic
  head-log failure recovery that preserves the committed effect reservation;
- hard recovery ceilings for state bytes, head bytes, record count, and record
  size, with bounded-reader rejection tests;
- coverage-guided fuzz harnesses for MCP message classification, policy and
  signed-input parsing, receipt verification, Guard effect/resource/payment
  mapping, and durable-state recovery.
- clean-runner CI for Rust 1.85 and stable Linux, macOS, and Windows, plus
  separate portable SDK verification and scheduled fuzz smoke jobs.
- machine-readable optimized Guard benchmarks for allowed, blocked, duplicate,
  payment-bearing, durable append, recovery, and state-growth workloads.
- redaction-safe JSON operational events for proxy lifecycle, committed
  decisions, and worker failure without raw requests, resources, or key data.
- experimental backup, restore, rotation, compromise, rollback, corruption,
  and disaster-recovery operator runbook with explicit unsupported paths.
- repeatable Guard recovery exercise covering signer compromise status, policy
  rollback, corrupt state, uncertain append recovery, and live proxy rotation.
- explicit pre-1.0 support windows and a negative sandbox-boundary test proving
  the wrapped server can create unmediated host effects.
- a Guard resource-limit contract, bounded configuration/receipt/key readers,
  capped unique payment allowlists, and unambiguous bounded policy trust lists.
- durable recovery of an empty or multiply lagging head-log prefix after
  validated journal commits, including interrupted genesis initialization.
- fail-closed state permission and symlink checks plus deterministic unavailable
  journal and uncertain head-write tests.
- live proxy failure scenarios for malformed and oversized child output and an
  abrupt nonzero child exit, including redacted failure-event verification.
- direct MCP boundary tests for string, container, aggregate node, and pending
  request ceilings.
- race-resistant `O_NOFOLLOW` opens for Unix private key, passphrase, state, and
  policy-cache files, with live rejection of a substituted cache symlink.

### Security

- negative coverage for tampering, replay, cross-session reuse, downgrade,
  stale policy, unknown critical extensions, authority amplification, payment
  limits, duplicate effects, JSON-RPC batches, and path traversal.
