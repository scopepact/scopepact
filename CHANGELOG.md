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

### Security

- negative coverage for tampering, replay, cross-session reuse, downgrade,
  stale policy, unknown critical extensions, authority amplification, payment
  limits, duplicate effects, JSON-RPC batches, and path traversal.
