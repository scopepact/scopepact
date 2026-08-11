# Conformance Guide

ScopePact separates evidence that is easy to explore from the deeper tests
needed to evaluate a security kernel. This prevents a polished demo from being
mistaken for a protocol certification.

## Coverage levels

### Level 1: wire interoperability

The local workbench signs frames in Python and verifies them in JavaScript. It
runs 15 scenarios across the following boundaries:

| Boundary | Cases | Invariants |
| --- | --- | --- |
| Happy path | signed offer and reply | I1, I6 |
| Integrity | payload tamper, invalid signature, schema mismatch | I1 |
| Identity and isolation | sender substitution, wrong audience, wrong session | I1, I9 |
| Freshness | replay, expiry, future issue time, excessive lifetime | I2 |
| Compatibility | unsupported version, unknown critical extension | I3 |
| Governance | stale policy epoch | I8 |
| Resource safety | oversized payload | I2 |

Run it with:

```sh
python3 conformance/server.py --port 8787
```

Open `http://127.0.0.1:8787`, run the suite, and use **Export report** to retain
the results. Each malicious input is expected to be rejected; that expected
rejection counts as a passing conformance case.

### Level 2: kernel security

The Rust adversarial tests cover behavior that does not fit truthfully into a
two-agent browser exchange:

- deterministic hello negotiation and downgrade resistance;
- one-time identity proof and transport, session, audience, and role binding;
- delegation attenuation across every authority dimension;
- subject, action, resource, payee, currency, call, and spend enforcement;
- grant revocation and policy rollover;
- duplicate effect suppression and interaction state transitions;
- optional JWT federation validation without authority elevation.

The Guard adapter tests additionally cover MCP tool mapping, resource and
payment policy, duplicate suppression, JSON-RPC batch rejection, path
traversal, receipt tampering, real stdio proxy behavior, and independent
JavaScript receipt verification. Rust, JavaScript, and Python also verify the
deterministic `conformance/vectors/guard-receipt-v1.json` fixture and reject a
mutated authenticated field.

Run the complete repository verification with:

```sh
./verify-all.sh
```

### Level 3: deployment profiles

The local MCP Guard now has persistent replay and budget state, authenticated
policy activation, encrypted local signer custody, and cross-signed signer
rotation. It still lacks a complete deployment profile: remote transport
interoperability, multi-node revocation propagation, A2A binding, remote MCP
identity binding, operating-system sandbox tests, and symlink-safe filesystem
enforcement remain outside the implemented boundary. The Guard therefore
remains an evaluation adapter and does not claim this deployment level. These
areas require profile-specific integration and operational suites before any
production certification claim is appropriate.

## Adopter expectations

The current suite is a reproducible reference implementation and evaluation
aid. It is not a standards-body certification mark. An independent
implementation should reproduce the signing transcript vectors, pass every
applicable negative case, and document any local limits that are stricter than
the v0 defaults.
