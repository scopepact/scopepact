# ScopePact

**One authorization and proof layer for consequential agent actions.**

ScopePact is an open-source security kernel for agents that communicate through
different runtimes and protocols. It keeps authority outside the language
model: every external effect must match a cryptographic identity, scoped
capability, resource, counterparty, lifetime, call budget, spend limit, and
active policy epoch.

> Project status: pre-release research implementation. The security invariants
> are executable, but the wire format and public APIs may still change.

Visit [scopepact.org](https://scopepact.org) for a visual introduction to the
architecture, Guard, conformance evidence, runtime support, and local
quickstart. Browse the source, releases, and project activity in the official
[GitHub repository](https://github.com/scopepact/scopepact).

## Why ScopePact

Our founding conviction is that the agentic world needs a common language for
authority. As agents move from answering questions to operating tools,
services, devices, and money, their authority cannot remain implicit in prompts
or trapped inside one vendor's control plane.

ScopePact checks authority at the effect boundary, where an agent's intent
becomes an external consequence. It binds identity, audience, capability,
resource, limits, freshness, and active policy into a deterministic decision,
then signs that decision as evidence another runtime can verify.

We hope to solve four structural problems: ambient authority hidden in prompts
and application state; trust that stops at runtime and organizational
boundaries; consequential effects without portable evidence; and fragmented
security stacks that force every protocol ecosystem to rebuild the same
guardrail. ScopePact exists so more capable agents do not require more ambient
trust. Their authority should become narrower, more portable, and more
accountable as their reach grows.

## Try ScopePact Guard

The fastest way to see the product is the local MCP guard. It allows an
in-scope project write, blocks an attempted write to `/etc/hosts`, signs both
decisions, and verifies the receipt:

```sh
./scripts/run-guard.sh
```

Run the complete stdio proxy demonstration:

```sh
./scripts/run-guard-proxy.sh
```

That demo forwards MCP initialization and the allowed `tools/call` to a mock
server, blocks the forbidden call before it reaches the server, writes an audit
log, and verifies the Rust-generated Ed25519 receipts independently in
JavaScript.

## What It Unifies

ScopePact does not replace MCP, A2A, payment protocols, or transports. It gives
them a common enforcement decision:

```text
MCP tools -----+
A2A tasks -----+-- adapter --> ScopePact kernel --> ALLOW / BLOCK + signed receipt
Payment intent +                 identity | scope | limits | replay | policy
```

The repository currently contains:

- `scopepact-protocol`: versioned Protobuf schema and generated wire types;
- `scopepact-core`: signed envelopes, authenticated handshake, replay defense,
  capability attenuation, per-effect authorization, payment limits, revocation,
  and state machines;
- `scopepact-guard`: an MCP stdio policy proxy with signed decision receipts;
- Python and JavaScript implementations of the v0 signing transcript;
- Flutter, Swift, Go, C++, and C# alpha SDKs on the same transcript vector;
- a 15-case cross-language conformance workbench;
- an optional sender-constrained JWT federation profile;
- the Protobuf v0 protocol schema and security documentation;
- the public website, discovery metadata, and publication-ready introduction article.

## Repository Layout

```text
crates/
  protocol/    Apache-2.0 wire schema and generated types
  core/        MPL-2.0 authority and interaction kernel
  guard/       MPL-2.0 local MCP enforcement runtime
conformance/   Python/JavaScript implementations and browser workbench
website/       Public site, SEO/GEO metadata, Cloudflare config, and Medium draft
sdks/          Flutter and Swift portable envelope packages
scripts/       Runnable demos and cross-language verification
examples/      Guard policies and tool-call fixtures
docs/          Protocol, threat model, profiles, ADRs, and governance
```

## Guard An MCP Server

Build the binary, then create separate protected keys for decision receipts and
policy issuance. The passphrase files must already exist with mode `0600`:

```sh
cargo build --release -p scopepact-guard
target/release/scopepact-guard keygen \
  --out scopepact-key.json \
  --passphrase-file scopepact-key.pass
target/release/scopepact-guard keygen \
  --out scopepact-policy-key.json \
  --passphrase-file scopepact-policy-key.pass
target/release/scopepact-guard policy trust-init \
  --issuer example-operator \
  --audience guard:production \
  --key scopepact-policy-key.json \
  --key-passphrase-file scopepact-policy-key.pass \
  --out scopepact-policy-trust.json
target/release/scopepact-guard policy sign \
  --policy examples/mcp-guard-policy.json \
  --issuer example-operator \
  --audience guard:production \
  --key scopepact-policy-key.json \
  --key-passphrase-file scopepact-policy-key.pass \
  --out scopepact-policy-bundle.json
```

Then place the guard in front of any newline-framed MCP stdio server:

```sh
target/release/scopepact-guard mcp \
  --policy-bundle scopepact-policy-bundle.json \
  --policy-trust scopepact-policy-trust.json \
  --policy-audience guard:production \
  --key scopepact-key.json \
  --key-passphrase-file scopepact-key.pass \
  --state scopepact-state.jsonl \
  --audit scopepact-audit.jsonl \
  -- your-mcp-server --its-arguments
```

See [the Guard guide](docs/GUARD.md) for policy fields, client configuration,
receipt verification, transcript encoding, security boundaries, and current
limitations. Its [resource-limit contract](docs/LIMITS.md) records hard
rejection ceilings and the controls that remain outside Guard. The
[migration guide](docs/MIGRATION.md) documents the current
v3-only state contract and conservative upgrade procedure. The experimental
[operations runbook](docs/OPERATIONS.md) covers backup, restore, rotation,
compromise, rollback, and disaster-recovery exercises.

## Conformance Workbench

Install the Python demo dependency and start the local inspector:

```sh
python3 -m pip install -r conformance/python/requirements.txt
python3 conformance/server.py --port 8787
```

Open `http://127.0.0.1:8787`. The workbench runs 15 acceptance and rejection
scenarios, explains each invariant in plain language, exposes the signed frame,
and exports JSON evidence. The [conformance guide](docs/CONFORMANCE.md)
separates this wire demo from deeper kernel and deployment testing.

## Verify The Repository

The core verifier checks Rust formatting, compilation, tests and lints; Python
and JavaScript implementations; browser code; the cross-language frame
exchange; and the MCP guard proxy:

```sh
./verify-all.sh
```

The optimized [Guard performance harness](docs/PERFORMANCE.md) emits
machine-readable latency, throughput, durable recovery, and state-growth
measurements with `./scripts/run-guard-benchmarks.sh`.

Flutter, Swift, Go, C++, and C# packages consume the same checked-in transcript
vector. Run their platform toolchains with:

```sh
./scripts/verify-sdks.sh
```

The default core build has no JWT dependency. Test the optional federation
adapter with:

```sh
cargo test -p scopepact-core --features jwt-federation
```

## Read The Design

Start with the [project charter](docs/CHARTER.md),
[threat model](docs/THREAT_MODEL.md), and
[security invariants](docs/SECURITY_INVARIANTS.md). Implementers should then
read the [protocol draft](docs/PROTOCOL.md), exact
[handshake transcripts](docs/HANDSHAKE.md), and
[Guard profile](docs/GUARD.md). Runtime capability levels and package status
are documented in [SDK support](docs/SDKS.md).

The name is intentionally **ScopePact**, not the already-used Open Agent
Communication Protocol or AgentPact. The dated shortlist and collision checks
are in [name research](docs/NAME_RESEARCH.md).

## Open-Source Project

ScopePact is community-first: adoption, independent implementations, and
stronger public evidence are the win. The official project does not sell
protocol access, governance votes, roadmap priority, or conformance outcomes.
Commercial use remains welcome under the open-source licenses. Read the
[community charter](COMMUNITY.md), join
[GitHub Discussions](https://github.com/scopepact/scopepact/discussions), or
choose a path in the [contribution guide](CONTRIBUTING.md).

The protocol specification, schemas, conformance assets, and documentation are
licensed under Apache-2.0. ScopePact Core and Community Guard are licensed
under MPL-2.0 so distributed changes to covered implementation files remain
available to the community. The exact file boundary is defined in
[LICENSING.md](LICENSING.md).

Contributions use the [Developer Certificate of Origin](DCO.md) rather than
copyright assignment. Start with the [contribution guide](CONTRIBUTING.md).
Project decisions follow [open governance](GOVERNANCE.md); security issues use
the private process in [SECURITY.md](SECURITY.md). Planned work is tracked in
[ROADMAP.md](ROADMAP.md), and user-visible changes are recorded in
[CHANGELOG.md](CHANGELOG.md).
