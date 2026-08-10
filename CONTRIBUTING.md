# Contributing To ScopePact

ScopePact welcomes protocol analysis, adversarial tests, adapters,
documentation, and implementation work. Security claims must be backed by an
executable test, a precise transcript, or a clearly stated assumption.

## Choose A Contribution Path

You do not need to understand the entire protocol before contributing.

- **First-time user:** run the workbench or Guard demo and report confusing
  language, setup friction, or an unexplained decision.
- **Application builder:** contribute a policy example, transport adapter, or
  integration profile based on a real use case.
- **Runtime implementer:** reproduce the shared transcript vector, add negative
  cases, or extend an SDK toward a documented capability level.
- **Security reviewer:** challenge a trust assumption, transcript boundary,
  downgrade path, parser behavior, or failure mode with a reproducible test.
- **Writer or educator:** improve examples, diagrams, accessibility,
  translations, or explanations while preserving precise security language.

Use [GitHub Discussions](https://github.com/scopepact/scopepact/discussions)
for questions and exploratory ideas. Use an issue template when the problem or
work is concrete. Community expectations and support routes are documented in
[COMMUNITY.md](COMMUNITY.md) and [SUPPORT.md](SUPPORT.md).

## Development Setup

Required tools:

- Rust 1.85 or newer with `rustfmt` and `clippy`;
- a Protobuf compiler (`protoc`);
- Python 3.11 or newer;
- Node.js 20 or newer.

Changes under `sdks/flutter/` also require a current stable Flutter toolchain.
Changes under `sdks/swift/` require Swift 6 and Apple CryptoKit.
Changes under `sdks/go/` require Go 1.22 or newer. C++ SDK changes require a
C++20 compiler, CMake, OpenSSL 1.1.1 or newer, and `nlohmann_json` for tests.
C# SDK changes require the .NET 8 SDK; its Ed25519 implementation is supplied
by the pinned NSec package.

Install the Python demo dependency:

```sh
python3 -m pip install -r conformance/python/requirements.txt
```

Run the same verifier used for project changes:

```sh
./verify-all.sh
```

When changing envelope transcripts, test every portable SDK as well:

```sh
./scripts/verify-sdks.sh
```

## Change Process

1. Open an issue or design discussion for wire changes, new trust assumptions,
   new cryptographic dependencies, or public API changes.
2. Keep one change focused on one security or interoperability outcome.
3. Add positive and negative tests. Security checks without a rejection case
   are incomplete.
4. Update the protocol, threat model, invariant, ADR, or profile document when
   behavior changes.
5. Run `./verify-all.sh` before requesting review.

Protocol changes should identify affected transcript bytes, compatibility
impact, downgrade behavior, and failure mode. New dependencies need a reason
and should use established libraries rather than custom cryptography.

## Pull Requests

A pull request should state:

- the problem and intended security property;
- the chosen design and important alternatives;
- tests added, including adversarial coverage;
- compatibility and migration impact;
- any part that remains intentionally incomplete.

Maintainers may ask for an ADR under `docs/adr/` when a decision changes the
protocol boundary or creates a lasting implementation constraint.

Every commit must include a Developer Certificate of Origin sign-off:

```text
Signed-off-by: Your Name <you@example.com>
```

Create it with `git commit -s`. The sign-off certifies the contribution under
the repository's applicable open-source license; it is not a copyright
assignment. Read [DCO.md](DCO.md) before contributing.

Reviews are public and evidence-based. Maintainers should explain requested
changes, identify blocking security or compatibility concerns, and avoid
treating unfamiliarity with the codebase as a contributor failure. Contributors
may ask for clarification and preserve reasoned disagreement in the record.

## Scope

Good first contributions include additional conformance vectors, independent
receipt verifiers, policy examples, fuzz targets, transport adapters, and
documentation that makes an invariant easier to implement correctly.

Do not submit real credentials, production private keys, vulnerability details,
or private user data. Report vulnerabilities through [SECURITY.md](SECURITY.md).
