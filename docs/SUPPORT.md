# ScopePact Support And Compatibility Policy

Status: pre-release. This policy defines the current narrow support window; it
does not promise production support.

## Current Window

- Only the current `main` branch receives fixes, including security fixes.
- Historical alpha commits and tags receive no backports or compatibility
  guarantee. Users must reproduce an issue on current `main`.
- Guard accepts state v3 only. Experimental v2 has no supported in-place
  migration. The procedure and risks are in `MIGRATION.md`.
- Guard policy schema v1 and receipt schema v1 are strict current contracts but
  remain pre-1.0 and may change with checked-in migration guidance.
- ScopePact Protocol v0 transcripts and portable SDKs are alpha interoperability
  artifacts, not stable enforcement-runtime APIs.
- The declared minimum Rust toolchain is 1.85. CI also targets stable Rust on
  Linux, macOS, and Windows; a platform is not release-supported until its clean
  workflow has passed for the release revision.

No pre-1.0 deprecation period is guaranteed. Breaking changes must update
schemas, vectors, negative cases, changelog, and applicable migration guidance
in the same change set.

## Security Fixes

Report vulnerabilities privately as described in `SECURITY.md`. Before 1.0,
fixes land on current `main`; maintainers may create a patched pre-release at
their discretion, but old alpha versions have no guaranteed embargo, patch, or
end-of-life window. Operators must track current advisories and upgrade only
after exercising their state copy with the candidate build.

## Migration Window

The current migration window contains state v3 to v3 only. A candidate binary
must open and verify a copied v3 journal with the unchanged active policy and
signer before it is used on live state. State v2 and unknown future versions
fail closed. Starting empty v3 state is an authority reset, not a migration.

## Stable-Release Requirement

Before Guard 1.0, this document must define supported release lines, security
backport duration, end-of-life notice, policy/receipt/state compatibility,
upgrade and downgrade windows, operating-system/toolchain versions, and an
incident contact. Protocol v1 has a separate compatibility gate and cannot
inherit Guard 1.x maturity by implication.
