# Public And Enterprise Repository Boundaries

ScopePact is developed as two operationally separate projects.

## Public: `scopepact`

The public repository contains everything required to implement, test, and use
the protocol without a proprietary service:

- normative protocol documents and the `crates/protocol` schema crate;
- `crates/core` and the `crates/guard` Community Guard;
- receipt transcripts and independent verifiers;
- `conformance` vectors, adversarial tests, and examples.

The Community Guard is a real local enforcement runtime, not a feature-limited
client for a hosted service.

The project website is published separately at
[scopepact.org](https://scopepact.org) and links back to the public repository.

## Private: `scopepact-enterprise`

The private repository may contain operational products built around the open
runtime:

- organization, workspace, and fleet management;
- authenticated policy distribution and revocation;
- trusted signer enrollment and receipt retention;
- SSO, SCIM, KMS, SIEM, approval, billing, and support integrations;
- hosted consoles, deployment automation, and service-level operations.

Enterprise services integrate through public formats and interfaces. A
commercial service cannot alter normative protocol behavior, privately define
conformance, or make the public implementation depend on it.

## Contribution Direction

Fixes and reusable enforcement capabilities belong upstream in the public
repository. Enterprise-specific orchestration remains separate. If an
enterprise change modifies an MPL-covered public file and is distributed, the
MPL-2.0 obligations apply to that covered file.
