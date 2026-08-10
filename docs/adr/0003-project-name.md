# ADR 0003: Adopt ScopePact as the project name

Status: accepted for the pre-release project.

## Context

The earlier working acronym `UAIP` is already used by unrelated public agent
projects. It is generic, difficult to search, and does not communicate the
protocol's distinguishing security model.

## Decision

Use **ScopePact** as the project and protocol name. The name captures the core
rule: agents may make verifiable agreements, but every agreement is bounded by
explicit capability, resource, counterparty, time, spend, and policy scope.

The implementation namespaces are:

- Rust package: `scopepact-core`;
- Protobuf package: `scopepact.v0`;
- extension namespace: `urn:scopepact:*`;
- signature domains: `SCOPEPACT-*-V0`.

## Consequences

Changing signature domains and the Protobuf namespace intentionally makes this
draft incompatible with artifacts produced under the temporary UAIP identity.
No stable release used that identity.

A preliminary ecosystem search found no exact ScopePact project or package
collision. The dated search notes and alternatives are recorded in
[`../NAME_RESEARCH.md`](../NAME_RESEARCH.md). This is not legal trademark
clearance; complete that review before a public standards launch or package
publication.
