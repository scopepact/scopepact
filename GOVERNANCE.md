# Governance

ScopePact is developed in the open. The objective is a small, independently
implementable security kernel rather than control by one agent vendor,
transport, identity provider, or payment network.

## Roles

- **Contributors** propose changes, tests, reviews, and documentation.
- **Maintainers** merge changes, manage releases, and protect protocol
  compatibility and the security boundary.
- **Profile owners** maintain a specific adapter or deployment profile under
  the same review and conformance requirements.

The bootstrap maintainer listed in [MAINTAINERS.md](MAINTAINERS.md) acts as the
initial maintainer. Additional maintainers should be added after sustained,
high-quality contributions and demonstrated security review judgment. The
public nomination and review path is documented in that file.

## Decisions

Routine changes use pull-request consensus. Changes to wire transcripts,
authority semantics, cryptographic algorithms, compatibility posture, or the
threat model require:

1. a public design proposal or ADR;
2. adversarial and interoperability evidence;
3. explicit maintainer approval;
4. documentation of dissent or material tradeoffs.

Security fixes may be developed privately until coordinated disclosure. Their
tests and design rationale should become public with the fix whenever doing so
does not put users at additional risk.

## Releases

Pre-release versions may break compatibility, but the change must be explicit.
A stable release requires a frozen transcript, published vectors, migration
policy, two independent implementations for the claimed conformance level, and
a completed external security review.

## Project Neutrality

No proprietary service is required to implement ScopePact. Hosted products may
build on the protocol, but normative specifications, test vectors, and the
reference conformance suite remain openly available under the repository
license.

The public project also maintains a usable Community Guard. Commercial
products may operate and extend it through public interfaces, but proprietary
control planes do not define protocol conformance and receive no private
influence over normative decisions. The repository boundary is documented in
[docs/REPOSITORY_BOUNDARIES.md](docs/REPOSITORY_BOUNDARIES.md).

## Community-First Governance

ScopePact exists to increase safe, interoperable adoption rather than maximize
protocol revenue. The official project does not charge for protocol use,
normative materials, participation, roadmap consideration, governance votes,
or conformance outcomes. Funding, employment, or commercial affiliation does
not confer project authority.

Maintainers and proposal authors disclose material personal or commercial
conflicts. A conflicted maintainer recuses from the final decision when a
reasonable observer could question their impartiality. Recusals and the
remaining decision basis are recorded publicly.

Commercial implementations and services are welcome under the licenses, but
exclusive features cannot enter the normative protocol through a private
decision. The full community commitments are in [COMMUNITY.md](COMMUNITY.md).
