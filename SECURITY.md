# Security Policy

## Supported Versions

ScopePact is pre-release. Only the current default branch receives security
fixes. No released version is currently approved for production use.

## Reporting A Vulnerability

Do not open a public issue for a suspected vulnerability.

Use [GitHub private vulnerability reporting](https://github.com/scopepact/scopepact/security/advisories/new)
and include:

- the affected component and revision;
- a minimal reproduction or failing test;
- the security boundary or invariant that is violated;
- realistic impact and attacker prerequisites;
- any proposed mitigation.

Do not include secrets or personal data in the initial report.

The maintainers will acknowledge a usable report, reproduce it privately,
coordinate a fix and regression test, and publish details after users have a
reasonable opportunity to update. Timing depends on severity and whether the
affected surface has been released.

## Security Posture

The implemented invariants and known deployment gaps are documented in
[the threat model](docs/THREAT_MODEL.md),
[security invariants](docs/SECURITY_INVARIANTS.md), and the relevant profile.
The MCP guard's specific limitations are listed in [docs/GUARD.md](docs/GUARD.md).
Its state compatibility and conservative upgrade procedure are documented in
[docs/MIGRATION.md](docs/MIGRATION.md).
The single-host incident and recovery procedures are in
[docs/OPERATIONS.md](docs/OPERATIONS.md).
Current version/security windows and the explicit absence of a sandbox profile
are in [docs/SUPPORT.md](docs/SUPPORT.md) and
[docs/SANDBOX.md](docs/SANDBOX.md).
