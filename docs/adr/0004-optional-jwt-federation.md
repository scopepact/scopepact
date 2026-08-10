# ADR 0004: JWT is an optional identity federation adapter

Status: accepted for prototype.

## Context

Enterprise agents may already have OAuth or OIDC identities, but generic
bearer JWTs have different security and authorization semantics from
ScopePact's signed sessions, attenuating capabilities, and per-effect checks.
Using a JWT as the protocol's native authority object would introduce token
substitution, confused-deputy, key-discovery, and privilege-smuggling risks.

## Decision

Keep JWT support behind the `jwt-federation` feature and off by default. Accept
only a dedicated, short-lived, EdDSA profile with a pinned issuer key and exact
type, key ID, issuer, and audience. Bind the token to the proof key, sender key,
session, policy epoch, and capability digest.

Successful validation returns non-authoritative identity evidence. JWT claims
cannot express actions, resources, delegation, payments, or spend. ScopePact
capabilities and the action broker remain the only effect-authority path.

## Consequences

Native deployments keep a smaller dependency and attack surface. Federated
deployments gain compatibility with existing identity control planes without
changing the protocol's authorization semantics. They must still implement
proof-of-possession verification, trust provisioning, rotation, revocation,
and replay storage at the deployment layer.
