# ADR 0005: Bind identity to negotiation and secure transport

Status: accepted for prototype.

## Context

A signed application envelope proves possession of an agent key but does not
by itself prove that the signer participated in the current secure connection.
Unauthenticated hello negotiation also permits a relay to remove supported
versions or extensions before identity is established.

## Decision

Hash the ordered initiator and responder hellos together with the deterministic
negotiated result. Require a fresh challenge and a second domain-separated
Ed25519 proof that binds the agent key, connection roles, session, audience,
negotiation digest, exact credentials, and a transport-provided channel
binding. Consume the challenge after successful verification. Do not expose a
state-machine transition that marks an unverified peer authenticated.

## Consequences

Transport termination and protocol authentication cannot be silently split
across different connections. Downgrade attempts change the signed transcript.
The core remains transport-independent, but every production transport profile
must define and correctly derive a strong channel binding.
