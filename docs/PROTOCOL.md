# Protocol Draft v0.1

This document describes the implemented foundation. It is not yet a stable
interoperability specification.

## Architecture

```text
LLM or planner
    | typed proposal/result
protocol kernel
    | identity, replay, policy, capability, state
action broker
    | typed authorized effect
tools, data stores, wallets, and remote peers
```

The local [Guard profile](GUARD.md) implements this action-broker boundary for
MCP stdio `tools/call`. It is an adapter to the kernel, not a replacement MCP
message format.

## Connection lifecycle

```text
New -> Secure -> Authenticated -> Authorized -> Active -> Closed
```

Each transition is explicit and irreversible. Authentication proofs are bound
to a secure transport exporter. The kernel implements and verifies this
binding but leaves TLS or another secure transport to a transport profile.

The initiator and responder each advertise complete `(major, minor)` versions,
payload codecs, extensions, and local resource limits. Negotiation chooses the
greatest common version, the lexicographically first common codec, the
intersection of extensions, and the lower resource limits. Both ordered hellos
and the selected result are hashed into the negotiation transcript. Reordering
the peer roles or removing an advertised option therefore changes the digest.

After secure transport establishment, the verifier issues a fresh one-time
challenge containing that negotiation digest and the accepted credential
types. The peer signs a domain-separated proof binding its role, session,
signing key, audience, challenge, channel binding, selected credential type,
and exact credential bytes. A successful proof is the only kernel path from
`Secure` to `Authenticated`; the challenge is then consumed. Exact transcript
encoding and transport-profile requirements are specified in
[HANDSHAKE.md](HANDSHAKE.md).

Native peers authenticate their envelope signing key. Deployments may also
validate an external credential through a federation profile. Federation
produces identity evidence for local policy; it does not install a capability
or move a connection into `Authorized` by itself.

## Interaction lifecycle

```text
Offered -> Accepted -> Running -> Completed
        -> Rejected | Cancelled | Failed | Expired
```

Terminal states cannot transition. Invalid transitions fail closed.

## Envelope

The signed envelope binds version, session, optional interaction, sequence,
nonce, issue and expiry time, sender, audience, policy epoch, message kind,
schema digest, and payload digest. The signature covers a domain-separated,
length-delimited transcript rather than raw Protobuf bytes. Protobuf is not a
canonical signature format.

## Authority

A capability grant identifies issuer and subject and constrains actions,
resources, time, calls, optional interaction, optional payment currency,
atomic spend, allowed payees, and remaining delegation depth. Payment limits
explicitly name the actions for which typed payment metadata is mandatory;
payment authority cannot be smuggled into another action or removed while
retaining a payment action.

Delegation is valid only when the child issuer is the parent subject and every
child constraint is equal or narrower. Relationship evidence is evaluated by
local policy before a grant is issued and is not passed to effect checking.

The optional JWT federation profile binds external identity evidence to the
sender key, session, proof key, policy epoch, and exact grant digest. The JWT
cannot contain action, resource, delegation, or spend authority. Local policy
must still install and validate the referenced ScopePact grant. See
[JWT_FEDERATION.md](JWT_FEDERATION.md).

## Effects

The action broker supplies an effect ID and digest with each request. The
kernel reserves the identifier and budget atomically in the v0 in-memory
model. Production implementations require transactional durable storage.
Duplicate identical requests return `Duplicate`; they are not authorized for
execution a second time. Conflicting reuse is rejected.

## Encoding

Operational frames use Protobuf. Signed long-lived grants, mandates, and
receipts will use deterministic CBOR with COSE after canonical test vectors
are specified. Large artifacts are transported by content-addressed
reference and digest.

The experimental Guard decision receipt is a JSON carrier with a separate
domain-separated binary signature transcript defined in [GUARD.md](GUARD.md).
It is not the future normative `EffectReceipt` encoding.

## Extension rule

Unknown critical extensions fail closed. Extensions may narrow core security
semantics but cannot weaken or replace them.
