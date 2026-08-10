# JWT Federation Profile

Status: experimental v0.1 profile.

## Purpose

ScopePact does not require JWT for native agent-to-agent communication. Native
peers already sign every envelope with an Ed25519 key and authorize every
effect with a narrowly scoped capability grant.

The optional `jwt-federation` Cargo feature lets a deployment accept identity
evidence from an existing OAuth or OIDC trust domain. A successfully validated
token produces `FederatedIdentityEvidence`. It never creates a capability,
authorizes an effect, increases trust based on a relationship label, or moves
money.

```text
external issuer -> strict JWT validation -> identity evidence
                                             |
                                             v
                                      local policy decision
                                             |
                                             v
                         ScopePact grant -> per-effect authorization
```

## Trust record

Each validator is configured for exactly one tuple:

- expected issuer;
- expected audience;
- expected `kid`;
- pinned Ed25519 issuer public key;
- maximum encoded size, lifetime, and clock skew.

The implementation does not fetch `jku`, `x5u`, embedded `jwk`, certificate
chains, or other key material from the token header. Key rotation is an
explicit control-plane operation that installs a new pinned trust record. A
deployment may run old and new validators during a short overlap window.

## Header profile

Required:

- `alg`: `EdDSA`;
- `typ`: `scopepact-session+jwt`;
- `kid`: exact match to the pinned trust record.

All other protected-header parameters are rejected. This intentionally
defines a narrow profile instead of accepting generic JWTs.

## Claim profile

The token uses a single string audience and requires:

```json
{
  "iss": "https://identity.example",
  "sub": "agent:alice",
  "aud": "scopepact:agent-b",
  "exp": 1700000300,
  "nbf": 1700000000,
  "iat": 1700000000,
  "jti": "issuer-unique-token-id",
  "cnf": { "jkt": "RFC-7638-SHA-256-JWK-thumbprint" },
  "scopepact": {
    "sender_key_id": "64-lowercase-hex-characters",
    "session_id": "32-lowercase-hex-characters",
    "policy_epoch": 7,
    "grant_digest": "64-lowercase-hex-characters"
  }
}
```

Unknown claims are rejected, including claims that attempt to encode actions,
resources, roles, delegation, spend limits, or payment authority. The grant
digest is only a binding to an independently validated ScopePact capability;
the JWT does not define that capability.

## Proof of possession

`cnf.jkt` identifies the sender-constrained proof key. The validator requires
the expected thumbprint from the handshake or transport profile. A production
HTTP profile should verify a DPoP proof for the request; a mutually
authenticated transport profile can bind the session to an equivalent
certificate or exporter proof. Checking `cnf.jkt` without checking possession
of that key is insufficient.

Do not pass refresh tokens peer to peer. Exchange them at an authorization
server for short-lived, audience-specific, sender-constrained credentials.
Never log complete tokens.

## Authorization boundary

The only output is identity evidence bound to an expected sender, session,
policy epoch, proof key, and capability digest. Local policy may use the issuer
and subject when deciding whether to install the referenced grant. The action
broker still revalidates that grant for every external effect.

Payment authorization remains a typed ScopePact capability or payment mandate.
An x402 payment response, OAuth scope, role claim, or valid JWT signature does
not bypass the spend, currency, payee, action, idempotency, and policy checks.

## Remaining deployment work

The library validates credential syntax, signature, registered claims, strict
shape, and handshake bindings. A complete deployment must additionally supply:

- TLS 1.3 or QUIC transport and channel/proof binding;
- issuer provisioning, key rotation, revocation, and audit policy;
- replay storage for accepted `jti` values when credentials can be reused;
- rate, concurrency, and parser resource limits before semantic processing;
- durable capability, effect, and revocation storage.
