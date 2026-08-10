# Threat Model

Status: experimental v0.1 design input.

## Protected assets

- principal data, credentials, signing keys, and private artifacts;
- authority to call tools, modify state, delegate, or spend funds;
- task and payment integrity;
- availability within configured resource limits;
- evidence required to attribute and audit external effects.

## Adversaries

The protocol assumes any combination of:

1. A remote agent that is malicious, compromised, or more capable than the
   local model.
2. A local language model manipulated by prompt injection.
3. A relay that can observe, delay, duplicate, reorder, or drop traffic.
4. A peer attempting replay, downgrade, capability amplification, confused
   deputy behavior, payment substitution, or cross-session data access.
5. A peer consuming excessive CPU, memory, bandwidth, storage, or model
   tokens.
6. A legitimate peer whose authority has expired or been revoked.
7. An identity issuer, discovery endpoint, or JWT parser used for algorithm,
   key-selection, audience, token-substitution, or bearer-token attacks.
8. A local agent attempting to bypass tool policy through malformed JSON-RPC,
   batching, request-ID reuse, path traversal, or manipulated payment fields.
9. A wrapped tool server that interprets a resource differently from the
   policy adapter or creates effects outside an admitted request.

## Trust boundaries

The language model proposes typed intents. It does not hold long-term signing
keys, payment keys, raw credentials, or unrestricted tool handles. The
protocol kernel validates envelopes and grants. An action broker validates
each external effect immediately before execution.

Relationship claims are evidence supplied to local policy; they never grant
authority directly. Natural-language content is permanently untrusted data.
External identity credentials are also evidence only. A valid JWT does not
authorize tools, data access, delegation, or payment.

## Security assumptions

- standard cryptographic primitives remain secure;
- the kernel, action broker, and their trusted storage are not fully
  compromised;
- local policy and root trust anchors were provisioned correctly;
- clocks have a bounded skew when expiry checks depend on wall time;
- transports provide their claimed properties and exporters are bound
  correctly by the selected transport profile.

## Explicitly out of scope

A fully compromised operating system, stolen root keys, malicious hardware,
or broken cryptographic primitives cannot be solved by the wire protocol.
The design goal is bounded damage and attributable effects, not an impossible
claim of perfect security.

## Required mitigations

- authenticate before invoking an LLM for unknown peers;
- impose frame, rate, concurrency, and cost limits before semantic work;
- bind signed envelopes to sender, audience, session, policy epoch, expiry,
  payload schema, and payload digest;
- bind ordered hello advertisements and selected parameters into a one-time
  identity proof scoped to the secure transport exporter;
- require narrow capabilities and re-authorize every external effect;
- keep delegation monotonically narrower than its parent grant;
- make retries idempotent and effect identifiers conflict-detecting;
- fail closed for unknown critical extensions or invalid state transitions;
- isolate keys and wallets behind typed signing APIs;
- retain tamper-evident receipts without recording private reasoning.

## Local guard mitigations

- inspect every client-to-server MCP `tools/call` before forwarding it;
- reject JSON-RPC batches rather than forwarding uninspected members;
- derive the effect identifier from the request ID and conflict-check reuse;
- bind the effect digest to the exact tool and key-sorted arguments;
- reject absolute resource paths containing parent traversal;
- enforce typed payment amount, currency, cumulative spend, and payee;
- sign decision receipts with an independently verifiable transcript;
- treat the downstream server, filesystem canonicalization, audit durability,
  and persistent replay state as separate deployment trust boundaries.

## Federation credential mitigations

- pin each trusted issuer, audience, key ID, algorithm, and Ed25519 public key;
- reject dynamic key URLs, embedded keys, unknown claims, and ambiguous token
  types instead of following attacker-controlled discovery metadata;
- require short lifetimes, bounded token size, unique token IDs, and explicit
  issuer, audience, subject, issue, not-before, and expiry claims;
- bind the credential to the sender key, session, proof key, policy epoch, and
  exact grant digest;
- require proof of possession at the transport profile; a copied token alone
  must not authenticate a new connection;
- rotate pinned trust records deliberately and keep old keys only for the
  minimum overlap window.
