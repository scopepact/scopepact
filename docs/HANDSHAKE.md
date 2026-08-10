# Native Handshake Profile v0

This profile defines the byte transcripts implemented by the Rust kernel. It
does not establish TLS or another secure transport. A transport profile must
provide the authenticated, confidential channel and a 32-byte binding unique
to that channel and negotiation.

## Integer and collection encoding

All integers are unsigned big-endian. `LP(value)` is a four-byte length followed
by the exact bytes. A collection is a four-byte item count followed by its
items. Sets are encoded in bytewise ascending order.

Protocol versions encode `major` and `minor` as two bytes each. Limits encode
`max_frame_bytes` as eight bytes and `max_concurrent_interactions` as four.
Names are non-empty visible ASCII strings no longer than 256 bytes.

## Hello negotiation

An `AgentHello` transcript is:

```text
COUNT(supported_versions)
  U16(major) || U16(minor) ...
COUNT(codecs) || LP(codec) ...
COUNT(extensions) || LP(extension) ...
U64(max_frame_bytes)
U32(max_concurrent_interactions)
```

The selected parameters are the greatest common version, the bytewise first
common codec, all common extensions, and the minimum of each resource limit.
No common version or codec fails the handshake.

The negotiation digest is SHA-256 over:

```text
"SCOPEPACT-NEGOTIATION-V0\0"
LP(initiator_hello_transcript)
LP(responder_hello_transcript)
U16(selected_major) || U16(selected_minor)
LP(selected_codec)
COUNT(selected_extensions) || LP(extension) ...
U64(selected_max_frame_bytes)
U32(selected_max_concurrent_interactions)
```

Initiator and responder order is normative. It prevents a reflected transcript
from being treated as the opposite connection role.

## Challenge

The verifier creates a fresh 16-byte challenge ID and independent 16-byte
nonce. Both must be unpredictable and must not be all zero. The challenge also
contains the negotiation digest and a non-empty set of accepted credential
types. `scopepact-native-ed25519-v0` identifies a native proof with no required
external credential.

The challenge is consumed after one successful verification. Failed attempts
do not change connection state, but deployments should rate-limit them and
expire pending challenges.

## Transport binding

A TLS 1.3 transport profile derives 32 exporter bytes using label
`EXPORTER-ScopePact-Identity-V0` and the negotiation digest as exporter context,
then supplies `SHA-256(exporter_bytes)` as the transport binding. Other secure
transport profiles must define an equivalent connection-unique,
transcript-scoped binding. An unbound constant or a value supplied by the
remote peer is not valid.

This construction uses the exporter interface from
[RFC 8446 section 7.5](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5).
The label requires registration before a stable standards-track profile is
published. The binding is authentication data, not an application secret or a
key for encrypting other values.

## Identity proof

The proof signature is Ed25519 over:

```text
"SCOPEPACT-IDENTITY-PROOF-V0\0"
U8(prover_role)                         # initiator = 1, responder = 2
LP(session_id)                          # 16 bytes
LP(agent_key_id)                        # SHA-256(raw Ed25519 public key)
LP(audience_key_id)                     # 32 bytes
LP(challenge_id)                        # 16 bytes
LP(challenge_nonce)                     # 16 bytes
LP(negotiation_digest)                  # 32 bytes
COUNT(accepted_credential_types) || LP(type) ...
LP(transport_binding)                   # 32 bytes
LP(selected_credential_type)
LP(principal_credential)
LP(workload_credential)
```

Each credential is limited to 64 KiB before signature verification. The
selected credential type must occur in the challenge. Credential bytes are
identity evidence for local policy; they do not install capability authority.

The verifier supplies the peer public key and expected session, role, audience,
negotiation, challenge, and transport binding from trusted connection state.
It must not populate expected values from the proof itself.

## Test vector

The executable vector is in `crates/core/tests/handshake_security.rs`. Its initiator hello
advertises versions `0.1`, `0.2`, and `1.0`, codecs `application/cbor` and
`application/protobuf`, extensions `a` and `b` in the ScopePact namespace, a
1,048,576-byte frame limit, and 32 interactions. The responder advertises
versions `0.1` and `0.2`, codecs `application/json` and
`application/protobuf`, extensions `b` and `c`, a 262,144-byte limit, and 8
interactions. The negotiation digest is:

```text
0cf043da0928cacda25e9a64492ac3384a15a1b58268eef931da79730511ea50
```

The proof uses an Ed25519 seed of 32 `01` bytes, an audience key from a seed of
32 `02` bytes, session `06` repeated 16 times, challenge ID `04` repeated 16
times, nonce `05` repeated 16 times, transport binding `07` repeated 32 times,
initiator role, native credential type, and ASCII credentials `principal
fixture` and `workload fixture`. Its signature is:

```text
992ed056d18a5345cd54d16010290b0827875faa8156c6fdf5ae22c04a5df8eb
98b2891207410493841f02988ddc28e16215a3b97ecc613ef2a26c4c376cf907
```
