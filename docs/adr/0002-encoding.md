# ADR 0002: Protobuf operations and canonical signed objects

Status: accepted for prototype.

Protobuf v3 is used for operational frames because it is compact, typed, and
widely implemented. Raw Protobuf serialization is not signed because it is
not a cross-version canonical encoding.

The prototype signs a fixed domain-separated transcript containing envelope
metadata and payload digest. The intended durable object format is
deterministic CBOR protected by COSE, subject to test vectors and review.
