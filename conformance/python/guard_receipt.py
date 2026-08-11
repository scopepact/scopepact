"""Independent ScopePact Guard receipt transcript verification."""

import hashlib
import json
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _field(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack(">I", len(encoded)) + encoded


def _optional_field(value: str | None) -> bytes:
    return b"\x00" if value is None else b"\x01" + _field(value)


def receipt_transcript(receipt: dict) -> bytes:
    decision = {"allowed": 1, "blocked": 2}.get(receipt["decision"])
    if decision is None:
        raise ValueError("receipt decision is invalid")
    request_id = json.dumps(
        receipt["request_id"], separators=(",", ":"), ensure_ascii=False
    )
    return b"".join(
        [
            b"SCOPEPACT-GUARD-RECEIPT-V0\x00",
            struct.pack(">H", receipt["receipt_version"]),
            bytes([decision]),
            _field(receipt["reason"]),
            struct.pack(">Q", receipt["policy_epoch"]),
            _field(receipt["principal"]),
            _field(receipt["agent"]),
            _field(request_id),
            _field(receipt["tool"]),
            _optional_field(receipt["resource"]),
            _optional_field(receipt["rule_id"]),
            bytes.fromhex(receipt["effect_id"]),
            bytes.fromhex(receipt["effect_digest"]),
            struct.pack(">q", receipt["issued_at_ms"]),
            bytes([1 if receipt["duplicate"] else 0]),
        ]
    )


def verify_guard_receipt(signed: dict) -> None:
    public_key = bytes.fromhex(signed["signer_public_key"])
    signature = bytes.fromhex(signed["signature"])
    if len(public_key) != 32 or len(signature) != 64:
        raise ValueError("receipt key or signature length is invalid")
    if hashlib.sha256(public_key).hexdigest() != signed["signer_key_id"]:
        raise ValueError("receipt key ID mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, receipt_transcript(signed["receipt"])
        )
    except InvalidSignature as error:
        raise ValueError("invalid receipt signature") from error
