#!/usr/bin/env python3
"""Python side of the ScopePact cross-language demo."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import struct
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

DOMAIN = b"SCOPEPACT-ENVELOPE-V0\0"
AGENT_A_SEED = bytes([11]) * 32
AGENT_B_SEED = bytes([12]) * 32
MAX_LIFETIME_MS = 120_000
MAX_PAYLOAD_BYTES = 4_096
MAX_CLOCK_SKEW_MS = 500
POLICY_EPOCH = 7


def private_key(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(key: Ed25519PublicKey) -> bytes:
    return hashlib.sha256(public_bytes(key)).digest()


def append_bytes(output: bytearray, value: bytes) -> None:
    output.extend(struct.pack(">I", len(value)))
    output.extend(value)


def signing_transcript(envelope: dict[str, Any]) -> bytes:
    output = bytearray(DOMAIN)
    output.extend(struct.pack(">H", envelope["protocol_major"]))
    output.extend(struct.pack(">H", envelope["protocol_minor"]))
    append_bytes(output, bytes.fromhex(envelope["session"]))
    interaction = envelope["interaction"]
    if interaction is None:
        output.append(0)
    else:
        output.append(1)
        append_bytes(output, bytes.fromhex(interaction))
    output.extend(struct.pack(">Q", envelope["sequence"]))
    append_bytes(output, bytes.fromhex(envelope["nonce"]))
    output.extend(struct.pack(">q", envelope["issued_at_ms"]))
    output.extend(struct.pack(">q", envelope["expires_at_ms"]))
    append_bytes(output, bytes.fromhex(envelope["sender"]))
    append_bytes(output, bytes.fromhex(envelope["audience"]))
    output.extend(struct.pack(">Q", envelope["policy_epoch"]))
    output.extend(struct.pack(">H", envelope["message_kind"]))
    append_bytes(output, bytes.fromhex(envelope["payload_schema"]))
    append_bytes(output, bytes.fromhex(envelope["payload_digest"]))
    extensions = envelope["critical_extensions"]
    output.extend(struct.pack(">I", len(extensions)))
    for extension in extensions:
        append_bytes(output, extension.encode())
    return bytes(output)


def encode_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()


class ReplayGuard:
    def __init__(self) -> None:
        self.nonces: set[str] = set()
        self.sequences: set[int] = set()

    def check_and_record(self, envelope: dict[str, Any]) -> None:
        if envelope["nonce"] in self.nonces:
            raise ValueError("replayed nonce")
        if envelope["sequence"] in self.sequences:
            raise ValueError("replayed sequence")
        self.nonces.add(envelope["nonce"])
        self.sequences.add(envelope["sequence"])


def make_frame(
    *,
    payload: bytes,
    signing_key: Ed25519PrivateKey,
    audience: Ed25519PublicKey,
    session: bytes,
    interaction: bytes,
    nonce: bytes,
    message_kind: int,
    schema_name: str,
    issued_at_ms: int | None = None,
    expires_at_ms: int | None = None,
    protocol_major: int = 0,
    protocol_minor: int = 1,
    sequence: int = 1,
    policy_epoch: int = POLICY_EPOCH,
    critical_extensions: list[str] | None = None,
) -> dict[str, Any]:
    issued_at_ms = issued_at_ms if issued_at_ms is not None else int(time.time() * 1000)
    expires_at_ms = expires_at_ms if expires_at_ms is not None else issued_at_ms + 60_000
    envelope = {
        "protocol_major": protocol_major,
        "protocol_minor": protocol_minor,
        "session": session.hex(),
        "interaction": interaction.hex(),
        "sequence": sequence,
        "nonce": nonce.hex(),
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": expires_at_ms,
        "sender": key_id(signing_key.public_key()).hex(),
        "audience": key_id(audience).hex(),
        "policy_epoch": policy_epoch,
        "message_kind": message_kind,
        "payload_schema": hashlib.sha256(schema_name.encode()).hexdigest(),
        "payload_digest": hashlib.sha256(payload).hexdigest(),
        "critical_extensions": critical_extensions or [],
    }
    return {
        "envelope": envelope,
        "payload_base64": base64.b64encode(payload).decode(),
        "signature": signing_key.sign(signing_transcript(envelope)).hex(),
    }


def verify_frame(
    frame: dict[str, Any],
    *,
    sender: Ed25519PublicKey,
    audience: Ed25519PublicKey,
    message_kind: int,
    expected_session: bytes | None = None,
    policy_epoch: int = POLICY_EPOCH,
    schema_name: str | None = None,
    schema_digest: bytes | None = None,
    known_critical_extensions: set[str] | None = None,
    replay_guard: ReplayGuard | None = None,
    now_ms: int | None = None,
    max_payload_bytes: int = MAX_PAYLOAD_BYTES,
    max_clock_skew_ms: int = MAX_CLOCK_SKEW_MS,
    max_lifetime_ms: int = MAX_LIFETIME_MS,
) -> dict[str, Any]:
    envelope = frame["envelope"]
    payload = base64.b64decode(frame["payload_base64"], validate=True)
    now_ms = now_ms if now_ms is not None else int(time.time() * 1000)

    if len(payload) > max_payload_bytes:
        raise ValueError("payload exceeds size limit")
    if (envelope["protocol_major"], envelope["protocol_minor"]) != (0, 1):
        raise ValueError("unsupported ScopePact version")
    if envelope["message_kind"] != message_kind:
        raise ValueError("unexpected message kind")
    if envelope["sender"] != key_id(sender).hex():
        raise ValueError("sender key ID mismatch")
    if envelope["audience"] != key_id(audience).hex():
        raise ValueError("audience key ID mismatch")
    if expected_session is not None and envelope["session"] != expected_session.hex():
        raise ValueError("session ID mismatch")
    if envelope["policy_epoch"] != policy_epoch:
        raise ValueError("policy epoch mismatch")
    expected_schema = schema_digest
    if expected_schema is None and schema_name is not None:
        expected_schema = hashlib.sha256(schema_name.encode()).digest()
    if expected_schema is not None and envelope["payload_schema"] != expected_schema.hex():
        raise ValueError("payload schema mismatch")
    if hashlib.sha256(payload).hexdigest() != envelope["payload_digest"]:
        raise ValueError("payload digest mismatch")
    known_extensions = known_critical_extensions or set()
    if any(
        extension not in known_extensions
        for extension in envelope["critical_extensions"]
    ):
        raise ValueError("unknown critical extension")
    if envelope["issued_at_ms"] > now_ms + max_clock_skew_ms:
        raise ValueError("message issued too far in the future")
    if now_ms > envelope["expires_at_ms"]:
        raise ValueError("message has expired")
    if envelope["expires_at_ms"] - envelope["issued_at_ms"] > max_lifetime_ms:
        raise ValueError("message lifetime exceeds local policy")

    try:
        sender.verify(bytes.fromhex(frame["signature"]), signing_transcript(envelope))
    except (InvalidSignature, ValueError) as error:
        raise ValueError("invalid Ed25519 signature") from error
    if replay_guard is not None:
        replay_guard.check_and_record(envelope)
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("payload is not valid JSON") from error


def create_offer(path: Path) -> None:
    agent_a = private_key(AGENT_A_SEED)
    agent_b = private_key(AGENT_B_SEED).public_key()
    session = os.urandom(16)
    interaction = os.urandom(16)
    payload = encode_payload(
        {
            "capability": {
                "actions": ["document.summarize"],
                "max_calls": 1,
                "resource": "urn:demo:report:42",
            },
            "relationship": "customer",
            "request": {"max_output_tokens": 400},
        }
    )
    frame = make_frame(
        payload=payload,
        signing_key=agent_a,
        audience=agent_b,
        session=session,
        interaction=interaction,
        nonce=os.urandom(16),
        message_kind=10,
        schema_name="scopepact.demo.task-offer.v0",
    )
    path.write_text(json.dumps(frame, indent=2) + "\n", encoding="utf-8")
    print(f"Python Agent A: signed task offer {interaction.hex()}")


def verify_reply(path: Path) -> None:
    frame = json.loads(path.read_text(encoding="utf-8"))
    payload = verify_frame(
        frame,
        sender=private_key(AGENT_B_SEED).public_key(),
        audience=private_key(AGENT_A_SEED).public_key(),
        message_kind=11,
    )
    if payload.get("accepted") is not True:
        raise ValueError("agent B did not accept the task")
    print("Python Agent A: verified JavaScript Agent B acceptance")


def tamper_frame(source: Path, destination: Path) -> None:
    frame = json.loads(source.read_text(encoding="utf-8"))
    payload = bytearray(base64.b64decode(frame["payload_base64"], validate=True))
    payload[0] ^= 1
    frame["payload_base64"] = base64.b64encode(payload).decode()
    destination.write_text(json.dumps(frame, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)
    offer = subcommands.add_parser("offer")
    offer.add_argument("output", type=Path)
    verify = subcommands.add_parser("verify-reply")
    verify.add_argument("input", type=Path)
    tamper = subcommands.add_parser("tamper")
    tamper.add_argument("input", type=Path)
    tamper.add_argument("output", type=Path)
    args = parser.parse_args()

    if args.command == "offer":
        create_offer(args.output)
    elif args.command == "verify-reply":
        verify_reply(args.input)
    else:
        tamper_frame(args.input, args.output)


if __name__ == "__main__":
    main()
