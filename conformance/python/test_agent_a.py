import base64
import json
import time
import unittest
from pathlib import Path

import agent_a

VECTOR = json.loads(
    (Path(__file__).parent.parent / "vectors" / "envelope-v0.json").read_text(
        encoding="utf-8"
    )
)


class ScopePactPythonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.agent_a = agent_a.private_key(agent_a.AGENT_A_SEED)
        self.agent_b = agent_a.private_key(agent_a.AGENT_B_SEED)
        self.frame = agent_a.make_frame(
            payload=agent_a.encode_payload({"relationship": "customer"}),
            signing_key=self.agent_a,
            audience=self.agent_b.public_key(),
            session=bytes([13]) * 16,
            interaction=bytes([14]) * 16,
            nonce=bytes([15]) * 16,
            message_kind=10,
            schema_name="scopepact.demo.task-offer.v0",
        )

    def verify(self) -> dict:
        return agent_a.verify_frame(
            self.frame,
            sender=self.agent_a.public_key(),
            audience=self.agent_b.public_key(),
            message_kind=10,
            expected_session=bytes([13]) * 16,
            schema_name="scopepact.demo.task-offer.v0",
        )

    def resign(self) -> None:
        self.frame["signature"] = self.agent_a.sign(
            agent_a.signing_transcript(self.frame["envelope"])
        ).hex()

    def test_accepts_valid_scoped_offer(self) -> None:
        self.assertEqual(self.verify(), {"relationship": "customer"})

    def test_rejects_payload_tampering(self) -> None:
        self.frame["payload_base64"] = base64.b64encode(
            b'{"relationship":"admin"}'
        ).decode()
        with self.assertRaisesRegex(ValueError, "payload digest mismatch"):
            self.verify()

    def test_rejects_wrong_audience(self) -> None:
        self.frame["envelope"]["audience"] = agent_a.key_id(
            self.agent_a.public_key()
        ).hex()
        self.resign()
        with self.assertRaisesRegex(ValueError, "audience key ID mismatch"):
            self.verify()

    def test_rejects_unknown_critical_extension(self) -> None:
        self.frame["envelope"]["critical_extensions"] = [
            "urn:scopepact:critical:test"
        ]
        self.resign()
        with self.assertRaisesRegex(ValueError, "unknown critical extension"):
            self.verify()

    def test_rejects_expired_message(self) -> None:
        now_ms = int(time.time() * 1000)
        self.frame["envelope"]["issued_at_ms"] = now_ms - 2_000
        self.frame["envelope"]["expires_at_ms"] = now_ms - 1_000
        self.resign()
        with self.assertRaisesRegex(ValueError, "message has expired"):
            self.verify()

    def test_rejects_bad_signature(self) -> None:
        signature = bytearray.fromhex(self.frame["signature"])
        signature[0] ^= 0x80
        self.frame["signature"] = signature.hex()
        with self.assertRaisesRegex(ValueError, "invalid Ed25519 signature"):
            self.verify()

    def test_rejects_wrong_session_and_policy_epoch(self) -> None:
        self.frame["envelope"]["session"] = (bytes([99]) * 16).hex()
        self.resign()
        with self.assertRaisesRegex(ValueError, "session ID mismatch"):
            self.verify()

        self.frame["envelope"]["session"] = (bytes([13]) * 16).hex()
        self.frame["envelope"]["policy_epoch"] = 6
        self.resign()
        with self.assertRaisesRegex(ValueError, "policy epoch mismatch"):
            self.verify()

    def test_rejects_wrong_schema(self) -> None:
        self.frame["envelope"]["payload_schema"] = bytes([99] * 32).hex()
        self.resign()
        with self.assertRaisesRegex(ValueError, "payload schema mismatch"):
            self.verify()

    def test_rejects_future_and_excessive_lifetime(self) -> None:
        now_ms = int(time.time() * 1000)
        self.frame["envelope"]["issued_at_ms"] = now_ms + 10_000
        self.frame["envelope"]["expires_at_ms"] = now_ms + 20_000
        self.resign()
        with self.assertRaisesRegex(ValueError, "message issued too far in the future"):
            self.verify()

        self.frame["envelope"]["issued_at_ms"] = now_ms
        self.frame["envelope"]["expires_at_ms"] = now_ms + agent_a.MAX_LIFETIME_MS + 1
        self.resign()
        with self.assertRaisesRegex(ValueError, "message lifetime exceeds local policy"):
            self.verify()

    def test_rejects_replay_and_oversized_payload(self) -> None:
        guard = agent_a.ReplayGuard()
        options = {
            "sender": self.agent_a.public_key(),
            "audience": self.agent_b.public_key(),
            "message_kind": 10,
            "expected_session": bytes([13]) * 16,
            "schema_name": "scopepact.demo.task-offer.v0",
            "replay_guard": guard,
        }
        agent_a.verify_frame(self.frame, **options)
        with self.assertRaisesRegex(ValueError, "replayed nonce"):
            agent_a.verify_frame(self.frame, **options)

        payload = b"x" * (agent_a.MAX_PAYLOAD_BYTES + 1)
        oversized = agent_a.make_frame(
            payload=payload,
            signing_key=self.agent_a,
            audience=self.agent_b.public_key(),
            session=bytes([13]) * 16,
            interaction=bytes([14]) * 16,
            nonce=bytes([16]) * 16,
            message_kind=10,
            schema_name="scopepact.demo.task-offer.v0",
        )
        with self.assertRaisesRegex(ValueError, "payload exceeds size limit"):
            agent_a.verify_frame(oversized, **options)

    def test_payload_is_typed_json(self) -> None:
        payload = base64.b64decode(self.frame["payload_base64"], validate=True)
        self.assertEqual(json.loads(payload), {"relationship": "customer"})

    def test_matches_shared_runtime_signature_vector(self) -> None:
        frame = agent_a.make_frame(
            payload=b'{"relationship":"customer"}',
            signing_key=self.agent_a,
            audience=self.agent_b.public_key(),
            session=bytes([13]) * 16,
            interaction=bytes([14]) * 16,
            nonce=bytes([15]) * 16,
            message_kind=10,
            schema_name="scopepact.demo.task-offer.v0",
            issued_at_ms=1_700_000_000_000,
            expires_at_ms=1_700_000_060_000,
        )
        self.assertEqual(
            agent_a.signing_transcript(frame["envelope"]).hex(),
            VECTOR["transcript_hex"],
        )
        self.assertEqual(frame["signature"], VECTOR["frame"]["signature"])


if __name__ == "__main__":
    unittest.main()
