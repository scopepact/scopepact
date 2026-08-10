#!/usr/bin/env python3
"""Local ScopePact protocol inspector server."""

from __future__ import annotations

import argparse
import base64
import copy
import contextlib
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

CONFORMANCE_ROOT = Path(__file__).resolve().parent
WEB_ROOT = CONFORMANCE_ROOT / "web"
JAVASCRIPT_AGENT = CONFORMANCE_ROOT / "javascript" / "agent_b.mjs"
SCENARIO_RUNNER = CONFORMANCE_ROOT / "javascript" / "scenario_runner.mjs"
sys.path.insert(0, str(CONFORMANCE_ROOT / "python"))

import agent_a  # noqa: E402

STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}
MAX_REQUEST_BYTES = 4_096

SCENARIOS = (
    {
        "id": "valid_exchange",
        "category": "Interoperability",
        "title": "Signed task exchange",
        "invariant": "I1 + I6",
        "expected_decision": "accepted",
        "rule": "Both runtimes must agree on identity, scope, payload, and signature bytes.",
        "expected": "Agent B accepts the offer and Agent A verifies the signed reply.",
        "impact": "Independent implementations can exchange a scoped task without shared process state.",
    },
    {
        "id": "payload_tamper",
        "category": "Integrity",
        "title": "Altered payload bytes",
        "invariant": "I1",
        "expected_decision": "rejected",
        "expected_reason": "payload digest mismatch",
        "rule": "The decoded payload must match the digest committed by the signed envelope.",
        "expected": "Reject before the altered JSON reaches application logic.",
        "impact": "A relay cannot rewrite task intent while preserving the original signature.",
    },
    {
        "id": "invalid_signature",
        "category": "Integrity",
        "title": "Invalid signature",
        "invariant": "I1",
        "expected_decision": "rejected",
        "expected_reason": "invalid Ed25519 signature",
        "rule": "The envelope transcript must verify under the declared sender key.",
        "expected": "Reject a frame whose signature bytes were modified.",
        "impact": "Only the holder of the agent signing key can authenticate a message.",
    },
    {
        "id": "wrong_sender",
        "category": "Identity",
        "title": "Sender key substitution",
        "invariant": "I1",
        "expected_decision": "rejected",
        "expected_reason": "sender key ID mismatch",
        "rule": "The declared sender ID must be the digest of the trusted verification key.",
        "expected": "Reject a message that claims another sender identity.",
        "impact": "A valid key cannot be used to impersonate a different registered agent.",
    },
    {
        "id": "wrong_audience",
        "category": "Isolation",
        "title": "Wrong audience",
        "invariant": "I1 + I9",
        "expected_decision": "rejected",
        "expected_reason": "audience key ID mismatch",
        "rule": "A signed frame is valid only for its named receiving agent.",
        "expected": "Reject a validly signed frame addressed to another key.",
        "impact": "Captured messages cannot be redirected to a different agent.",
    },
    {
        "id": "wrong_session",
        "category": "Isolation",
        "title": "Cross-session message",
        "invariant": "I9",
        "expected_decision": "rejected",
        "expected_reason": "session ID mismatch",
        "rule": "Every message must belong to the active authenticated session.",
        "expected": "Reject a signed frame copied into another session.",
        "impact": "Authority and conversation state stay isolated between connections.",
    },
    {
        "id": "replayed_message",
        "category": "Freshness",
        "title": "Replayed message",
        "invariant": "I2",
        "expected_decision": "rejected",
        "expected_reason": "replayed nonce",
        "rule": "A sender nonce and sequence may be accepted only once per session.",
        "expected": "Accept the first delivery and reject the identical retry.",
        "impact": "Recorded traffic cannot trigger the same application work twice.",
    },
    {
        "id": "expired_message",
        "category": "Freshness",
        "title": "Expired message",
        "invariant": "I2",
        "expected_decision": "rejected",
        "expected_reason": "message has expired",
        "rule": "The verifier clock must be inside the signed validity interval.",
        "expected": "Reject a correctly signed frame after its expiry time.",
        "impact": "Old authority cannot remain ambient after its intended lifetime.",
    },
    {
        "id": "future_message",
        "category": "Freshness",
        "title": "Future-issued message",
        "invariant": "I2",
        "expected_decision": "rejected",
        "expected_reason": "message issued too far in the future",
        "rule": "Issue time may exceed the verifier clock only by bounded clock skew.",
        "expected": "Reject a frame dated beyond the configured skew allowance.",
        "impact": "A sender cannot manufacture a validity window that starts far ahead.",
    },
    {
        "id": "excessive_lifetime",
        "category": "Resources",
        "title": "Excessive lifetime",
        "invariant": "I2",
        "expected_decision": "rejected",
        "expected_reason": "message lifetime exceeds local policy",
        "rule": "Signed message lifetime is capped even when its expiry is still in the future.",
        "expected": "Reject a frame valid for longer than 120 seconds.",
        "impact": "Long-lived captured messages do not become durable bearer artifacts.",
    },
    {
        "id": "unsupported_version",
        "category": "Compatibility",
        "title": "Unsupported version",
        "invariant": "I3",
        "expected_decision": "rejected",
        "expected_reason": "unsupported ScopePact version",
        "rule": "Only an explicitly supported protocol version may enter the session.",
        "expected": "Reject a validly signed frame from an unsupported major version.",
        "impact": "Peers cannot silently downgrade or reinterpret protocol semantics.",
    },
    {
        "id": "stale_policy",
        "category": "Governance",
        "title": "Stale policy epoch",
        "invariant": "I8",
        "expected_decision": "rejected",
        "expected_reason": "policy epoch mismatch",
        "rule": "Messages must reference the receiver's current policy epoch.",
        "expected": "Reject a frame authorized under an obsolete policy revision.",
        "impact": "Policy rollover invalidates stale session assumptions immediately.",
    },
    {
        "id": "unknown_extension",
        "category": "Compatibility",
        "title": "Unknown critical extension",
        "invariant": "I3",
        "expected_decision": "rejected",
        "expected_reason": "unknown critical extension",
        "rule": "Every critical extension must be understood by the receiver.",
        "expected": "Reject rather than ignore an unknown mandatory semantic.",
        "impact": "Extensions cannot weaken core checks through ambiguous interpretation.",
    },
    {
        "id": "schema_mismatch",
        "category": "Integrity",
        "title": "Unexpected payload schema",
        "invariant": "I1",
        "expected_decision": "rejected",
        "expected_reason": "payload schema mismatch",
        "rule": "The payload schema digest must match the message contract selected by policy.",
        "expected": "Reject valid JSON encoded under an unexpected schema.",
        "impact": "Typed content cannot be reinterpreted as a different operation.",
    },
    {
        "id": "oversized_payload",
        "category": "Resources",
        "title": "Oversized payload",
        "invariant": "I2",
        "expected_decision": "rejected",
        "expected_reason": "payload exceeds size limit",
        "rule": "Frame size limits are enforced before signature and semantic work.",
        "expected": "Reject payload bytes above the local 4 KiB demo limit.",
        "impact": "Untrusted peers cannot force unbounded parsing or model input cost.",
    },
)
SCENARIO_BY_ID = {scenario["id"]: scenario for scenario in SCENARIOS}


def credential_profile() -> dict[str, str]:
    return {
        "identity": "Native Ed25519",
        "federation": "Not presented",
        "authority": "Capability grant",
    }


def frame_view(frame: dict[str, Any]) -> dict[str, Any]:
    payload = base64.b64decode(frame["payload_base64"], validate=True)
    try:
        decoded_payload: Any = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        decoded_payload = {"raw_utf8": payload.decode("utf-8", errors="replace")}
    return {
        "envelope": frame["envelope"],
        "payload": decoded_payload,
        "signature": frame["signature"],
    }


def scenario_catalog() -> list[dict[str, Any]]:
    return [copy.deepcopy(scenario) for scenario in SCENARIOS]


def resign(frame: dict[str, Any]) -> None:
    signing_key = agent_a.private_key(agent_a.AGENT_A_SEED)
    frame["signature"] = signing_key.sign(
        agent_a.signing_transcript(frame["envelope"])
    ).hex()


def scenario_frames(
    scenario_id: str,
    original: dict[str, Any],
    now_ms: int,
) -> tuple[list[dict[str, Any]], bool]:
    frame = copy.deepcopy(original)
    replay_guard = False

    if scenario_id == "payload_tamper":
        payload = bytearray(base64.b64decode(frame["payload_base64"], validate=True))
        payload[0] ^= 1
        frame["payload_base64"] = base64.b64encode(payload).decode()
    elif scenario_id == "invalid_signature":
        signature = bytearray.fromhex(frame["signature"])
        signature[0] ^= 0x80
        frame["signature"] = signature.hex()
    elif scenario_id == "wrong_sender":
        frame["envelope"]["sender"] = bytes([99] * 32).hex()
        resign(frame)
    elif scenario_id == "wrong_audience":
        sender = agent_a.private_key(agent_a.AGENT_A_SEED).public_key()
        frame["envelope"]["audience"] = agent_a.key_id(sender).hex()
        resign(frame)
    elif scenario_id == "wrong_session":
        frame["envelope"]["session"] = bytes([99] * 16).hex()
        resign(frame)
    elif scenario_id == "replayed_message":
        replay_guard = True
        return [frame, copy.deepcopy(frame)], replay_guard
    elif scenario_id == "expired_message":
        frame["envelope"]["issued_at_ms"] = now_ms - 2_000
        frame["envelope"]["expires_at_ms"] = now_ms - 1_000
        resign(frame)
    elif scenario_id == "future_message":
        frame["envelope"]["issued_at_ms"] = now_ms + 10_000
        frame["envelope"]["expires_at_ms"] = now_ms + 70_000
        resign(frame)
    elif scenario_id == "excessive_lifetime":
        frame["envelope"]["issued_at_ms"] = now_ms - 100
        frame["envelope"]["expires_at_ms"] = now_ms + agent_a.MAX_LIFETIME_MS + 1
        resign(frame)
    elif scenario_id == "unsupported_version":
        frame["envelope"]["protocol_major"] = 1
        resign(frame)
    elif scenario_id == "stale_policy":
        frame["envelope"]["policy_epoch"] = agent_a.POLICY_EPOCH - 1
        resign(frame)
    elif scenario_id == "unknown_extension":
        frame["envelope"]["critical_extensions"] = [
            "urn:scopepact:critical:unrecognized"
        ]
        resign(frame)
    elif scenario_id == "schema_mismatch":
        frame["envelope"]["payload_schema"] = hashlib.sha256(
            b"scopepact.demo.other-schema.v0"
        ).hexdigest()
        resign(frame)
    elif scenario_id == "oversized_payload":
        payload = json.dumps({"blob": "x" * agent_a.MAX_PAYLOAD_BYTES}).encode()
        frame["payload_base64"] = base64.b64encode(payload).decode()
        frame["envelope"]["payload_digest"] = hashlib.sha256(payload).hexdigest()
        resign(frame)
    else:
        raise KeyError(scenario_id)

    return [frame], replay_guard


def run_node_scenario(
    request_path: Path,
) -> dict[str, Any]:
    node = subprocess.run(
        ["node", str(SCENARIO_RUNNER), str(request_path)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if node.returncode != 0:
        raise RuntimeError(failure_reason(node.stderr))
    try:
        return json.loads(node.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("scenario runner returned malformed evidence") from error


def failure_reason(stderr: str) -> str:
    for line in stderr.splitlines():
        if line.startswith("Error: "):
            return line.removeprefix("Error: ")
    return "signed frame rejected"


def run_exchange(*, tamper: bool) -> dict[str, Any]:
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="scopepact-inspector-") as temp:
        temp_root = Path(temp)
        offer_path = temp_root / "offer.json"
        input_path = offer_path
        reply_path = temp_root / "reply.json"
        with contextlib.redirect_stdout(io.StringIO()):
            agent_a.create_offer(offer_path)

        original = json.loads(offer_path.read_text(encoding="utf-8"))
        submitted = original
        if tamper:
            input_path = temp_root / "tampered.json"
            agent_a.tamper_frame(offer_path, input_path)
            submitted = json.loads(input_path.read_text(encoding="utf-8"))

        node = subprocess.run(
            ["node", str(JAVASCRIPT_AGENT), str(input_path), str(reply_path)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

        if tamper:
            if node.returncode == 0:
                raise RuntimeError("tampered payload was accepted")
            return {
                "mode": "tamper",
                "result": "rejected",
                "reason": failure_reason(node.stderr),
                "credential": credential_profile(),
                "elapsed_ms": elapsed_ms,
                "offer": frame_view(submitted),
                "reply": None,
                "stages": [
                    {"label": "Offer signed", "runtime": "Python", "status": "passed"},
                    {"label": "Payload altered", "runtime": "Inspector", "status": "warning"},
                    {"label": "Digest checked", "runtime": "JavaScript", "status": "rejected"},
                    {"label": "Effect blocked", "runtime": "ScopePact", "status": "passed"},
                ],
            }

        if node.returncode != 0:
            raise RuntimeError(failure_reason(node.stderr))
        reply = json.loads(reply_path.read_text(encoding="utf-8"))
        payload = agent_a.verify_frame(
            reply,
            sender=agent_a.private_key(agent_a.AGENT_B_SEED).public_key(),
            audience=agent_a.private_key(agent_a.AGENT_A_SEED).public_key(),
            message_kind=11,
        )
        if payload.get("accepted") is not True:
            raise RuntimeError("agent B did not accept the task")
        return {
            "mode": "exchange",
            "result": "accepted",
            "reason": "Both signed frames verified",
            "credential": credential_profile(),
            "elapsed_ms": elapsed_ms,
            "offer": frame_view(original),
            "reply": frame_view(reply),
            "stages": [
                {"label": "Offer signed", "runtime": "Python", "status": "passed"},
                {"label": "Offer verified", "runtime": "JavaScript", "status": "passed"},
                {"label": "Acceptance signed", "runtime": "JavaScript", "status": "passed"},
                {"label": "Acceptance verified", "runtime": "Python", "status": "passed"},
            ],
        }


def run_scenario(scenario_id: str) -> dict[str, Any]:
    scenario = SCENARIO_BY_ID.get(scenario_id)
    if scenario is None:
        raise KeyError(scenario_id)

    started = time.perf_counter()
    if scenario_id == "valid_exchange":
        exchange = run_exchange(tamper=False)
        decision = exchange["result"]
        expected = scenario["expected_decision"]
        return {
            "scenario": copy.deepcopy(scenario),
            "status": "passed" if decision == expected else "failed",
            "decision": decision,
            "expected_decision": expected,
            "reason": exchange["reason"],
            "elapsed_ms": exchange["elapsed_ms"],
            "credential": exchange["credential"],
            "offer": exchange["offer"],
            "reply": exchange["reply"],
            "checks": [
                {
                    "label": stage["label"],
                    "runtime": stage["runtime"],
                    "status": stage["status"],
                    "attempt": 1,
                }
                for stage in exchange["stages"]
            ],
            "runtimes": ["Python signer", "JavaScript verifier"],
        }

    with tempfile.TemporaryDirectory(prefix="scopepact-scenario-") as temp:
        temp_root = Path(temp)
        offer_path = temp_root / "offer.json"
        request_path = temp_root / "request.json"
        with contextlib.redirect_stdout(io.StringIO()):
            agent_a.create_offer(offer_path)
        original = json.loads(offer_path.read_text(encoding="utf-8"))
        now_ms = int(time.time() * 1000)
        frames, replay_guard = scenario_frames(scenario_id, original, now_ms)
        request = {
            "frames": frames,
            "message_kind": 10,
            "expected_session": original["envelope"]["session"],
            "policy_epoch": agent_a.POLICY_EPOCH,
            "schema_digest": original["envelope"]["payload_schema"],
            "known_critical_extensions": [],
            "replay_guard": replay_guard,
            "now_ms": now_ms,
            "max_payload_bytes": agent_a.MAX_PAYLOAD_BYTES,
            "max_clock_skew_ms": agent_a.MAX_CLOCK_SKEW_MS,
            "max_lifetime_ms": agent_a.MAX_LIFETIME_MS,
        }
        request_path.write_text(json.dumps(request), encoding="utf-8")
        evidence = run_node_scenario(request_path)

    decision = evidence["decision"]
    expected_decision = scenario["expected_decision"]
    expected_reason = scenario.get("expected_reason")
    passed = decision == expected_decision and (
        expected_reason is None or evidence["reason"] == expected_reason
    )
    return {
        "scenario": copy.deepcopy(scenario),
        "status": "passed" if passed else "failed",
        "decision": decision,
        "expected_decision": expected_decision,
        "reason": evidence["reason"],
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
        "credential": credential_profile(),
        "offer": frame_view(frames[-1]),
        "reply": None,
        "checks": evidence["checks"],
        "runtimes": ["Python signer", "JavaScript verifier"],
    }


def run_suite() -> dict[str, Any]:
    started = time.perf_counter()
    results = [run_scenario(scenario["id"]) for scenario in SCENARIOS]
    passed = sum(result["status"] == "passed" for result in results)
    return {
        "status": "passed" if passed == len(results) else "failed",
        "passed": passed,
        "total": len(results),
        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
        "results": results,
    }


def health() -> dict[str, Any]:
    return {
        "status": "ready" if shutil.which("node") else "missing-runtime",
        "protocol": "ScopePact v0.1",
        "host": "127.0.0.1",
        "credential": credential_profile(),
        "python": sys.version.split()[0],
        "node": shutil.which("node") is not None,
        "scenario_count": len(SCENARIOS),
    }


class InspectorHandler(BaseHTTPRequestHandler):
    server_version = "ScopePactInspector/0.1"

    def send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        encoded = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/api/health":
            self.send_json(health())
            return
        if self.path == "/api/scenarios":
            self.send_json({"scenarios": scenario_catalog()})
            return
        if self.path == "/favicon.ico":
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
            return
        static = STATIC_FILES.get(self.path)
        if static is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        filename, content_type = static
        content = (WEB_ROOT / filename).read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in {"/api/exchange", "/api/tamper", "/api/run", "/api/suite"}:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        if length > MAX_REQUEST_BYTES:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return
        body = self.rfile.read(length) if length else b"{}"
        try:
            request = json.loads(body)
            if not isinstance(request, dict):
                raise ValueError("request body must be an object")
            if self.path == "/api/run":
                scenario_id = request.get("scenario_id")
                if not isinstance(scenario_id, str):
                    raise ValueError("scenario_id is required")
                self.send_json(run_scenario(scenario_id))
            elif self.path == "/api/suite":
                self.send_json(run_suite())
            else:
                self.send_json(run_exchange(tamper=self.path == "/api/tamper"))
        except KeyError as error:
            self.send_json(
                {"result": "error", "reason": f"unknown scenario: {error.args[0]}"},
                HTTPStatus.NOT_FOUND,
            )
        except json.JSONDecodeError:
            self.send_json(
                {"result": "error", "reason": "malformed JSON request"},
                HTTPStatus.BAD_REQUEST,
            )
        except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
            self.send_json(
                {"result": "error", "reason": str(error)},
                HTTPStatus.BAD_REQUEST if isinstance(error, ValueError) else HTTPStatus.INTERNAL_SERVER_ERROR,
            )

    def log_message(self, message: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {message % args}")


def make_server(port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), InspectorHandler)
    server.daemon_threads = True
    return server


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    server = make_server(args.port)
    print(f"ScopePact inspector: http://127.0.0.1:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
