import assert from "node:assert/strict";
import { createPublicKey } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AGENT_A_SEED,
  AGENT_B_SEED,
  MAX_LIFETIME_MS,
  MAX_PAYLOAD_BYTES,
  ReplayGuard,
  makeFrame,
  privateKey,
  signingTranscript,
  verifyFrame,
} from "./agent_b.mjs";

const vector = JSON.parse(
  await readFile(new URL("../vectors/envelope-v0.json", import.meta.url), "utf8"),
);

const agentA = privateKey(AGENT_A_SEED);
const agentB = privateKey(AGENT_B_SEED);
const agentAPublic = createPublicKey(agentA);
const agentBPublic = createPublicKey(agentB);

function offer(overrides = {}) {
  return makeFrame({
    payload: Buffer.from('{"relationship":"customer"}'),
    signingKey: agentA,
    audience: agentBPublic,
    session: Buffer.alloc(16, 13).toString("hex"),
    interaction: Buffer.alloc(16, 14).toString("hex"),
    messageKind: 10,
    schemaName: "scopepact.demo.task-offer.v0",
    ...overrides,
  });
}

function verifyOffer(frame) {
  return verifyFrame(frame, {
    sender: agentAPublic,
    audience: agentBPublic,
    messageKind: 10,
    expectedSession: Buffer.alloc(16, 13).toString("hex"),
    schemaName: "scopepact.demo.task-offer.v0",
  });
}

test("accepts a valid scoped offer", () => {
  assert.deepEqual(verifyOffer(offer()), { relationship: "customer" });
});

test("rejects payload tampering", () => {
  const frame = offer();
  frame.payload_base64 = Buffer.from('{"relationship":"admin"}').toString("base64");
  assert.throws(() => verifyOffer(frame), /payload digest mismatch/);
});

test("rejects the wrong local audience", () => {
  const frame = offer();
  assert.throws(
    () =>
      verifyFrame(frame, {
        sender: agentAPublic,
        audience: agentAPublic,
        messageKind: 10,
      }),
    /audience key ID mismatch/,
  );
});

test("rejects unknown critical extensions", () => {
  const frame = offer();
  frame.envelope.critical_extensions = ["urn:scopepact:critical:test"];
  assert.throws(() => verifyOffer(frame), /unknown critical extension/);
});

test("rejects expired messages", () => {
  const now = Date.now();
  const frame = offer({ issuedAtMs: now - 2_000, expiresAtMs: now - 1_000 });
  assert.throws(() => verifyOffer(frame), /message has expired/);
});

test("rejects an invalid signature", () => {
  const frame = offer();
  const signature = Buffer.from(frame.signature, "hex");
  signature[0] ^= 0x80;
  frame.signature = signature.toString("hex");
  assert.throws(() => verifyOffer(frame), /invalid Ed25519 signature/);
});

test("rejects cross-session and stale-policy frames", () => {
  assert.throws(
    () =>
      verifyFrame(offer(), {
        sender: agentAPublic,
        audience: agentBPublic,
        messageKind: 10,
        expectedSession: Buffer.alloc(16, 99).toString("hex"),
      }),
    /session ID mismatch/,
  );
  assert.throws(() => verifyOffer(offer({ policyEpoch: 6 })), /policy epoch mismatch/);
});

test("rejects an unexpected schema", () => {
  assert.throws(
    () =>
      verifyFrame(offer(), {
        sender: agentAPublic,
        audience: agentBPublic,
        messageKind: 10,
        schemaName: "scopepact.demo.other-schema.v0",
      }),
    /payload schema mismatch/,
  );
});

test("rejects future-issued and excessively long frames", () => {
  const now = Date.now();
  assert.throws(
    () => verifyOffer(offer({ issuedAtMs: now + 10_000, expiresAtMs: now + 20_000 })),
    /message issued too far in the future/,
  );
  assert.throws(
    () => verifyOffer(offer({ issuedAtMs: now, expiresAtMs: now + MAX_LIFETIME_MS + 1 })),
    /message lifetime exceeds local policy/,
  );
});

test("rejects replayed and oversized payloads", () => {
  const frame = offer();
  const replayGuard = new ReplayGuard();
  const options = {
    sender: agentAPublic,
    audience: agentBPublic,
    messageKind: 10,
    expectedSession: frame.envelope.session,
    replayGuard,
  };
  verifyFrame(frame, options);
  assert.throws(() => verifyFrame(frame, options), /replayed nonce/);
  assert.throws(
    () => verifyOffer(offer({ payload: Buffer.alloc(MAX_PAYLOAD_BYTES + 1, "x") })),
    /payload exceeds size limit/,
  );
});

test("matches the shared runtime signature vector", () => {
  const frame = offer({
    nonce: Buffer.alloc(16, 15).toString("hex"),
    issuedAtMs: 1_700_000_000_000,
    expiresAtMs: 1_700_000_060_000,
  });
  assert.equal(signingTranscript(frame.envelope).toString("hex"), vector.transcript_hex);
  assert.equal(frame.signature, vector.frame.signature);
});
