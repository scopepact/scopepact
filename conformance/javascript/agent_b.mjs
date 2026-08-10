#!/usr/bin/env node

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign,
  verify,
} from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const DOMAIN = Buffer.from("SCOPEPACT-ENVELOPE-V0\0", "ascii");
const AGENT_A_SEED = Buffer.alloc(32, 11);
const AGENT_B_SEED = Buffer.alloc(32, 12);
const MAX_LIFETIME_MS = 120_000;
const MAX_PAYLOAD_BYTES = 4_096;
const MAX_CLOCK_SKEW_MS = 500;
const POLICY_EPOCH = 7;

function privateKey(seed) {
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({ key: Buffer.concat([prefix, seed]), format: "der", type: "pkcs8" });
}

function rawPublic(key) {
  const publicKey = key.type === "public" ? key : createPublicKey(key);
  const der = publicKey.export({ format: "der", type: "spki" });
  return der.subarray(der.length - 32);
}

function sha256(value) {
  return createHash("sha256").update(value).digest();
}

function keyId(key) {
  return sha256(rawPublic(key));
}

function u16(value) {
  const output = Buffer.alloc(2);
  output.writeUInt16BE(value);
  return output;
}

function u32(value) {
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
}

function u64(value) {
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(BigInt(value));
  return output;
}

function i64(value) {
  const output = Buffer.alloc(8);
  output.writeBigInt64BE(BigInt(value));
  return output;
}

function bytes(value) {
  return Buffer.concat([u32(value.length), value]);
}

function fromHex(value, expectedLength) {
  const output = Buffer.from(value, "hex");
  if (output.length !== expectedLength || output.toString("hex") !== value.toLowerCase()) {
    throw new Error(`invalid ${expectedLength}-byte hexadecimal field`);
  }
  return output;
}

class ReplayGuard {
  constructor() {
    this.nonces = new Set();
    this.sequences = new Set();
  }

  checkAndRecord(envelope) {
    if (this.nonces.has(envelope.nonce)) throw new Error("replayed nonce");
    if (this.sequences.has(envelope.sequence)) throw new Error("replayed sequence");
    this.nonces.add(envelope.nonce);
    this.sequences.add(envelope.sequence);
  }
}

function check(onCheck, label, condition, error) {
  if (!condition) {
    onCheck?.({ label, status: "rejected", detail: error });
    throw new Error(error);
  }
  onCheck?.({ label, status: "passed" });
}

function decodePayload(encoded, onCheck) {
  check(onCheck, "Payload encoding", typeof encoded === "string", "malformed payload encoding");
  const payload = Buffer.from(encoded, "base64");
  const canonical = payload.toString("base64").replace(/=+$/u, "");
  check(
    onCheck,
    "Payload encoding",
    canonical === encoded.replace(/=+$/u, ""),
    "malformed payload encoding",
  );
  return payload;
}

function signingTranscript(envelope) {
  const interaction = envelope.interaction;
  const extensions = envelope.critical_extensions;
  return Buffer.concat([
    DOMAIN,
    u16(envelope.protocol_major),
    u16(envelope.protocol_minor),
    bytes(fromHex(envelope.session, 16)),
    interaction === null
      ? Buffer.from([0])
      : Buffer.concat([Buffer.from([1]), bytes(fromHex(interaction, 16))]),
    u64(envelope.sequence),
    bytes(fromHex(envelope.nonce, 16)),
    i64(envelope.issued_at_ms),
    i64(envelope.expires_at_ms),
    bytes(fromHex(envelope.sender, 32)),
    bytes(fromHex(envelope.audience, 32)),
    u64(envelope.policy_epoch),
    u16(envelope.message_kind),
    bytes(fromHex(envelope.payload_schema, 32)),
    bytes(fromHex(envelope.payload_digest, 32)),
    u32(extensions.length),
    ...extensions.map((extension) => bytes(Buffer.from(extension, "utf8"))),
  ]);
}

function verifyFrame(
  frame,
  {
    sender,
    audience,
    messageKind,
    expectedSession,
    policyEpoch = POLICY_EPOCH,
    schemaName,
    schemaDigest,
    knownCriticalExtensions = [],
    replayGuard,
    nowMs = Date.now(),
    maxPayloadBytes = MAX_PAYLOAD_BYTES,
    maxClockSkewMs = MAX_CLOCK_SKEW_MS,
    maxLifetimeMs = MAX_LIFETIME_MS,
    onCheck,
  },
) {
  const { envelope } = frame;
  const payload = decodePayload(frame.payload_base64, onCheck);
  check(onCheck, "Payload size", payload.length <= maxPayloadBytes, "payload exceeds size limit");
  check(
    onCheck,
    "Protocol version",
    envelope.protocol_major === 0 && envelope.protocol_minor === 1,
    "unsupported ScopePact version",
  );
  check(onCheck, "Message kind", envelope.message_kind === messageKind, "unexpected message kind");
  check(
    onCheck,
    "Sender binding",
    envelope.sender === keyId(sender).toString("hex"),
    "sender key ID mismatch",
  );
  check(
    onCheck,
    "Audience binding",
    envelope.audience === keyId(audience).toString("hex"),
    "audience key ID mismatch",
  );
  if (expectedSession !== undefined) {
    check(
      onCheck,
      "Session binding",
      envelope.session === expectedSession,
      "session ID mismatch",
    );
  }
  check(
    onCheck,
    "Policy epoch",
    envelope.policy_epoch === policyEpoch,
    "policy epoch mismatch",
  );
  const expectedSchema = schemaDigest ?? (schemaName ? sha256(schemaName).toString("hex") : null);
  if (expectedSchema !== null) {
    check(
      onCheck,
      "Payload schema",
      envelope.payload_schema === expectedSchema,
      "payload schema mismatch",
    );
  }
  check(
    onCheck,
    "Payload digest",
    envelope.payload_digest === sha256(payload).toString("hex"),
    "payload digest mismatch",
  );
  const knownExtensions = new Set(knownCriticalExtensions);
  check(
    onCheck,
    "Critical extensions",
    envelope.critical_extensions.every((extension) => knownExtensions.has(extension)),
    "unknown critical extension",
  );
  check(
    onCheck,
    "Issue time",
    envelope.issued_at_ms <= nowMs + maxClockSkewMs,
    "message issued too far in the future",
  );
  check(onCheck, "Expiry", nowMs <= envelope.expires_at_ms, "message has expired");
  check(
    onCheck,
    "Bounded lifetime",
    envelope.expires_at_ms - envelope.issued_at_ms <= maxLifetimeMs,
    "message lifetime exceeds local policy",
  );
  let signatureValid = false;
  try {
    signatureValid = verify(
      null,
      signingTranscript(envelope),
      sender,
      Buffer.from(frame.signature, "hex"),
    );
  } catch {
    signatureValid = false;
  }
  check(onCheck, "Ed25519 signature", signatureValid, "invalid Ed25519 signature");
  if (replayGuard) {
    try {
      replayGuard.checkAndRecord(envelope);
      onCheck?.({ label: "Replay guard", status: "passed" });
    } catch (error) {
      onCheck?.({ label: "Replay guard", status: "rejected", detail: error.message });
      throw error;
    }
  }
  try {
    const decoded = JSON.parse(payload.toString("utf8"));
    onCheck?.({ label: "Typed payload", status: "passed" });
    return decoded;
  } catch {
    onCheck?.({ label: "Typed payload", status: "rejected", detail: "payload is not valid JSON" });
    throw new Error("payload is not valid JSON");
  }
}

function makeFrame({
  payload,
  signingKey,
  audience,
  session,
  interaction,
  messageKind,
  schemaName,
  nonce = randomBytes(16).toString("hex"),
  issuedAtMs = Date.now(),
  expiresAtMs = issuedAtMs + 60_000,
  protocolMajor = 0,
  protocolMinor = 1,
  sequence = 1,
  policyEpoch = POLICY_EPOCH,
  criticalExtensions = [],
}) {
  const envelope = {
    protocol_major: protocolMajor,
    protocol_minor: protocolMinor,
    session,
    interaction,
    sequence,
    nonce,
    issued_at_ms: issuedAtMs,
    expires_at_ms: expiresAtMs,
    sender: keyId(signingKey).toString("hex"),
    audience: keyId(audience).toString("hex"),
    policy_epoch: policyEpoch,
    message_kind: messageKind,
    payload_schema: sha256(schemaName).toString("hex"),
    payload_digest: sha256(payload).toString("hex"),
    critical_extensions: criticalExtensions,
  };
  return {
    envelope,
    payload_base64: payload.toString("base64"),
    signature: sign(null, signingTranscript(envelope), signingKey).toString("hex"),
  };
}

function makeReply(offer) {
  const agentB = privateKey(AGENT_B_SEED);
  const agentA = createPublicKey(privateKey(AGENT_A_SEED));
  const payload = Buffer.from(JSON.stringify({ accepted: true, max_output_tokens: 400 }));
  return makeFrame({
    payload,
    signingKey: agentB,
    audience: agentA,
    session: offer.envelope.session,
    interaction: offer.envelope.interaction,
    messageKind: 11,
    schemaName: "scopepact.demo.task-accept.v0",
  });
}

async function main() {
  const [offerPath, replyPath] = process.argv.slice(2);
  if (!offerPath || !replyPath) {
    throw new Error("usage: agent_b.mjs OFFER_PATH REPLY_PATH");
  }
  const offer = JSON.parse(await readFile(offerPath, "utf8"));
  const payload = verifyFrame(offer, {
    sender: createPublicKey(privateKey(AGENT_A_SEED)),
    audience: createPublicKey(privateKey(AGENT_B_SEED)),
    messageKind: 10,
  });
  if (payload.relationship !== "customer" || payload.capability.max_calls !== 1) {
    throw new Error("offer violates the demo's relationship policy");
  }
  await writeFile(replyPath, `${JSON.stringify(makeReply(offer), null, 2)}\n`);
  console.log("JavaScript Agent B: verified scoped offer and signed acceptance");
}

export {
  AGENT_A_SEED,
  AGENT_B_SEED,
  MAX_CLOCK_SKEW_MS,
  MAX_LIFETIME_MS,
  MAX_PAYLOAD_BYTES,
  POLICY_EPOCH,
  ReplayGuard,
  makeFrame,
  makeReply,
  privateKey,
  signingTranscript,
  verifyFrame,
};

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}
