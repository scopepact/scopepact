#!/usr/bin/env node

import { createPublicKey } from "node:crypto";
import { readFile } from "node:fs/promises";

import {
  AGENT_A_SEED,
  AGENT_B_SEED,
  ReplayGuard,
  privateKey,
  verifyFrame,
} from "./agent_b.mjs";

const [requestPath] = process.argv.slice(2);
if (!requestPath) throw new Error("usage: scenario_runner.mjs REQUEST_PATH");

const request = JSON.parse(await readFile(requestPath, "utf8"));
const sender = createPublicKey(privateKey(AGENT_A_SEED));
const audience = createPublicKey(privateKey(AGENT_B_SEED));
const replayGuard = request.replay_guard ? new ReplayGuard() : undefined;
const checks = [];
let payload = null;

try {
  request.frames.forEach((frame, index) => {
    payload = verifyFrame(frame, {
      sender,
      audience,
      messageKind: request.message_kind,
      expectedSession: request.expected_session,
      policyEpoch: request.policy_epoch,
      schemaDigest: request.schema_digest,
      knownCriticalExtensions: request.known_critical_extensions,
      replayGuard,
      nowMs: request.now_ms,
      maxPayloadBytes: request.max_payload_bytes,
      maxClockSkewMs: request.max_clock_skew_ms,
      maxLifetimeMs: request.max_lifetime_ms,
      onCheck: (result) => checks.push({ ...result, attempt: index + 1 }),
    });
  });
  process.stdout.write(JSON.stringify({ decision: "accepted", reason: "frame accepted", checks, payload }));
} catch (error) {
  process.stdout.write(JSON.stringify({ decision: "rejected", reason: error.message, checks }));
}
