import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";

const [outputPath, auditPath] = process.argv.slice(2);
if (!outputPath || !auditPath) {
  throw new Error("usage: verify_guard_proxy.mjs OUTPUT AUDIT");
}

function lines(value) {
  return value.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
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

function field(value) {
  const bytes = Buffer.from(value, "utf8");
  return Buffer.concat([u32(bytes.length), bytes]);
}

function optionalField(value) {
  return value === null
    ? Buffer.from([0])
    : Buffer.concat([Buffer.from([1]), field(value)]);
}

function receiptTranscript(receipt) {
  return Buffer.concat([
    Buffer.from("SCOPEPACT-GUARD-RECEIPT-V0\0", "utf8"),
    u16(receipt.receipt_version),
    Buffer.from([receipt.decision === "allowed" ? 1 : 2]),
    field(receipt.reason),
    u64(receipt.policy_epoch),
    field(receipt.principal),
    field(receipt.agent),
    field(JSON.stringify(receipt.request_id)),
    field(receipt.tool),
    optionalField(receipt.resource),
    optionalField(receipt.rule_id),
    Buffer.from(receipt.effect_id, "hex"),
    Buffer.from(receipt.effect_digest, "hex"),
    i64(receipt.issued_at_ms),
    Buffer.from([receipt.duplicate ? 1 : 0]),
  ]);
}

function verifyReceipt(signed) {
  const rawKey = Buffer.from(signed.signer_public_key, "hex");
  const keyId = createHash("sha256").update(rawKey).digest("hex");
  if (keyId !== signed.signer_key_id) throw new Error("receipt key ID mismatch");
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const key = createPublicKey({
    key: Buffer.concat([spkiPrefix, rawKey]),
    format: "der",
    type: "spki",
  });
  if (!verify(null, receiptTranscript(signed.receipt), key, Buffer.from(signed.signature, "hex"))) {
    throw new Error(`invalid receipt signature for request ${signed.receipt.request_id}`);
  }
}

const output = lines(await readFile(outputPath, "utf8"));
const audit = lines(await readFile(auditPath, "utf8"));
const byId = new Map(output.map((message) => [message.id, message]));

if (byId.get(0)?.result?.serverInfo?.name !== "scopepact-mock") {
  throw new Error("initialize was not forwarded to the MCP server");
}
if (byId.get(1)?.result?.isError !== false) {
  throw new Error("allowed tool call was not forwarded to the MCP server");
}
if (byId.get(2)?.error?.code !== -32042) {
  throw new Error("blocked tool call did not return the ScopePact JSON-RPC error");
}
if (audit.length !== 2) throw new Error(`expected 2 receipts, received ${audit.length}`);
for (const receipt of audit) verifyReceipt(receipt);
if (audit.find((entry) => entry.receipt.request_id === 1)?.receipt.decision !== "allowed") {
  throw new Error("allowed receipt is missing");
}
if (audit.find((entry) => entry.receipt.request_id === 2)?.receipt.decision !== "blocked") {
  throw new Error("blocked receipt is missing");
}

process.stdout.write("ScopePact MCP proxy and JavaScript receipt verification passed.\n");
