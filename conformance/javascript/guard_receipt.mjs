import { createHash, createPublicKey, verify } from "node:crypto";

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

export function receiptTranscript(receipt) {
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

export function verifyGuardReceipt(signed) {
  const rawKey = Buffer.from(signed.signer_public_key, "hex");
  if (rawKey.length !== 32) throw new Error("receipt public key length is invalid");
  const keyId = createHash("sha256").update(rawKey).digest("hex");
  if (keyId !== signed.signer_key_id) throw new Error("receipt key ID mismatch");
  const signature = Buffer.from(signed.signature, "hex");
  if (signature.length !== 64) throw new Error("receipt signature length is invalid");
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const key = createPublicKey({
    key: Buffer.concat([spkiPrefix, rawKey]),
    format: "der",
    type: "spki",
  });
  if (!verify(null, receiptTranscript(signed.receipt), key, signature)) {
    throw new Error(`invalid receipt signature for request ${signed.receipt.request_id}`);
  }
}
