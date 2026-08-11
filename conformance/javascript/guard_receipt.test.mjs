import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { verifyGuardReceipt } from "./guard_receipt.mjs";

const vector = JSON.parse(
  await readFile(new URL("../vectors/guard-receipt-v1.json", import.meta.url), "utf8"),
);

test("JavaScript verifies the Rust Guard receipt vector", () => {
  assert.doesNotThrow(() => verifyGuardReceipt(vector.signed_receipt));
});

test("JavaScript rejects a mutated Guard receipt", () => {
  const tampered = structuredClone(vector.signed_receipt);
  tampered.receipt.resource = "/workspace/project/other.txt";
  assert.throws(() => verifyGuardReceipt(tampered), /invalid receipt signature/);
});
