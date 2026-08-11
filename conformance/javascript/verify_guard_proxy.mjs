import { readFile } from "node:fs/promises";
import { verifyGuardReceipt } from "./guard_receipt.mjs";

const [outputPath, auditPath, eventsPath] = process.argv.slice(2);
if (!outputPath || !auditPath || !eventsPath) {
  throw new Error("usage: verify_guard_proxy.mjs OUTPUT AUDIT EVENTS");
}

function lines(value) {
  return value.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}

const output = lines(await readFile(outputPath, "utf8"));
const audit = lines(await readFile(auditPath, "utf8"));
const eventsSource = await readFile(eventsPath, "utf8");
const events = lines(eventsSource);
const byId = new Map(output.map((message) => [message.id, message]));

if (output.some((message) => message.method === "sampling/createMessage")) {
  throw new Error("server-initiated sampling request crossed the Guard boundary");
}

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
for (const receipt of audit) verifyGuardReceipt(receipt);
if (audit.find((entry) => entry.receipt.request_id === 1)?.receipt.decision !== "allowed") {
  throw new Error("allowed receipt is missing");
}
if (audit.find((entry) => entry.receipt.request_id === 2)?.receipt.decision !== "blocked") {
  throw new Error("blocked receipt is missing");
}

if (events.some((event) => event.format !== "scopepact-guard-event-v1")) {
  throw new Error("operational event format is missing or unsupported");
}
if (!events.some((event) => event.event === "proxy_started")) {
  throw new Error("proxy start event is missing");
}
if (!events.some((event) => event.event === "proxy_stopped")) {
  throw new Error("proxy stop event is missing");
}
const decisions = events.filter((event) => event.event === "decision_committed");
if (decisions.length !== 2 || !decisions.some((event) => event.outcome === "allowed") ||
    !decisions.some((event) => event.outcome === "blocked")) {
  throw new Error("redacted decision events do not match proxy decisions");
}
for (const forbidden of [
  "request_id", "tool", "resource", "arguments", "reason", "signature",
  "public_key", "/workspace/project/README.md", "/etc/hosts",
]) {
  if (eventsSource.includes(forbidden)) {
    throw new Error(`operational events leaked forbidden value: ${forbidden}`);
  }
}
if (eventsSource.includes('"content"')) {
  throw new Error("operational events leaked tool arguments");
}

process.stdout.write("ScopePact MCP proxy and JavaScript receipt verification passed.\n");
