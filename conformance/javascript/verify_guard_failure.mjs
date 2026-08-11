import { readFile } from "node:fs/promises";

const [eventsPath, expected] = process.argv.slice(2);
if (!eventsPath || !["worker_failure", "child_exit"].includes(expected)) {
  throw new Error("usage: verify_guard_failure.mjs EVENTS worker_failure|child_exit");
}

const source = await readFile(eventsPath, "utf8");
const events = source
  .split("\n")
  .filter((line) => line.startsWith("{"))
  .map((line) => JSON.parse(line));

if (!events.some((event) => event.event === "proxy_started")) {
  throw new Error("failure scenario did not emit proxy_started");
}
if (events.some((event) => event.format !== "scopepact-guard-event-v1")) {
  throw new Error("failure scenario emitted an unsupported event format");
}

if (expected === "worker_failure") {
  const failures = events.filter((event) => event.event === "proxy_worker_failed");
  if (failures.length !== 1 || failures[0].worker !== "output") {
    throw new Error(
      `invalid child output did not produce one output-worker failure: ${JSON.stringify(events)}`,
    );
  }
} else {
  const stopped = events.find((event) => event.event === "proxy_stopped");
  if (!stopped || stopped.child_success !== false || stopped.child_code !== 23) {
    throw new Error("abrupt child exit did not preserve its failure status");
  }
}

for (const forbidden of [
  "request_id", "tool", "resource", "arguments", "reason", "signature", "public_key",
]) {
  if (events.some((event) => Object.hasOwn(event, forbidden))) {
    throw new Error(`failure event exposed forbidden field: ${forbidden}`);
  }
}
