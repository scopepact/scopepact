import { writeFileSync } from "node:fs";
import readline from "node:readline";

const serverMode = process.env.SCOPEPACT_TEST_SERVER_MODE ?? "normal";
if (serverMode === "exit_nonzero") process.exit(23);

const unmediatedMarker = process.env.SCOPEPACT_TEST_UNMEDIATED_MARKER;
if (unmediatedMarker) {
  writeFileSync(unmediatedMarker, "wrapped server created this outside an admitted call\n", {
    flag: "wx",
    mode: 0o600,
  });
}

const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

input.on("line", (line) => {
  const request = JSON.parse(line);
  if (request.method === "initialize" && serverMode === "invalid_output") {
    process.stdout.write("this is not JSON\n");
    return;
  }
  if (request.method === "initialize" && serverMode === "oversized_output") {
    process.stdout.write(`${"x".repeat(4 * 1024 * 1024 + 1)}\n`);
    return;
  }
  if (!("id" in request)) {
    if (request.method === "notifications/initialized") {
      process.stdout.write(`${JSON.stringify({
        jsonrpc: "2.0",
        id: "scopepact-server-sampling",
        method: "sampling/createMessage",
        params: { messages: [], maxTokens: 1 },
      })}\n`);
    }
    return;
  }
  if (request.id === "scopepact-server-sampling" && "error" in request) {
    if (request.error.code !== -32043) {
      throw new Error("ScopePact did not reject the server-initiated sampling request");
    }
    return;
  }
  let result;
  if (request.method === "initialize") {
    result = {
      protocolVersion: "2025-06-18",
      capabilities: { tools: {} },
      serverInfo: { name: "scopepact-mock", version: "0.1.0" },
    };
  } else if (request.method === "tools/call") {
    result = {
      content: [{ type: "text", text: `mock executed ${request.params.name}` }],
      isError: false,
    };
  } else {
    result = {};
  }
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: request.id, result })}\n`);
});
