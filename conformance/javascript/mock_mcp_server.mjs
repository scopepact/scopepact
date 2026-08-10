import readline from "node:readline";

const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

input.on("line", (line) => {
  const request = JSON.parse(line);
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
