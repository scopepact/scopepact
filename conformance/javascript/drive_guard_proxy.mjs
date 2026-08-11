import { spawn } from "node:child_process";
import readline from "node:readline";

const [command, ...args] = process.argv.slice(2);
if (!command) throw new Error("usage: drive_guard_proxy.mjs COMMAND [ARG ...]");

const child = spawn(command, args, { stdio: ["pipe", "pipe", "inherit"] });
const output = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
const completed = new Set();
let initialized = false;

const send = (message) => child.stdin.write(`${JSON.stringify(message)}\n`);

output.on("line", (line) => {
  process.stdout.write(`${line}\n`);
  const message = JSON.parse(line);
  if (message.id === 0 && !initialized) {
    initialized = true;
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    send({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "write_file",
        arguments: { path: "/workspace/project/README.md", content: "allowed" },
      },
    });
    send({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "write_file",
        arguments: { path: "/etc/hosts", content: "blocked" },
      },
    });
    return;
  }
  if (message.id === 1 || message.id === 2) completed.add(message.id);
  if (completed.size === 2) child.stdin.end();
});

send({
  jsonrpc: "2.0",
  id: 0,
  method: "initialize",
  params: {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "scopepact-demo", version: "0.1.0" },
  },
});

const exitCode = await new Promise((resolve, reject) => {
  child.once("error", reject);
  child.once("exit", (code, signal) => {
    if (signal) reject(new Error(`Guard terminated by ${signal}`));
    else resolve(code ?? 1);
  });
});
if (exitCode !== 0) process.exitCode = exitCode;
