# ScopePact Guard Sandbox Boundary

Status: no operating-system sandbox profile is implemented.

ScopePact Guard authorizes newline-framed MCP messages before forwarding an
admitted `tools/call`. It does not confine the wrapped server process. These are
separate security boundaries and must not be represented as equivalent.

## What Guard Enforces

- MCP 2025-06-18 lifecycle and JSON-RPC structure;
- bounded message, JSON, pending-request, progress, and decision dimensions;
- exact tool, opaque resource string/prefix, call count, payment, policy epoch,
  effect ID, and effect digest authority;
- durable commit before an allowed message is forwarded;
- signed decision receipts and server-request rejection policy.

## What Guard Does Not Enforce

The wrapped process inherits the operating-system identity, environment,
working directory, open-descriptor policy, filesystem access, network access,
process-spawn rights, resource limits, and platform sandbox of the Guard
launcher. Guard does not inspect or prevent:

- filesystem or network effects created at process startup or background time;
- effects created by a server without a corresponding MCP request;
- symlink or mount changes between string authorization and server access;
- subprocesses, local IPC, credential reads, or direct service access;
- host compromise, debugger access, memory inspection, or key theft.

An absolute `argument` resource policy performs only lexical validation and an
opaque prefix check. It rejects parent traversal but does not canonicalize
symlinks. It must not be used to claim filesystem containment. A filesystem
deployment needs an adapter/action broker that resolves and opens the resource
inside the same confinement boundary as the effect, plus OS controls that
restrict alternate paths.

## Boundary Test

`scripts/run-guard-proxy.sh` gives the mock wrapped server a protected temporary
marker path. The server creates that marker immediately at startup, outside any
admitted `tools/call`, and the test requires the marker to exist. The same run
then proves Guard still blocks the out-of-policy MCP call.

This is an intentional negative boundary test: it prevents future documentation
or UI from implying that protocol mediation sandboxed the child process.

## Deployment Requirement

Until a supported profile is published, operators must provide and test their
own least-privilege process identity, filesystem namespace, network egress
policy, credential isolation, process/resource limits, and syscall/application
confinement. The controls and bypass tests must be platform-specific. Merely
launching a server through `scopepact-guard mcp` does not satisfy this
requirement.
