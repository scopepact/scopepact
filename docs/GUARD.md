# ScopePact Guard Profile

Status: experimental v0.1

`scopepact-guard` is a local enforcement proxy for MCP stdio servers. It
intercepts client-to-server `tools/call` requests, translates each call into a
typed ScopePact effect, evaluates an installed capability, and either forwards
the original bytes or returns a JSON-RPC policy error.

Every recognized tool call produces an Ed25519-signed decision receipt. Calls
that are not covered by policy fail closed and never reach the wrapped server.

## CLI

```text
scopepact-guard keygen --out KEY.json
scopepact-guard check --policy POLICY.json --key KEY.json < request.json
scopepact-guard verify [--expect-key-id HEX] < receipt.json
scopepact-guard mcp --policy POLICY.json --key KEY.json [--audit FILE] -- COMMAND [ARG...]
```

`check` exits with status `0` for an allowed call and `3` for a policy block.
Configuration and malformed-input errors use status `2`. `mcp` returns the
wrapped process status, except local configuration errors use status `2`.

## MCP Client Configuration

Build a release binary and use it as the configured MCP command. The actual
server and its arguments follow the `--` separator:

```json
{
  "mcpServers": {
    "guarded-files": {
      "command": "/absolute/path/to/scopepact-guard",
      "args": [
        "mcp",
        "--policy", "/absolute/path/to/policy.json",
        "--key", "/absolute/path/to/key.json",
        "--audit", "/absolute/path/to/audit.jsonl",
        "--",
        "/absolute/path/to/filesystem-server"
      ]
    }
  }
}
```

The guard passes non-tool JSON-RPC objects through unchanged. JSON-RPC batches
are rejected because forwarding a batch without inspecting every member would
allow a tool call to bypass enforcement.

## Policy

See [`examples/mcp-guard-policy.json`](../examples/mcp-guard-policy.json) for a
complete runnable policy.

Top-level fields:

| Field | Meaning |
| --- | --- |
| `policy_version` | Must be `1`. |
| `policy_epoch` | Non-zero revision bound into grants and receipts. |
| `principal` | Accountable local authority that issued the policy. |
| `agent` | Agent identity receiving the bounded capability. |
| `valid_for_ms` | Grant lifetime from process start, capped at 31 days. |
| `rules` | One or more tool capabilities, capped at 1,024. |

Each rule contains a unique `id`, exact MCP `tool` name, `max_calls`, a resource
selector, and optional payment limits.

Literal resource:

```json
{
  "type": "literal",
  "value": "urn:payments:vendor"
}
```

Argument resource:

```json
{
  "type": "argument",
  "pointer": "/path",
  "prefix": "/workspace/project/"
}
```

`pointer` is an RFC 6901 JSON Pointer inside `params.arguments`. Absolute path
prefixes must end in `/`; absolute resource values containing a parent (`..`)
component are rejected before capability evaluation.

Optional payment policy:

```json
{
  "currency": "USD-CENTS",
  "amount_pointer": "/amount_cents",
  "payee_pointer": "/payee",
  "max_spend_atomic": 5000,
  "allowed_payees": ["vendor-a"]
}
```

The kernel enforces currency, positive integer amount, allowed payee,
cumulative spend, and call count. A payment rule cannot be evaluated without
both typed payment arguments.

## Effect Mapping

For each `tools/call`, the adapter creates:

| ScopePact field | MCP source |
| --- | --- |
| action | `mcp.tool.call:` followed by `params.name` |
| resource | literal policy value or selected argument string |
| actor | SHA-256-derived identifier for the policy's `agent` |
| effect ID | domain-separated digest of the JSON-RPC request ID |
| effect digest | domain-separated digest of tool name and key-sorted arguments |
| payment | typed amount, currency, and derived payee ID when configured |

An identical request ID and effect is treated as a duplicate and is not
forwarded a second time. Reusing the ID with different content is an effect
conflict and is also blocked.

## Block Response

Policy blocks use JSON-RPC error code `-32042`:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "error": {
    "code": -32042,
    "message": "ScopePact blocked tool call",
    "data": { "receipt": {} }
  }
}
```

Malformed tool calls use `-32602`; invalid JSON uses `-32700`.

## Signed Receipt Transcript

Receipts are JSON carriers, but the signature does not depend on JSON object
ordering. The Ed25519 transcript is the following exact concatenation:

```text
"SCOPEPACT-GUARD-RECEIPT-V0\0"
receipt_version                       u16 big-endian
decision                              u8: allowed=1, blocked=2
reason                                length-delimited UTF-8
policy_epoch                          u64 big-endian
principal                             length-delimited UTF-8
agent                                 length-delimited UTF-8
request_id                            length-delimited compact JSON
tool                                  length-delimited UTF-8
resource                              optional UTF-8
rule_id                               optional UTF-8
effect_id                             16 raw bytes
effect_digest                         32 raw bytes
issued_at_ms                          i64 big-endian
duplicate                             u8: false=0, true=1
```

A length-delimited field is a `u32` big-endian byte length followed by bytes.
An optional field starts with `0` when absent or `1` followed by a
length-delimited field when present.

The receipt contains the raw public key and its SHA-256 key ID. Self-contained
verification proves integrity, not trust. Production consumers must pin the
expected key ID through configuration or another authenticated channel.

## Security Boundary And Limitations

The v0.1 guard is an evaluation aid, not a production sandbox:

- counters, effect reservations, and replay state are in memory and reset when
  the guard restarts;
- key files contain a raw Ed25519 seed protected only by local file permissions;
- audit append is not yet transactional, tamper-evident, or durably synced;
- the adapter covers client-to-server `tools/call` over newline-framed stdio;
- it does not sandbox the wrapped process or inspect effects the process creates
  outside an admitted tool call;
- lexical path checks cannot detect symlink escapes inside the downstream
  server; filesystem servers must resolve and enforce canonical roots too;
- request IDs must be unique within one guard process;
- numeric request IDs must be JavaScript-safe integers; string IDs are
  preserved exactly;
- policy activation time is local process start, not an externally signed time.

Production work requires durable atomic state, protected key custody,
authenticated policy distribution, complete MCP bidirectional request coverage,
and adapter-specific resource canonicalization.
