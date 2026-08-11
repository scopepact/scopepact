# ScopePact Guard Resource Limits

Status: implemented limits for the experimental v0.1 local MCP Guard. These are
compatibility and rejection ceilings, not production capacity promises.

Guard fails closed when an input exceeds a limit. It does not truncate policy,
trust, receipt, MCP, or state data into a form that could authorize a different
effect. Client protocol errors receive a local JSON-RPC error when a request ID
can be handled safely. Invalid child output, durable-state failures, and local
I/O failures stop the proxy and terminate the wrapped server.

## Configuration And Cryptographic Inputs

| Dimension | Hard limit | Rejection behavior |
| --- | ---: | --- |
| Any policy, signed bundle, policy trust, receipt trust, protected key, passphrase file, or CLI JSON input | 4 MiB | Stop before parsing bytes beyond the limit. |
| Guard policy rules | 1,024 | Reject the complete policy. |
| Principal, agent, rule ID, tool, payee, issuer, and audience | 1-256 UTF-8 bytes; no control characters | Reject the complete object. |
| Literal resource or resource prefix | 1-1,024 UTF-8 bytes; no control characters | Reject the policy or tool call. |
| JSON Pointer | 1-256 UTF-8 bytes, valid RFC 6901 form | Reject the policy. |
| Policy validity or signed-bundle lifetime | 1 ms through 31 days | Reject the policy or bundle. |
| Payment currency | 1-32 printable ASCII bytes | Reject the policy. |
| Payment payee allowlist | 1-1,024 unique names | Reject the policy. |
| Pinned policy issuers | 1-64 entries with unique issuer/key identities | Reject the trust file. |
| Protected-key passphrase | 16-4,096 bytes after one line ending is removed | Reject before key derivation. |
| Future policy activation clock tolerance | 5 minutes | Reject as not currently active. |

The 4 MiB reader bounds allocation before JSON parsing. More restrictive
semantic limits still apply after parsing. JSON Schema string lengths count
Unicode code points, while the runtime uses UTF-8 bytes; runtime validation is
authoritative and can therefore reject a multibyte string accepted by schema
validation alone.

## MCP Connection

| Dimension | Hard limit | Rejection behavior |
| --- | ---: | --- |
| Newline-framed client input or child output | 4 MiB including the delimiter | Reject client input locally; stop on oversized child output. |
| JSON nesting | 64 levels | Reject the message. |
| JSON values | 65,536 nodes per message | Reject the message. |
| Array or object entries | 4,096 per container | Reject the message. |
| JSON string or object key | 1 MiB UTF-8 bytes | Reject the message. |
| Request ID or progress token string | 1-256 UTF-8 bytes; no control characters | Reject the message. |
| Numeric request ID or progress token | JavaScript-safe signed integer | Reject the message. |
| MCP method | 1-256 UTF-8 bytes; no control characters | Reject the message. |
| Cancellation reason | 1-1,024 UTF-8 bytes when present | Reject the message. |
| Progress message | 1-4,096 UTF-8 bytes when present | Reject the message. |
| Pending requests | 1,024 in each direction | Reject a new request until a pending request completes. |
| Guard decision computation | 5 seconds | Do not commit or forward; return `-32044`. |

Input and output are processed by one worker per direction. Exact ID and
progress-token correlation prevents pending-map amplification through reuse.
There is no batch mode. The proxy does not impose a lifetime message-count or
throughput quota; deployments that expose an MCP client to an untrusted peer
must apply process, CPU, and connection controls outside Guard.

## Durable State

| Dimension | Hard limit | Rejection behavior |
| --- | ---: | --- |
| Journal | 64 MiB | Refuse startup or recovery. |
| Head log | 16 MiB | Refuse startup or recovery. |
| Journal or head records | 50,000 | Refuse startup or recovery. |
| One journal record | 8 MiB | Refuse commit or recovery. |
| One head record | 1 KiB | Refuse recovery. |

Every accepted durable record is still hash, sequence, signature, policy,
signer, and commitment validated. Reaching a state ceiling stops authorization;
Guard never evicts replay or budget history automatically. Rotation into a new
state generation is not yet implemented and remains a release blocker.

## Outside The Guard Limit Boundary

Guard does not constrain the wrapped server's memory, CPU, subprocesses,
filesystem access, network access, or effects outside admitted MCP calls. It
also does not provide a wall-clock deadline for a blocked stdio reader/writer or
a storage quota for the optional audit file. Apply operating-system sandbox,
service-manager, filesystem-quota, and log-rotation controls as described in
[the sandbox boundary](SANDBOX.md) and [operations runbook](OPERATIONS.md).
