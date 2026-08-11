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
scopepact-guard keygen --out KEY.json --passphrase-file PASSPHRASE
scopepact-guard check --policy POLICY.json --key KEY.json --key-passphrase-file PASSPHRASE < request.json
scopepact-guard verify [--expect-key-id HEX] [--trust-bundle TRUST.json] < receipt.json
scopepact-guard policy trust-init --issuer ISSUER --audience AUDIENCE --key ISSUER_KEY.json --key-passphrase-file PASSPHRASE --out POLICY_TRUST.json
scopepact-guard policy sign --policy POLICY.json --issuer ISSUER --audience AUDIENCE --key ISSUER_KEY.json --key-passphrase-file PASSPHRASE [--revoke-rule RULE_ID ...] --out POLICY_BUNDLE.json
scopepact-guard policy verify --policy-bundle POLICY_BUNDLE.json --policy-trust POLICY_TRUST.json --policy-audience AUDIENCE
scopepact-guard mcp --policy-bundle POLICY_BUNDLE.json --policy-trust POLICY_TRUST.json --policy-audience AUDIENCE --key KEY.json --key-passphrase-file PASSPHRASE --state STATE.jsonl [--audit FILE] -- COMMAND [ARG...]
```

`check` exits with status `0` for an allowed call and `3` for a policy block.
Configuration and malformed-input errors use status `2`. `mcp` returns the
wrapped process status, except local configuration errors use status `2`.
`check` accepts a raw policy as a local diagnostic. Proxy and state commands
require a signed bundle, pinned issuer trust, and an exact audience.

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
        "--policy-bundle", "/absolute/path/to/policy-bundle.json",
        "--policy-trust", "/absolute/path/to/policy-trust.json",
        "--policy-audience", "guard:production",
        "--key", "/absolute/path/to/key.json",
        "--key-passphrase-file", "/run/secrets/scopepact-key-passphrase",
        "--state", "/absolute/path/to/state.jsonl",
        "--audit", "/absolute/path/to/audit.jsonl",
        "--",
        "/absolute/path/to/filesystem-server"
      ]
    }
  }
}
```

`keygen` writes an authenticated encrypted key file using Argon2id and
XChaCha20-Poly1305. The passphrase is read non-interactively from a separate
regular file and is never accepted on the command line. Both files must deny
group and other access on Unix; symlinks and special files are rejected. The
passphrase must contain at least 16 bytes. A deployment should provision the
passphrase file from its secret manager into a protected runtime path rather
than storing it beside source code.

The Guard validates both stdio directions against the MCP `2025-06-18` base
protocol. JSON-RPC batches are forbidden by that MCP revision and are rejected.

`--state` is mandatory for proxy mode. It names an append-only, hash-chained
decision journal. The guard takes an exclusive lock, commits and synchronizes
every allowed effect before forwarding it, and replays committed effects and
budgets after restart. A sibling `.head` log detects a journal that has been
truncated independently. Reusing the state with different policy contents,
another policy epoch, or a signer that is not currently active fails closed.
Recovery accepts at most 50,000 journal/head records, a 64 MiB journal, a
16 MiB head log, and 8 MiB per journal record. Exceeding a limit fails before
the complete file is parsed or replayed. These are hard compatibility limits,
not recommended operating targets.

Validate a stopped Guard's journal and replay every committed authority change:

```sh
scopepact-guard state inspect \
  --policy-bundle POLICY_BUNDLE.json --policy-trust POLICY_TRUST.json \
  --policy-audience AUDIENCE \
  --key KEY.json --key-passphrase-file PASSPHRASE \
  --state STATE.jsonl
```

Reconstruct a plain JSONL audit file from the authoritative journal:

```sh
scopepact-guard state export-audit \
  --policy-bundle POLICY_BUNDLE.json --policy-trust POLICY_TRUST.json \
  --policy-audience AUDIENCE \
  --key KEY.json --key-passphrase-file PASSPHRASE \
  --state STATE.jsonl \
  --out AUDIT.jsonl
```

If a crash leaves bytes after the last complete newline, inspection fails
closed. After backing up both state files, remove only those incomplete bytes
with the explicit recovery command:

```sh
scopepact-guard state recover-tail \
  --policy-bundle POLICY_BUNDLE.json --policy-trust POLICY_TRUST.json \
  --policy-audience AUDIENCE \
  --key KEY.json --key-passphrase-file PASSPHRASE \
  --state STATE.jsonl
```

Recovery validates every complete journal and head record before truncating
anything. It never removes a complete record or resets a committed budget.

## Receipt Signer Rotation

Generate a replacement protected key, then commit a cross-signed rotation while
the old key is still available:

```sh
scopepact-guard state rotate-signer \
  --policy-bundle POLICY_BUNDLE.json --policy-trust POLICY_TRUST.json \
  --policy-audience AUDIENCE --state STATE.jsonl \
  --key OLD.json --key-passphrase-file OLD_PASS \
  --new-key NEW.json --new-key-passphrase-file NEW_PASS
```

The old and new providers sign the same transcript binding the policy digest,
both key identities, activation time, and journal sequence. After commit, the
old key cannot reopen the journal. It remains trusted only for receipts issued
before rotation, so historical evidence continues to verify.

Export the journal-derived trust history and use it for offline verification:

```sh
scopepact-guard state export-trust \
  --policy-bundle POLICY_BUNDLE.json --policy-trust POLICY_TRUST.json \
  --policy-audience AUDIENCE --state STATE.jsonl \
  --key NEW.json --key-passphrase-file NEW_PASS \
  --out SIGNER-TRUST.json

scopepact-guard verify --trust-bundle SIGNER-TRUST.json < receipt.json
```

The exported receipt trust file is a pinned local input. Protect its provenance
and distribute it through an authenticated configuration channel.

## Signed Policy Lifecycle

Use a policy issuer key that is separate from the receipt key. First pin the
issuer identity, public key, and intended deployment audience:

```sh
scopepact-guard policy trust-init \
  --issuer example-operator --audience guard:production \
  --key POLICY_KEY.json --key-passphrase-file POLICY_PASS \
  --out POLICY_TRUST.json
```

Sign the validated raw policy, then verify it offline before installation:

```sh
scopepact-guard policy sign \
  --policy POLICY.json \
  --issuer example-operator --audience guard:production \
  --key POLICY_KEY.json --key-passphrase-file POLICY_PASS \
  --out POLICY_BUNDLE.json

scopepact-guard policy verify \
  --policy-bundle POLICY_BUNDLE.json \
  --policy-trust POLICY_TRUST.json \
  --policy-audience guard:production
```

The signature covers the issuer, audience, policy epoch, exact validity window,
all rules, and explicit rule revocations. Bundle and trust objects reject
unknown JSON fields. Verification rejects an unknown or revoked issuer, wrong
audience, invalid signature, malformed revocation, or inactive time window.
Use repeated `--revoke-rule RULE_ID` options when signing to disable installed
rules without deleting the signed policy record.

The trust file is a local root of trust, not a self-authenticating artifact.
Provision it through an authenticated configuration channel. A bundle expires
at its signed deadline and is never extended implicitly. Activate a replacement
before that deadline while the Guard is stopped:

```sh
scopepact-guard state activate-policy \
  --policy-bundle CURRENT.json \
  --policy-trust POLICY_TRUST.json \
  --policy-audience guard:production \
  --new-policy-bundle NEXT.json \
  --new-policy-trust POLICY_TRUST.json \
  --new-policy-audience guard:production \
  --key KEY.json --key-passphrase-file PASSPHRASE \
  --state STATE.jsonl
```

The next epoch must be greater than the active epoch and cannot change the
principal or agent identity. The active receipt signer authenticates the
transition, which is synchronized into the state journal before the command
returns. Reopening with the old bundle then fails. Commitments from prior
epochs remain auditable but are not replayed into the new epoch's budgets;
historical receipts remain verifiable through the exported trust history.

State format v3 is not compatible with the earlier experimental v2 journal.
The Guard fails closed on v2 input; an explicit v2-to-v3 migration command is
still roadmap work.

After a bundle successfully opens the journal, proxy mode atomically caches it
as `STATE.jsonl.policy-cache.json`. If the configured bundle later becomes
unreadable or invalid, proxy startup may use that last-known-good copy only
after re-verifying it against the currently configured issuer trust, exact
audience, signature, and current time. The cache cannot extend expiration or
override issuer revocation. A successful `state activate-policy` replaces the
cache with the newly committed bundle. Cache files must be private regular
files; on Unix, Guard opens them with `O_NOFOLLOW` and rejects group/other
permissions or symlink substitution.

## Raw Policy Format

See [`examples/mcp-guard-policy.json`](../examples/mcp-guard-policy.json) for a
complete runnable policy and
[`schemas/guard-policy-v1.schema.json`](../schemas/guard-policy-v1.schema.json)
for the strict Draft 2020-12 schema. Schema validation covers the portable JSON
contract; Guard validation additionally enforces UTF-8 byte limits, unique rule
IDs, RFC 6901 pointer syntax, and path-prefix semantics.

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

## MCP 2025-06-18 Message Boundary

The stdio proxy classifies every line as one JSON-RPC request, notification,
success response, or error response. It requires a valid initialize request and
response followed by `notifications/initialized` before application traffic.

| Direction and class | Behavior |
| --- | --- |
| client `initialize` | Inspect version and required capability/client metadata, then pass. |
| client `tools/call` request | Inspect, decide, durably commit, then pass or return `-32042`. |
| other client request | Validate lifecycle, ID, params, progress token, and pending limit, then pass. |
| client notification | Validate and pass; cancellation and progress must reference active work. |
| client response | Pass only when its exact ID matches a pending server `ping`. |
| server response | Pass only when its exact ID matches a pending client request. |
| server notification | Validate and pass; progress and cancellation must correlate. |
| server `ping` request | Track and pass to the client. |
| any other server request | Do not expose it to the client; answer the server with `-32043`. |

Request IDs preserve both value and JSON type: string `"1"` does not correlate
with number `1`. Numbers must be JavaScript-safe integers. At most 1,024
requests may be pending in either direction, and active progress tokens must be
unique. Progress values must increase. General IDs may be reused only after the
matching response; `tools/call` IDs additionally derive durable effect IDs, so
reusing one after completion or process restart is suppressed as a duplicate or
conflict.

Each input or child-output line is capped at 4 MiB. Parsed JSON is capped at 64
levels, 65,536 nodes, 4,096 entries per container, and 1 MiB per string. A Guard
tool decision taking more than five seconds is not committed or forwarded.
Invalid client traffic receives a local JSON-RPC error. Invalid, oversized, or
uncorrelated child output fails the proxy and terminates the wrapped server.
Stdio has no reconnect operation; a new Guard process creates a new connection
tracker while its durable tool-effect and budget history remains in force.
The complete configuration, protocol, state, and cryptographic ceilings are in
[the Guard resource-limit contract](LIMITS.md).

Guard stderr contains one-line `scopepact-guard-event-v1` JSON operational
events for proxy start, committed decisions, worker failure, and proxy stop.
Decision events include only timestamp, policy epoch, coarse outcome, effect
ID, and signer key ID. They omit request IDs, tools, resource paths, arguments,
free-form reasons, prompts, credentials, signatures, and public or private key
material. Complete signed receipts remain in the authoritative journal and in
the optional audit file. A stderr or audit write failure stops the proxy before
an allowed call is forwarded.

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

The v0.1 guard is an evaluation aid, not a production sandbox.

The separate [sandbox boundary](SANDBOX.md) documents and negatively tests the
fact that a wrapped process can create unmediated host effects.

- durable state currently uses a single-writer local journal and requires a
  filesystem whose append and synchronization guarantees are trustworthy;
- the protected local signer still decrypts key material into Guard process
  memory; operating-system keystore, PKCS#11, and KMS/HSM providers are not yet
  implemented;
- the optional plain JSON audit is durably synced but derived from the
  authoritative hash-chained state journal; an audit write failure stops the
  proxy before an allowed call is forwarded;
- the adapter covers MCP `2025-06-18` over newline-framed stdio and deliberately
  rejects server-initiated sampling, elicitation, roots, and extension requests;
- it does not sandbox the wrapped process or inspect effects the process creates
  outside an admitted tool call;
- lexical path checks cannot detect symlink escapes inside the downstream
  server; filesystem servers must resolve and enforce canonical roots too;
- numeric request IDs must be JavaScript-safe integers; string IDs and their
  type are preserved exactly.

Production work still requires rollback anchoring outside the state directory,
adapter-specific resource canonicalization, an operating-system sandbox
profile, state migration tooling, and external security review.
