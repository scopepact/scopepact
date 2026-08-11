# AI Agents Need Bounded Authority, Not More Trust

> Introducing ScopePact, an open-source security layer for least-privilege AI agent actions, MCP tool calls, and verifiable decision receipts.

Imagine giving an AI agent permission to update one file in a project.

The agent has a simple mandate: edit `/workspace/project/README.md`. But the tool it can call runs with access to the whole machine. The boundary exists in the instruction, not in the execution path. If the model misunderstands the task, follows a malicious prompt, or calls the tool with the wrong argument, a sentence in a prompt is all that stands between the intended edit and a write to `/etc/hosts`.

This is the authority gap in agentic systems.

We are getting better at connecting agents to tools, services, other agents, and payment systems. We are not yet equally good at expressing exactly what each agent is allowed to do, enforcing that authority at the moment of consequence, and proving why the action was allowed afterward.

[ScopePact](https://scopepact.org) is our attempt to close that gap with an open, portable authorization and proof layer for consequential agent actions.

## The problem is not only what an agent can access

Traditional application security starts with users, roles, sessions, and API credentials. Those controls still matter, but agents introduce a different operational shape.

An agent can interpret an ambiguous goal, choose among tools, construct arguments, retry after a failure, delegate work, and cross system boundaries in seconds. A credential may tell a service which application is calling, but it often does not answer the narrower questions that matter for an individual effect:

- Which agent is acting, and for whom?
- Which exact action was delegated?
- Which resources or counterparties are in scope?
- How many calls or how much money may be spent?
- When does the authority expire?
- Can it be delegated again?
- Has this effect already been executed?
- Which policy produced the decision?

When these answers live only in a prompt, framework state, or vendor-specific control plane, they are difficult to enforce consistently and even harder to carry across organizational boundaries.

A prompt is useful context. It is not a security boundary.

## What is ScopePact?

ScopePact is an open-source security kernel that keeps authority outside the language model. It turns an agent's proposed action into a deterministic authorization decision based on cryptographic identity, scoped capabilities, resource constraints, time limits, call and spend budgets, replay protection, and active policy.

The core idea is straightforward:

> Agents propose. ScopePact decides. Tools execute only inside granted scope.

ScopePact checks authority at the **effect boundary**, the point where an agent's intent is about to become an external consequence. That consequence might be a tool call, a task delegated to another agent, a file modification, an API request, or a payment.

If the proposed effect is in scope, the action broker may execute it. If it is outside the mandate, expired, revoked, duplicated, or inconsistent with policy, it fails closed. Either way, the decision can produce a signed receipt that another runtime can verify independently.

```text
MCP tools -----+
A2A tasks -----+-- adapter --> ScopePact kernel --> ALLOW / BLOCK + signed receipt
Payment intent +                 identity | scope | limits | replay | policy
```

ScopePact does not ask the model to judge its own permissions. The enforcement code does that.

## Five design choices behind ScopePact

### 1. Authority stays outside the model

Models can help interpret intent and plan work, but the final security decision should not depend on a model remembering a rule or resisting a cleverly worded instruction.

ScopePact evaluates explicit data: the actor, audience, action, resource, capability grant, expiry, budgets, effect identifier, and current policy epoch. The decision is reproducible and testable without inspecting private chain-of-thought or trusting another model call.

This does not eliminate prompt injection or model error. It limits what those failures can turn into.

### 2. Capabilities describe narrow mandates

A broad application credential answers, "Can this application reach the service?" A ScopePact capability is intended to answer a narrower question: "May this actor perform this action on this resource, for this audience, within these limits, right now?"

A grant can constrain actions, resource prefixes, lifetime, call count, payment currency, cumulative spend, allowed payees, and delegation depth. Delegated authority can stay the same or become narrower; it cannot silently expand.

The aim is least privilege that travels with the work instead of disappearing when an agent crosses a runtime or organizational boundary.

### 3. Enforcement happens before consequence

Audit logs are valuable, but a perfect record of an unauthorized action is still a record of failure.

ScopePact sits before the tool, service, wallet, or remote peer. It evaluates the proposed effect before forwarding it. This placement matters: policy becomes a gate in the execution path rather than an instruction the agent is expected to remember or a log reviewed after damage is done.

### 4. Retries and conflicts are security events

Agent workflows retry. Networks duplicate messages. Clients crash after an action succeeds but before receiving the response.

For a consequential effect, "at least once" can mean twice.

ScopePact binds each proposed effect to an identifier and digest. An identical retry is recognized as a duplicate and is not authorized for execution a second time. Reusing the same identifier for a different effect is a conflict and fails closed. The current Guard commits effect reservations, call and spend budgets, policy state, and receipt-chain position to a versioned hash-chained journal before forwarding an allowed call, then restores those decisions after restart. State migration, complete crash-point coverage, and an external rollback anchor remain release blockers.

### 5. Decisions become portable evidence

An allow or block response is useful to the caller. A signed decision receipt is useful to everyone who must understand the action later.

A ScopePact Guard receipt binds the effect, policy, rule, decision, reason, timestamp, and signing identity into a domain-separated signature transcript. It can be checked outside the runtime that made the decision.

That creates a path from "the agent did this" to stronger evidence: which mandate covered the effect, which policy evaluated it, and whether the receipt has been altered.

Receipts are not a claim that the whole system is trustworthy. They make one important decision independently inspectable.

## How does ScopePact secure MCP tool calls?

The first concrete product is [ScopePact Guard](https://github.com/scopepact/scopepact/blob/main/docs/GUARD.md), a local policy enforcement proxy for Model Context Protocol (MCP) servers using standard input and output.

Guard sits between an MCP client and server. It forwards initialization and other protocol traffic, intercepts `tools/call`, maps the proposed call into ScopePact's authority model, and forwards only an effect covered by the installed policy.

In the repository demo, a rule permits a tool to write beneath `/workspace/project/`. A request for `/workspace/project/README.md` is durably allowed. A request using the same tool to write `/etc/hosts` is blocked before it reaches the MCP server. Replaying the first effect after restart is recognized as a duplicate, and hostile or oversized child-process output stops the proxy. Decisions are signed, committed to a receipt chain, written to redaction-safe audit and event streams, and verified independently in JavaScript.

The policy can bind an exact tool name, literal resources or argument prefixes, call budgets, cumulative spend, currencies, and allowed payees. Guard accepts signed, audience-bound policy bundles from locally pinned issuers, uses encrypted local receipt keys, supports cross-signed key rotation, and enforces the declared MCP 2025-06-18 message boundary with bounded inputs. It remains deliberately local and inspectable: no account, hosted control plane, or network token is required to run it.

## Does ScopePact replace MCP, A2A, or existing identity systems?

No.

MCP describes how AI applications connect to tools and contextual resources. Agent-to-Agent protocols describe how agents discover and collaborate with one another. Identity systems establish who a user, workload, or organization is. Payment protocols move value.

Those are different jobs from deciding whether this actor may cause this exact effect under this mandate.

ScopePact is designed as an adapter-friendly layer beneath those protocols. Existing identity evidence can inform local policy, but identity alone does not create authority. An authenticated agent still needs a scoped grant. A valid message still needs replay checks. A connected tool still needs an effect-level decision.

The long-term goal is not one universal agent protocol. It is one common enforcement contract that different protocols can call when intent becomes consequence.

## Why make the protocol open?

Authority infrastructure becomes less useful when its guarantees stop at a vendor boundary.

If two organizations cannot inspect the decision rules, reproduce the signature transcript, or implement an independent verifier, they are still relying on private trust. That is why ScopePact publishes its protocol schema, security invariants, [threat model](https://github.com/scopepact/scopepact/blob/main/docs/THREAT_MODEL.md), conformance scenarios, negative test vectors, governance process, and implementation source.

The protocol materials are Apache-2.0 licensed. The reference security kernel and Community Guard use MPL-2.0, allowing them to be combined with larger systems while keeping distributed changes to covered implementation files available.

The project does not sell protocol access, governance votes, roadmap priority, or favorable conformance outcomes. Commercial use is welcome. The shared trust layer remains public.

## What exists today?

ScopePact is a pre-release research implementation, not a finished security standard.

The repository currently includes:

- a Rust authority kernel with signed envelopes, authenticated handshake, replay defense, capability attenuation, payment limits, revocation, and effect authorization;
- ScopePact Guard for durable local MCP `tools/call` policy enforcement, authenticated policy bundles, encrypted and rotatable receipt keys, duplicate suppression, and signed decision receipts;
- a versioned Protobuf schema;
- cross-language transcript implementations, negative conformance tests, schema validation, shared vectors, property tests, and four fuzz targets;
- runtime implementations and packages across Rust, Python, JavaScript, Flutter, Swift, Go, C++, and C#, each at an explicitly documented maturity level;
- public protocol, threat-model, resource-limit, operations, migration, sandbox, support, licensing, and governance documentation;
- repository verification, recovery-exercise, benchmark, and CI workflows whose release evidence is still being completed.

Important work remains. The wire format and public APIs may change. State migration, adapter-level filesystem canonicalization, complete fault and load testing, platform CI and reproducible signed release evidence, external review, a production-like pilot, A2A and payment bindings, and independent full-kernel implementations are still on the [public roadmap](https://github.com/scopepact/scopepact/blob/main/ROADMAP.md).

We would rather state those boundaries plainly than market a research implementation as a solved security problem.

## What would success look like?

Success is not every agent running the same framework. It is independent systems sharing a precise answer to a consequential question:

> Is this action within the authority that was actually granted?

We want an agent's reach to grow without its ambient authority growing with it. We want narrow mandates to survive delegation. We want duplicate effects to be safe. We want a tool call or payment to carry verifiable evidence of why it was allowed. And we want those properties to be challenged through public implementations and adversarial tests, not accepted because one vendor says they work.

ScopePact is early enough that the most valuable contribution may be disagreement. Try the Guard. Read the threat model. Break a transcript assumption. Bring an MCP workflow that the current policy cannot express. Implement a verifier in another runtime. Show us where the abstraction fails.

The agentic world needs more than increasingly capable models. It needs a common language for bounded authority.

That is the idea behind ScopePact.

---

Explore ScopePact at [scopepact.org](https://scopepact.org), browse the [source and documentation on GitHub](https://github.com/scopepact/scopepact), or join the project in [GitHub Discussions](https://github.com/scopepact/scopepact/discussions).

## Medium publishing notes

**HTML preview/import source:** `public/articles/ai-agents-need-bounded-authority.html`

**Subtitle:** Introducing ScopePact, an open-source security layer for least-privilege AI agent actions, MCP tool calls, and verifiable decision receipts.

**Suggested topics:** AI Agents, Cybersecurity, Open Source, Model Context Protocol, Artificial Intelligence

**Suggested preview description:** ScopePact keeps authority outside the language model, enforces least privilege before an AI agent action becomes a real-world effect, and produces signed receipts others can verify.

**Suggested header image:** Use `public/assets/scopepact-workbench-2026-08-11.png`. In Medium, set the image alt text to: "ScopePact conformance workbench showing protocol scenarios, verification checks, and signed envelope evidence."
