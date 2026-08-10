# Project Name Research

Research date: 2026-08-10

## Recommendation

Keep **ScopePact** for the pre-release project. It names the protocol's central
idea directly: an agent agreement is enforceable only inside explicit identity,
authority, resource, counterparty, time, and policy scope.

It is more distinctive and accurate than a generic communication-protocol
name. It also supports clear vocabulary: ScopePact envelope, ScopePact grant,
ScopePact kernel, and ScopePact conformance suite.

## Shortlist

| Name | Position | Reason |
| --- | --- | --- |
| ScopePact | recommended | Expresses both bounded authority and verifiable agreement. |
| PactWire | reserve | Sounds like a wire protocol, but says less about the security boundary and has an old social handle collision. |
| VouchWire | reserve | Strong for identity and attestations, but under-describes authorization and effects. |
| IntentPact | reserve | Approachable, but “intent” can imply natural language is authoritative, which the protocol explicitly rejects. |

## Names rejected

- **Open Agent Communication Protocol / OACP** is already used by an active
  agent discovery and task network with published Python and npm SDKs:
  <https://www.oacp-agora.com/>.
- **AgentPact** is crowded across multiple agent marketplaces and an open coding
  agent governance standard: <https://www.agentpact.io/>,
  <https://agentpact.xyz/>, and <https://kyr.is/agentpact>.
- **MandateWire** is an established Financial Times institutional intelligence
  product: <https://www.mandatewire.com/>.
- **ProofRail** is an active AI governance product covering agent chains,
  approvals, spending, receipts, and MCP integration, making it both a name and
  category collision: <https://www.proofrail.dev/>.
- **PactGate** is already used by Bladnir Tech for governed AI actions:
  <https://bladnirtech.com/platform>.
- **ScopeSeal** is already used by an active software product:
  <https://scopeseal.codezela.com/>.
- **PactProof** is already an active rights and signature product:
  <https://pactproofapp.com/>.
- **ScopeProof** is crowded across active security, construction, and signed
  change-order products, including an open-source Burp Suite extension:
  <https://scopeproof.io/> and <https://scopeproof.com/>.

Additional exact-name exploration found no obvious product collision for
**PermitMesh**, **GrantSeal**, or **EffectPact** on the research date. None is a
better project name: PermitMesh implies a distributed network, GrantSeal
implies document certification, and EffectPact is less immediate to say and
understand. They remain research notes, not launch recommendations.

## Registry observations

On the research date, exact package lookups for `scopepact`, `pactwire`,
`vouchwire`, and `intentpact` returned no package record on npm, PyPI, or
crates.io. The `.com` domains returned registered RDAP records for all four
names. The corresponding `.org` lookups returned no public RDAP record.

Package and domain status can change without notice. A missing registry record
does not reserve a name, and a missing RDAP response is not a purchase
guarantee.

## Remaining launch checks

Before publishing a stable standard or package namespace:

1. Complete a professional trademark search in the intended jurisdictions and
   relevant software, security, and communication classes.
2. Register the project domains and organization handles before announcing the
   name broadly.
3. Reserve package namespaces together so the Rust, Python, JavaScript, and
   Protobuf identities cannot be split across owners.
4. Repeat exact-name, code-hosting, package, and domain searches immediately
   before launch.

This document records product and ecosystem research, not legal clearance.
