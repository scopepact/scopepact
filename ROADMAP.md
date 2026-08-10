# Roadmap

The roadmap describes intended engineering order, not release promises.

## Now: Adoptable Local Guard

- MCP stdio `tools/call` enforcement;
- resource, call-count, payee, currency, and cumulative spend policy;
- signed decision receipts and cross-language verification;
- conformance workbench and negative test catalog;
- shared Rust, Python, JavaScript, Flutter, Swift, Go, C++, and C# transcript vectors;
- open contribution, governance, and security processes.

## Next: Durable Enforcement

- transactional replay, effect, call, and spend state;
- protected key providers and key rotation;
- signed policy bundles, revocation, and epoch activation;
- complete MCP client/server request coverage;
- policy schema publication and generated SDK types;
- fuzzing, property tests, and reproducible release artifacts.

## Then: Protocol Bindings

- A2A task and artifact binding;
- remote MCP identity and authorization binding;
- typed payment mandate profile;
- secure transport profiles and exporter integration;
- receipts linked into tamper-evident audit chains;
- independent full-kernel implementations beyond the Rust reference;
- generated model bindings for Rust, Python, JavaScript, Flutter, Swift, Go,
  C++, and C#.

## Stable Release Gate

- frozen v1 transcript and wire compatibility rules;
- external cryptographic and authorization review;
- at least two independent conforming implementations;
- deployment threat models and operational runbooks;
- measured performance and denial-of-service limits;
- public vulnerability response and release-signing process.
