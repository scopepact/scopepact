# Cross-language conformance demo

This demo runs ScopePact wire interactions across two scripting runtimes:

1. Python Agent A signs a customer task offer with a one-call capability.
2. JavaScript Agent B validates the version, sender, audience, payload digest,
   lifetime, critical extensions, and Ed25519 signature.
3. JavaScript Agent B signs an acceptance over the same session and interaction.
4. Python Agent A verifies the acceptance.
5. The conformance runner exercises 15 accepted and rejected protocol cases.

The cases cover a successful exchange plus payload and signature integrity,
sender and audience binding, session isolation, replay, validity windows,
resource limits, version negotiation, policy epoch, critical extensions, and
payload schema binding. Each result includes the rule, expected behavior,
observed decision, and verifier checks so it can be reviewed without reading
the implementation first.

The exchanged JSON is an inspectable demo carrier, not the normative wire
encoding. The signing transcript exactly follows the Rust kernel. Production
operational frames use the Protobuf schema in
`crates/protocol/proto/scopepact/v0/core.proto`.

The keys are deterministic public demo fixtures and must never be used outside
this example.

## Run

```sh
python3 -m pip install -r conformance/python/requirements.txt
./scripts/run-cross-language.sh
```

Run the language-local unit tests with:

```sh
python3 -m unittest discover -s conformance/python -p 'test_*.py'
node --test conformance/javascript/agent_b.test.mjs
```

## Local inspector

```sh
python3 conformance/server.py --port 8787
```

Open `http://127.0.0.1:8787` to run one scenario or the complete suite, inspect
envelopes and payloads, and export a JSON report. A rejected malicious frame is
a passing conformance result when rejection is the expected decision.

The browser suite demonstrates the cross-language wire checks. The Rust tests
remain authoritative for authenticated handshake, delegation attenuation,
effect authorization, revocation, interaction state, and optional JWT
federation behavior. See [the conformance guide](../docs/CONFORMANCE.md).
