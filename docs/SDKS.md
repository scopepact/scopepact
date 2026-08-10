# SDK And Runtime Support

ScopePact uses capability levels so a transcript implementation is not confused
with a complete enforcement runtime.

| Runtime | Location | Current level | Verified surface |
| --- | --- | --- | --- |
| Rust | `crates/core`, `crates/guard`, `crates/protocol` | Reference | Authority kernel, Guard, receipts, wire types |
| Python | `conformance/python` | Conformance | Envelope signing, verification, rejection cases |
| JavaScript | `conformance/javascript` | Conformance | Envelope verification, receipts, browser evidence |
| Flutter | `sdks/flutter` | Alpha SDK | Dart transcript and Ed25519 signing/verification |
| Swift | `sdks/swift` | Alpha SDK | CryptoKit transcript and Ed25519 signing/verification |
| Go | `sdks/go` | Alpha SDK | Standard-library transcript and Ed25519 signing/verification |
| C++ | `sdks/cpp` | Alpha SDK | C++20 transcript and OpenSSL Ed25519 signing/verification |
| C# / .NET | `sdks/dotnet` | Alpha SDK | .NET 8 transcript and NSec Ed25519 signing/verification |

All eight runtimes use `conformance/vectors/envelope-v0.json`. A runtime is not
listed as conforming merely because it can parse JSON or Protobuf: it must emit
the exact domain-separated transcript, verify the shared Ed25519 signature,
sign and verify locally, and reject an authenticated-field mutation. Runtimes
using deterministic RFC 8032 signing also reproduce the vector signature.

Apple CryptoKit intentionally randomizes Ed25519 signatures. Swift therefore
verifies the deterministic shared signature and produces a different valid
signature for the same transcript; signature byte equality is not a protocol
requirement.

Go uses the standard library Ed25519 implementation. C++ delegates PureEdDSA
to OpenSSL's one-shot EVP interface. C# uses the established NSec package,
which is backed by libsodium. None of the portable packages implements a custom
cryptographic primitive.

The Flutter, Swift, Go, C++, and C# packages intentionally stop at the portable
envelope boundary. They do not yet implement capability attenuation, replay
persistence, payment accounting, or Guard policy evaluation. Those controls
remain in the Rust reference implementation until their portable contracts
stabilize.

## Verification

Run the Rust, Python, and JavaScript suite:

```sh
./verify-all.sh
```

Run all portable SDK packages:

```sh
./scripts/verify-sdks.sh
```

SDK files are Apache-2.0 to maximize adoption. Rust Core and Community Guard
remain MPL-2.0 under the repository licensing map.
