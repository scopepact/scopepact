# ScopePact For Flutter

This pre-release package implements the portable ScopePact v0 envelope signing
transcript and Ed25519 signing/verification contract. It uses
`package:cryptography`, which supports Flutter on Android, iOS, macOS, web,
Windows, and Linux.

It is not yet a full policy kernel or Guard implementation. Use the Rust
`scopepact-core` and `scopepact-guard` crates for enforcement.

Run the shared interoperability vector:

```sh
flutter test sdks/flutter
```

The package is covered by Apache-2.0 under the repository's licensing map.
