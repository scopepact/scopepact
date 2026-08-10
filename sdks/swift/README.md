# ScopePact For Swift

This pre-release Swift Package implements the portable ScopePact v0 envelope
signing transcript and Ed25519 signing/verification contract with Apple
CryptoKit. It supports iOS 16+ and macOS 13+.

It is not yet a full policy kernel or Guard implementation. Use the Rust
`scopepact-core` and `scopepact-guard` crates for enforcement.

Run the shared interoperability vector:

```sh
swift test --package-path sdks/swift
```

The package is covered by Apache-2.0 under the repository's licensing map.
