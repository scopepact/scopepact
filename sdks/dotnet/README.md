# ScopePact For C# And .NET

This pre-release .NET 8 library implements the portable ScopePact v0 envelope
transcript and Ed25519 signing/verification contract. It uses
`NSec.Cryptography`, an established libsodium-backed cryptography package.

It is not yet a full policy kernel or Guard implementation. Use the Rust
`scopepact-core` and `scopepact-guard` crates for enforcement.

Run the shared interoperability vector:

```sh
dotnet run --project sdks/dotnet/tests/ScopePact.Envelope.Conformance
```

The library is covered by Apache-2.0 under the repository's licensing map.
