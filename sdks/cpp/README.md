# ScopePact For C++

This pre-release C++20 library implements the portable ScopePact v0 envelope
transcript and Ed25519 signing/verification contract. Cryptographic operations
use OpenSSL's one-shot Ed25519 EVP interface; no cryptographic primitive is
implemented by ScopePact.

It is not yet a full policy kernel or Guard implementation. Use the Rust
`scopepact-core` and `scopepact-guard` crates for enforcement.

Build and run the shared interoperability vector:

```sh
cmake -S sdks/cpp -B sdks/cpp/build
cmake --build sdks/cpp/build
ctest --test-dir sdks/cpp/build --output-on-failure
```

OpenSSL 1.1.1 or newer is required. Tests use `nlohmann_json` 3.11 or newer to
load the canonical repository vector. The library is covered by Apache-2.0
under the repository's licensing map.
