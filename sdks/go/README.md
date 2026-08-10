# ScopePact For Go

This pre-release Go module implements the portable ScopePact v0 envelope
transcript and Ed25519 signing/verification contract using the Go standard
library.

It is not yet a full policy kernel or Guard implementation. Use the Rust
`scopepact-core` and `scopepact-guard` crates for enforcement.

Run the shared interoperability vector:

```sh
cd sdks/go
go test ./...
```

The module requires Go 1.22 or newer and is covered by Apache-2.0 under the
repository's licensing map.
