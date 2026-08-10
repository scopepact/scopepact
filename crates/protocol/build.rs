fn main() {
    println!("cargo:rerun-if-changed=proto/scopepact/v0/core.proto");
    prost_build::compile_protos(&["proto/scopepact/v0/core.proto"], &["proto"])
        .expect("ScopePact protobuf schema must compile");
}
