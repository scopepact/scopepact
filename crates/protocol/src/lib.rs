//! Versioned wire types generated from the public `ScopePact` schema.

#[allow(clippy::all, clippy::pedantic)]
pub mod wire {
    include!(concat!(env!("OUT_DIR"), "/scopepact.v0.rs"));
}
