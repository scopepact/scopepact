//! Experimental protocol security kernel.
//!
//! The crate intentionally keeps authorization outside the language model.
//! It is not a production network stack and its public API is not stable.

pub mod authorization;
pub mod envelope;
pub mod error;
#[cfg(feature = "jwt-federation")]
pub mod federation;
pub mod handshake;
pub mod interaction;
pub mod replay;
pub mod signing;
pub mod types;

pub use error::{ProtocolError, Result};
pub use scopepact_protocol::wire;
