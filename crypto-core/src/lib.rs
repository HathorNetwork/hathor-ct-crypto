//! Hathor confidential-transaction crypto core.
//!
//! Pure-Rust primitives for shielded outputs — no language bindings.
//! Consumed by the per-platform binding crates (`hathor-ct-crypto-node`,
//! `hathor-ct-crypto-wasm`) which sit alongside this crate in the
//! monorepo and expose subsets of this surface to JS/TS via NAPI,
//! UniFFI, or wasm-bindgen.
//!
//! See `packages/ct-crypto-provider` for the JS-level abstract class
//! that wraps any of the resulting platform bindings into a uniform
//! `IShieldedCryptoProvider` interface.

pub mod balance;
pub mod ecdh;
pub mod error;
pub mod generators;
pub mod pedersen;
pub mod rangeproof;
pub mod surjection;
pub mod types;

pub use error::{HathorCtError, Result};
pub use types::*;
