//! NAPI bindings for the Hathor confidential-transaction crypto core.
//!
//! The crypto primitives live in `hathor-ct-crypto-core` (workspace member);
//! this crate only exposes them via Node's NAPI. The mobile (UniFFI
//! Swift/Kotlin) surface lives in the sibling `hathor-ct-crypto-mobile` crate.
//!
//! Build artifacts:
//!   - `.node` addon: `cargo build --features napi --release`

// Re-export the core so binding modules can `use hathor_ct_crypto_core::xxx`
// without going through the workspace dep name (cleaner imports + the napi
// attribute macros only operate on items defined in this crate).
pub use hathor_ct_crypto_core::*;

#[cfg(feature = "napi")]
pub mod napi_bindings;
