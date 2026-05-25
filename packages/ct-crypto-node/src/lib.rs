//! NAPI + UniFFI bindings for the Hathor confidential-transaction crypto core.
//!
//! The crypto primitives live in `hathor-ct-crypto-core` (workspace member);
//! this crate only exposes them via Node's NAPI and via UniFFI (consumed by
//! `hathor-wallet-mobile`'s iOS + Android RN native modules).
//!
//! Build artifacts:
//!   - `.node` addon: `cargo build --features napi --release`
//!   - Swift / Kotlin bindings: `cargo run --features uniffi-cli --bin uniffi-bindgen ...`

// Re-export the core so binding modules can `use hathor_ct_crypto_core::xxx`
// without going through the workspace dep name (cleaner imports + the napi /
// uniffi attribute macros only operate on items defined in this crate).
pub use hathor_ct_crypto_core::*;

#[cfg(feature = "napi")]
pub mod napi_bindings;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!("hathor_ct_crypto");

#[cfg(feature = "uniffi")]
pub mod uniffi_bindings;
