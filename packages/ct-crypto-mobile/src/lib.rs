//! UniFFI (Swift / Kotlin) bindings for the Hathor confidential-transaction
//! crypto core, consumed by `hathor-wallet-mobile` through the
//! `@hathor/ct-crypto-mobile` React Native package in this repo.
//!
//! The crypto primitives live in `hathor-ct-crypto-core` (workspace member);
//! this crate only exposes them over FFI. The Node NAPI surface lives in the
//! sibling `hathor-ct-crypto-node` crate.
//!
//! Build artifacts:
//!   - iOS:     `cargo build --release --target aarch64-apple-ios` (staticlib →
//!              XCFramework, see .github/workflows/build-mobile.yml)
//!   - Android: `cargo ndk -t arm64-v8a ... build --release` (cdylib → jniLibs)
//!   - Bindings: `cargo run --features uniffi-cli --bin uniffi-bindgen -- \
//!              generate --library <dylib> --language swift|kotlin ...`

// Re-export the core so binding modules can `use hathor_ct_crypto_core::xxx`
// without going through the workspace dep name.
pub use hathor_ct_crypto_core::*;

// The UniFFI namespace stays `hathor_ct_crypto` — it predates the crate split
// and is baked into the generated Swift/Kotlin API names and checksums.
uniffi::setup_scaffolding!("hathor_ct_crypto");

pub mod uniffi_bindings;
