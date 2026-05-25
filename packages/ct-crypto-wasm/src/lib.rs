//! Browser-compatible (wasm-bindgen) build of the Hathor confidential-transaction crypto.
//!
//! Two scoped surfaces:
//!
//! 1. **Verifier** (since 0.1.0): `createCommitment`,
//!    `createAssetCommitment`, `deriveTag`, `deriveAssetTag`,
//!    `htrAssetTag`. Used by the block explorer's "view tx unblinded"
//!    path to confirm that a shared `(value, vbf, abf?)` opens to the
//!    on-chain commitment bytes.
//!
//! 2. **Auditor rewind** (since 0.2.0): `rewindAmountShieldedOutput`,
//!    `rewindFullShieldedOutput`, `deriveEcdhSharedSecret`. Used by
//!    the `shielded-outputs-audit` browser app to recover
//!    `(value, vbf, abf?, tokenUid)` from a scan xpriv + on-chain
//!    output, without ever sending the xpriv to a server.
//!
//! Surjection-proof creation, signing, and balancing-blinding-factor
//! computation stay in `@hathor/ct-crypto-node` — those are wallet
//! responsibilities, not browser ones.
//!
//! The crypto primitives themselves live in `hathor-ct-crypto-core`
//! (workspace member). This crate is a thin wasm-bindgen wrapper.

pub mod wasm_bindings;
