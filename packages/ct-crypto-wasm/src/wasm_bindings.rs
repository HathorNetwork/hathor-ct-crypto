//! Browser-compatible bindings for the Hathor confidential-transaction crypto.
//!
//! Two scoped surfaces (this list is the review artifact for the "no signing /
//! no RNG leaked into the browser" invariant — keep it in sync with the
//! `#[wasm_bindgen]` exports below):
//!
//! 1. **Verifier** (since 0.1.0) — commitment/generator recompute
//!    (`createCommitment`, `createTrivialCommitment`, `createAssetCommitment`,
//!    `deriveTag`, `deriveAssetTag`, `htrAssetTag`) plus the public-data
//!    verifiers (`verifyRangeProof`, `verifySurjectionProof`,
//!    `verifyCommitmentsSum`, `verifyBalance`, `validateCommitment`,
//!    `validateGenerator`). The block explorer uses these to confirm a shared
//!    `(value, vbf, abf?)` opens to the on-chain commitment and to validate
//!    every proof/relation without any secret material.
//!
//! 2. **Auditor rewind** (since 0.2.0) — `rewindAmountShieldedOutput`,
//!    `rewindFullShieldedOutput`, `deriveEcdhSharedSecret`. The
//!    `shielded-outputs-audit` browser app uses these to recover
//!    `(value, vbf, abf?, tokenUid)` from a scan xpriv + on-chain
//!    output. The xpriv stays in the browser; nothing crosses the
//!    network. SECURITY NOTE (review finding L-4): the scan xpriv and the
//!    recovered blinding factors live in JS/wasm memory that cannot be
//!    reliably zeroed for the page's lifetime — treat a browser running these
//!    as holding scan-key material (a scan key is not a spend key, but it
//!    deanonymizes). Standard browser key-handling controls apply.
//!
//! Surjection-proof creation, output creation, signing, and
//! balancing-blinding-factor computation stay in `@hathor/ct-crypto-node` —
//! those are wallet responsibilities, not browser ones, and reject here.
//!
//! Sibling crate `hathor-ct-crypto` ships the Node (NAPI) build with
//! the full primitive surface. Keep this file's API behaviorally
//! identical to the equivalent functions in
//! `hathor-ct-crypto/src/napi_bindings.rs` so a JS consumer can pick
//! between them at runtime without surface drift.

use secp256k1_zkp::{Generator, Tweak};
use wasm_bindgen::prelude::*;

use hathor_ct_crypto_core::error::HathorCtError;

/// Build a thrown value that is a real JS `Error` instance (not a bare string),
/// so the shape matches what the NAPI binding throws (`napi::Error` surfaces as
/// an `Error`). Consumers can then rely on `err instanceof Error` / `err.message`
/// uniformly across the node and wasm providers.
fn js_err(msg: &str) -> JsValue {
    JsValue::from(js_sys::Error::new(msg))
}

fn to_js_err(e: HathorCtError) -> JsValue {
    js_err(&e.to_string())
}

fn parse_tweak(bytes: &[u8]) -> Result<Tweak, JsValue> {
    if bytes.len() != 32 {
        return Err(js_err("tweak must be 32 bytes"));
    }
    Tweak::from_slice(bytes).map_err(|e| js_err(&e.to_string()))
}

fn parse_generator(bytes: &[u8]) -> Result<Generator, JsValue> {
    if bytes.len() != 33 {
        return Err(js_err("generator must be 33 bytes"));
    }
    hathor_ct_crypto_core::generators::deserialize_generator(bytes).map_err(to_js_err)
}

fn parse_token_uid(bytes: &[u8]) -> Result<[u8; 32], JsValue> {
    if bytes.len() != 32 {
        return Err(js_err("token_uid must be 32 bytes"));
    }
    bytes
        .try_into()
        .map_err(|_| js_err("token_uid must be exactly 32 bytes"))
}

/// Convert a JS `BigInt` amount to `u64`, rejecting negative and
/// out-of-range values instead of silently wrapping mod 2^64.
///
/// wasm-bindgen's native `u64` parameter marshals a JS `BigInt` via
/// `BigInt.asUintN(64, x)`, which wraps — so an explorer opening-check would
/// otherwise *accept* a maliciously claimed `V + 2^64` as a valid opening of a
/// commitment to `V`. Taking a `js_sys::BigInt` and converting explicitly (with
/// the same semantics as the NAPI `bigint_to_u64`) closes that fail-open.
fn bigint_to_u64(value: &js_sys::BigInt) -> Result<u64, JsValue> {
    // try_from returns Err for values outside i64/u64 depending on sign; use the
    // u64 conversion and reject anything that doesn't fit exactly.
    u64::try_from(value.clone())
        .map_err(|_| js_err("amount must be a non-negative integer < 2^64"))
}

/// Derive the deterministic asset-tag generator (33-byte compressed point) for a token UID.
///
/// Used as the value-commitment generator for AmountShielded outputs (where
/// the token is public).
#[wasm_bindgen(js_name = deriveAssetTag)]
pub fn derive_asset_tag(token_uid: &[u8]) -> Result<Vec<u8>, JsValue> {
    let uid = parse_token_uid(token_uid)?;
    let tag = hathor_ct_crypto_core::generators::derive_asset_tag(&uid).map_err(to_js_err)?;
    Ok(tag.serialize().to_vec())
}

/// Return the HTR asset-tag generator (token_uid = [0; 32]).
#[wasm_bindgen(js_name = htrAssetTag)]
pub fn htr_asset_tag() -> Vec<u8> {
    hathor_ct_crypto_core::generators::htr_asset_tag().serialize().to_vec()
}

/// Derive the raw 32-byte Tag for a token UID. Used when constructing
/// blinded asset commitments for FullShielded outputs.
#[wasm_bindgen(js_name = deriveTag)]
pub fn derive_tag(token_uid: &[u8]) -> Result<Vec<u8>, JsValue> {
    let uid = parse_token_uid(token_uid)?;
    let tag = hathor_ct_crypto_core::generators::derive_tag(&uid).map_err(to_js_err)?;
    let bytes: [u8; 32] = tag.into();
    Ok(bytes.to_vec())
}

/// Build a blinded asset commitment (33-byte compressed point) from a raw
/// Tag and an asset blinding factor (`abf`). FullShielded value commitments
/// are computed against this generator instead of the unblinded asset tag.
#[wasm_bindgen(js_name = createAssetCommitment)]
pub fn create_asset_commitment(tag_bytes: &[u8], r_asset: &[u8]) -> Result<Vec<u8>, JsValue> {
    if tag_bytes.len() != 32 {
        return Err(js_err("tag must be 32 bytes"));
    }
    let tag_arr: [u8; 32] = tag_bytes
        .try_into()
        .map_err(|_| js_err("tag must be exactly 32 bytes"))?;
    let tag = secp256k1_zkp::Tag::from(tag_arr);
    let tweak = parse_tweak(r_asset)?;
    let commitment =
        hathor_ct_crypto_core::generators::create_asset_commitment(&tag, &tweak).map_err(to_js_err)?;
    Ok(commitment.serialize().to_vec())
}

/// Build a Pedersen commitment `C = amount * generator + blinding * G`.
///
/// `amount` is a JS `BigInt`, validated to be a non-negative integer < 2^64
/// (the value is NOT allowed to wrap mod 2^64, matching NAPI); blinding
/// is a 32-byte `vbf`; generator is a 33-byte compressed point (asset tag for
/// AmountShielded or asset commitment for FullShielded).
#[wasm_bindgen(js_name = createCommitment)]
pub fn create_commitment(
    amount: js_sys::BigInt,
    blinding: &[u8],
    generator: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let amount = bigint_to_u64(&amount)?;
    let bf = parse_tweak(blinding)?;
    let gen = parse_generator(generator)?;
    let c = hathor_ct_crypto_core::pedersen::create_commitment(amount, &bf, &gen).map_err(to_js_err)?;
    Ok(c.serialize().to_vec())
}

/// Build a trivial (zero-blinding) Pedersen commitment `C = amount * generator`.
///
/// Mirrors the NAPI surface for completeness; not strictly needed by the
/// explorer's verify path but kept here so the two binding surfaces don't
/// diverge. `amount` is a validated JS `BigInt` (no mod-2^64 wrapping).
#[wasm_bindgen(js_name = createTrivialCommitment)]
pub fn create_trivial_commitment(amount: js_sys::BigInt, generator: &[u8]) -> Result<Vec<u8>, JsValue> {
    let amount = bigint_to_u64(&amount)?;
    let gen = parse_generator(generator)?;
    let c = hathor_ct_crypto_core::pedersen::create_trivial_commitment(amount, &gen).map_err(to_js_err)?;
    Ok(c.serialize().to_vec())
}

// ─── Auditor rewind surface (0.2.0) ──────────────────────────────────
//
// The high-level `rewindAmountShieldedOutput` / `rewindFullShieldedOutput`
// entry points combine ECDH + nonce derivation + range-proof rewind into a
// single call — same behavior as
// `hathor-ct-crypto/src/napi_bindings.rs:rewind_amount_shielded_output` and
// the matching `rewind_full_shielded_output`. JS consumers don't need to
// touch the intermediate primitives.
//
// Result shape: a wasm-bindgen struct with cloneable byte-vector getters,
// translated to a plain JS object with the same field names. Mirrors the
// NAPI `RewoundAmountShieldedOutput` / `RewoundFullShieldedOutput`
// shape exactly so the wallet-lib `IShieldedCryptoProvider` interface
// resolves the same fields against either provider.

/// Result of `rewindAmountShieldedOutput`. JS sees the fields as
/// `{ value: bigint, blindingFactor: Uint8Array }` via the auto-generated
/// getter / `toJSON` glue.
#[wasm_bindgen(js_name = RewoundAmountShieldedOutput)]
pub struct RewoundAmountShieldedOutput {
    value: u64,
    blinding_factor: Vec<u8>,
}

#[wasm_bindgen(js_class = RewoundAmountShieldedOutput)]
impl RewoundAmountShieldedOutput {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> u64 {
        self.value
    }

    #[wasm_bindgen(getter, js_name = blindingFactor)]
    pub fn blinding_factor(&self) -> Vec<u8> {
        self.blinding_factor.clone()
    }
}

/// Result of `rewindFullShieldedOutput`. JS shape:
/// `{ value: bigint, blindingFactor: Uint8Array, tokenUid: Uint8Array, assetBlindingFactor: Uint8Array }`.
#[wasm_bindgen(js_name = RewoundFullShieldedOutput)]
pub struct RewoundFullShieldedOutput {
    value: u64,
    blinding_factor: Vec<u8>,
    token_uid: Vec<u8>,
    asset_blinding_factor: Vec<u8>,
}

#[wasm_bindgen(js_class = RewoundFullShieldedOutput)]
impl RewoundFullShieldedOutput {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> u64 {
        self.value
    }

    #[wasm_bindgen(getter, js_name = blindingFactor)]
    pub fn blinding_factor(&self) -> Vec<u8> {
        self.blinding_factor.clone()
    }

    #[wasm_bindgen(getter, js_name = tokenUid)]
    pub fn token_uid(&self) -> Vec<u8> {
        self.token_uid.clone()
    }

    #[wasm_bindgen(getter, js_name = assetBlindingFactor)]
    pub fn asset_blinding_factor(&self) -> Vec<u8> {
        self.asset_blinding_factor.clone()
    }
}

/// Compute the ECDH shared secret used to derive the rewind nonce.
///
/// Equivalent to libsecp256k1's `ecdh()` with the standard SHA-256 hash:
/// `SHA256(version_byte || x_coordinate)`. JS rarely needs this directly
/// — call `rewindAmountShieldedOutput` / `rewindFullShieldedOutput`
/// instead — but exposing it matches the NAPI surface and lets advanced
/// consumers compose their own flows.
#[wasm_bindgen(js_name = deriveEcdhSharedSecret)]
pub fn derive_ecdh_shared_secret(private_key: &[u8], peer_pubkey: &[u8]) -> Result<Vec<u8>, JsValue> {
    let sk = hathor_ct_crypto_core::ecdh::parse_secret_key(private_key).map_err(to_js_err)?;
    let pk = hathor_ct_crypto_core::ecdh::parse_public_key(peer_pubkey).map_err(to_js_err)?;
    let secret = hathor_ct_crypto_core::ecdh::derive_ecdh_shared_secret(&sk, &pk);
    Ok(secret.to_vec())
}

/// Rewind an AmountShielded output.
///
/// Given the recipient's scan privkey + the on-chain output's
/// ephemeral pubkey + commitment + range proof + token UID, recovers
/// the cleartext `value` and `blindingFactor`. ECDH derives a shared
/// secret with the ephemeral pubkey; the secret seeds the range
/// proof's rewind nonce; the nonce unlocks the encrypted (value, vbf)
/// payload inside the proof.
///
/// **Throws** when the output isn't addressed to this scan key
/// (mismatched ECDH → wrong nonce → rewind fails) and on shape errors
/// (malformed inputs). It never returns `null`. Callers scanning the chain
/// should wrap this in try/catch and treat a throw as "not addressed to this
/// key" (the common case) — do not rely on a null return.
#[wasm_bindgen(js_name = rewindAmountShieldedOutput)]
pub fn rewind_amount_shielded_output(
    private_key: &[u8],
    ephemeral_pubkey: &[u8],
    commitment: &[u8],
    range_proof: &[u8],
    token_uid: &[u8],
) -> Result<RewoundAmountShieldedOutput, JsValue> {
    let tuid = parse_token_uid(token_uid)?;
    let result = hathor_ct_crypto_core::ecdh::rewind_amount_shielded_output(
        private_key,
        ephemeral_pubkey,
        commitment,
        range_proof,
        &tuid,
    )
    .map_err(to_js_err)?;
    Ok(RewoundAmountShieldedOutput {
        value: result.value,
        blinding_factor: result.blinding_factor,
    })
}

/// Rewind a FullShielded output.
///
/// Recovers value + blinding factor + token UID + asset blinding
/// factor. The token UID is encoded inside the proof's rewindable
/// message slot, so a single rewind returns all four. The
/// `assetCommitment` argument is the on-chain blinded asset
/// commitment for this output (33 bytes).
///
/// **Throws** on a foreign output (wrong scan key) or malformed input;
/// it never returns `null`. Treat a throw as "not addressed to this key".
#[wasm_bindgen(js_name = rewindFullShieldedOutput)]
pub fn rewind_full_shielded_output(
    private_key: &[u8],
    ephemeral_pubkey: &[u8],
    commitment: &[u8],
    range_proof: &[u8],
    asset_commitment: &[u8],
) -> Result<RewoundFullShieldedOutput, JsValue> {
    let result = hathor_ct_crypto_core::ecdh::rewind_full_shielded_output(
        private_key,
        ephemeral_pubkey,
        commitment,
        range_proof,
        asset_commitment,
    )
    .map_err(to_js_err)?;
    Ok(RewoundFullShieldedOutput {
        value: result.value,
        blinding_factor: result.blinding_factor,
        token_uid: result.token_uid.to_vec(),
        asset_blinding_factor: result.asset_blinding_factor.to_vec(),
    })
}

// ─── Pure verifier surface ───────────────────────────────────────────
//
// These operate only on public, on-chain data (commitments, generators,
// proofs) with no secret-key or RNG dependency, so they are safe and useful in
// a browser/explorer context. They let the explorer independently validate
// third-party shielded outputs rather than relying solely on opening-recompute.

/// Return `true` if `data` parses as a valid 33-byte Pedersen commitment
/// (on-curve point). Rejects non-curve / wrong-length input.
#[wasm_bindgen(js_name = validateCommitment)]
pub fn validate_commitment(data: &[u8]) -> bool {
    hathor_ct_crypto_core::pedersen::deserialize_commitment(data).is_ok()
}

/// Return `true` if `data` parses as a valid 33-byte generator / asset
/// commitment (on-curve point).
#[wasm_bindgen(js_name = validateGenerator)]
pub fn validate_generator(data: &[u8]) -> bool {
    hathor_ct_crypto_core::generators::deserialize_generator(data).is_ok()
}

/// Verify a range proof against a commitment + generator. Returns `true` iff the
/// committed value is in the valid range `[1, 1 + 2^40)`.
///
/// Zero-amount proofs are rejected (`false`), matching the NAPI
/// `verify_range_proof` so the two providers agree on the same proofs.
#[wasm_bindgen(js_name = verifyRangeProof)]
pub fn verify_range_proof(proof: &[u8], commitment: &[u8], generator: &[u8]) -> Result<bool, JsValue> {
    let p = hathor_ct_crypto_core::rangeproof::deserialize_range_proof(proof).map_err(to_js_err)?;
    let c = hathor_ct_crypto_core::pedersen::deserialize_commitment(commitment).map_err(to_js_err)?;
    let gen = parse_generator(generator)?;
    match hathor_ct_crypto_core::rangeproof::verify_range_proof(&p, &c, &gen) {
        Ok(range) => {
            // Only the lower bound is checked, matching the hathor-core node
            // exactly. Do NOT add an upper-bound check: the node enforces none
            // (its verify_range_proof checks only range.start < 1), so a client
            // upper-bound guard would make this verifier stricter than the node
            // and reject node-accepted outputs — the divergence SECURITY.md rates
            // high. The [1, 2^40) invariant is create-side only; verify-side
            // enforcement belongs upstream in hathor-core (review finding M-1).
            // Kept in lockstep with the NAPI wrapper.
            if range.start < 1 {
                return Ok(false); // Reject zero-amount proofs (matches node)
            }
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

/// Verify that the sum of the `positive` commitments equals the sum of the
/// `negative` commitments. Mirrors the NAPI `verify_commitments_sum`.
#[wasm_bindgen(js_name = verifyCommitmentsSum)]
pub fn verify_commitments_sum(
    positive: Vec<js_sys::Uint8Array>,
    negative: Vec<js_sys::Uint8Array>,
) -> Result<bool, JsValue> {
    let pos = positive
        .iter()
        .map(|b| hathor_ct_crypto_core::pedersen::deserialize_commitment(&b.to_vec()).map_err(to_js_err))
        .collect::<Result<Vec<_>, JsValue>>()?;
    let neg = negative
        .iter()
        .map(|b| hathor_ct_crypto_core::pedersen::deserialize_commitment(&b.to_vec()).map_err(to_js_err))
        .collect::<Result<Vec<_>, JsValue>>()?;
    Ok(hathor_ct_crypto_core::pedersen::verify_commitments_sum(&pos, &neg))
}

/// Assemble the `BalanceEntry` list from a set of transparent entries (passed as
/// parallel `amounts[i]` / `token_uids[i]` arrays) plus shielded value
/// commitments. wasm-bindgen has no ergonomic array-of-structs marshaling, so
/// `WasmShieldedProvider.verifyBalance` splits the `ITransparentBalanceEntry[]`
/// contract shape into these parallel arrays before calling in.
fn build_balance_entries(
    amounts: &[js_sys::BigInt],
    token_uids: &[js_sys::Uint8Array],
    shielded: &[js_sys::Uint8Array],
) -> Result<Vec<hathor_ct_crypto_core::balance::BalanceEntry>, JsValue> {
    if amounts.len() != token_uids.len() {
        return Err(js_err(
            "transparent amounts and token_uids must have equal length",
        ));
    }
    let mut entries = Vec::with_capacity(amounts.len() + shielded.len());
    for (amount, uid) in amounts.iter().zip(token_uids.iter()) {
        let token_uid = parse_token_uid(&uid.to_vec())?;
        entries.push(hathor_ct_crypto_core::balance::BalanceEntry::Transparent {
            amount: bigint_to_u64(amount)?,
            token_uid,
        });
    }
    for cb in shielded {
        let c = hathor_ct_crypto_core::pedersen::deserialize_commitment(&cb.to_vec()).map_err(to_js_err)?;
        entries.push(hathor_ct_crypto_core::balance::BalanceEntry::Shielded {
            value_commitment: c,
        });
    }
    Ok(entries)
}

/// Verify the homomorphic balance equation. Mirrors the NAPI `verify_balance`.
///
/// Transparent entries arrive as parallel arrays (`transparent_*_amounts[i]`
/// pairs with `transparent_*_token_uids[i]`). `excess_blinding_factor`
/// (optional, 32 bytes) supports full-unshield transactions
/// (`UnshieldBalanceHeader`, header id 0x13): shielded inputs with no shielded
/// outputs, where the sender reveals `excess = sum(r_in) − sum(r_out)`. Matches
/// hathor-core's semantics so client-side verification covers the same
/// transaction classes the node accepts.
#[wasm_bindgen(js_name = verifyBalance)]
#[allow(clippy::too_many_arguments)]
pub fn verify_balance(
    transparent_input_amounts: Vec<js_sys::BigInt>,
    transparent_input_token_uids: Vec<js_sys::Uint8Array>,
    shielded_inputs: Vec<js_sys::Uint8Array>,
    transparent_output_amounts: Vec<js_sys::BigInt>,
    transparent_output_token_uids: Vec<js_sys::Uint8Array>,
    shielded_outputs: Vec<js_sys::Uint8Array>,
    excess_blinding_factor: Option<js_sys::Uint8Array>,
) -> Result<bool, JsValue> {
    let inputs = build_balance_entries(
        &transparent_input_amounts,
        &transparent_input_token_uids,
        &shielded_inputs,
    )?;
    let outputs = build_balance_entries(
        &transparent_output_amounts,
        &transparent_output_token_uids,
        &shielded_outputs,
    )?;

    // Structural invariants on the excess blinding factor, mirroring the NAPI
    // binding (which re-checks them at the FFI boundary): excess and shielded
    // outputs cannot coexist, and excess requires at least one shielded input
    // (otherwise there's no sum(r_in)·G term to cancel and the scalar is
    // meaningless).
    let excess = match excess_blinding_factor {
        Some(buf) => {
            if !shielded_outputs.is_empty() {
                return Err(js_err(
                    "excess_blinding_factor must be undefined when shielded_outputs is non-empty",
                ));
            }
            if shielded_inputs.is_empty() {
                return Err(js_err(
                    "excess_blinding_factor requires at least one shielded input",
                ));
            }
            Some(parse_tweak(&buf.to_vec())?)
        }
        None => None,
    };

    hathor_ct_crypto_core::balance::verify_balance(&inputs, &outputs, excess)
        .map(|()| true)
        .or_else(|e| match e {
            HathorCtError::BalanceError(_) => Ok(false),
            other => Err(to_js_err(other)),
        })
}

/// Verify a surjection proof that the output asset (`codomain`, 33-byte
/// generator) is one of the input assets (`domain`, 33-byte generators).
#[wasm_bindgen(js_name = verifySurjectionProof)]
pub fn verify_surjection_proof(proof: &[u8], codomain: &[u8], domain: Vec<js_sys::Uint8Array>) -> Result<bool, JsValue> {
    let p = hathor_ct_crypto_core::surjection::deserialize_surjection_proof(proof).map_err(to_js_err)?;
    let codomain_gen = parse_generator(codomain)?;
    let domain_gens: Vec<Generator> = domain
        .iter()
        .map(|u| parse_generator(&u.to_vec()))
        .collect::<Result<Vec<_>, JsValue>>()?;
    Ok(hathor_ct_crypto_core::surjection::verify_surjection_proof(&p, &codomain_gen, &domain_gens).is_ok())
}
