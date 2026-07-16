use std::ops::Range;

use secp256k1_zkp::{Generator, PedersenCommitment, RangeProof, SecretKey, Tweak, SECP256K1};

use crate::error::{HathorCtError, Result};

/// Fixed bit-width for all range proofs.
///
/// The secp256k1-zkp `min_bits` parameter is a *floor* on the proof's mantissa:
/// the proof covers at least `[0, 2^min_bits)`, but for a value whose magnitude
/// exceeds that floor the C code sizes the proof to the value's actual
/// bit-length instead. With `min_value = 1` the prover covers `amount − 1`, so
/// the proven range is `[1, 1 + 2^40)`. Pinning `min_bits = 40` gives every
/// in-range proof the same size (~3213 B) — leaking value magnitude through
/// proof length would otherwise defeat the privacy goal. Amounts that would
/// push `amount − 1` past the 40-bit floor are rejected up front (see
/// `MAX_PROVABLE_AMOUNT`) rather than silently producing an oversize,
/// magnitude-revealing proof.
///
/// Declared `usize` to match hathor-core (kept identical to keep future diffs
/// against the node clean); cast to `u8` at the `RangeProof::new` call site.
pub const RANGE_PROOF_BITS: usize = 40;

/// Largest amount that still yields a constant-size 40-bit proof.
///
/// With `min_value = 1` the prover proves `amount − 1 ∈ [0, 2^40)`, so
/// `amount = 2^40` is the largest safe value. Anything larger is rejected in
/// `create_range_proof` to prevent the oversize/magnitude-leaking proof class.
pub const MAX_PROVABLE_AMOUNT: u64 = 1u64 << RANGE_PROOF_BITS; // = 2^40

/// Maximum serialized range-proof size accepted by `deserialize_range_proof`.
///
/// Mirrors `MAX_RANGE_PROOF_SIZE` in hathorlib's `shielded_tx_output.py`
/// (the node's consensus wire-deserializer cap). MUST be changed in lockstep
/// with the node.
pub const MAX_RANGE_PROOF_SIZE: usize = 3328;

/// Create a Borromean range proof proving that the committed amount is in [1, 1 + 2^40).
///
/// The proof always covers the fixed 40-bit range (see `RANGE_PROOF_BITS`) so
/// that every proof is the same length — leaking value magnitude through
/// proof size would otherwise defeat the privacy goal.
///
/// # Arguments
/// * `amount` - The secret value to prove is in range
/// * `blinding` - The blinding factor (Tweak) used in the commitment
/// * `commitment` - The Pedersen commitment to prove
/// * `generator` - The generator (asset tag) used in the commitment
/// * `message` - Optional message to embed in the proof
/// * `nonce` - Optional nonce key. If None, a random nonce is used. If Some, the provided
///   key is used as the nonce, enabling `rewind_range_proof` to recover the committed values.
pub fn create_range_proof(
    amount: u64,
    blinding: &Tweak,
    commitment: &PedersenCommitment,
    generator: &Generator,
    message: Option<&[u8]>,
    nonce: Option<&SecretKey>,
) -> Result<RangeProof> {
    // Reject amounts that would exceed the fixed 40-bit floor. Above
    // this bound secp256k1-zkp sizes the proof to the value's true bit-length,
    // leaking magnitude through proof length; the node accepts such proofs, so
    // rejecting here (rather than producing them) is the only safe behavior.
    // (amount == 0 is additionally rejected by min_value = 1, but we fail fast
    // with a clear error here.)
    if amount == 0 || amount > MAX_PROVABLE_AMOUNT {
        return Err(HathorCtError::RangeProofError(format!(
            "amount {} outside provable range [1, {}] (40-bit range-proof capacity)",
            amount, MAX_PROVABLE_AMOUNT
        )));
    }

    let msg = message.unwrap_or(&[]);
    // Use provided nonce or generate a random one
    let sk = match nonce {
        Some(key) => *key,
        None => SecretKey::new(&mut rand::thread_rng()),
    };

    let proof = RangeProof::new(
        SECP256K1,
        1, // min_value: reject zero-amount commitments
        *commitment,
        amount,     // value
        *blinding,  // commitment_blinding
        msg,        // message
        &[],        // additional_commitment
        sk,         // sk (nonce key)
        0,          // exp
        RANGE_PROOF_BITS as u8, // min_bits: fixed 40-bit range → constant ~3213 B proof
        *generator, // additional_generator
    )
    .map_err(|e| HathorCtError::RangeProofError(e.to_string()))?;

    Ok(proof)
}

/// Rewind a Borromean range proof to recover the committed value, blinding factor, and message.
///
/// This requires the same nonce key that was used when creating the proof.
/// Returns (value, blinding_factor, message) on success.
pub fn rewind_range_proof(
    proof: &RangeProof,
    commitment: &PedersenCommitment,
    nonce: &SecretKey,
    generator: &Generator,
) -> Result<(u64, Tweak, Vec<u8>)> {
    let (opening, _range) = proof
        .rewind(SECP256K1, *commitment, *nonce, &[], *generator)
        .map_err(|e| HathorCtError::RangeProofError(format!("range proof rewind failed: {}", e)))?;

    Ok((
        opening.value,
        opening.blinding_factor,
        opening.message.into_vec(),
    ))
}

/// Verify a Borromean range proof.
///
/// Checks that the committed value is in the valid range.
/// Returns the proven range [min, max) on success.
pub fn verify_range_proof(
    proof: &RangeProof,
    commitment: &PedersenCommitment,
    generator: &Generator,
) -> Result<Range<u64>> {
    let range = proof
        .verify(SECP256K1, *commitment, &[], *generator)
        .map_err(|e| {
            HathorCtError::RangeProofError(format!("range proof verification failed: {}", e))
        })?;
    // Enforce min_value >= 1 to reject zero-amount commitments.
    // This check is also in the FFI wrappers, but we enforce it here as defense-in-depth.
    if range.start < 1 {
        return Err(HathorCtError::RangeProofError(
            "range proof min_value must be >= 1 (zero-amount commitments are not allowed)".into(),
        ));
    }
    Ok(range)
}

/// Batch-verify multiple range proofs.
// TODO: This is sequential, not truly batched. Investigate secp256k1-zkp batch verification API.
pub fn batch_verify_range_proofs(
    proofs: &[RangeProof],
    commitments: &[PedersenCommitment],
    generators: &[Generator],
) -> Result<()> {
    if proofs.len() != commitments.len() || proofs.len() != generators.len() {
        return Err(HathorCtError::RangeProofError(
            "mismatched lengths for batch verification".into(),
        ));
    }

    for (i, ((proof, commitment), generator)) in proofs
        .iter()
        .zip(commitments.iter())
        .zip(generators.iter())
        .enumerate()
    {
        let range = verify_range_proof(proof, commitment, generator)
            .map_err(|e| HathorCtError::RangeProofError(format!("proof {} failed: {}", i, e)))?;
        if range.start < 1 {
            return Err(HathorCtError::RangeProofError(format!(
                "proof {} has min_value {} < 1 (zero-amount rejected)",
                i, range.start
            )));
        }
    }

    Ok(())
}

/// Serialize a range proof to bytes.
pub fn serialize_range_proof(proof: &RangeProof) -> Vec<u8> {
    proof.serialize()
}

/// Deserialize a range proof from bytes.
///
/// Enforce the node's consensus wire cap (`MAX_RANGE_PROOF_SIZE`) so the
/// library is self-protecting against oversize attacker-supplied buffers rather
/// than relying on every consumer to bound the input.
pub fn deserialize_range_proof(bytes: &[u8]) -> Result<RangeProof> {
    if bytes.len() > MAX_RANGE_PROOF_SIZE {
        return Err(HathorCtError::RangeProofError(format!(
            "range proof size {} exceeds maximum {}",
            bytes.len(),
            MAX_RANGE_PROOF_SIZE
        )));
    }
    RangeProof::from_slice(bytes).map_err(|e| {
        HathorCtError::RangeProofError(format!("failed to deserialize range proof: {}", e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generators::htr_asset_tag;
    use crate::pedersen::create_commitment;

    #[test]
    fn test_valid_range_proof() {
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        let amount = 1000u64;
        let commitment = create_commitment(amount, &blinding, &gen).unwrap();

        let proof = create_range_proof(amount, &blinding, &commitment, &gen, None, None).unwrap();
        assert!(verify_range_proof(&proof, &commitment, &gen).is_ok());
    }

    #[test]
    fn test_zero_amount_rejected() {
        // Zero-amount range proofs must be rejected (min_value=1).
        // With min_value=1, creating a range proof for amount=0 should fail.
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        let amount = 0u64;
        let commitment = create_commitment(amount, &blinding, &gen).unwrap();

        // Creating a range proof with amount=0 and min_value=1 should fail
        let result = create_range_proof(amount, &blinding, &commitment, &gen, None, None);
        assert!(
            result.is_err(),
            "zero-amount range proof creation should fail with min_value=1"
        );
    }

    #[test]
    fn test_large_amount() {
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        let amount = 1_000_000_000u64;
        let commitment = create_commitment(amount, &blinding, &gen).unwrap();

        let proof = create_range_proof(amount, &blinding, &commitment, &gen, None, None).unwrap();
        assert!(verify_range_proof(&proof, &commitment, &gen).is_ok());
    }

    #[test]
    fn test_wrong_commitment_fails() {
        let gen = htr_asset_tag();
        let blinding1 = Tweak::new(&mut rand::thread_rng());
        let blinding2 = Tweak::new(&mut rand::thread_rng());

        let commitment1 = create_commitment(1000, &blinding1, &gen).unwrap();
        let commitment2 = create_commitment(2000, &blinding2, &gen).unwrap();

        let proof = create_range_proof(1000, &blinding1, &commitment1, &gen, None, None).unwrap();
        // Verify with wrong commitment should fail
        assert!(verify_range_proof(&proof, &commitment2, &gen).is_err());
    }

    #[test]
    fn test_batch_verify() {
        let gen = htr_asset_tag();
        let amounts = [100u64, 200, 300];
        let mut proofs = Vec::new();
        let mut commitments = Vec::new();
        let generators = vec![gen; 3];

        for amount in amounts {
            let blinding = Tweak::new(&mut rand::thread_rng());
            let commitment = create_commitment(amount, &blinding, &gen).unwrap();
            let proof =
                create_range_proof(amount, &blinding, &commitment, &gen, None, None).unwrap();
            proofs.push(proof);
            commitments.push(commitment);
        }

        assert!(batch_verify_range_proofs(&proofs, &commitments, &generators).is_ok());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        let commitment = create_commitment(500, &blinding, &gen).unwrap();
        let proof = create_range_proof(500, &blinding, &commitment, &gen, None, None).unwrap();

        let bytes = serialize_range_proof(&proof);
        let proof2 = deserialize_range_proof(&bytes).unwrap();
        assert!(verify_range_proof(&proof2, &commitment, &gen).is_ok());
    }

    #[test]
    fn test_proof_with_message() {
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        let amount = 42u64;
        let commitment = create_commitment(amount, &blinding, &gen).unwrap();

        let msg = b"test message";
        let proof =
            create_range_proof(amount, &blinding, &commitment, &gen, Some(msg), None).unwrap();
        assert!(verify_range_proof(&proof, &commitment, &gen).is_ok());
    }

    #[test]
    fn test_create_with_optional_nonce() {
        // Backward compat: None nonce generates random (proof still verifies)
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        let amount = 777u64;
        let commitment = create_commitment(amount, &blinding, &gen).unwrap();
        let proof = create_range_proof(amount, &blinding, &commitment, &gen, None, None).unwrap();
        assert!(verify_range_proof(&proof, &commitment, &gen).is_ok());
    }

    #[test]
    fn test_rewind_roundtrip() {
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        let amount = 12345u64;
        let commitment = create_commitment(amount, &blinding, &gen).unwrap();

        let nonce = SecretKey::new(&mut rand::thread_rng());
        let msg = b"hello world rewind";
        let proof = create_range_proof(
            amount,
            &blinding,
            &commitment,
            &gen,
            Some(msg),
            Some(&nonce),
        )
        .unwrap();

        // Verify the proof is valid
        assert!(verify_range_proof(&proof, &commitment, &gen).is_ok());

        // Rewind to recover value, blinding, and message
        let (recovered_value, recovered_blinding, recovered_message) =
            rewind_range_proof(&proof, &commitment, &nonce, &gen).unwrap();

        assert_eq!(recovered_value, amount);
        assert_eq!(recovered_blinding.as_ref(), blinding.as_ref());
        // The message is padded to 4096 bytes; check that it starts with our message
        assert!(recovered_message.starts_with(msg));
    }

    #[test]
    fn test_proof_size_is_constant() {
        // Regression: with min_bits=0 ("auto"), proof size scaled with the
        // value's bit-width, leaking magnitude and overflowing the fullnode's
        // fixed-size cap for larger amounts. Pinning min_bits=RANGE_PROOF_BITS
        // must make proof length independent of the proven value.
        let gen = htr_asset_tag();
        let mut sizes = Vec::new();
        for amount in [1u64, 100, 10_000, 1_000_000, 1_000_000_000, 1_000_000_000_000] {
            let blinding = Tweak::new(&mut rand::thread_rng());
            let commitment = create_commitment(amount, &blinding, &gen).unwrap();
            let proof =
                create_range_proof(amount, &blinding, &commitment, &gen, None, None).unwrap();
            sizes.push(serialize_range_proof(&proof).len());
        }
        let first = sizes[0];
        assert!(
            sizes.iter().all(|&s| s == first),
            "range proof sizes vary with value: {:?}",
            sizes
        );
    }

    #[test]
    fn test_proof_size_fits_fullnode_cap() {
        // Regression: the serialized proof must fit the node's consensus
        // wire cap (MAX_RANGE_PROOF_SIZE = 3328, mirroring hathorlib). If this
        // ever exceeds the cap the client would build proofs the node rejects.
        let gen = htr_asset_tag();
        for amount in [1u64, 1000, MAX_PROVABLE_AMOUNT] {
            let blinding = Tweak::new(&mut rand::thread_rng());
            let commitment = create_commitment(amount, &blinding, &gen).unwrap();
            let proof =
                create_range_proof(amount, &blinding, &commitment, &gen, None, None).unwrap();
            let size = serialize_range_proof(&proof).len();
            assert!(
                size <= MAX_RANGE_PROOF_SIZE,
                "range proof size {} exceeds fullnode cap {} for amount {}",
                size,
                MAX_RANGE_PROOF_SIZE,
                amount
            );
        }
    }

    #[test]
    fn test_oversize_amount_rejected() {
        // Amounts past the 40-bit floor must be rejected, not turned
        // into oversize, magnitude-leaking proofs.
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        // MAX_PROVABLE_AMOUNT is accepted; one above it is rejected.
        let ok_commit = create_commitment(MAX_PROVABLE_AMOUNT, &blinding, &gen).unwrap();
        assert!(create_range_proof(MAX_PROVABLE_AMOUNT, &blinding, &ok_commit, &gen, None, None).is_ok());

        let over = MAX_PROVABLE_AMOUNT + 1;
        // (commitment creation itself is fine; the proof step must reject)
        let over_commit = create_commitment(over, &blinding, &gen).unwrap();
        assert!(
            create_range_proof(over, &blinding, &over_commit, &gen, None, None).is_err(),
            "amount above 2^40 must be rejected"
        );
    }

    #[test]
    fn test_deserialize_oversize_proof_rejected() {
        // A buffer larger than the node's wire cap is rejected before
        // it reaches the C parser.
        let too_big = vec![0u8; MAX_RANGE_PROOF_SIZE + 1];
        assert!(deserialize_range_proof(&too_big).is_err());
    }

    #[test]
    fn test_rewind_wrong_nonce_fails() {
        let gen = htr_asset_tag();
        let blinding = Tweak::new(&mut rand::thread_rng());
        let amount = 999u64;
        let commitment = create_commitment(amount, &blinding, &gen).unwrap();

        let nonce = SecretKey::new(&mut rand::thread_rng());
        let wrong_nonce = SecretKey::new(&mut rand::thread_rng());

        let proof =
            create_range_proof(amount, &blinding, &commitment, &gen, None, Some(&nonce)).unwrap();

        // Rewind with wrong nonce should fail
        let result = rewind_range_proof(&proof, &commitment, &wrong_nonce, &gen);
        assert!(result.is_err());
    }
}
