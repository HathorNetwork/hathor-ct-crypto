use secp256k1_zkp::ecdh::SharedSecret;
use secp256k1_zkp::{PublicKey, SecretKey, Tweak};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::HathorCtError;
use crate::types::TokenUid;

const NONCE_DOMAIN_SEPARATOR: &[u8] = b"Hathor_CT_nonce_v1";

/// Generate a random 32-byte blinding factor suitable for Pedersen commitments.
///
/// Uses a cryptographically secure RNG and rejection-samples until the bytes are
/// a valid secp256k1 scalar (non-zero and < curve order).
///
/// NEW-07: `Tweak::new` is a raw `fill_bytes` with no validation, and
/// `Tweak::from_slice` accepts all-zero, so neither guarantees the "non-zero
/// valid scalar" this function's callers (and the client guide) rely on. We
/// validate with `SecretKey::from_slice`, which rejects both zero and
/// out-of-range values. The retry probability is negligible (~2^-128).
pub fn generate_random_blinding_factor() -> [u8; 32] {
    loop {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        if SecretKey::from_slice(&bytes).is_ok() {
            return bytes;
        }
        // Not a valid scalar (zero or >= order): wipe and resample.
        bytes.zeroize();
    }
}

/// Generate a fresh ephemeral secp256k1 key pair.
///
/// Returns (private_key_bytes_32B, compressed_pubkey_bytes_33B).
pub fn generate_ephemeral_keypair() -> ([u8; 32], [u8; 33]) {
    let sk = SecretKey::new(&mut rand::thread_rng());
    let pk = PublicKey::from_secret_key_global(&sk);
    (sk.secret_bytes(), pk.serialize())
}

/// Compute ECDH shared secret using libsecp256k1's default hash: SHA256(version || x).
///
/// Returns 32-byte shared secret.
pub fn derive_ecdh_shared_secret(
    private_key: &SecretKey,
    peer_pubkey: &PublicKey,
) -> [u8; 32] {
    SharedSecret::new(peer_pubkey, private_key).secret_bytes()
}

/// Derive a deterministic nonce from a shared secret, guaranteed to be a valid SecretKey.
///
/// nonce = SHA256("Hathor_CT_nonce_v1" || shared_secret)
///
/// If the hash output is not a valid secp256k1 scalar (probability ~2^-128),
/// we rehash iteratively until we get a valid one.
pub fn derive_rewind_nonce(shared_secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NONCE_DOMAIN_SEPARATOR);
    hasher.update(shared_secret);
    let mut result: [u8; 32] = hasher.finalize().into();

    // Ensure the result is a valid secp256k1 scalar (non-zero and < curve order).
    // The probability of needing a retry is negligible (~2^-128), but this guarantees
    // SecretKey::from_slice will never fail downstream.
    let mut counter: u8 = 0;
    while SecretKey::from_slice(&result).is_err() {
        let mut retry_hasher = Sha256::new();
        retry_hasher.update(NONCE_DOMAIN_SEPARATOR);
        retry_hasher.update(&result);
        retry_hasher.update([counter]);
        result = retry_hasher.finalize().into();
        counter = counter.wrapping_add(1);
    }

    result
}

/// Parse a 32-byte slice into a SecretKey.
pub fn parse_secret_key(bytes: &[u8]) -> Result<SecretKey, HathorCtError> {
    if bytes.len() != 32 {
        return Err(HathorCtError::Secp256k1Error("secret key must be 32 bytes".into()));
    }
    SecretKey::from_slice(bytes).map_err(|e| HathorCtError::Secp256k1Error(e.to_string()))
}

/// Result of creating a shielded output, with all fields as serialized bytes.
pub struct FullShieldedOutputResult {
    /// Compressed ephemeral public key (33 bytes).
    pub ephemeral_pubkey: [u8; 33],
    /// Serialized Pedersen commitment (33 bytes).
    pub commitment: Vec<u8>,
    /// Serialized Borromean range proof.
    pub range_proof: Vec<u8>,
    /// Value blinding factor (32 bytes, passed through).
    pub value_blinding_factor: [u8; 32],
    /// Serialized blinded asset commitment (33 bytes).
    pub asset_commitment: Vec<u8>,
    /// Asset blinding factor (32 bytes, passed through).
    pub asset_blinding_factor: [u8; 32],
}

/// Create a FullShielded output with both blinding factors provided externally.
///
/// This is needed for the last output in a FullShielded transaction where the balance
/// equation requires pre-computing the vbf using a known abf.
pub fn create_full_shielded_output(
    value: u64,
    recipient_pubkey: &[u8],
    token_uid: &TokenUid,
    value_blinding_factor: &[u8; 32],
    asset_blinding_factor: &[u8; 32],
) -> Result<FullShieldedOutputResult, HathorCtError> {
    // 1. Generate ephemeral keypair and derive ECDH nonce
    let (eph_pk_bytes, nonce_sk) = generate_ecdh_nonce(recipient_pubkey)?;

    // 2. Create blinded asset commitment using provided abf
    let tag = crate::generators::derive_tag(token_uid)?;
    let abf_tweak = Tweak::from_slice(asset_blinding_factor)
        .map_err(|e| HathorCtError::Secp256k1Error(e.to_string()))?;
    let asset_comm = crate::generators::create_asset_commitment(&tag, &abf_tweak)?;

    // 3. Create commitment and range proof with provided vbf
    //    Embed token_uid(32B) + asset_blinding_factor(32B) in message for recipient recovery
    let vbf_tweak = Tweak::from_slice(value_blinding_factor)
        .map_err(|e| HathorCtError::Secp256k1Error(e.to_string()))?;
    let comm = crate::pedersen::create_commitment(value, &vbf_tweak, &asset_comm)?;
    let mut message = [0u8; 64];
    message[..32].copy_from_slice(token_uid);
    message[32..64].copy_from_slice(asset_blinding_factor);
    let proof = crate::rangeproof::create_range_proof(
        value, &vbf_tweak, &comm, &asset_comm, Some(&message), Some(&nonce_sk),
    )?;

    Ok(FullShieldedOutputResult {
        ephemeral_pubkey: eph_pk_bytes,
        commitment: comm.serialize().to_vec(),
        range_proof: proof.serialize(),
        value_blinding_factor: *value_blinding_factor,
        asset_commitment: asset_comm.serialize().to_vec(),
        asset_blinding_factor: *asset_blinding_factor,
    })
}

/// Result of creating an AmountShielded output (amount hidden, token visible).
pub struct AmountFullShieldedOutputResult {
    /// Compressed ephemeral public key (33 bytes).
    pub ephemeral_pubkey: [u8; 33],
    /// Serialized Pedersen commitment (33 bytes).
    pub commitment: Vec<u8>,
    /// Serialized Borromean range proof.
    pub range_proof: Vec<u8>,
    /// Value blinding factor (32 bytes).
    pub value_blinding_factor: [u8; 32],
}

/// Create an AmountShielded output (amount hidden, token visible).
///
/// Uses `derive_asset_tag(token_uid)` as the unblinded generator.
pub fn create_amount_shielded_output(
    value: u64,
    recipient_pubkey: &[u8],
    token_uid: &TokenUid,
    value_blinding_factor: &[u8; 32],
) -> Result<AmountFullShieldedOutputResult, HathorCtError> {
    // 1. Generate ephemeral keypair and derive ECDH nonce
    let (eph_pk_bytes, nonce_sk) = generate_ecdh_nonce(recipient_pubkey)?;

    // 2. Use unblinded asset tag as generator
    let generator = crate::generators::derive_asset_tag(token_uid)?;

    // 3. Create commitment and range proof
    let vbf_tweak = Tweak::from_slice(value_blinding_factor)
        .map_err(|e| HathorCtError::Secp256k1Error(e.to_string()))?;
    let comm = crate::pedersen::create_commitment(value, &vbf_tweak, &generator)?;
    let proof = crate::rangeproof::create_range_proof(
        value, &vbf_tweak, &comm, &generator, None, Some(&nonce_sk),
    )?;

    Ok(AmountFullShieldedOutputResult {
        ephemeral_pubkey: eph_pk_bytes,
        commitment: comm.serialize().to_vec(),
        range_proof: proof.serialize(),
        value_blinding_factor: *value_blinding_factor,
    })
}

/// Result of rewinding an AmountShielded output.
pub struct RewindAmountShieldedResult {
    /// Recovered value.
    pub value: u64,
    /// Recovered value blinding factor (32 bytes).
    pub blinding_factor: Vec<u8>,
}

/// Rewind an AmountShielded output to recover value and blinding factor.
///
/// The recipient uses their private key + the ephemeral pubkey from the output
/// to derive the ECDH nonce, then rewinds the range proof.
pub fn rewind_amount_shielded_output(
    private_key: &[u8],
    ephemeral_pubkey: &[u8],
    commitment: &[u8],
    range_proof: &[u8],
    token_uid: &TokenUid,
) -> Result<RewindAmountShieldedResult, HathorCtError> {
    // 1. Derive ECDH nonce
    let nonce_sk = derive_rewind_nonce_from_keys(private_key, ephemeral_pubkey)?;

    // 2. Use unblinded asset tag as generator
    let generator = crate::generators::derive_asset_tag(token_uid)?;

    // 3. Rewind range proof
    let comm = crate::pedersen::deserialize_commitment(commitment)?;
    let proof = crate::rangeproof::deserialize_range_proof(range_proof)?;
    let (value, blinding, _message) =
        crate::rangeproof::rewind_range_proof(&proof, &comm, &nonce_sk, &generator)?;

    Ok(RewindAmountShieldedResult {
        value,
        blinding_factor: blinding.as_ref().to_vec(),
    })
}

/// Result of rewinding a FullShielded output.
pub struct RewindFullShieldedResult {
    /// Recovered value.
    pub value: u64,
    /// Recovered value blinding factor (32 bytes).
    pub blinding_factor: Vec<u8>,
    /// Recovered token UID (32 bytes, from message).
    pub token_uid: [u8; 32],
    /// Recovered asset blinding factor (32 bytes, from message).
    pub asset_blinding_factor: [u8; 32],
}

/// Rewind a FullShielded output to recover value, blinding factor, token UID and asset blinding.
///
/// For FullShielded, the generator is the `asset_commitment` from the output,
/// and the message contains `token_uid(32B) || asset_blinding_factor(32B)`.
pub fn rewind_full_shielded_output(
    private_key: &[u8],
    ephemeral_pubkey: &[u8],
    commitment: &[u8],
    range_proof: &[u8],
    asset_commitment: &[u8],
) -> Result<RewindFullShieldedResult, HathorCtError> {
    // 1. Derive ECDH nonce
    let nonce_sk = derive_rewind_nonce_from_keys(private_key, ephemeral_pubkey)?;

    // 2. Use asset_commitment as generator
    let generator = crate::generators::deserialize_generator(asset_commitment)?;

    // 3. Rewind range proof
    let comm = crate::pedersen::deserialize_commitment(commitment)?;
    let proof = crate::rangeproof::deserialize_range_proof(range_proof)?;
    let (value, blinding, message) =
        crate::rangeproof::rewind_range_proof(&proof, &comm, &nonce_sk, &generator)?;

    // 4. Extract token_uid and asset_blinding_factor from message
    if message.len() < 64 {
        return Err(HathorCtError::RangeProofError(
            "message too short: expected at least 64 bytes (token_uid + asset_blinding_factor)".into(),
        ));
    }
    let mut token_uid = [0u8; 32];
    let mut asset_blinding_factor = [0u8; 32];
    token_uid.copy_from_slice(&message[..32]);
    asset_blinding_factor.copy_from_slice(&message[32..64]);

    // 5. Verify that token_uid + asset_blinding_factor reproduce the asset_commitment.
    //    This prevents a malicious sender from embedding a wrong token_uid.
    let tag = crate::generators::derive_tag(&token_uid)?;
    let abf_tweak = Tweak::from_slice(&asset_blinding_factor)
        .map_err(|e| HathorCtError::Secp256k1Error(e.to_string()))?;
    let recomputed = crate::generators::create_asset_commitment(&tag, &abf_tweak)?;
    // SEC-06: this equality is intentionally variable-time. Both operands are
    // public, attacker-known values — `generator` is the on-chain
    // asset_commitment and `recomputed` is derived from the sender-embedded
    // (token_uid, abf) in the proof message — so there is no secret to leak via
    // timing. Do NOT copy this pattern to a comparison where either operand is
    // secret-dependent (e.g. a MAC/tag over a private key); use a constant-time
    // equality there.
    if recomputed.serialize() != generator.serialize() {
        return Err(HathorCtError::RangeProofError(
            "asset commitment verification failed: extracted token_uid and asset_blinding_factor \
             do not reproduce the asset_commitment from the output"
                .into(),
        ));
    }

    Ok(RewindFullShieldedResult {
        value,
        blinding_factor: blinding.as_ref().to_vec(),
        token_uid,
        asset_blinding_factor,
    })
}

/// Internal helper: generate ephemeral keypair, compute ECDH, return (ephemeral_pubkey, nonce_sk).
///
/// SEC-03: the intermediate ephemeral private key, ECDH shared secret and nonce
/// bytes are wiped from the stack before returning so they do not linger in
/// freed memory. (Full zeroization across the FFI/JS boundary is tracked
/// separately; this covers the crypto-core hot path.)
fn generate_ecdh_nonce(recipient_pubkey: &[u8]) -> Result<([u8; 33], SecretKey), HathorCtError> {
    let (mut eph_sk_bytes, eph_pk_bytes) = generate_ephemeral_keypair();
    let eph_sk = parse_secret_key(&eph_sk_bytes)?;
    let recipient_pk = parse_public_key(recipient_pubkey)?;
    let mut shared_secret = derive_ecdh_shared_secret(&eph_sk, &recipient_pk);
    let mut nonce = derive_rewind_nonce(&shared_secret);
    let nonce_sk = SecretKey::from_slice(&nonce)
        .map_err(|e| HathorCtError::Secp256k1Error(e.to_string()));
    eph_sk_bytes.zeroize();
    shared_secret.zeroize();
    nonce.zeroize();
    Ok((eph_pk_bytes, nonce_sk?))
}

/// Internal helper: derive rewind nonce SecretKey from private key + ephemeral pubkey.
///
/// SEC-03: wipe the intermediate ECDH shared secret and nonce bytes.
fn derive_rewind_nonce_from_keys(
    private_key: &[u8],
    ephemeral_pubkey: &[u8],
) -> Result<SecretKey, HathorCtError> {
    let sk = parse_secret_key(private_key)?;
    let pk = parse_public_key(ephemeral_pubkey)?;
    let mut shared_secret = derive_ecdh_shared_secret(&sk, &pk);
    let mut nonce = derive_rewind_nonce(&shared_secret);
    let nonce_sk = SecretKey::from_slice(&nonce)
        .map_err(|e| HathorCtError::Secp256k1Error(e.to_string()));
    shared_secret.zeroize();
    nonce.zeroize();
    nonce_sk
}

/// Parse a 33-byte compressed public key.
pub fn parse_public_key(bytes: &[u8]) -> Result<PublicKey, HathorCtError> {
    if bytes.len() != 33 {
        return Err(HathorCtError::Secp256k1Error(
            "compressed public key must be 33 bytes".into(),
        ));
    }
    PublicKey::from_slice(bytes).map_err(|e| HathorCtError::Secp256k1Error(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_sizes() {
        let (sk, pk) = generate_ephemeral_keypair();
        assert_eq!(sk.len(), 32);
        assert_eq!(pk.len(), 33);
        assert!(pk[0] == 0x02 || pk[0] == 0x03);
    }

    #[test]
    fn test_ecdh_symmetric() {
        let (sk_a, pk_a) = generate_ephemeral_keypair();
        let (sk_b, pk_b) = generate_ephemeral_keypair();

        let sk_a = SecretKey::from_slice(&sk_a).unwrap();
        let pk_a = PublicKey::from_slice(&pk_a).unwrap();
        let sk_b = SecretKey::from_slice(&sk_b).unwrap();
        let pk_b = PublicKey::from_slice(&pk_b).unwrap();

        let secret_ab = derive_ecdh_shared_secret(&sk_a, &pk_b);
        let secret_ba = derive_ecdh_shared_secret(&sk_b, &pk_a);
        assert_eq!(secret_ab, secret_ba);
    }

    #[test]
    fn test_nonce_deterministic() {
        let secret = [0x42u8; 32];
        let n1 = derive_rewind_nonce(&secret);
        let n2 = derive_rewind_nonce(&secret);
        assert_eq!(n1, n2);
        assert_eq!(n1.len(), 32);
    }

    #[test]
    fn test_different_secrets_different_nonces() {
        let n1 = derive_rewind_nonce(&[0x01u8; 32]);
        let n2 = derive_rewind_nonce(&[0x02u8; 32]);
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_random_blinding_factor_is_valid_scalar() {
        // NEW-07: the generator must always return a valid, non-zero scalar.
        for _ in 0..100 {
            let bf = generate_random_blinding_factor();
            assert!(SecretKey::from_slice(&bf).is_ok());
            assert_ne!(bf, [0u8; 32]);
        }
    }

    // TEST-03: full create -> rewind round-trip for AmountShielded.
    #[test]
    fn test_amount_shielded_create_rewind_roundtrip() {
        let (recipient_sk, recipient_pk) = generate_ephemeral_keypair();
        let token_uid: TokenUid = [3u8; 32];
        let vbf = generate_random_blinding_factor();

        let out = create_amount_shielded_output(5000, &recipient_pk, &token_uid, &vbf).unwrap();
        let rewound = rewind_amount_shielded_output(
            &recipient_sk,
            &out.ephemeral_pubkey,
            &out.commitment,
            &out.range_proof,
            &token_uid,
        )
        .unwrap();

        assert_eq!(rewound.value, 5000);
        assert_eq!(rewound.blinding_factor, vbf.to_vec());
    }

    // TEST-03: full create -> rewind round-trip for FullShielded, incl. the
    // mandatory token-uid / asset-blinding recovery.
    #[test]
    fn test_full_shielded_create_rewind_roundtrip() {
        let (recipient_sk, recipient_pk) = generate_ephemeral_keypair();
        let token_uid: TokenUid = [9u8; 32];
        let vbf = generate_random_blinding_factor();
        let abf = generate_random_blinding_factor();

        let out =
            create_full_shielded_output(7777, &recipient_pk, &token_uid, &vbf, &abf).unwrap();
        let rewound = rewind_full_shielded_output(
            &recipient_sk,
            &out.ephemeral_pubkey,
            &out.commitment,
            &out.range_proof,
            &out.asset_commitment,
        )
        .unwrap();

        assert_eq!(rewound.value, 7777);
        assert_eq!(rewound.blinding_factor, vbf.to_vec());
        assert_eq!(rewound.token_uid, token_uid);
        assert_eq!(rewound.asset_blinding_factor, abf);
    }

    // TEST-03: wrong recipient cannot rewind (expected during scanning).
    #[test]
    fn test_wrong_recipient_rewind_fails() {
        let (_recipient_sk, recipient_pk) = generate_ephemeral_keypair();
        let (wrong_sk, _wrong_pk) = generate_ephemeral_keypair();
        let token_uid: TokenUid = [3u8; 32];
        let vbf = generate_random_blinding_factor();

        let out = create_amount_shielded_output(5000, &recipient_pk, &token_uid, &vbf).unwrap();
        assert!(rewind_amount_shielded_output(
            &wrong_sk,
            &out.ephemeral_pubkey,
            &out.commitment,
            &out.range_proof,
            &token_uid,
        )
        .is_err());
    }

    // TEST-03 / SEC anti-spoof: a FullShielded output whose embedded token_uid
    // does not match the asset_commitment must be rejected by the cross-check.
    #[test]
    fn test_full_shielded_token_uid_spoof_rejected() {
        let (recipient_sk, recipient_pk) = generate_ephemeral_keypair();
        let real_token: TokenUid = [9u8; 32];
        let vbf = generate_random_blinding_factor();
        let abf = generate_random_blinding_factor();

        let out =
            create_full_shielded_output(7777, &recipient_pk, &real_token, &vbf, &abf).unwrap();

        // Tamper: present a different asset_commitment (for another token) as the
        // generator. The (token_uid, abf) recovered from the proof message will
        // no longer reproduce it, so the cross-check must fail.
        let other_tag = crate::generators::derive_tag(&[1u8; 32]).unwrap();
        let other_abf = Tweak::from_slice(&abf).unwrap();
        let other_ac = crate::generators::create_asset_commitment(&other_tag, &other_abf).unwrap();

        let res = rewind_full_shielded_output(
            &recipient_sk,
            &out.ephemeral_pubkey,
            &out.commitment,
            &out.range_proof,
            &other_ac.serialize(),
        );
        assert!(res.is_err());
    }
}
