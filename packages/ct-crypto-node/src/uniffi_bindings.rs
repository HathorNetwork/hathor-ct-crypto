//! UniFFI bindings for iOS (Swift) and Android (Kotlin).
//!
//! Uses proc-macro approach — no .udl file needed.

use secp256k1_zkp::{Generator, PublicKey, SecretKey, Tweak, ZERO_TWEAK, SECP256K1};
use hathor_ct_crypto_core::error::HathorCtError;

/// Backward-compat wrapper: accepts raw byte slices and returns shared secret bytes.
fn ecdh_shared_secret_bytes(privkey: &[u8; 32], pubkey: &[u8; 33]) -> Result<[u8; 32], CryptoError> {
    let sk = SecretKey::from_slice(privkey)
        .map_err(|e| CryptoError::InvalidInput { msg: e.to_string() })?;
    let pk = PublicKey::from_slice(pubkey)
        .map_err(|e| CryptoError::InvalidInput { msg: e.to_string() })?;
    Ok(hathor_ct_crypto_core::ecdh::derive_ecdh_shared_secret(&sk, &pk))
}

// --- Error ---

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CryptoError {
    #[error("Invalid input: {msg}")]
    InvalidInput { msg: String },
    #[error("Crypto operation failed: {msg}")]
    CryptoFailed { msg: String },
}

impl From<HathorCtError> for CryptoError {
    fn from(e: HathorCtError) -> Self {
        CryptoError::CryptoFailed { msg: e.to_string() }
    }
}

fn to_uid(bytes: &[u8]) -> Result<[u8; 32], CryptoError> {
    bytes.try_into().map_err(|_| CryptoError::InvalidInput { msg: "must be 32 bytes".into() })
}

fn to_tweak(bytes: &[u8]) -> Result<Tweak, CryptoError> {
    if bytes.len() != 32 {
        return Err(CryptoError::InvalidInput { msg: "must be 32 bytes".into() });
    }
    Tweak::from_slice(bytes).map_err(|e| CryptoError::InvalidInput { msg: e.to_string() })
}

fn to_sk(bytes: &[u8]) -> Result<SecretKey, CryptoError> {
    if bytes.len() != 32 {
        return Err(CryptoError::InvalidInput { msg: "must be 32 bytes".into() });
    }
    SecretKey::from_slice(bytes).map_err(|e| CryptoError::InvalidInput { msg: e.to_string() })
}

fn to_gen(bytes: &[u8]) -> Result<Generator, CryptoError> {
    if bytes.len() != 33 {
        return Err(CryptoError::InvalidInput { msg: "must be 33 bytes".into() });
    }
    hathor_ct_crypto_core::generators::deserialize_generator(bytes).map_err(CryptoError::from)
}

// --- Records ---

#[derive(uniffi::Record)]
pub struct CreatedShieldedOutput {
    pub ephemeral_pubkey: Vec<u8>,
    pub commitment: Vec<u8>,
    pub range_proof: Vec<u8>,
    pub blinding_factor: Vec<u8>,
    pub asset_commitment: Option<Vec<u8>>,
    pub asset_blinding_factor: Option<Vec<u8>>,
}

#[derive(uniffi::Record)]
pub struct DecryptedShieldedOutput {
    pub value: u64,
    pub blinding_factor: Vec<u8>,
    pub token_uid: Vec<u8>,
    pub asset_blinding_factor: Option<Vec<u8>>,
    pub output_type: String,
}

#[derive(uniffi::Record)]
pub struct RewindResult {
    pub value: u64,
    pub blinding_factor: Vec<u8>,
    pub message: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct SurjectionDomainEntry {
    pub generator: Vec<u8>,
    pub tag: Vec<u8>,
    pub blinding_factor: Vec<u8>,
}

// --- Exported functions ---

#[uniffi::export]
pub fn derive_asset_tag_uniffi(token_uid: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let uid = to_uid(&token_uid)?;
    let tag = hathor_ct_crypto_core::generators::derive_asset_tag(&uid)?;
    Ok(tag.serialize().to_vec())
}

#[uniffi::export]
pub fn derive_tag_uniffi(token_uid: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let uid = to_uid(&token_uid)?;
    let tag = hathor_ct_crypto_core::generators::derive_tag(&uid)?;
    let tag_bytes: [u8; 32] = tag.into();
    Ok(tag_bytes.to_vec())
}

#[uniffi::export]
pub fn htr_asset_tag_uniffi() -> Vec<u8> {
    hathor_ct_crypto_core::generators::htr_asset_tag().serialize().to_vec()
}

#[uniffi::export]
pub fn create_asset_commitment_uniffi(tag: Vec<u8>, blinding_factor: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let t = secp256k1_zkp::Tag::from(to_uid(&tag)?);
    let bf = to_tweak(&blinding_factor)?;
    let gen = hathor_ct_crypto_core::generators::create_asset_commitment(&t, &bf)?;
    Ok(gen.serialize().to_vec())
}

#[uniffi::export]
pub fn derive_ecdh_shared_secret_uniffi(privkey: Vec<u8>, pubkey: Vec<u8>) -> Result<Vec<u8>, CryptoError> {
    let pk: [u8; 32] = privkey.as_slice().try_into()
        .map_err(|_| CryptoError::InvalidInput { msg: "privkey must be 32 bytes".into() })?;
    let pub_bytes: [u8; 33] = pubkey.as_slice().try_into()
        .map_err(|_| CryptoError::InvalidInput { msg: "pubkey must be 33 bytes".into() })?;
    let result = ecdh_shared_secret_bytes(&pk, &pub_bytes)?;
    Ok(result.to_vec())
}

#[uniffi::export]
pub fn derive_rewind_nonce_uniffi(shared_secret: Vec<u8>) -> Vec<u8> {
    let ss: [u8; 32] = shared_secret.as_slice().try_into().unwrap_or([0u8; 32]);
    hathor_ct_crypto_core::ecdh::derive_rewind_nonce(&ss).to_vec()
}

#[uniffi::export]
pub fn create_shielded_output_uniffi(
    value: u64,
    recipient_pubkey: Vec<u8>,
    token_uid: Vec<u8>,
    fully_shielded: bool,
) -> Result<CreatedShieldedOutput, CryptoError> {
    let pub_bytes: [u8; 33] = recipient_pubkey.as_slice().try_into()
        .map_err(|_| CryptoError::InvalidInput { msg: "pubkey must be 33 bytes".into() })?;
    let tuid = to_uid(&token_uid)?;

    let (eph_sk, eph_pk) = SECP256K1.generate_keypair(&mut rand::thread_rng());
    let shared_secret = ecdh_shared_secret_bytes(&eph_sk.secret_bytes(), &pub_bytes)?;
    let nonce = hathor_ct_crypto_core::ecdh::derive_rewind_nonce(&shared_secret);
    let nonce_sk = to_sk(&nonce)?;

    // For FullShielded outputs, the rangeproof message MUST embed
    // `token_uid(32B) || asset_blinding_factor(32B)` so the recipient can
    // recover them on rewind. Without this the cross-check in
    // rewind_full_shielded_output fails ("asset commitment verification failed").
    let (generator, ac_bytes, abf_bytes, message) = if fully_shielded {
        let abf_sk = SecretKey::new(&mut rand::thread_rng());
        let abf = abf_sk.secret_bytes();
        let tag = hathor_ct_crypto_core::generators::derive_tag(&tuid)?;
        let abf_tweak = to_tweak(&abf)?;
        let asset_comm = hathor_ct_crypto_core::generators::create_asset_commitment(&tag, &abf_tweak)?;
        let mut msg = [0u8; 64];
        msg[..32].copy_from_slice(&tuid);
        msg[32..64].copy_from_slice(&abf);
        (asset_comm, Some(asset_comm.serialize().to_vec()), Some(abf.to_vec()), Some(msg))
    } else {
        (hathor_ct_crypto_core::generators::derive_asset_tag(&tuid)?, None, None, None)
    };

    let bf_sk = SecretKey::new(&mut rand::thread_rng());
    let bf = bf_sk.secret_bytes();
    let bf_tweak = to_tweak(&bf)?;
    let comm = hathor_ct_crypto_core::pedersen::create_commitment(value, &bf_tweak, &generator)?;
    let proof = hathor_ct_crypto_core::rangeproof::create_range_proof(
        value, &bf_tweak, &comm, &generator,
        message.as_ref().map(|m| m.as_slice()),
        Some(&nonce_sk),
    )?;

    Ok(CreatedShieldedOutput {
        ephemeral_pubkey: eph_pk.serialize().to_vec(),
        commitment: comm.serialize().to_vec(),
        range_proof: proof.serialize(),
        blinding_factor: bf.to_vec(),
        asset_commitment: ac_bytes,
        asset_blinding_factor: abf_bytes,
    })
}

#[uniffi::export]
pub fn create_shielded_output_with_blinding_uniffi(
    value: u64,
    recipient_pubkey: Vec<u8>,
    token_uid: Vec<u8>,
    fully_shielded: bool,
    blinding_factor: Vec<u8>,
) -> Result<CreatedShieldedOutput, CryptoError> {
    let pub_bytes: [u8; 33] = recipient_pubkey.as_slice().try_into()
        .map_err(|_| CryptoError::InvalidInput { msg: "pubkey must be 33 bytes".into() })?;
    let tuid = to_uid(&token_uid)?;
    let bf = to_uid(&blinding_factor)?;

    let (eph_sk, eph_pk) = SECP256K1.generate_keypair(&mut rand::thread_rng());
    let shared_secret = ecdh_shared_secret_bytes(&eph_sk.secret_bytes(), &pub_bytes)?;
    let nonce = hathor_ct_crypto_core::ecdh::derive_rewind_nonce(&shared_secret);
    let nonce_sk = to_sk(&nonce)?;

    // See comment in create_shielded_output_uniffi above — FullShielded must
    // embed (token_uid || abf) in the rangeproof message for recipient recovery.
    let (generator, ac_bytes, abf_bytes, message) = if fully_shielded {
        let abf_sk = SecretKey::new(&mut rand::thread_rng());
        let abf = abf_sk.secret_bytes();
        let tag = hathor_ct_crypto_core::generators::derive_tag(&tuid)?;
        let abf_tweak = to_tweak(&abf)?;
        let asset_comm = hathor_ct_crypto_core::generators::create_asset_commitment(&tag, &abf_tweak)?;
        let mut msg = [0u8; 64];
        msg[..32].copy_from_slice(&tuid);
        msg[32..64].copy_from_slice(&abf);
        (asset_comm, Some(asset_comm.serialize().to_vec()), Some(abf.to_vec()), Some(msg))
    } else {
        (hathor_ct_crypto_core::generators::derive_asset_tag(&tuid)?, None, None, None)
    };

    let bf_tweak = to_tweak(&bf)?;
    let comm = hathor_ct_crypto_core::pedersen::create_commitment(value, &bf_tweak, &generator)?;
    let proof = hathor_ct_crypto_core::rangeproof::create_range_proof(
        value, &bf_tweak, &comm, &generator,
        message.as_ref().map(|m| m.as_slice()),
        Some(&nonce_sk),
    )?;

    Ok(CreatedShieldedOutput {
        ephemeral_pubkey: eph_pk.serialize().to_vec(),
        commitment: comm.serialize().to_vec(),
        range_proof: proof.serialize(),
        blinding_factor: bf.to_vec(),
        asset_commitment: ac_bytes,
        asset_blinding_factor: abf_bytes,
    })
}

#[uniffi::export]
pub fn create_shielded_output_with_both_blindings_uniffi(
    value: u64,
    recipient_pubkey: Vec<u8>,
    token_uid: Vec<u8>,
    value_blinding_factor: Vec<u8>,
    asset_blinding_factor: Vec<u8>,
) -> Result<CreatedShieldedOutput, CryptoError> {
    let pub_bytes: [u8; 33] = recipient_pubkey.as_slice().try_into()
        .map_err(|_| CryptoError::InvalidInput { msg: "pubkey must be 33 bytes".into() })?;
    let tuid = to_uid(&token_uid)?;
    let vbf = to_uid(&value_blinding_factor)?;
    let abf = to_uid(&asset_blinding_factor)?;

    let (eph_sk, eph_pk) = SECP256K1.generate_keypair(&mut rand::thread_rng());
    let shared_secret = ecdh_shared_secret_bytes(&eph_sk.secret_bytes(), &pub_bytes)?;
    let nonce = hathor_ct_crypto_core::ecdh::derive_rewind_nonce(&shared_secret);
    let nonce_sk = to_sk(&nonce)?;

    let tag = hathor_ct_crypto_core::generators::derive_tag(&tuid)?;
    let abf_tweak = to_tweak(&abf)?;
    let asset_comm = hathor_ct_crypto_core::generators::create_asset_commitment(&tag, &abf_tweak)?;
    let vbf_tweak = to_tweak(&vbf)?;
    let comm = hathor_ct_crypto_core::pedersen::create_commitment(value, &vbf_tweak, &asset_comm)?;
    // FullShielded: embed (token_uid || abf) in the rangeproof message so
    // the recipient can recover them on rewind and verify the asset_commitment.
    let mut message = [0u8; 64];
    message[..32].copy_from_slice(&tuid);
    message[32..64].copy_from_slice(&abf);
    let proof = hathor_ct_crypto_core::rangeproof::create_range_proof(
        value, &vbf_tweak, &comm, &asset_comm, Some(&message), Some(&nonce_sk),
    )?;

    Ok(CreatedShieldedOutput {
        ephemeral_pubkey: eph_pk.serialize().to_vec(),
        commitment: comm.serialize().to_vec(),
        range_proof: proof.serialize(),
        blinding_factor: vbf.to_vec(),
        asset_commitment: Some(asset_comm.serialize().to_vec()),
        asset_blinding_factor: Some(abf.to_vec()),
    })
}

#[uniffi::export]
pub fn decrypt_shielded_output_uniffi(
    recipient_privkey: Vec<u8>,
    ephemeral_pubkey: Vec<u8>,
    commitment: Vec<u8>,
    range_proof: Vec<u8>,
    token_uid: Option<Vec<u8>>,
    asset_commitment: Option<Vec<u8>>,
) -> Result<DecryptedShieldedOutput, CryptoError> {
    // FullShielded path: recover token_uid and asset_blinding_factor from the
    // rangeproof message. Delegates to the same well-tested implementation the
    // Node binding uses (hathor_ct_crypto_core::ecdh::rewind_full_shielded_output), which also
    // performs the asset_commitment cross-check for malicious-sender protection.
    if let Some(ref ac) = asset_commitment {
        let result = hathor_ct_crypto_core::ecdh::rewind_full_shielded_output(
            &recipient_privkey,
            &ephemeral_pubkey,
            &commitment,
            &range_proof,
            ac,
        )
        .map_err(|e| CryptoError::InvalidInput { msg: e.to_string() })?;
        return Ok(DecryptedShieldedOutput {
            value: result.value,
            blinding_factor: result.blinding_factor.to_vec(),
            token_uid: result.token_uid.to_vec(),
            asset_blinding_factor: Some(result.asset_blinding_factor.to_vec()),
            output_type: "FullShielded".into(),
        });
    }

    // AmountShielded path: token_uid is visible in the on-chain token_data field,
    // so the caller passes it in directly and the generator is derived from it.
    let tuid_bytes = token_uid.ok_or(CryptoError::InvalidInput {
        msg: "token_uid is required for AmountShielded decryption".into(),
    })?;

    let pk: [u8; 32] = recipient_privkey.as_slice().try_into()
        .map_err(|_| CryptoError::InvalidInput { msg: "privkey must be 32 bytes".into() })?;
    let eph: [u8; 33] = ephemeral_pubkey.as_slice().try_into()
        .map_err(|_| CryptoError::InvalidInput { msg: "ephemeral_pubkey must be 33 bytes".into() })?;
    let tuid = to_uid(&tuid_bytes)?;

    let shared_secret = ecdh_shared_secret_bytes(&pk, &eph)?;
    let nonce = hathor_ct_crypto_core::ecdh::derive_rewind_nonce(&shared_secret);
    let nonce_sk = to_sk(&nonce)?;

    let generator = hathor_ct_crypto_core::generators::derive_asset_tag(&tuid)?;

    let proof = hathor_ct_crypto_core::rangeproof::deserialize_range_proof(&range_proof)?;
    let comm = hathor_ct_crypto_core::pedersen::deserialize_commitment(&commitment)?;
    let (value, blinding, _msg) = hathor_ct_crypto_core::rangeproof::rewind_range_proof(&proof, &comm, &nonce_sk, &generator)?;
    hathor_ct_crypto_core::rangeproof::verify_range_proof(&proof, &comm, &generator)?;

    Ok(DecryptedShieldedOutput {
        value,
        blinding_factor: blinding.as_ref().to_vec(),
        token_uid: tuid.to_vec(),
        asset_blinding_factor: None,
        output_type: "AmountShielded".into(),
    })
}

#[uniffi::export]
pub fn create_surjection_proof_uniffi(
    codomain_tag: Vec<u8>,
    codomain_blinding_factor: Vec<u8>,
    domain: Vec<SurjectionDomainEntry>,
) -> Result<Vec<u8>, CryptoError> {
    let ct = secp256k1_zkp::Tag::from(to_uid(&codomain_tag)?);
    let cbf = to_tweak(&codomain_blinding_factor)?;
    let domain_vec: Vec<(Generator, secp256k1_zkp::Tag, Tweak)> = domain
        .iter()
        .map(|e| Ok((to_gen(&e.generator)?, secp256k1_zkp::Tag::from(to_uid(&e.tag)?), to_tweak(&e.blinding_factor)?)))
        .collect::<Result<Vec<_>, CryptoError>>()?;
    let proof = hathor_ct_crypto_core::surjection::create_surjection_proof(&ct, &cbf, &domain_vec)?;
    Ok(hathor_ct_crypto_core::surjection::serialize_surjection_proof(&proof))
}

#[uniffi::export]
pub fn compute_balancing_blinding_factor_uniffi(
    other_blinding_factors: Vec<Vec<u8>>,
) -> Result<Vec<u8>, CryptoError> {
    use secp256k1_zkp::Scalar;

    if other_blinding_factors.is_empty() {
        return Err(CryptoError::InvalidInput { msg: "need at least one blinding factor".into() });
    }

    let first_bf: [u8; 32] = other_blinding_factors[0].as_slice().try_into()
        .map_err(|_| CryptoError::InvalidInput { msg: "bf must be 32 bytes".into() })?;
    let mut sum = SecretKey::from_slice(&first_bf)
        .map_err(|e| CryptoError::InvalidInput { msg: e.to_string() })?;

    for bf_buf in &other_blinding_factors[1..] {
        let bf: [u8; 32] = bf_buf.as_slice().try_into()
            .map_err(|_| CryptoError::InvalidInput { msg: "bf must be 32 bytes".into() })?;
        let scalar = Scalar::from_be_bytes(bf)
            .map_err(|e| CryptoError::InvalidInput { msg: e.to_string() })?;
        sum = sum.add_tweak(&scalar)
            .map_err(|e| CryptoError::CryptoFailed { msg: e.to_string() })?;
    }
    Ok(sum.negate().secret_bytes().to_vec())
}

#[derive(uniffi::Record)]
pub struct BlindingEntry {
    pub value: u64,
    pub vbf: Vec<u8>,
    pub gbf: Vec<u8>,
}

#[uniffi::export]
pub fn compute_balancing_blinding_factor_full_uniffi(
    value: u64,
    generator_blinding_factor: Vec<u8>,
    inputs: Vec<BlindingEntry>,
    other_outputs: Vec<BlindingEntry>,
) -> Result<Vec<u8>, CryptoError> {
    let gbf = to_tweak(&generator_blinding_factor)?;

    let in_secrets: Vec<secp256k1_zkp::CommitmentSecrets> = inputs
        .iter()
        .map(|e| {
            let vbf = to_tweak(&e.vbf)?;
            let gbf = to_tweak(&e.gbf)?;
            Ok(secp256k1_zkp::CommitmentSecrets::new(e.value, vbf, gbf))
        })
        .collect::<Result<Vec<_>, CryptoError>>()?;

    let out_secrets: Vec<secp256k1_zkp::CommitmentSecrets> = other_outputs
        .iter()
        .map(|e| {
            let vbf = to_tweak(&e.vbf)?;
            let gbf = to_tweak(&e.gbf)?;
            Ok(secp256k1_zkp::CommitmentSecrets::new(e.value, vbf, gbf))
        })
        .collect::<Result<Vec<_>, CryptoError>>()?;

    let result = secp256k1_zkp::compute_adaptive_blinding_factor(
        SECP256K1, value, gbf, &in_secrets, &out_secrets,
    );
    Ok(result.as_ref().to_vec())
}

#[uniffi::export]
pub fn get_zero_tweak_uniffi() -> Vec<u8> {
    ZERO_TWEAK.as_ref().to_vec()
}

/// Generate a random 32-byte blinding factor (valid secp256k1 scalar).
///
/// Mirrors `napi_bindings::generate_random_blinding_factor`. Exposed via
/// UniFFI so the mobile RN bridge (and any future UniFFI consumer) can
/// call a dedicated RNG primitive — without this, mobile had to call
/// `create_shielded_output_uniffi` with dummy inputs and extract the
/// blinding factor from the unused result. That workaround is removed
/// once mobile picks up this new export.
#[uniffi::export]
pub fn generate_random_blinding_factor_uniffi() -> Vec<u8> {
    use rand::RngCore;
    let mut bf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bf);
    bf.to_vec()
}

/// Build a 33-byte Pedersen commitment `value * generator + blinding_factor * G`.
///
/// Mirrors `napi_bindings::create_commitment`. Required by the abstract
/// shielded crypto provider's composed `openAmountShieldedCommitment` /
/// `openFullShieldedCommitment` methods — mobile would otherwise be
/// unable to verify cleartext openings against on-chain commitments.
#[uniffi::export]
pub fn create_commitment_uniffi(
    value: u64,
    blinding_factor: Vec<u8>,
    generator: Vec<u8>,
) -> Result<Vec<u8>, CryptoError> {
    let bf_tweak = to_tweak(&blinding_factor)?;
    let gen = hathor_ct_crypto_core::generators::deserialize_generator(&generator)
        .map_err(CryptoError::from)?;
    let comm = hathor_ct_crypto_core::pedersen::create_commitment(value, &bf_tweak, &gen)?;
    Ok(comm.serialize().to_vec())
}
