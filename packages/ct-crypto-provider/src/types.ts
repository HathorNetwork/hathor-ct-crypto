/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

/**
 * Shielded output modes matching the Hathor protocol.
 */
export enum ShieldedOutputMode {
  AMOUNT_SHIELDED = 1,
  FULLY_SHIELDED = 2,
}

/**
 * Result of creating a shielded output via the crypto provider.
 * `assetCommitment` and `assetBlindingFactor` are present only for FullShielded outputs.
 */
export interface ICreatedShieldedOutput {
  ephemeralPubkey: Buffer;
  commitment: Buffer;
  rangeProof: Buffer;
  blindingFactor: Buffer;
  assetCommitment?: Buffer;
  assetBlindingFactor?: Buffer;
}

/**
 * Result of rewinding an AmountShielded output.
 */
export interface IRewoundAmountShieldedOutput {
  value: bigint;
  blindingFactor: Buffer;
}

/**
 * Result of rewinding a FullShielded output.
 * `tokenUid` is hex-encoded (32 bytes → 64 hex chars) — the abstract class
 * normalises raw bytes returned by the binding before exposing them.
 */
export interface IRewoundFullShieldedOutput {
  value: bigint;
  blindingFactor: Buffer;
  tokenUid: string;
  assetBlindingFactor: Buffer;
}

/**
 * Entry in the input/output list passed to computeBalancingBlindingFactor.
 * Long-form names — no `vbf`/`gbf` shorthand. The naming-impedance debate
 * is settled: every level of the stack uses the long form.
 */
export interface IBlindingEntry {
  value: bigint;
  valueBlindingFactor: Buffer;
  generatorBlindingFactor: Buffer;
}

/**
 * Entry in the domain list passed to createSurjectionProof.
 */
export interface ISurjectionDomainEntry {
  generator: Buffer;
  tag: Buffer;
  blindingFactor: Buffer;
}

/**
 * Result of opening a FullShielded commitment.
 */
export interface IOpenedFullShieldedCommitment {
  valueCommitment: Buffer;
  assetCommitment: Buffer;
}

/**
 * Swappable crypto provider for shielded output operations.
 *
 * Function names follow the SHIELDED-OUTPUTS-CLIENT-GUIDE.md specification.
 *
 * Implementations:
 *   - Node.js: @hathor/ct-crypto-node (NAPI native addon)
 *   - Browser: @hathor/ct-crypto-wasm (wasm-bindgen, verifier-only)
 *   - Mobile:  hathor-wallet-mobile/src/shieldedCryptoProvider.js (UniFFI via RN bridge)
 *
 * Every method returns `Promise<T>`. Sync underlying calls (NAPI is sync,
 * wasm-bindgen is sync) are wrapped in `async` by the abstract class so
 * callers never face a `T | Promise<T>` union.
 *
 * Conformance is structural — anything matching this interface is accepted
 * by wallet-lib's `setShieldedCryptoProvider`. The recommended path is to
 * extend `AbstractShieldedProvider`, which pre-implements every method and
 * delegates to a smaller set of abstract `_raw*` methods that subclasses
 * fill in per platform.
 */
export interface IShieldedCryptoProvider {
  /**
   * Generate a random 32-byte blinding factor (valid secp256k1 scalar).
   * MUST use the Rust crypto RNG — never JS crypto.randomBytes (see the
   * SHIELDED-OUTPUTS-CLIENT-GUIDE.md "RNG" section for why).
   */
  generateRandomBlindingFactor(): Promise<Buffer>;

  /**
   * Create an AmountShielded output (amount hidden, token visible).
   * Caller provides the value blinding factor.
   */
  createAmountShieldedOutput(
    value: bigint,
    recipientPubkey: Buffer,
    tokenUid: Buffer,
    valueBlindingFactor: Buffer
  ): Promise<ICreatedShieldedOutput>;

  /**
   * Create a FullShielded output (amount AND token hidden).
   * Caller provides both the value and asset blinding factors.
   */
  createShieldedOutputWithBothBlindings(
    value: bigint,
    recipientPubkey: Buffer,
    tokenUid: Buffer,
    valueBlindingFactor: Buffer,
    assetBlindingFactor: Buffer
  ): Promise<ICreatedShieldedOutput>;

  /**
   * Rewind an AmountShielded output to recover value and blinding factor.
   * The token UID is known from the visible token_data field.
   */
  rewindAmountShieldedOutput(
    privateKey: Buffer,
    ephemeralPubkey: Buffer,
    commitment: Buffer,
    rangeProof: Buffer,
    tokenUid: Buffer
  ): Promise<IRewoundAmountShieldedOutput>;

  /**
   * Rewind a FullShielded output to recover value, blinding factor, token UID,
   * and asset blinding factor. Does NOT take tokenUid — it's recovered from
   * the proof message and cross-checked against the on-chain asset commitment
   * by the caller (SHIELDED-OUTPUTS-CLIENT-GUIDE.md "FullShielded cross-check").
   */
  rewindFullShieldedOutput(
    privateKey: Buffer,
    ephemeralPubkey: Buffer,
    commitment: Buffer,
    rangeProof: Buffer,
    assetCommitment: Buffer
  ): Promise<IRewoundFullShieldedOutput>;

  /**
   * Compute the balancing blinding factor for the last shielded output.
   * The homomorphic balance equation requires `Σr_in = Σr_out`; this helper
   * solves for the last output's bf given everything else.
   *
   * @param value - The value of the last output
   * @param generatorBlindingFactor - For the last output (ZERO_TWEAK for AmountShielded)
   * @param inputs - All inputs (transparent + shielded), long-form
   * @param otherOutputs - All other outputs (not the last), long-form
   */
  computeBalancingBlindingFactor(
    value: bigint,
    generatorBlindingFactor: Buffer,
    inputs: IBlindingEntry[],
    otherOutputs: IBlindingEntry[]
  ): Promise<Buffer>;

  /**
   * Derive the raw 32-byte Tag scalar from a token UID. Used by surjection
   * proofs and asset commitments.
   */
  deriveTag(tokenUid: Buffer): Promise<Buffer>;

  /**
   * Derive the 33-byte unblinded asset generator from a token UID. Used as
   * the value-commitment generator for AmountShielded outputs.
   */
  deriveAssetTag(tokenUid: Buffer): Promise<Buffer>;

  /**
   * Build the 33-byte Pedersen commitment `value*generator + bf*G`.
   */
  createCommitment(value: bigint, blindingFactor: Buffer, generator: Buffer): Promise<Buffer>;

  /**
   * Build the 33-byte blinded asset generator `Tag*G + bf*H`.
   */
  createAssetCommitment(tag: Buffer, blindingFactor: Buffer): Promise<Buffer>;

  /**
   * Create a surjection proof proving the output asset derives from one
   * of the input assets in the domain.
   */
  createSurjectionProof(
    codomainTag: Buffer,
    codomainBlindingFactor: Buffer,
    domain: ISurjectionDomainEntry[]
  ): Promise<Buffer>;

  /**
   * ECDH shared secret derivation (scan optimization, advanced consumers).
   */
  deriveEcdhSharedSecret(privateKey: Buffer, peerPubkey: Buffer): Promise<Buffer>;

  /**
   * Recompute the AmountShielded value commitment from a cleartext opening
   * (value, blinding factor, public token UID). Verifier-only — used by
   * "view tx unblinded" flows to validate a shared opening matches the
   * on-chain commitment without needing a range proof.
   */
  openAmountShieldedCommitment(
    value: bigint,
    valueBlindingFactor: Buffer,
    tokenUid: Buffer
  ): Promise<Buffer>;

  /**
   * Recompute both the value and asset commitments for a FullShielded
   * output from a cleartext opening (value, vbf, tokenUid, abf).
   * Verifier-only.
   */
  openFullShieldedCommitment(
    value: bigint,
    valueBlindingFactor: Buffer,
    tokenUid: Buffer,
    assetBlindingFactor: Buffer
  ): Promise<IOpenedFullShieldedCommitment>;
}
