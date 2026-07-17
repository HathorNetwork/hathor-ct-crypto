/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { Buffer } from 'buffer';
import { AbstractShieldedProvider } from '@hathor/ct-crypto-provider';
import * as wasm from './hathor_ct_crypto_wasm.js';

// Browsers do not provide a `Buffer` global. Import it from the
// `buffer` package so every provider call works in a bundled browser
// environment with no consumer configuration (webpack's ProvidePlugin does not
// define `Buffer` by default).

/**
 * Release a wasm-bindgen result object's Rust-side allocation. The rewind
 * results hold the recovered blinding factor in linear memory until `.free()`
 * (or eventual GC via FinalizationRegistry); freeing eagerly keeps secret
 * material from lingering. Guarded so it is a no-op against the test stub (and
 * any build whose result is a plain object without `.free`).
 */
function freeWasmResult(result) {
  if (result && typeof result.free === 'function') {
    result.free();
  }
}

/**
 * Browser-side shielded crypto provider, backed by this package's
 * wasm-bindgen build.
 *
 * Concrete subclass of `AbstractShieldedProvider`. Verifier-only by
 * policy: signing, RNG, surjection-proof creation, and balancing-blinding
 * factor computation throw via the base class's `_unsupported` helper.
 * Browser environments are an attack-surface explosion for key handling;
 * use `@hathor/ct-crypto-node` instead for those operations.
 *
 * The abstract class composes `openAmountShieldedCommitment` and
 * `openFullShieldedCommitment` from `deriveTag` / `deriveAssetTag` /
 * `createAssetCommitment` / `createCommitment` — all of which we DO
 * implement — so the verifier path Just Works without dedicated open*
 * exports in the WASM surface.
 *
 * Marshaling: wasm-bindgen returns `Uint8Array`; the rest of wallet-lib
 * (and the abstract class's contract) speaks `Buffer`. The base-class
 * marshaling hooks normalize at the boundary.
 */
export class WasmShieldedProvider extends AbstractShieldedProvider {
  _encodeBytes(buf) {
    // wasm-bindgen accepts both Uint8Array and Buffer for `&[u8]` arguments.
    // Pass through — no copy needed.
    return buf;
  }
  _decodeBytes(raw) {
    return Buffer.from(raw);
  }

  // ─── verifier primitives (implemented) ─────────────────────────────────

  async _rawDeriveTag(tokenUid) {
    return wasm.deriveTag(tokenUid);
  }
  async _rawDeriveAssetTag(tokenUid) {
    return wasm.deriveAssetTag(tokenUid);
  }
  async _rawCreateCommitment(value, blindingFactor, generator) {
    return wasm.createCommitment(value, blindingFactor, generator);
  }
  async _rawCreateAssetCommitment(tag, blindingFactor) {
    return wasm.createAssetCommitment(tag, blindingFactor);
  }
  async _rawDeriveEcdhSharedSecret(privateKey, peerPubkey) {
    return wasm.deriveEcdhSharedSecret(privateKey, peerPubkey);
  }
  async _rawRewindAmountShieldedOutput(
    privateKey,
    ephemeralPubkey,
    commitment,
    rangeProof,
    tokenUid
  ) {
    const result = wasm.rewindAmountShieldedOutput(
      privateKey,
      ephemeralPubkey,
      commitment,
      rangeProof,
      tokenUid
    );
    // The wasm-bindgen result is a Rust-backed object holding the recovered
    // blinding factor in linear memory; copy the getters out, then `.free()`
    // so the allocation is released immediately instead of lingering until GC.
    try {
      return {
        value: result.value,
        blindingFactor: result.blindingFactor,
      };
    } finally {
      freeWasmResult(result);
    }
  }
  async _rawRewindFullShieldedOutput(
    privateKey,
    ephemeralPubkey,
    commitment,
    rangeProof,
    assetCommitment
  ) {
    const result = wasm.rewindFullShieldedOutput(
      privateKey,
      ephemeralPubkey,
      commitment,
      rangeProof,
      assetCommitment
    );
    try {
      return {
        value: result.value,
        blindingFactor: result.blindingFactor,
        tokenUid: result.tokenUid,
        assetBlindingFactor: result.assetBlindingFactor,
      };
    } finally {
      freeWasmResult(result);
    }
  }

  /**
   * Recognise the binding's scan-miss signal so the base class can translate it
   * into the exported `ScanMissError`. crypto-core surfaces a foreign output
   * (wrong scan key → wrong ECDH nonce → the range-proof rewind fails) as a
   * `RangeProofError("range proof rewind failed: …")`; after the error-shape
   * fix the binding throws a real `Error` carrying that message. Malformed input
   * (bad lengths / off-curve points) uses different messages and stays a hard
   * error.
   */
  _isScanMiss(err) {
    const msg = err && err.message ? String(err.message) : String(err);
    return msg.includes('range proof rewind failed');
  }

  // ─── optional verifier surface (public, on-chain data only) ─────────────

  async verifyRangeProof(proof, commitment, generator) {
    return wasm.verifyRangeProof(
      this._encodeBytes(proof),
      this._encodeBytes(commitment),
      this._encodeBytes(generator)
    );
  }

  async verifySurjectionProof(proof, codomain, domain) {
    return wasm.verifySurjectionProof(
      this._encodeBytes(proof),
      this._encodeBytes(codomain),
      domain.map(d => this._encodeBytes(d))
    );
  }

  async verifyBalance(
    transparentInputs,
    shieldedInputs,
    transparentOutputs,
    shieldedOutputs,
    excessBlindingFactor
  ) {
    // wasm-bindgen has no ergonomic array-of-structs marshaling, so the
    // ITransparentBalanceEntry[] contract shape is split into parallel
    // amounts/tokenUids arrays that the Rust `verifyBalance` re-pairs.
    return wasm.verifyBalance(
      transparentInputs.map(e => e.amount),
      transparentInputs.map(e => this._encodeBytes(e.tokenUid)),
      shieldedInputs.map(c => this._encodeBytes(c)),
      transparentOutputs.map(e => e.amount),
      transparentOutputs.map(e => this._encodeBytes(e.tokenUid)),
      shieldedOutputs.map(c => this._encodeBytes(c)),
      excessBlindingFactor != null ? this._encodeBytes(excessBlindingFactor) : undefined
    );
  }

  async verifyCommitmentsSum(positive, negative) {
    return wasm.verifyCommitmentsSum(
      positive.map(c => this._encodeBytes(c)),
      negative.map(c => this._encodeBytes(c))
    );
  }

  async validateCommitment(data) {
    return wasm.validateCommitment(this._encodeBytes(data));
  }

  async validateGenerator(data) {
    return wasm.validateGenerator(this._encodeBytes(data));
  }

  // ─── policy floor: signing / RNG / surjection / balancing all throw ────

  _rawGenerateRandomBlindingFactor() {
    return this._unsupported('generateRandomBlindingFactor');
  }
  _rawCreateAmountShieldedOutput() {
    return this._unsupported('createAmountShieldedOutput');
  }
  _rawCreateShieldedOutputWithBothBlindings() {
    return this._unsupported('createShieldedOutputWithBothBlindings');
  }
  _rawComputeBalancingBlindingFactor() {
    return this._unsupported('computeBalancingBlindingFactor');
  }
  _rawCreateSurjectionProof() {
    return this._unsupported('createSurjectionProof');
  }
}

/**
 * Factory. Async because wasm-pack `--target web` ships a default-export
 * init that fetches and instantiates the `.wasm` over HTTP; we await it
 * once before handing out the provider.
 */
export async function createBrowserShieldedCryptoProvider() {
  if (typeof wasm.default === 'function') {
    await wasm.default();
  }
  return new WasmShieldedProvider();
}
