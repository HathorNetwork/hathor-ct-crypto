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
    return {
      value: result.value,
      blindingFactor: result.blindingFactor,
    };
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
    return {
      value: result.value,
      blindingFactor: result.blindingFactor,
      tokenUid: result.tokenUid,
      assetBlindingFactor: result.assetBlindingFactor,
    };
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
