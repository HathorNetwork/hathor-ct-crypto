/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

'use strict';

// React Native provides no Buffer global — depend on the polyfill explicitly
// (same rule as the wasm provider).
const { Buffer } = require('buffer');
const { AbstractShieldedProvider } = require('@hathor/ct-crypto-provider');

/**
 * Mobile (React Native) shielded crypto provider, backed by the Rust
 * `hathor-ct-crypto-mobile` crate over UniFFI, exposed to JS through the
 * `HathorCtCrypto` native module in this package.
 *
 * Marshaling across the RN bridge (the bridge carries neither raw bytes nor
 * BigInt):
 *   - bytes  → base64 strings (`_encodeBytes` / `_decodeBytes`)
 *   - u64    → decimal strings (values can exceed 2^53, Number is unsafe)
 *
 * The abstract class handles everything else (Promise wrapping, tokenUid
 * hex normalisation, open* composition).
 */
class MobileShieldedProvider extends AbstractShieldedProvider {
  constructor(nativeModule) {
    super();
    if (!nativeModule) {
      throw new Error(
        'MobileShieldedProvider requires the HathorCtCrypto native module. ' +
        'Use createMobileShieldedCryptoProvider(), or pass { nativeModule } explicitly.'
      );
    }
    this._native = nativeModule;
  }

  _encodeBytes(buf) {
    return Buffer.from(buf).toString('base64');
  }

  _decodeBytes(raw) {
    if (typeof raw !== 'string') {
      throw new Error('MobileShieldedProvider expected a base64 string from the native bridge');
    }
    return Buffer.from(raw, 'base64');
  }

  // The RN bridge cannot carry BigInt inside objects either — entries cross
  // with `value` as a decimal string.
  _encodeBlindingEntry(entry) {
    return {
      value: entry.value.toString(),
      valueBlindingFactor: this._encodeBytes(entry.valueBlindingFactor),
      generatorBlindingFactor: this._encodeBytes(entry.generatorBlindingFactor),
    };
  }

  // ─── raw primitives (all args already encoded by the abstract class) ─────

  async _rawGenerateRandomBlindingFactor() {
    return this._native.generateRandomBlindingFactor();
  }

  async _rawCreateAmountShieldedOutput(value, recipientPubkey, tokenUid, valueBlindingFactor) {
    return this._native.createAmountShieldedOutput(
      value.toString(),
      recipientPubkey,
      tokenUid,
      valueBlindingFactor
    );
  }

  async _rawCreateShieldedOutputWithBothBlindings(
    value,
    recipientPubkey,
    tokenUid,
    valueBlindingFactor,
    assetBlindingFactor
  ) {
    return this._native.createShieldedOutputWithBothBlindings(
      value.toString(),
      recipientPubkey,
      tokenUid,
      valueBlindingFactor,
      assetBlindingFactor
    );
  }

  async _rawRewindAmountShieldedOutput(privateKey, ephemeralPubkey, commitment, rangeProof, tokenUid) {
    const raw = await this._native.rewindAmountShieldedOutput(
      privateKey,
      ephemeralPubkey,
      commitment,
      rangeProof,
      tokenUid
    );
    return {
      value: BigInt(raw.value),
      blindingFactor: raw.blindingFactor,
    };
  }

  async _rawRewindFullShieldedOutput(privateKey, ephemeralPubkey, commitment, rangeProof, assetCommitment) {
    const raw = await this._native.rewindFullShieldedOutput(
      privateKey,
      ephemeralPubkey,
      commitment,
      rangeProof,
      assetCommitment
    );
    return {
      value: BigInt(raw.value),
      blindingFactor: raw.blindingFactor,
      tokenUid: raw.tokenUid,
      assetBlindingFactor: raw.assetBlindingFactor,
    };
  }

  async _rawComputeBalancingBlindingFactor(value, generatorBlindingFactor, inputs, otherOutputs) {
    return this._native.computeBalancingBlindingFactor(
      value.toString(),
      generatorBlindingFactor,
      inputs,
      otherOutputs
    );
  }

  async _rawDeriveTag(tokenUid) {
    return this._native.deriveTag(tokenUid);
  }

  async _rawDeriveAssetTag(tokenUid) {
    return this._native.deriveAssetTag(tokenUid);
  }

  async _rawCreateCommitment(value, blindingFactor, generator) {
    return this._native.createCommitment(value.toString(), blindingFactor, generator);
  }

  async _rawCreateAssetCommitment(tag, blindingFactor) {
    return this._native.createAssetCommitment(tag, blindingFactor);
  }

  async _rawCreateSurjectionProof(codomainTag, codomainBlindingFactor, domain) {
    return this._native.createSurjectionProof(codomainTag, codomainBlindingFactor, domain);
  }

  async _rawDeriveEcdhSharedSecret(privateKey, peerPubkey) {
    return this._native.deriveEcdhSharedSecret(privateKey, peerPubkey);
  }
}

/**
 * Factory. Resolves the native module from React Native unless one is
 * injected (tests / custom setups).
 *
 *   const { createMobileShieldedCryptoProvider } = require('@hathor/ct-crypto-mobile');
 *   wallet.setShieldedCryptoProvider(createMobileShieldedCryptoProvider());
 */
function createMobileShieldedCryptoProvider(options = {}) {
  let native = options.nativeModule;
  if (!native) {
    let NativeModules;
    try {
      // Lazy require: keeps this package importable (and testable) outside a
      // React Native runtime as long as a nativeModule is injected.
      // eslint-disable-next-line global-require
      ({ NativeModules } = require('react-native'));
    } catch (e) {
      throw new Error(
        'HathorCtCrypto native module not found: react-native is not available ' +
        'in this environment. Pass { nativeModule } to inject one.'
      );
    }
    native = NativeModules.HathorCtCrypto;
  }
  if (!native) {
    throw new Error(
      'HathorCtCrypto native module not found. Rebuild the app after installing ' +
      '@hathor/ct-crypto-mobile (pod install on iOS, gradle sync on Android) so ' +
      'React Native autolinking picks it up.'
    );
  }
  return new MobileShieldedProvider(native);
}

module.exports = { createMobileShieldedCryptoProvider, MobileShieldedProvider };
