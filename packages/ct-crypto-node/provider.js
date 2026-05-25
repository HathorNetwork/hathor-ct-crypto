/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

'use strict';

const { AbstractShieldedProvider } = require('@hathor/ct-crypto-provider');
const ct = require('./index');

/**
 * Node shielded crypto provider, backed by this package's NAPI bindings.
 *
 * Concrete subclass of `AbstractShieldedProvider` from
 * `@hathor/ct-crypto-provider`. The abstract class handles every wrapping
 * concern (Promise wrapping, tokenUid Buffer→hex at the rewind boundary,
 * `openAmount/Full` composition from primitives). This file only fills in
 * the platform-specific bits:
 *
 *   - byte marshaling is a no-op: NAPI already uses Buffer everywhere
 *   - each `_rawXxx` delegates to the matching NAPI function in `./index.js`
 *
 * Usage:
 *
 *   const { createDefaultShieldedCryptoProvider } = require('@hathor/ct-crypto-node/provider');
 *   wallet.setShieldedCryptoProvider(createDefaultShieldedCryptoProvider());
 */
class NodeShieldedProvider extends AbstractShieldedProvider {
  // NAPI exposes Buffer in and Buffer out — no marshaling needed at the
  // byte boundary. The base class's marshaling hooks become identity
  // functions.
  _encodeBytes(buf) {
    return buf;
  }
  _decodeBytes(raw) {
    return raw;
  }

  // ─── raw primitives ────────────────────────────────────────────────────

  async _rawGenerateRandomBlindingFactor() {
    return ct.generateRandomBlindingFactor();
  }

  async _rawCreateAmountShieldedOutput(value, recipientPubkey, tokenUid, valueBlindingFactor) {
    return ct.createAmountShieldedOutput(value, recipientPubkey, tokenUid, valueBlindingFactor);
  }

  async _rawCreateShieldedOutputWithBothBlindings(
    value,
    recipientPubkey,
    tokenUid,
    valueBlindingFactor,
    assetBlindingFactor
  ) {
    return ct.createShieldedOutputWithBothBlindings(
      value,
      recipientPubkey,
      tokenUid,
      valueBlindingFactor,
      assetBlindingFactor
    );
  }

  async _rawRewindAmountShieldedOutput(
    privateKey,
    ephemeralPubkey,
    commitment,
    rangeProof,
    tokenUid
  ) {
    return ct.rewindAmountShieldedOutput(
      privateKey,
      ephemeralPubkey,
      commitment,
      rangeProof,
      tokenUid
    );
  }

  async _rawRewindFullShieldedOutput(
    privateKey,
    ephemeralPubkey,
    commitment,
    rangeProof,
    assetCommitment
  ) {
    return ct.rewindFullShieldedOutput(
      privateKey,
      ephemeralPubkey,
      commitment,
      rangeProof,
      assetCommitment
    );
  }

  async _rawComputeBalancingBlindingFactor(value, generatorBlindingFactor, inputs, otherOutputs) {
    // NAPI's BlindingEntry uses long-form field names that match the abstract
    // class's IRawBlindingEntry — no per-field translation needed.
    return ct.computeBalancingBlindingFactor(value, generatorBlindingFactor, inputs, otherOutputs);
  }

  async _rawDeriveTag(tokenUid) {
    return ct.deriveTag(tokenUid);
  }

  async _rawDeriveAssetTag(tokenUid) {
    return ct.deriveAssetTag(tokenUid);
  }

  async _rawCreateCommitment(value, blindingFactor, generator) {
    return ct.createCommitment(value, blindingFactor, generator);
  }

  async _rawCreateAssetCommitment(tag, blindingFactor) {
    return ct.createAssetCommitment(tag, blindingFactor);
  }

  async _rawCreateSurjectionProof(codomainTag, codomainBlindingFactor, domain) {
    return ct.createSurjectionProof(codomainTag, codomainBlindingFactor, domain);
  }

  async _rawDeriveEcdhSharedSecret(privateKey, peerPubkey) {
    return ct.deriveEcdhSharedSecret(privateKey, peerPubkey);
  }
}

/**
 * Factory function. Returns a fresh `NodeShieldedProvider` instance backed
 * by the NAPI addon loaded from this package.
 */
function createDefaultShieldedCryptoProvider() {
  return new NodeShieldedProvider();
}

module.exports = { createDefaultShieldedCryptoProvider, NodeShieldedProvider };
