/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

'use strict';

/**
 * Tests the MobileShieldedProvider's marshaling contract against a fake
 * native module (no React Native runtime here): bytes cross as base64,
 * u64 values as decimal strings, records with the provider's camelCase keys.
 * The real end-to-end path (JS → bridge → Rust) is exercised in
 * hathor-wallet-mobile's integration tests.
 */

const { Buffer } = require('buffer');
const { createMobileShieldedCryptoProvider, MobileShieldedProvider } = require('../index');

const b64 = buf => Buffer.from(buf).toString('base64');

function makeFakeNative() {
  const calls = {};
  const record = (name, args, result) => {
    calls[name] = args;
    return Promise.resolve(result);
  };
  return {
    calls,
    generateRandomBlindingFactor: (...a) =>
      record('generateRandomBlindingFactor', a, b64(Buffer.alloc(32, 1))),
    createAmountShieldedOutput: (...a) =>
      record('createAmountShieldedOutput', a, {
        ephemeralPubkey: b64(Buffer.alloc(33, 2)),
        commitment: b64(Buffer.alloc(33, 3)),
        rangeProof: b64(Buffer.alloc(100, 4)),
        blindingFactor: b64(Buffer.alloc(32, 5)),
        assetCommitment: null,
        assetBlindingFactor: null,
      }),
    createShieldedOutputWithBothBlindings: (...a) =>
      record('createShieldedOutputWithBothBlindings', a, {
        ephemeralPubkey: b64(Buffer.alloc(33, 2)),
        commitment: b64(Buffer.alloc(33, 3)),
        rangeProof: b64(Buffer.alloc(100, 4)),
        blindingFactor: b64(Buffer.alloc(32, 5)),
        assetCommitment: b64(Buffer.alloc(33, 6)),
        assetBlindingFactor: b64(Buffer.alloc(32, 7)),
      }),
    rewindAmountShieldedOutput: (...a) =>
      record('rewindAmountShieldedOutput', a, {
        // Deliberately > 2^53 to prove the decimal-string path is lossless.
        value: '9007199254740993',
        blindingFactor: b64(Buffer.alloc(32, 8)),
      }),
    rewindFullShieldedOutput: (...a) =>
      record('rewindFullShieldedOutput', a, {
        value: '42',
        blindingFactor: b64(Buffer.alloc(32, 8)),
        tokenUid: b64(Buffer.alloc(32, 0xaa)),
        assetBlindingFactor: b64(Buffer.alloc(32, 9)),
      }),
    computeBalancingBlindingFactor: (...a) =>
      record('computeBalancingBlindingFactor', a, b64(Buffer.alloc(32, 10))),
    deriveTag: (...a) => record('deriveTag', a, b64(Buffer.alloc(32, 11))),
    deriveAssetTag: (...a) => record('deriveAssetTag', a, b64(Buffer.alloc(33, 12))),
    createCommitment: (...a) => record('createCommitment', a, b64(Buffer.alloc(33, 13))),
    createAssetCommitment: (...a) => record('createAssetCommitment', a, b64(Buffer.alloc(33, 14))),
    createSurjectionProof: (...a) => record('createSurjectionProof', a, b64(Buffer.alloc(50, 15))),
    deriveEcdhSharedSecret: (...a) => record('deriveEcdhSharedSecret', a, b64(Buffer.alloc(32, 16))),
  };
}

describe('createMobileShieldedCryptoProvider', () => {
  it('throws without a native module outside React Native', () => {
    expect(() => createMobileShieldedCryptoProvider()).toThrow(/native module/i);
  });

  it('accepts an injected native module', () => {
    const provider = createMobileShieldedCryptoProvider({ nativeModule: makeFakeNative() });
    expect(provider).toBeInstanceOf(MobileShieldedProvider);
  });
});

describe('MobileShieldedProvider marshaling', () => {
  let native;
  let provider;

  beforeEach(() => {
    native = makeFakeNative();
    provider = createMobileShieldedCryptoProvider({ nativeModule: native });
  });

  it('generateRandomBlindingFactor decodes base64 to a 32-byte Buffer', async () => {
    const bf = await provider.generateRandomBlindingFactor();
    expect(Buffer.isBuffer(bf)).toBe(true);
    expect(bf).toEqual(Buffer.alloc(32, 1));
  });

  it('createAmountShieldedOutput sends value as decimal string and bytes as base64', async () => {
    const pubkey = Buffer.alloc(33, 0x02);
    const uid = Buffer.alloc(32, 0);
    const vbf = Buffer.alloc(32, 0x51);
    const created = await provider.createAmountShieldedOutput(1234n, pubkey, uid, vbf);

    expect(native.calls.createAmountShieldedOutput).toEqual([
      '1234', b64(pubkey), b64(uid), b64(vbf),
    ]);
    expect(created.commitment).toEqual(Buffer.alloc(33, 3));
    expect(created.assetCommitment).toBeUndefined(); // null normalised to undefined
  });

  it('createShieldedOutputWithBothBlindings decodes the asset fields', async () => {
    const created = await provider.createShieldedOutputWithBothBlindings(
      5n, Buffer.alloc(33, 2), Buffer.alloc(32, 0xaa), Buffer.alloc(32, 1), Buffer.alloc(32, 2)
    );
    expect(created.assetCommitment).toEqual(Buffer.alloc(33, 6));
    expect(created.assetBlindingFactor).toEqual(Buffer.alloc(32, 7));
  });

  it('rewindAmountShieldedOutput parses value losslessly beyond 2^53', async () => {
    const res = await provider.rewindAmountShieldedOutput(
      Buffer.alloc(32, 1), Buffer.alloc(33, 2), Buffer.alloc(33, 3), Buffer.alloc(100, 4), Buffer.alloc(32, 0)
    );
    expect(res.value).toBe(9007199254740993n);
    expect(res.blindingFactor).toEqual(Buffer.alloc(32, 8));
  });

  it('rewindFullShieldedOutput returns hex tokenUid per the provider contract', async () => {
    const res = await provider.rewindFullShieldedOutput(
      Buffer.alloc(32, 1), Buffer.alloc(33, 2), Buffer.alloc(33, 3), Buffer.alloc(100, 4), Buffer.alloc(33, 6)
    );
    expect(res.value).toBe(42n);
    expect(res.tokenUid).toBe('aa'.repeat(32));
    expect(res.assetBlindingFactor).toEqual(Buffer.alloc(32, 9));
  });

  it('computeBalancingBlindingFactor stringifies entry values (no BigInt on the bridge)', async () => {
    const entry = {
      value: 1000n,
      valueBlindingFactor: Buffer.alloc(32, 1),
      generatorBlindingFactor: Buffer.alloc(32, 0),
    };
    await provider.computeBalancingBlindingFactor(400n, Buffer.alloc(32, 0), [entry], []);

    const [value, gbf, inputs, otherOutputs] = native.calls.computeBalancingBlindingFactor;
    expect(value).toBe('400');
    expect(typeof gbf).toBe('string');
    expect(inputs).toEqual([{
      value: '1000',
      valueBlindingFactor: b64(Buffer.alloc(32, 1)),
      generatorBlindingFactor: b64(Buffer.alloc(32, 0)),
    }]);
    expect(otherOutputs).toEqual([]);
  });

  it('createSurjectionProof encodes domain entries with base64 fields', async () => {
    await provider.createSurjectionProof(Buffer.alloc(32, 1), Buffer.alloc(32, 2), [
      { generator: Buffer.alloc(33, 3), tag: Buffer.alloc(32, 4), blindingFactor: Buffer.alloc(32, 5) },
    ]);
    const [, , domain] = native.calls.createSurjectionProof;
    expect(domain).toEqual([{
      generator: b64(Buffer.alloc(33, 3)),
      tag: b64(Buffer.alloc(32, 4)),
      blindingFactor: b64(Buffer.alloc(32, 5)),
    }]);
  });

  it('open* composition works through the mobile primitives', async () => {
    const commitment = await provider.openAmountShieldedCommitment(
      7n, Buffer.alloc(32, 1), Buffer.alloc(32, 0)
    );
    // deriveAssetTag result (33 bytes of 12) feeds createCommitment.
    expect(native.calls.createCommitment).toEqual([
      '7', b64(Buffer.alloc(32, 1)), b64(Buffer.alloc(33, 12)),
    ]);
    expect(commitment).toEqual(Buffer.alloc(33, 13));
  });

  it('rejects non-string byte payloads from the bridge', async () => {
    native.deriveTag = () => Promise.resolve(12345);
    await expect(provider.deriveTag(Buffer.alloc(32, 0))).rejects.toThrow(/base64/);
  });
});
