/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import {
  createBrowserShieldedCryptoProvider,
  WasmShieldedProvider,
} from '../provider.js';
import { __getRecordedCalls, __resetRecordedCalls } from './wasm-stub.js';

describe('WasmShieldedProvider — verifier-only subset', () => {
  let provider;
  beforeAll(async () => {
    provider = await createBrowserShieldedCryptoProvider();
  });
  beforeEach(() => {
    __resetRecordedCalls();
  });

  it('factory returns a WasmShieldedProvider instance', () => {
    expect(provider).toBeInstanceOf(WasmShieldedProvider);
  });

  describe('verifier primitives — implemented', () => {
    it('deriveTag returns a Buffer (decoded from Uint8Array)', async () => {
      const out = await provider.deriveTag(Buffer.alloc(32, 0xff));
      expect(Buffer.isBuffer(out)).toBe(true);
      expect(out.length).toBe(32);
      expect(out[0]).toBe(0xa1);
      expect(__getRecordedCalls()[0].name).toBe('deriveTag');
    });

    it('deriveAssetTag returns a Buffer', async () => {
      const out = await provider.deriveAssetTag(Buffer.alloc(32, 0xff));
      expect(Buffer.isBuffer(out)).toBe(true);
      expect(out.length).toBe(33);
      expect(out[0]).toBe(0xa2);
    });

    it('createCommitment forwards args + returns Buffer', async () => {
      const out = await provider.createCommitment(
        123n,
        Buffer.alloc(32, 0x11),
        Buffer.alloc(33, 0x22)
      );
      expect(Buffer.isBuffer(out)).toBe(true);
      expect(out[0]).toBe(0xa3);
      const call = __getRecordedCalls()[0];
      expect(call.name).toBe('createCommitment');
      expect(call.args[0]).toBe(123n);
    });

    it('createAssetCommitment forwards args + returns Buffer', async () => {
      const out = await provider.createAssetCommitment(
        Buffer.alloc(32, 0x33),
        Buffer.alloc(32, 0x44)
      );
      expect(Buffer.isBuffer(out)).toBe(true);
    });

    it('deriveEcdhSharedSecret returns a Buffer', async () => {
      const out = await provider.deriveEcdhSharedSecret(
        Buffer.alloc(32, 0x55),
        Buffer.alloc(33, 0x66)
      );
      expect(Buffer.isBuffer(out)).toBe(true);
    });
  });

  describe('rewind primitives — implemented (auditor surface)', () => {
    it('rewindAmountShieldedOutput unwraps result + decodes bf', async () => {
      const out = await provider.rewindAmountShieldedOutput(
        Buffer.alloc(32),
        Buffer.alloc(33),
        Buffer.alloc(33),
        Buffer.alloc(64),
        Buffer.alloc(32)
      );
      expect(out.value).toBe(42n);
      expect(Buffer.isBuffer(out.blindingFactor)).toBe(true);
    });

    it('rewindFullShieldedOutput hex-encodes tokenUid at the boundary', async () => {
      const out = await provider.rewindFullShieldedOutput(
        Buffer.alloc(32),
        Buffer.alloc(33),
        Buffer.alloc(33),
        Buffer.alloc(64),
        Buffer.alloc(33)
      );
      expect(out.value).toBe(99n);
      expect(typeof out.tokenUid).toBe('string');
      expect(out.tokenUid).toBe('a8'.repeat(32));
      expect(Buffer.isBuffer(out.assetBlindingFactor)).toBe(true);
    });
  });

  describe('rewind frees the wasm result after copying getters', () => {
    it('calls .free() on the amount-shielded result', async () => {
      await provider.rewindAmountShieldedOutput(
        Buffer.alloc(32),
        Buffer.alloc(33),
        Buffer.alloc(33),
        Buffer.alloc(64),
        Buffer.alloc(32)
      );
      const names = __getRecordedCalls().map(c => c.name);
      expect(names).toContain('rewindAmountShieldedOutput.free');
    });

    it('calls .free() on the full-shielded result', async () => {
      await provider.rewindFullShieldedOutput(
        Buffer.alloc(32),
        Buffer.alloc(33),
        Buffer.alloc(33),
        Buffer.alloc(64),
        Buffer.alloc(33)
      );
      const names = __getRecordedCalls().map(c => c.name);
      expect(names).toContain('rewindFullShieldedOutput.free');
    });
  });

  describe('optional verifier surface — implemented', () => {
    it('verifyRangeProof forwards proof/commitment/generator + returns boolean', async () => {
      const out = await provider.verifyRangeProof(
        Buffer.alloc(64, 0x01),
        Buffer.alloc(33, 0x02),
        Buffer.alloc(33, 0x03)
      );
      expect(out).toBe(true);
      const call = __getRecordedCalls()[0];
      expect(call.name).toBe('verifyRangeProof');
      expect(call.args).toHaveLength(3);
    });

    it('verifySurjectionProof passes the domain as an array', async () => {
      const out = await provider.verifySurjectionProof(
        Buffer.alloc(64, 0x01),
        Buffer.alloc(33, 0x02),
        [Buffer.alloc(33, 0x03), Buffer.alloc(33, 0x04)]
      );
      expect(out).toBe(true);
      const call = __getRecordedCalls()[0];
      expect(call.name).toBe('verifySurjectionProof');
      expect(Array.isArray(call.args[2])).toBe(true);
      expect(call.args[2]).toHaveLength(2);
    });

    it('verifyBalance splits ITransparentBalanceEntry[] into parallel arrays', async () => {
      const out = await provider.verifyBalance(
        [
          { amount: 100n, tokenUid: Buffer.alloc(32, 0x00) },
          { amount: 5n, tokenUid: Buffer.alloc(32, 0x11) },
        ],
        [Buffer.alloc(33, 0x22)],
        [{ amount: 105n, tokenUid: Buffer.alloc(32, 0x00) }],
        [Buffer.alloc(33, 0x33)],
        Buffer.alloc(32, 0x44)
      );
      expect(out).toBe(true);
      const call = __getRecordedCalls()[0];
      expect(call.name).toBe('verifyBalance');
      // amounts array, tokenUids array, shielded inputs, then outputs, excess.
      expect(call.args[0]).toEqual([100n, 5n]);
      expect(call.args[1]).toHaveLength(2);
      expect(call.args[2]).toHaveLength(1); // shielded inputs
      expect(call.args[3]).toEqual([105n]);
      expect(call.args[4]).toHaveLength(1);
      expect(call.args[5]).toHaveLength(1); // shielded outputs
      expect(Buffer.isBuffer(call.args[6])).toBe(true); // excess
    });

    it('verifyBalance passes undefined excess when omitted', async () => {
      await provider.verifyBalance([], [], [], []);
      const call = __getRecordedCalls()[0];
      expect(call.args[6]).toBeUndefined();
    });

    it('verifyCommitmentsSum maps both commitment lists', async () => {
      const out = await provider.verifyCommitmentsSum(
        [Buffer.alloc(33, 0x01), Buffer.alloc(33, 0x02)],
        [Buffer.alloc(33, 0x03)]
      );
      expect(out).toBe(true);
      const call = __getRecordedCalls()[0];
      expect(call.name).toBe('verifyCommitmentsSum');
      expect(call.args[0]).toHaveLength(2);
      expect(call.args[1]).toHaveLength(1);
    });

    it('validateCommitment / validateGenerator forward a single Buffer', async () => {
      expect(await provider.validateCommitment(Buffer.alloc(33, 0x05))).toBe(true);
      expect(await provider.validateGenerator(Buffer.alloc(33, 0x06))).toBe(true);
      const names = __getRecordedCalls().map(c => c.name);
      expect(names).toEqual(['validateCommitment', 'validateGenerator']);
    });
  });

  describe('_isScanMiss recognises the rewind scan-miss signal', () => {
    it('returns true for a range-proof rewind failure (foreign output)', () => {
      const err = new Error(
        'range proof error: range proof rewind failed: failed to verify range proof'
      );
      expect(provider._isScanMiss(err)).toBe(true);
    });

    it('returns false for a malformed-input error (genuine failure)', () => {
      expect(provider._isScanMiss(new Error('token_uid must be 32 bytes'))).toBe(false);
      expect(provider._isScanMiss(new Error('generator must be 33 bytes'))).toBe(false);
    });

    it('tolerates a non-Error thrown value', () => {
      expect(provider._isScanMiss('range proof rewind failed: x')).toBe(true);
      expect(provider._isScanMiss(undefined)).toBe(false);
    });
  });

  describe('composed openers — work via verifier primitives', () => {
    it('openAmountShieldedCommitment composes deriveAssetTag + createCommitment', async () => {
      const out = await provider.openAmountShieldedCommitment(
        100n,
        Buffer.alloc(32, 0x77),
        Buffer.alloc(32, 0xff)
      );
      expect(Buffer.isBuffer(out)).toBe(true);
      const names = __getRecordedCalls().map(c => c.name);
      expect(names).toEqual(['deriveAssetTag', 'createCommitment']);
    });

    it('openFullShieldedCommitment composes 3 primitives', async () => {
      const out = await provider.openFullShieldedCommitment(
        200n,
        Buffer.alloc(32, 0x77),
        Buffer.alloc(32, 0xff),
        Buffer.alloc(32, 0x88)
      );
      expect(Buffer.isBuffer(out.valueCommitment)).toBe(true);
      expect(Buffer.isBuffer(out.assetCommitment)).toBe(true);
      const names = __getRecordedCalls().map(c => c.name);
      expect(names).toEqual(['deriveTag', 'createAssetCommitment', 'createCommitment']);
    });
  });

  describe('policy floor — signing/RNG/surjection/balancing throw', () => {
    it('throws on generateRandomBlindingFactor', async () => {
      await expect(provider.generateRandomBlindingFactor()).rejects.toThrow(
        /generateRandomBlindingFactor is not supported/
      );
    });

    it('throws on createAmountShieldedOutput', async () => {
      await expect(
        provider.createAmountShieldedOutput(
          1n,
          Buffer.alloc(33),
          Buffer.alloc(32),
          Buffer.alloc(32)
        )
      ).rejects.toThrow(/createAmountShieldedOutput is not supported/);
    });

    it('throws on createShieldedOutputWithBothBlindings', async () => {
      await expect(
        provider.createShieldedOutputWithBothBlindings(
          1n,
          Buffer.alloc(33),
          Buffer.alloc(32),
          Buffer.alloc(32),
          Buffer.alloc(32)
        )
      ).rejects.toThrow(/createShieldedOutputWithBothBlindings is not supported/);
    });

    it('throws on computeBalancingBlindingFactor', async () => {
      await expect(
        provider.computeBalancingBlindingFactor(1n, Buffer.alloc(32), [], [])
      ).rejects.toThrow(/computeBalancingBlindingFactor is not supported/);
    });

    it('throws on createSurjectionProof', async () => {
      await expect(
        provider.createSurjectionProof(Buffer.alloc(32), Buffer.alloc(32), [])
      ).rejects.toThrow(/createSurjectionProof is not supported/);
    });
  });
});
