/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import {
  AbstractShieldedProvider,
  IRawBlindingEntry,
  IRawCreatedShieldedOutput,
  IRawRewoundAmountShieldedOutput,
  IRawRewoundFullShieldedOutput,
  IRawSurjectionDomainEntry,
} from '../src/abstract';
import { ScanMissError } from '../src/errors';
import { ZERO_TWEAK } from '../src/constants';

/**
 * Fake subclass that:
 *   - uses Buffer as the platform-native byte type (no-op encode/decode)
 *   - records every raw call for assertion
 *   - returns canned values
 *
 * This isolates the abstract class's marshaling / composition logic from
 * any real crypto, so the tests are deterministic and fast.
 */
class FakeShieldedProvider extends AbstractShieldedProvider {
  public calls: Array<{ method: string; args: unknown[] }> = [];

  // Pre-canned outputs the fake returns from each raw method.
  public canned = {
    rng: Buffer.alloc(32, 0xaa),
    create: {
      ephemeralPubkey: Buffer.alloc(33, 0x01),
      commitment: Buffer.alloc(33, 0x02),
      rangeProof: Buffer.alloc(64, 0x03),
      blindingFactor: Buffer.alloc(32, 0x04),
      assetCommitment: Buffer.alloc(33, 0x05),
      assetBlindingFactor: Buffer.alloc(32, 0x06),
    } as IRawCreatedShieldedOutput,
    rewindAmount: {
      value: 1234n,
      blindingFactor: Buffer.alloc(32, 0x07),
    } as IRawRewoundAmountShieldedOutput,
    rewindFull: {
      value: 5678n,
      blindingFactor: Buffer.alloc(32, 0x08),
      // 32 bytes that hex-encodes to predictable bytes
      tokenUid: Buffer.from('aa'.repeat(32), 'hex'),
      assetBlindingFactor: Buffer.alloc(32, 0x09),
    } as IRawRewoundFullShieldedOutput,
    balancing: Buffer.alloc(32, 0x0a),
    tag: Buffer.alloc(32, 0x0b),
    assetTag: Buffer.alloc(33, 0x0c),
    commitment: Buffer.alloc(33, 0x0d),
    assetCommitment: Buffer.alloc(33, 0x0e),
    surjection: Buffer.alloc(100, 0x0f),
    ecdh: Buffer.alloc(32, 0x10),
  };

  protected _encodeBytes(buf: Buffer): Buffer {
    return buf;
  }
  protected _decodeBytes(raw: unknown): Buffer {
    return raw as Buffer;
  }

  protected async _rawGenerateRandomBlindingFactor(): Promise<Buffer> {
    this.calls.push({ method: '_rawGenerateRandomBlindingFactor', args: [] });
    return this.canned.rng;
  }
  protected async _rawCreateAmountShieldedOutput(
    value: bigint,
    recipientPubkey: unknown,
    tokenUid: unknown,
    valueBlindingFactor: unknown
  ): Promise<IRawCreatedShieldedOutput> {
    this.calls.push({
      method: '_rawCreateAmountShieldedOutput',
      args: [value, recipientPubkey, tokenUid, valueBlindingFactor],
    });
    // AmountShielded — strip the asset fields
    return {
      ephemeralPubkey: this.canned.create.ephemeralPubkey,
      commitment: this.canned.create.commitment,
      rangeProof: this.canned.create.rangeProof,
      blindingFactor: this.canned.create.blindingFactor,
    };
  }
  protected async _rawCreateShieldedOutputWithBothBlindings(
    value: bigint,
    recipientPubkey: unknown,
    tokenUid: unknown,
    valueBlindingFactor: unknown,
    assetBlindingFactor: unknown
  ): Promise<IRawCreatedShieldedOutput> {
    this.calls.push({
      method: '_rawCreateShieldedOutputWithBothBlindings',
      args: [value, recipientPubkey, tokenUid, valueBlindingFactor, assetBlindingFactor],
    });
    return this.canned.create;
  }
  protected async _rawRewindAmountShieldedOutput(
    privateKey: unknown,
    ephemeralPubkey: unknown,
    commitment: unknown,
    rangeProof: unknown,
    tokenUid: unknown
  ): Promise<IRawRewoundAmountShieldedOutput> {
    this.calls.push({
      method: '_rawRewindAmountShieldedOutput',
      args: [privateKey, ephemeralPubkey, commitment, rangeProof, tokenUid],
    });
    return this.canned.rewindAmount;
  }
  protected async _rawRewindFullShieldedOutput(
    privateKey: unknown,
    ephemeralPubkey: unknown,
    commitment: unknown,
    rangeProof: unknown,
    assetCommitment: unknown
  ): Promise<IRawRewoundFullShieldedOutput> {
    this.calls.push({
      method: '_rawRewindFullShieldedOutput',
      args: [privateKey, ephemeralPubkey, commitment, rangeProof, assetCommitment],
    });
    return this.canned.rewindFull;
  }
  protected async _rawComputeBalancingBlindingFactor(
    value: bigint,
    generatorBlindingFactor: unknown,
    inputs: IRawBlindingEntry[],
    otherOutputs: IRawBlindingEntry[]
  ): Promise<Buffer> {
    this.calls.push({
      method: '_rawComputeBalancingBlindingFactor',
      args: [value, generatorBlindingFactor, inputs, otherOutputs],
    });
    return this.canned.balancing;
  }
  protected async _rawDeriveTag(tokenUid: unknown): Promise<Buffer> {
    this.calls.push({ method: '_rawDeriveTag', args: [tokenUid] });
    return this.canned.tag;
  }
  protected async _rawDeriveAssetTag(tokenUid: unknown): Promise<Buffer> {
    this.calls.push({ method: '_rawDeriveAssetTag', args: [tokenUid] });
    return this.canned.assetTag;
  }
  protected async _rawCreateCommitment(
    value: bigint,
    blindingFactor: unknown,
    generator: unknown
  ): Promise<Buffer> {
    this.calls.push({
      method: '_rawCreateCommitment',
      args: [value, blindingFactor, generator],
    });
    return this.canned.commitment;
  }
  protected async _rawCreateAssetCommitment(
    tag: unknown,
    blindingFactor: unknown
  ): Promise<Buffer> {
    this.calls.push({
      method: '_rawCreateAssetCommitment',
      args: [tag, blindingFactor],
    });
    return this.canned.assetCommitment;
  }
  protected async _rawCreateSurjectionProof(
    codomainTag: unknown,
    codomainBlindingFactor: unknown,
    domain: IRawSurjectionDomainEntry[]
  ): Promise<Buffer> {
    this.calls.push({
      method: '_rawCreateSurjectionProof',
      args: [codomainTag, codomainBlindingFactor, domain],
    });
    return this.canned.surjection;
  }
  protected async _rawDeriveEcdhSharedSecret(
    privateKey: unknown,
    peerPubkey: unknown
  ): Promise<Buffer> {
    this.calls.push({
      method: '_rawDeriveEcdhSharedSecret',
      args: [privateKey, peerPubkey],
    });
    return this.canned.ecdh;
  }
}

/**
 * Verifier-only fake — all signing/RNG methods throw via `_unsupported`.
 * Models the WASM subclass shape.
 */
class VerifierOnlyFakeProvider extends AbstractShieldedProvider {
  protected _encodeBytes(buf: Buffer): Buffer {
    return buf;
  }
  protected _decodeBytes(raw: unknown): Buffer {
    return raw as Buffer;
  }
  protected _rawGenerateRandomBlindingFactor(): Promise<never> {
    return this._unsupported('generateRandomBlindingFactor');
  }
  protected _rawCreateAmountShieldedOutput(): Promise<never> {
    return this._unsupported('createAmountShieldedOutput');
  }
  protected _rawCreateShieldedOutputWithBothBlindings(): Promise<never> {
    return this._unsupported('createShieldedOutputWithBothBlindings');
  }
  protected _rawRewindAmountShieldedOutput(): Promise<never> {
    return this._unsupported('rewindAmountShieldedOutput');
  }
  protected _rawRewindFullShieldedOutput(): Promise<never> {
    return this._unsupported('rewindFullShieldedOutput');
  }
  protected _rawComputeBalancingBlindingFactor(): Promise<never> {
    return this._unsupported('computeBalancingBlindingFactor');
  }
  protected async _rawDeriveTag(): Promise<Buffer> {
    return Buffer.alloc(32, 0xa0);
  }
  protected async _rawDeriveAssetTag(): Promise<Buffer> {
    return Buffer.alloc(33, 0xa1);
  }
  protected async _rawCreateCommitment(): Promise<Buffer> {
    return Buffer.alloc(33, 0xa2);
  }
  protected async _rawCreateAssetCommitment(): Promise<Buffer> {
    return Buffer.alloc(33, 0xa3);
  }
  protected _rawCreateSurjectionProof(): Promise<never> {
    return this._unsupported('createSurjectionProof');
  }
  protected _rawDeriveEcdhSharedSecret(): Promise<never> {
    return this._unsupported('deriveEcdhSharedSecret');
  }
}

describe('AbstractShieldedProvider — marshaling', () => {
  let p: FakeShieldedProvider;
  beforeEach(() => {
    p = new FakeShieldedProvider();
  });

  it('generateRandomBlindingFactor returns decoded buffer', async () => {
    const out = await p.generateRandomBlindingFactor();
    expect(Buffer.isBuffer(out)).toBe(true);
    expect(out.equals(Buffer.alloc(32, 0xaa))).toBe(true);
    expect(p.calls).toHaveLength(1);
    expect(p.calls[0].method).toBe('_rawGenerateRandomBlindingFactor');
  });

  it('createAmountShieldedOutput encodes inputs and decodes outputs', async () => {
    const recipient = Buffer.alloc(33, 0x02);
    const token = Buffer.alloc(32, 0xff);
    const vbf = Buffer.alloc(32, 0x42);

    const out = await p.createAmountShieldedOutput(123n, recipient, token, vbf);

    expect(out.commitment.equals(Buffer.alloc(33, 0x02))).toBe(true);
    expect(out.assetCommitment).toBeUndefined();
    expect(out.assetBlindingFactor).toBeUndefined();
    expect(p.calls[0].args).toEqual([123n, recipient, token, vbf]);
  });

  it('createShieldedOutputWithBothBlindings keeps the asset fields', async () => {
    const recipient = Buffer.alloc(33, 0x02);
    const token = Buffer.alloc(32, 0xff);
    const vbf = Buffer.alloc(32, 0x42);
    const abf = Buffer.alloc(32, 0x43);

    const out = await p.createShieldedOutputWithBothBlindings(99n, recipient, token, vbf, abf);

    expect(out.assetCommitment).toBeDefined();
    expect(out.assetBlindingFactor).toBeDefined();
    expect(out.assetCommitment!.equals(Buffer.alloc(33, 0x05))).toBe(true);
    expect(p.calls[0].args).toEqual([99n, recipient, token, vbf, abf]);
  });

  it('rewindAmountShieldedOutput returns value+bf, no token', async () => {
    const out = await p.rewindAmountShieldedOutput(
      Buffer.alloc(32, 0x11),
      Buffer.alloc(33, 0x12),
      Buffer.alloc(33, 0x13),
      Buffer.alloc(64, 0x14),
      Buffer.alloc(32, 0x15)
    );
    expect(out.value).toBe(1234n);
    expect(Buffer.isBuffer(out.blindingFactor)).toBe(true);
  });

  it('rewindFullShieldedOutput hex-encodes tokenUid at the boundary', async () => {
    const out = await p.rewindFullShieldedOutput(
      Buffer.alloc(32, 0x21),
      Buffer.alloc(33, 0x22),
      Buffer.alloc(33, 0x23),
      Buffer.alloc(64, 0x24),
      Buffer.alloc(33, 0x25)
    );
    expect(out.value).toBe(5678n);
    expect(typeof out.tokenUid).toBe('string');
    expect(out.tokenUid).toBe('aa'.repeat(32));
    expect(Buffer.isBuffer(out.assetBlindingFactor)).toBe(true);
  });

  it('computeBalancingBlindingFactor encodes inputs/otherOutputs', async () => {
    const inputs = [
      {
        value: 100n,
        valueBlindingFactor: Buffer.alloc(32, 0x31),
        generatorBlindingFactor: Buffer.alloc(32, 0x32),
      },
    ];
    const outs = [
      {
        value: 40n,
        valueBlindingFactor: Buffer.alloc(32, 0x33),
        generatorBlindingFactor: Buffer.alloc(32, 0x34),
      },
    ];
    const bf = await p.computeBalancingBlindingFactor(
      60n,
      Buffer.alloc(32, 0x30),
      inputs,
      outs
    );
    expect(bf.equals(Buffer.alloc(32, 0x0a))).toBe(true);
    const recorded = p.calls[0].args as [bigint, Buffer, IRawBlindingEntry[], IRawBlindingEntry[]];
    expect(recorded[0]).toBe(60n);
    expect(recorded[2][0].value).toBe(100n);
    // Long-form names propagated
    expect((recorded[2][0] as IRawBlindingEntry).valueBlindingFactor).toBeDefined();
    expect((recorded[2][0] as IRawBlindingEntry).generatorBlindingFactor).toBeDefined();
  });

  it('createSurjectionProof encodes the domain entries', async () => {
    const proof = await p.createSurjectionProof(
      Buffer.alloc(32, 0x41),
      Buffer.alloc(32, 0x42),
      [
        {
          generator: Buffer.alloc(33, 0x43),
          tag: Buffer.alloc(32, 0x44),
          blindingFactor: Buffer.alloc(32, 0x45),
        },
      ]
    );
    expect(proof.equals(Buffer.alloc(100, 0x0f))).toBe(true);
  });
});

describe('AbstractShieldedProvider — composed openers', () => {
  it('openAmountShieldedCommitment composes deriveAssetTag + createCommitment', async () => {
    const p = new FakeShieldedProvider();
    const out = await p.openAmountShieldedCommitment(
      777n,
      Buffer.alloc(32, 0x55),
      Buffer.alloc(32, 0xff)
    );
    expect(out.equals(Buffer.alloc(33, 0x0d))).toBe(true);
    expect(p.calls.map(c => c.method)).toEqual([
      '_rawDeriveAssetTag',
      '_rawCreateCommitment',
    ]);
  });

  it('openFullShieldedCommitment composes deriveTag + createAssetCommitment + createCommitment', async () => {
    const p = new FakeShieldedProvider();
    const out = await p.openFullShieldedCommitment(
      999n,
      Buffer.alloc(32, 0x55),
      Buffer.alloc(32, 0xff),
      Buffer.alloc(32, 0x56)
    );
    expect(Buffer.isBuffer(out.valueCommitment)).toBe(true);
    expect(Buffer.isBuffer(out.assetCommitment)).toBe(true);
    expect(p.calls.map(c => c.method)).toEqual([
      '_rawDeriveTag',
      '_rawCreateAssetCommitment',
      '_rawCreateCommitment',
    ]);
  });
});

/**
 * Subclass whose rewind raw calls always throw, to exercise the scan-miss
 * translation wiring. `recognizeScanMiss` toggles the `_isScanMiss` opt-in.
 */
class RewindThrowingProvider extends FakeShieldedProvider {
  public recognizeScanMiss = false;
  public readonly rawError = new Error('ecdh mismatch: not addressed to key');

  protected _isScanMiss(err: unknown): boolean {
    return this.recognizeScanMiss && err === this.rawError;
  }
  protected async _rawRewindAmountShieldedOutput(): Promise<IRawRewoundAmountShieldedOutput> {
    throw this.rawError;
  }
  protected async _rawRewindFullShieldedOutput(): Promise<IRawRewoundFullShieldedOutput> {
    throw this.rawError;
  }
}

describe('AbstractShieldedProvider — scan-miss translation', () => {
  const rewindAmount = (p: RewindThrowingProvider) =>
    p.rewindAmountShieldedOutput(
      Buffer.alloc(32),
      Buffer.alloc(33),
      Buffer.alloc(33),
      Buffer.alloc(64),
      Buffer.alloc(32)
    );

  it('re-throws the original error unchanged when _isScanMiss is not overridden', async () => {
    const p = new RewindThrowingProvider();
    await expect(rewindAmount(p)).rejects.toBe(p.rawError);
    await expect(rewindAmount(p)).rejects.not.toBeInstanceOf(ScanMissError);
  });

  it('translates a recognised scan-miss into ScanMissError, preserving cause', async () => {
    const p = new RewindThrowingProvider();
    p.recognizeScanMiss = true;
    let caught: unknown;
    try {
      await rewindAmount(p);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ScanMissError);
    expect(caught).toBeInstanceOf(Error); // generic catchers still work
    expect((caught as ScanMissError & { cause?: unknown }).cause).toBe(p.rawError);
  });

  it('translates full-shielded rewind scan-miss too', async () => {
    const p = new RewindThrowingProvider();
    p.recognizeScanMiss = true;
    await expect(
      p.rewindFullShieldedOutput(
        Buffer.alloc(32),
        Buffer.alloc(33),
        Buffer.alloc(33),
        Buffer.alloc(64),
        Buffer.alloc(33)
      )
    ).rejects.toBeInstanceOf(ScanMissError);
  });
});

describe('ZERO_TWEAK constant', () => {
  it('is 32 zero bytes', () => {
    expect(Buffer.isBuffer(ZERO_TWEAK)).toBe(true);
    expect(ZERO_TWEAK).toHaveLength(32);
    expect(ZERO_TWEAK.equals(Buffer.alloc(32))).toBe(true);
  });
});

describe('AbstractShieldedProvider — verifier-only subclass', () => {
  let p: VerifierOnlyFakeProvider;
  beforeEach(() => {
    p = new VerifierOnlyFakeProvider();
  });

  it('throws on generateRandomBlindingFactor', async () => {
    await expect(p.generateRandomBlindingFactor()).rejects.toThrow(
      /generateRandomBlindingFactor is not supported/
    );
  });

  it('throws on createAmountShieldedOutput', async () => {
    await expect(
      p.createAmountShieldedOutput(
        1n,
        Buffer.alloc(33),
        Buffer.alloc(32),
        Buffer.alloc(32)
      )
    ).rejects.toThrow(/createAmountShieldedOutput is not supported/);
  });

  it('throws on rewindFullShieldedOutput', async () => {
    await expect(
      p.rewindFullShieldedOutput(
        Buffer.alloc(32),
        Buffer.alloc(33),
        Buffer.alloc(33),
        Buffer.alloc(64),
        Buffer.alloc(33)
      )
    ).rejects.toThrow(/rewindFullShieldedOutput is not supported/);
  });

  it('verify path (openAmountShieldedCommitment) still works via composition', async () => {
    // _rawDeriveAssetTag + _rawCreateCommitment are implemented; composition succeeds.
    const out = await p.openAmountShieldedCommitment(
      1n,
      Buffer.alloc(32),
      Buffer.alloc(32)
    );
    expect(Buffer.isBuffer(out)).toBe(true);
  });

  it('verify path (openFullShieldedCommitment) still works via composition', async () => {
    const out = await p.openFullShieldedCommitment(
      1n,
      Buffer.alloc(32),
      Buffer.alloc(32),
      Buffer.alloc(32)
    );
    expect(Buffer.isBuffer(out.valueCommitment)).toBe(true);
    expect(Buffer.isBuffer(out.assetCommitment)).toBe(true);
  });
});
