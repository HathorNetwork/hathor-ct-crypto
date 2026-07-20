/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

'use strict';

/**
 * Bridge-glue tests for the JS end of the RN native module (js/index.js).
 *
 * The RN bridge carries neither raw bytes nor BigInt, so MobileShieldedProvider
 * marshals:
 *   - u64  ↔ decimal strings  (`value.toString()` outbound, `BigInt(raw.value)`
 *            inbound) — Number would silently lose precision beyond 2^53;
 *   - bytes ↔ base64 strings  (`_encodeBytes` / `_decodeBytes`).
 *
 * These are the two conversions with real correctness risk, and until now they
 * had no dedicated coverage. The u64 decimal parse and the base64 *decode* on
 * the NATIVE side (Swift `UInt64(_)` / `Data(base64Encoded:)`, Kotlin
 * `toULongOrNull` / strict-regex + `Base64.decode`) are not exercised here —
 * this repo ships no XCTest/JUnit harness for the bridge modules, so the native
 * halves are covered by hathor-wallet-mobile's on-device integration tests.
 * This file locks down the JS half of the contract.
 */

const { Buffer } = require('buffer');
const { ScanMissError } = require('@hathor/ct-crypto-provider');
const { createMobileShieldedCryptoProvider } = require('../index');

const b64 = buf => Buffer.from(buf).toString('base64');

// u64 boundary values that must survive the decimal-string bridge losslessly.
// Several are chosen specifically to break if anything downgrades to Number.
const U64_BOUNDARIES = [
  0n,
  1n,
  (1n << 53n) - 1n, // 9007199254740991  — Number.MAX_SAFE_INTEGER
  1n << 53n, //         9007199254740992  — first integer Number can't +1
  (1n << 53n) + 1n, //  9007199254740993  — Number rounds this to ...992
  1n << 63n, //         9223372036854775808
  (1n << 64n) - 1n, //  18446744073709551615 — max u64
];

// A created-output result shaped as the native bridge would return it.
const createdResult = () => ({
  ephemeralPubkey: b64(Buffer.alloc(33, 2)),
  commitment: b64(Buffer.alloc(33, 3)),
  rangeProof: b64(Buffer.alloc(100, 4)),
  blindingFactor: b64(Buffer.alloc(32, 5)),
  assetCommitment: null,
  assetBlindingFactor: null,
});

// Minimal fake native module. Each method records the exact arguments that
// crossed the bridge and returns a caller-supplied value (or a default).
function makeFakeNative(overrides = {}) {
  const calls = {};
  const wrap = (name, result) => (...args) => {
    calls[name] = args;
    return Promise.resolve(result);
  };
  return {
    calls,
    generateRandomBlindingFactor: wrap('generateRandomBlindingFactor', b64(Buffer.alloc(32, 1))),
    createAmountShieldedOutput: wrap('createAmountShieldedOutput', createdResult()),
    createShieldedOutputWithBothBlindings: wrap('createShieldedOutputWithBothBlindings', createdResult()),
    rewindAmountShieldedOutput: wrap('rewindAmountShieldedOutput', {
      value: '0',
      blindingFactor: b64(Buffer.alloc(32, 8)),
    }),
    rewindFullShieldedOutput: wrap('rewindFullShieldedOutput', {
      value: '0',
      blindingFactor: b64(Buffer.alloc(32, 8)),
      tokenUid: b64(Buffer.alloc(32, 0xaa)),
      assetBlindingFactor: b64(Buffer.alloc(32, 9)),
    }),
    computeBalancingBlindingFactor: wrap('computeBalancingBlindingFactor', b64(Buffer.alloc(32, 10))),
    deriveTag: wrap('deriveTag', b64(Buffer.alloc(32, 11))),
    deriveAssetTag: wrap('deriveAssetTag', b64(Buffer.alloc(33, 12))),
    createCommitment: wrap('createCommitment', b64(Buffer.alloc(33, 13))),
    createAssetCommitment: wrap('createAssetCommitment', b64(Buffer.alloc(33, 14))),
    createSurjectionProof: wrap('createSurjectionProof', b64(Buffer.alloc(50, 15))),
    deriveEcdhSharedSecret: wrap('deriveEcdhSharedSecret', b64(Buffer.alloc(32, 16))),
    ...overrides,
  };
}

const providerWith = overrides =>
  createMobileShieldedCryptoProvider({ nativeModule: makeFakeNative(overrides) });

describe('bridge glue — u64 across the decimal-string bridge', () => {
  const pubkey = Buffer.alloc(33, 2);
  const uid = Buffer.alloc(32, 0);
  const vbf = Buffer.alloc(32, 1);

  it.each(U64_BOUNDARIES)('sends value %s outbound as an exact decimal string', async v => {
    const native = makeFakeNative();
    const provider = createMobileShieldedCryptoProvider({ nativeModule: native });
    await provider.createAmountShieldedOutput(v, pubkey, uid, vbf);
    const [sentValue] = native.calls.createAmountShieldedOutput;
    expect(typeof sentValue).toBe('string');
    expect(sentValue).toBe(v.toString());
  });

  it.each(U64_BOUNDARIES)('sends balancing value + entry values %s as exact decimal strings', async v => {
    const native = makeFakeNative();
    const provider = createMobileShieldedCryptoProvider({ nativeModule: native });
    const entry = { value: v, valueBlindingFactor: vbf, generatorBlindingFactor: Buffer.alloc(32, 0) };
    await provider.computeBalancingBlindingFactor(v, Buffer.alloc(32, 0), [entry], []);
    const [topValue, , inputs] = native.calls.computeBalancingBlindingFactor;
    expect(topValue).toBe(v.toString());
    expect(inputs[0].value).toBe(v.toString());
    // The entry value must be a plain string, never a BigInt (unserialisable
    // across the RN bridge) or a lossy Number.
    expect(typeof inputs[0].value).toBe('string');
  });

  it.each(U64_BOUNDARIES)('parses inbound value %s back to an exact BigInt (AmountShielded)', async v => {
    const provider = providerWith({
      rewindAmountShieldedOutput: () =>
        Promise.resolve({ value: v.toString(), blindingFactor: b64(Buffer.alloc(32, 8)) }),
    });
    const res = await provider.rewindAmountShieldedOutput(
      Buffer.alloc(32, 1), Buffer.alloc(33, 2), Buffer.alloc(33, 3), Buffer.alloc(100, 4), Buffer.alloc(32, 0)
    );
    expect(typeof res.value).toBe('bigint');
    expect(res.value).toBe(v);
  });

  it.each(U64_BOUNDARIES)('parses inbound value %s back to an exact BigInt (FullShielded)', async v => {
    const provider = providerWith({
      rewindFullShieldedOutput: () =>
        Promise.resolve({
          value: v.toString(),
          blindingFactor: b64(Buffer.alloc(32, 8)),
          tokenUid: b64(Buffer.alloc(32, 0xaa)),
          assetBlindingFactor: b64(Buffer.alloc(32, 9)),
        }),
    });
    const res = await provider.rewindFullShieldedOutput(
      Buffer.alloc(32, 1), Buffer.alloc(33, 2), Buffer.alloc(33, 3), Buffer.alloc(100, 4), Buffer.alloc(33, 6)
    );
    expect(res.value).toBe(v);
  });
});

describe('bridge glue — base64 byte marshaling', () => {
  const provider = providerWith();

  const BUFFERS = {
    empty: Buffer.alloc(0),
    oneByte: Buffer.from([0x00]),
    allZero32: Buffer.alloc(32, 0x00),
    allOnes32: Buffer.alloc(32, 0xff),
    pubkey33: Buffer.alloc(33, 0x02),
    // Every byte value 0..255 — catches any sign/rounding issue in the codec.
    everyByte: Buffer.from(Array.from({ length: 256 }, (_, i) => i)),
    // Odd length that forces both '=' and '==' padding forms across slices.
    len31: Buffer.from(Array.from({ length: 31 }, (_, i) => (i * 7) & 0xff)),
  };

  it.each(Object.entries(BUFFERS))('round-trips %s through encode→decode', (_name, buf) => {
    const encoded = provider._encodeBytes(buf);
    expect(typeof encoded).toBe('string');
    // Canonical, padded base64 — the exact form both native decoders accept.
    expect(encoded).toBe(buf.toString('base64'));
    const decoded = provider._decodeBytes(encoded);
    expect(Buffer.isBuffer(decoded)).toBe(true);
    expect(decoded).toEqual(buf);
  });

  it('round-trips a payload back through a provider call (deriveTag echo)', async () => {
    const tokenUid = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 11) & 0xff));
    // Native echoes the tokenUid string it received straight back.
    const echo = providerWith({
      deriveTag: encodedUid => Promise.resolve(encodedUid),
    });
    const out = await echo.deriveTag(tokenUid);
    expect(out).toEqual(tokenUid);
  });

  it('rejects a non-string payload from the bridge', () => {
    expect(() => provider._decodeBytes(12345)).toThrow(/base64/);
    expect(() => provider._decodeBytes(Buffer.alloc(4))).toThrow(/base64/);
  });

  // L-7: a malformed native-side string must fail loudly, not silently decode
  // to the wrong bytes (Buffer.from(_, 'base64') drops invalid chars / truncates).
  it('rejects malformed / non-canonical base64 rather than silently corrupting', () => {
    expect(() => provider._decodeBytes('not valid base64!!')).toThrow(/base64/); // '!' not in alphabet
    expect(() => provider._decodeBytes('AAAA=')).toThrow(/base64/);              // bad length (5)
    expect(() => provider._decodeBytes('AB=A')).toThrow(/base64/);               // '=' mid-string
    expect(() => provider._decodeBytes('AAA')).toThrow(/base64/);                // unpadded (length 3)
    // Sanity: a canonical string still decodes.
    expect(provider._decodeBytes('AAAA')).toEqual(Buffer.from([0, 0, 0]));
  });
});

describe('bridge glue — rewind error → ScanMissError translation', () => {
  const amountArgs = [
    Buffer.alloc(32, 1), Buffer.alloc(33, 2), Buffer.alloc(33, 3), Buffer.alloc(100, 4), Buffer.alloc(32, 0),
  ];
  const fullArgs = [
    Buffer.alloc(32, 1), Buffer.alloc(33, 2), Buffer.alloc(33, 3), Buffer.alloc(100, 4), Buffer.alloc(33, 6),
  ];

  // A rejection shaped like an RN native-module error (code + message).
  const nativeReject = code => () => {
    const err = new Error('boom');
    err.code = code;
    return Promise.reject(err);
  };

  it('translates a CryptoFailed AmountShielded rewind into ScanMissError (cause preserved)', async () => {
    const provider = providerWith({ rewindAmountShieldedOutput: nativeReject('CryptoFailed') });
    const err = await provider.rewindAmountShieldedOutput(...amountArgs).catch(e => e);
    expect(err).toBeInstanceOf(ScanMissError);
    expect(err).toBeInstanceOf(Error);
    expect(err.cause).toBeInstanceOf(Error);
    expect(err.cause.code).toBe('CryptoFailed');
  });

  it('translates a CryptoFailed FullShielded rewind into ScanMissError', async () => {
    const provider = providerWith({ rewindFullShieldedOutput: nativeReject('CryptoFailed') });
    const err = await provider.rewindFullShieldedOutput(...fullArgs).catch(e => e);
    expect(err).toBeInstanceOf(ScanMissError);
    expect(err.cause.code).toBe('CryptoFailed');
  });

  it('propagates an InvalidInput rewind error unchanged (NOT a scan-miss)', async () => {
    const provider = providerWith({ rewindAmountShieldedOutput: nativeReject('InvalidInput') });
    const err = await provider.rewindAmountShieldedOutput(...amountArgs).catch(e => e);
    expect(err).not.toBeInstanceOf(ScanMissError);
    expect(err.code).toBe('InvalidInput');
  });

  it('propagates a code-less rewind error unchanged', async () => {
    const provider = providerWith({ rewindFullShieldedOutput: nativeReject(undefined) });
    const err = await provider.rewindFullShieldedOutput(...fullArgs).catch(e => e);
    expect(err).not.toBeInstanceOf(ScanMissError);
    expect(err.message).toBe('boom');
  });
});
