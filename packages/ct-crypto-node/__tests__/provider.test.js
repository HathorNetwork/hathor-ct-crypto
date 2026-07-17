/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

'use strict';

/**
 * Round-trip tests against the real NAPI addon. Verifies:
 *   - The NodeShieldedProvider conforms structurally to IShieldedCryptoProvider
 *   - Commitment math actually works (open* reproduces what create* produced)
 *   - RNG comes from the NAPI generate_random_blinding_factor (the mobile
 *     package carries the equivalent test for its own surface).
 *
 * If the prebuild for the local platform isn't available the entire suite
 * is skipped — a CI matrix without ct-crypto-node prebuilds won't fail.
 */

let createDefaultShieldedCryptoProvider;
let ct;
let providerLoadError;
try {
  ({ createDefaultShieldedCryptoProvider } = require('../provider'));
  // Raw NAPI addon — the provider doesn't surface generateEphemeralKeypair, but
  // the rewind round-trip needs a recipient keypair whose private key we control.
  ct = require('../index');
} catch (e) {
  providerLoadError = e;
}

// Pure-JS dependency (no native load), so this require is always safe.
const { ScanMissError } = require('@hathor/ct-crypto-provider');

// In CI we set CT_CRYPTO_REQUIRE_NATIVE=1 so a missing/broken addon
// FAILS the suite instead of silently skipping (which would let the "real
// crypto" job go green having exercised nothing). Locally the var is unset and
// the suite skips gracefully when no prebuild exists for the platform.
if (providerLoadError && process.env.CT_CRYPTO_REQUIRE_NATIVE) {
  throw new Error(
    'CT_CRYPTO_REQUIRE_NATIVE is set but the ct-crypto-node native addon failed to load: ' +
    providerLoadError.message
  );
}

const describeIfProvider = providerLoadError ? describe.skip : describe;

if (providerLoadError) {
  // eslint-disable-next-line no-console
  console.warn(
    'Skipping NodeShieldedProvider tests — ct-crypto-node native addon not buildable:',
    providerLoadError.message
  );
}

// Valid compressed secp256k1 pubkey (well-known generator point).
const RECIPIENT_PUBKEY = Buffer.from(
  '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
  'hex'
);
const HTR_TOKEN_UID = Buffer.alloc(32, 0);
const CUSTOM_TOKEN_UID = Buffer.alloc(32, 0xaa);

describeIfProvider('NodeShieldedProvider — interface conformance', () => {
  const provider = createDefaultShieldedCryptoProvider();

  const requiredMethods = [
    'generateRandomBlindingFactor',
    'createAmountShieldedOutput',
    'createShieldedOutputWithBothBlindings',
    'rewindAmountShieldedOutput',
    'rewindFullShieldedOutput',
    'computeBalancingBlindingFactor',
    'deriveTag',
    'deriveAssetTag',
    'createCommitment',
    'createAssetCommitment',
    'createSurjectionProof',
    'deriveEcdhSharedSecret',
    'openAmountShieldedCommitment',
    'openFullShieldedCommitment',
  ];

  it.each(requiredMethods)('exposes %s as a function', method => {
    expect(typeof provider[method]).toBe('function');
  });
});

describeIfProvider('NodeShieldedProvider — round-trip', () => {
  const provider = createDefaultShieldedCryptoProvider();

  it('generateRandomBlindingFactor returns a 32-byte Buffer', async () => {
    const bf = await provider.generateRandomBlindingFactor();
    expect(Buffer.isBuffer(bf)).toBe(true);
    expect(bf.length).toBe(32);
  });

  it('openAmountShieldedCommitment reproduces createAmountShieldedOutput commitment', async () => {
    const value = 1234n;
    const vbf = await provider.generateRandomBlindingFactor();

    const created = await provider.createAmountShieldedOutput(
      value,
      RECIPIENT_PUBKEY,
      HTR_TOKEN_UID,
      vbf
    );
    expect(Buffer.isBuffer(created.commitment)).toBe(true);
    expect(created.commitment.length).toBe(33);

    const recomputed = await provider.openAmountShieldedCommitment(value, vbf, HTR_TOKEN_UID);
    expect(created.commitment.equals(recomputed)).toBe(true);
  });

  it('openFullShieldedCommitment reproduces both commitments of a FullShielded output', async () => {
    const value = 5678n;
    const vbf = await provider.generateRandomBlindingFactor();
    const abf = await provider.generateRandomBlindingFactor();

    const created = await provider.createShieldedOutputWithBothBlindings(
      value,
      RECIPIENT_PUBKEY,
      CUSTOM_TOKEN_UID,
      vbf,
      abf
    );
    expect(created.assetCommitment).toBeDefined();
    expect(created.assetBlindingFactor).toBeDefined();

    const recomputed = await provider.openFullShieldedCommitment(
      value,
      vbf,
      CUSTOM_TOKEN_UID,
      abf
    );
    expect(created.commitment.equals(recomputed.valueCommitment)).toBe(true);
    expect(created.assetCommitment.equals(recomputed.assetCommitment)).toBe(true);
  });

  it('tampered vbf produces a different commitment', async () => {
    const value = 100n;
    const vbf = await provider.generateRandomBlindingFactor();

    const created = await provider.createAmountShieldedOutput(
      value,
      RECIPIENT_PUBKEY,
      HTR_TOKEN_UID,
      vbf
    );

    const tampered = Buffer.from(vbf);
    tampered[0] ^= 0x01;

    const recomputed = await provider.openAmountShieldedCommitment(value, tampered, HTR_TOKEN_UID);
    expect(created.commitment.equals(recomputed)).toBe(false);
  });

  it('rewindAmountShieldedOutput round-trips value + blinding factor for the matching recipient', async () => {
    // RECIPIENT_PUBKEY above is the secp256k1 generator (no known private key),
    // so mint a real keypair from the addon whose private key we control.
    const { privateKey, publicKey } = ct.generateEphemeralKeypair();
    const value = 4242n;
    const vbf = await provider.generateRandomBlindingFactor();

    const created = await provider.createAmountShieldedOutput(
      value,
      publicKey,
      HTR_TOKEN_UID,
      vbf
    );

    const rewound = await provider.rewindAmountShieldedOutput(
      privateKey,
      created.ephemeralPubkey,
      created.commitment,
      created.rangeProof,
      HTR_TOKEN_UID
    );

    // Real round-trip: the recovered value and blinding factor equal the
    // originals (and the bf the create step reported).
    expect(rewound.value).toBe(value);
    expect(Buffer.isBuffer(rewound.blindingFactor)).toBe(true);
    expect(rewound.blindingFactor.equals(vbf)).toBe(true);
    expect(rewound.blindingFactor.equals(created.blindingFactor)).toBe(true);
  });

  it('rewindAmountShieldedOutput throws ScanMissError for a non-matching scan key', async () => {
    const { publicKey } = ct.generateEphemeralKeypair();
    const wrong = ct.generateEphemeralKeypair(); // unrelated keypair
    const vbf = await provider.generateRandomBlindingFactor();

    const created = await provider.createAmountShieldedOutput(
      1000n,
      publicKey,
      HTR_TOKEN_UID,
      vbf
    );

    // The wrong private key derives a different ECDH nonce, so the range-proof
    // rewind fails: a benign scan-miss, surfaced as the typed ScanMissError
    // (a subclass of Error, with the original native error kept as `cause`).
    const err = await provider
      .rewindAmountShieldedOutput(
        wrong.privateKey,
        created.ephemeralPubkey,
        created.commitment,
        created.rangeProof,
        HTR_TOKEN_UID
      )
      .then(
        () => null,
        e => e
      );
    expect(err).toBeInstanceOf(ScanMissError);
    expect(err).toBeInstanceOf(Error);
    expect(err.cause).toBeDefined();
  });
});

describeIfProvider('NodeShieldedProvider — error paths', () => {
  const provider = createDefaultShieldedCryptoProvider();

  it('createCommitment rejects a wrong-length blinding factor', async () => {
    const generator = await provider.deriveAssetTag(HTR_TOKEN_UID);
    await expect(
      provider.createCommitment(1n, Buffer.alloc(31), generator)
    ).rejects.toThrow(/32 bytes/);
  });

  it('createAmountShieldedOutput rejects a malformed recipient pubkey', async () => {
    const vbf = await provider.generateRandomBlindingFactor();
    await expect(
      provider.createAmountShieldedOutput(1n, Buffer.alloc(10), HTR_TOKEN_UID, vbf)
    ).rejects.toThrow();
  });

  it('deriveAssetTag rejects a wrong-length token UID', async () => {
    await expect(provider.deriveAssetTag(Buffer.alloc(31))).rejects.toThrow(/32 bytes/);
  });

  it('rewindAmountShieldedOutput surfaces malformed input as a non-scan-miss Error', async () => {
    // A genuinely malformed commitment fails at deserialization, before the
    // range-proof rewind step, so it must NOT be reclassified as a scan-miss.
    const { privateKey, publicKey } = ct.generateEphemeralKeypair();
    const vbf = await provider.generateRandomBlindingFactor();
    const created = await provider.createAmountShieldedOutput(
      500n,
      publicKey,
      HTR_TOKEN_UID,
      vbf
    );
    const truncatedCommitment = created.commitment.subarray(0, 10);

    const err = await provider
      .rewindAmountShieldedOutput(
        privateKey,
        created.ephemeralPubkey,
        truncatedCommitment,
        created.rangeProof,
        HTR_TOKEN_UID
      )
      .then(
        () => null,
        e => e
      );
    // The addon throws a genuine Error, but it originates in Node's outer realm
    // (native addons don't use jest's sandboxed globals), so `instanceof Error`
    // is unreliable here — assert error-hood realm-agnostically instead.
    expect(Object.prototype.toString.call(err)).toBe('[object Error]');
    expect(err).not.toBeInstanceOf(ScanMissError);
    expect(err.message).toMatch(/commitment/);
  });
});

describeIfProvider('NodeShieldedProvider — verifier surface', () => {
  const provider = createDefaultShieldedCryptoProvider();

  it('validateCommitment / validateGenerator accept valid points and reject garbage', async () => {
    const generator = await provider.deriveAssetTag(HTR_TOKEN_UID);
    const vbf = await provider.generateRandomBlindingFactor();
    const commitment = await provider.createCommitment(100n, vbf, generator);

    expect(await provider.validateCommitment(commitment)).toBe(true);
    expect(await provider.validateGenerator(generator)).toBe(true);
    // 33 bytes but not a valid curve point.
    expect(await provider.validateCommitment(Buffer.alloc(33, 0x01))).toBe(false);
  });

  it('verifyRangeProof accepts a matching proof and rejects a mismatched commitment', async () => {
    const { publicKey } = ct.generateEphemeralKeypair();
    const generator = await provider.deriveAssetTag(HTR_TOKEN_UID);
    const good = await provider.createAmountShieldedOutput(
      50n,
      publicKey,
      HTR_TOKEN_UID,
      await provider.generateRandomBlindingFactor()
    );
    const other = await provider.createAmountShieldedOutput(
      60n,
      publicKey,
      HTR_TOKEN_UID,
      await provider.generateRandomBlindingFactor()
    );

    expect(await provider.verifyRangeProof(good.rangeProof, good.commitment, generator)).toBe(true);
    expect(await provider.verifyRangeProof(good.rangeProof, other.commitment, generator)).toBe(
      false
    );
  });

  it('verifyCommitmentsSum and verifyBalance evaluate the homomorphic sum', async () => {
    const generator = await provider.deriveAssetTag(HTR_TOKEN_UID);
    const vbf = await provider.generateRandomBlindingFactor();
    const commitment = await provider.createCommitment(100n, vbf, generator);

    // Same commitment on both sides sums to zero.
    expect(await provider.verifyCommitmentsSum([commitment], [commitment])).toBe(true);
    expect(await provider.verifyCommitmentsSum([commitment], [])).toBe(false);

    // Transparent balance: 100 in == 100 out (same token) balances; 100 vs 99 does not.
    const token = Buffer.alloc(32, 0x07);
    expect(
      await provider.verifyBalance([{ amount: 100n, tokenUid: token }], [], [{ amount: 100n, tokenUid: token }], [])
    ).toBe(true);
    expect(
      await provider.verifyBalance([{ amount: 100n, tokenUid: token }], [], [{ amount: 99n, tokenUid: token }], [])
    ).toBe(false);
  });
});
