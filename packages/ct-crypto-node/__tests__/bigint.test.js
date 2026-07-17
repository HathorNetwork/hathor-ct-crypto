/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

'use strict';

/**
 * End-to-end BigInt boundary tests through the NAPI bindings.
 *
 * The Rust-side unit tests in `src/napi_bindings.rs` cover the `bigint_to_u64`
 * conversion in isolation. This suite exercises the same boundary *through the
 * real addon*, which the Rust tests cannot: the binding functions return napi
 * `Buffer`s whose `Drop` links against symbols only present inside a running
 * Node.js. Two properties matter at this boundary:
 *
 *   1. The 40-bit range-proof cap (`MAX_PROVABLE_AMOUNT = 2^40`, a consensus
 *      value shared with hathor-core): amounts at the cap are provable, amounts
 *      above it are rejected up front rather than turned into oversize,
 *      magnitude-leaking proofs.
 *   2. BigInt marshaling is lossless past 2^53 (the largest integer a JS Number
 *      holds exactly) all the way to the u64 range — the reason the boundary
 *      takes BigInt, not number.
 *
 * Skips gracefully when the local platform has no prebuild, and FAILS loudly
 * under CT_CRYPTO_REQUIRE_NATIVE=1 (the "real crypto" CI job).
 */

let ct;
let providerLoadError;
try {
  ct = require('../index');
} catch (e) {
  providerLoadError = e;
}

if (providerLoadError && process.env.CT_CRYPTO_REQUIRE_NATIVE) {
  throw new Error(
    'CT_CRYPTO_REQUIRE_NATIVE is set but the ct-crypto-node native addon failed to load: ' +
      providerLoadError.message
  );
}

const describeIfNative = providerLoadError ? describe.skip : describe;

if (providerLoadError) {
  // eslint-disable-next-line no-console
  console.warn(
    'Skipping BigInt boundary tests — ct-crypto-node native addon not buildable:',
    providerLoadError.message
  );
}

const HTR_TOKEN_UID = Buffer.alloc(32, 0);

// MAX_PROVABLE_AMOUNT — mirrors crypto-core's `RANGE_PROOF_BITS = 40` cap.
const MAX_PROVABLE_AMOUNT = 1n << 40n;

describeIfNative('BigInt boundary — 40-bit range-proof cap', () => {
  const recipientPubkey = providerLoadError ? null : ct.generateEphemeralKeypair().publicKey;
  const vbf = providerLoadError ? null : ct.generateRandomBlindingFactor();

  it('accepts the maximum provable amount (2^40)', () => {
    const out = ct.createAmountShieldedOutput(
      MAX_PROVABLE_AMOUNT,
      recipientPubkey,
      HTR_TOKEN_UID,
      vbf
    );
    expect(Buffer.isBuffer(out.commitment)).toBe(true);
    expect(out.commitment.length).toBe(33);
  });

  it('rejects amounts one above the cap (2^40 + 1)', () => {
    expect(() =>
      ct.createAmountShieldedOutput(
        MAX_PROVABLE_AMOUNT + 1n,
        recipientPubkey,
        HTR_TOKEN_UID,
        ct.generateRandomBlindingFactor()
      )
    ).toThrow(/provable range/);
  });
});

describeIfNative('BigInt boundary — lossless marshaling past 2^53', () => {
  const generator = providerLoadError ? null : ct.deriveAssetTag(HTR_TOKEN_UID);
  const blinding = providerLoadError ? null : ct.generateRandomBlindingFactor();

  it('does not truncate values above the JS safe-integer range (2^53 vs 2^53 + 1)', () => {
    // Number(2^53) === Number(2^53 + 1) — a lossy marshaling would collapse both
    // to the same value and produce identical commitments. Distinct commitments
    // prove the BigInt reached the u64 boundary intact.
    const a = 1n << 53n;
    const commitmentA = ct.createCommitment(a, blinding, generator);
    const commitmentB = ct.createCommitment(a + 1n, blinding, generator);
    expect(commitmentA.length).toBe(33);
    expect(commitmentA.equals(commitmentB)).toBe(false);
  });

  it('marshals a large u64-range amount (2^63) without error', () => {
    const commitment = ct.createCommitment((1n << 63n) + 12345n, blinding, generator);
    expect(Buffer.isBuffer(commitment)).toBe(true);
    expect(commitment.length).toBe(33);
  });

  it('rejects negative amounts', () => {
    expect(() => ct.createCommitment(-1n, blinding, generator)).toThrow(/non-negative/);
  });

  it('rejects amounts beyond the u64 range (2^64)', () => {
    expect(() => ct.createCommitment(1n << 64n, blinding, generator)).toThrow(/exceeds u64 range/);
  });
});
