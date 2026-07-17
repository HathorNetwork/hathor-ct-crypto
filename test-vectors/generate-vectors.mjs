/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

/**
 * Regenerate the canonical cross-implementation parity fixture
 * (`test-vectors/shielded-parity-vectors.json`).
 *
 * The vectors are REAL, not invented: every byte string below is produced by
 * running the `@hathor/ct-crypto-node` NAPI binding against the shared
 * `crypto-core` Rust implementation — the same consensus code the wasm and
 * mobile bindings compile. Because that core is byte-compatible with upstream
 * hathor-core, these vectors double as a regression guard: if a future edit to
 * crypto-core (or any binding) changes a commitment / tag / generator / proof
 * on the wire, `parity.test.mjs` fails.
 *
 * Determinism: every operation captured here is a pure function of its inputs
 * OR is fed a fixed nonce, so re-running this generator reproduces the SAME
 * bytes for the deterministic sections (tags, commitments, asset commitments,
 * range proofs with a fixed nonce, surjection proofs, balance cases). The only
 * exception is the higher-level `shieldedOutputs` section, which exercises
 * `createAmountShieldedOutput` — that API mints a fresh random ephemeral key
 * internally, so its bytes differ each run. That section is captured once as a
 * real artifact and stays valid forever (the parity test only ever *verifies*
 * and *rewinds* it, never regenerates it), but if you regenerate the fixture
 * those particular bytes will change. That is expected and harmless.
 *
 * Usage:
 *   node test-vectors/generate-vectors.mjs            # writes the fixture
 *   node test-vectors/generate-vectors.mjs --check    # regenerate to a temp
 *                                                     # buffer and diff the
 *                                                     # deterministic sections
 *
 * Requires the `@hathor/ct-crypto-node` native addon to be built for this
 * platform (packages/ct-crypto-node/prebuilds/<platform>/ct-crypto.node). If it
 * is missing the generator exits with a clear message — build it first
 * (`npm --workspace @hathor/ct-crypto-node run build`) or run the generator on a
 * machine/CI job that has the prebuild.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { Buffer } from 'node:buffer';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

const NODE_INDEX = path.resolve(__dirname, '../packages/ct-crypto-node/index.js');
const OUT_FILE = path.resolve(__dirname, 'shielded-parity-vectors.json');

let ct;
try {
  ct = require(NODE_INDEX);
} catch (err) {
  console.error(
    '\n[generate-vectors] FAILED to load @hathor/ct-crypto-node native addon.\n' +
      `Tried: ${NODE_INDEX}\n` +
      `Error: ${err.message}\n\n` +
      'Build it first:  npm --workspace @hathor/ct-crypto-node run build\n' +
      '(or run this generator on a CI job that produced the prebuild).\n'
  );
  process.exit(1);
}

// ─── byte helpers ──────────────────────────────────────────────────────────

const hex = buf => Buffer.from(buf).toString('hex');
/** Fill a 32-byte scalar with a repeated byte — stable, human-recognisable. */
const scalar = b => Buffer.alloc(32, b);
const uid = b => Buffer.alloc(32, b);

// ─── fixed inputs ───────────────────────────────────────────────────────────

const HTR = uid(0x00); // HTR: all-zero token uid
const TOKEN_A = uid(0xaa);
const TOKEN_B = uid(0xbb);
const ZERO = ct.getZeroTweak();

const tokens = [
  { label: 'HTR', tokenUid: HTR },
  { label: 'token-AA', tokenUid: TOKEN_A },
  { label: 'token-BB', tokenUid: TOKEN_B },
];

// ─── 1. tags + generators (deterministic, pure functions of the uid) ────────

const tags = tokens.map(t => ({
  label: t.label,
  tokenUid: hex(t.tokenUid),
  deriveTag: hex(ct.deriveTag(t.tokenUid)), // 32-byte Tag scalar
  deriveAssetTag: hex(ct.deriveAssetTag(t.tokenUid)), // 33-byte unblinded generator
}));

const htrAssetTag = hex(ct.htrAssetTag());

// ─── 2. Pedersen commitments (deterministic) ─────────────────────────────────
// generator = deriveAssetTag(tokenUid) — the AmountShielded value-commitment
// generator (asset generator is unblinded there).

const commitmentInputs = [
  { value: 0n, blinding: scalar(0x01), token: HTR },
  { value: 1n, blinding: scalar(0x02), token: HTR },
  { value: 123n, blinding: scalar(0x07), token: HTR },
  { value: 4242n, blinding: scalar(0x09), token: TOKEN_A },
  { value: 18446744073709551615n, blinding: scalar(0x11), token: TOKEN_B }, // u64::MAX
];

const commitments = commitmentInputs.map(c => {
  const generator = ct.deriveAssetTag(c.token);
  const commitment = ct.createCommitment(c.value, c.blinding, generator);
  return {
    value: c.value.toString(),
    blindingFactor: hex(c.blinding),
    tokenUid: hex(c.token),
    generator: hex(generator),
    commitment: hex(commitment),
  };
});

// ─── 3. asset commitments (deterministic): Tag*G + bf*H ──────────────────────

const assetCommitmentInputs = [
  { token: TOKEN_A, blinding: scalar(0x01) },
  { token: TOKEN_B, blinding: scalar(0x02) },
  { token: HTR, blinding: scalar(0x03) },
];

const assetCommitments = assetCommitmentInputs.map(a => {
  const tag = ct.deriveTag(a.token);
  const assetCommitment = ct.createAssetCommitment(tag, a.blinding);
  return {
    tokenUid: hex(a.token),
    tag: hex(tag),
    blindingFactor: hex(a.blinding),
    assetCommitment: hex(assetCommitment),
  };
});

// ─── 4. range proofs (deterministic via a fixed nonce) ───────────────────────
// createRangeProof(amount, blinding, commitment, generator, message, nonce) is
// deterministic when `nonce` is fixed, so we can store the exact proof bytes.
// Any binding exposing verifyRangeProof MUST return true for (proof, commitment,
// generator); node's rewindRangeProof recovers (amount, blinding).

const rangeProofInputs = [
  { value: 4242n, blinding: scalar(0x09), token: HTR, nonce: scalar(0x11) },
  { value: 1n, blinding: scalar(0x05), token: TOKEN_A, nonce: scalar(0x22) },
];

const rangeProofs = rangeProofInputs.map(r => {
  const generator = ct.deriveAssetTag(r.token);
  const commitment = ct.createCommitment(r.value, r.blinding, generator);
  const proof = ct.createRangeProof(r.value, r.blinding, commitment, generator, null, r.nonce);
  const rewound = ct.rewindRangeProof(proof, commitment, r.nonce, generator);
  if (rewound.value !== r.value || !Buffer.from(rewound.blindingFactor).equals(r.blinding)) {
    throw new Error('range-proof self-check failed: rewind did not reproduce inputs');
  }
  if (!ct.verifyRangeProof(proof, commitment, generator)) {
    throw new Error('range-proof self-check failed: verifyRangeProof returned false');
  }
  return {
    value: r.value.toString(),
    blindingFactor: hex(r.blinding),
    tokenUid: hex(r.token),
    generator: hex(generator),
    commitment: hex(commitment),
    nonce: hex(r.nonce),
    message: null,
    proof: hex(proof),
    rewind: { value: r.value.toString(), blindingFactor: hex(r.blinding) },
  };
});

// ─── 5. shielded outputs (higher-level; ECDH round-trip) ─────────────────────
// createAmountShieldedOutput mints a RANDOM ephemeral key internally, so these
// bytes are captured once (not reproducible byte-for-byte on regenerate) but
// stay valid forever. Parity test: every binding with rewindAmountShieldedOutput
// recovers (value, blindingFactor); every binding with verifyRangeProof accepts
// the proof; a foreign scan key yields a scan-miss.

const shieldedOutputInputs = [
  { mode: 'amount', value: 424242n, token: HTR, vbf: scalar(0x33) },
  { mode: 'amount', value: 7n, token: TOKEN_A, vbf: scalar(0x44) },
];

const shieldedOutputs = shieldedOutputInputs.map(s => {
  const kp = ct.generateEphemeralKeypair(); // recipient keypair (test-only secret)
  const generator = ct.deriveAssetTag(s.token);
  const out = ct.createAmountShieldedOutput(s.value, kp.publicKey, s.token, s.vbf);
  // Self-check: the sender-side blinding factor round-trips.
  const rw = ct.rewindAmountShieldedOutput(
    kp.privateKey,
    out.ephemeralPubkey,
    out.commitment,
    out.rangeProof,
    s.token
  );
  if (rw.value !== s.value || !Buffer.from(rw.blindingFactor).equals(Buffer.from(out.blindingFactor))) {
    throw new Error('shielded-output self-check failed: rewind mismatch');
  }
  return {
    mode: s.mode,
    value: s.value.toString(),
    tokenUid: hex(s.token),
    generator: hex(generator),
    recipientPrivateKey: hex(kp.privateKey), // TEST-ONLY throwaway secret
    recipientPubkey: hex(kp.publicKey),
    ephemeralPubkey: hex(out.ephemeralPubkey),
    commitment: hex(out.commitment),
    rangeProof: hex(out.rangeProof),
    blindingFactor: hex(out.blindingFactor),
    expected: { value: s.value.toString(), blindingFactor: hex(out.blindingFactor) },
  };
});

// ─── 6. surjection proofs (deterministic) ────────────────────────────────────
// Domain = two candidate input assets (blinded generators); codomain = the
// output asset. A valid proof shows the output asset is one of the domain
// assets. verifySurjectionProof(proof, codomainGenerator, domainGenerators) is
// the same on every binding that exposes it.

function buildSurjection(codomainToken, codomainBf, domainSpec) {
  const domain = domainSpec.map(d => {
    const tag = ct.deriveTag(d.token);
    const generator = ct.createAssetCommitment(tag, d.bf);
    return { token: d.token, tag, bf: d.bf, generator };
  });
  const codomainTag = ct.deriveTag(codomainToken);
  const codomainGenerator = ct.createAssetCommitment(codomainTag, codomainBf);
  const proof = ct.createSurjectionProof(
    codomainTag,
    codomainBf,
    domain.map(d => ({ generator: d.generator, tag: d.tag, blindingFactor: d.bf }))
  );
  return { codomainToken, codomainBf, codomainTag, codomainGenerator, domain, proof };
}

const surjectionValid = buildSurjection(TOKEN_A, scalar(0x03), [
  { token: TOKEN_A, bf: scalar(0x01) },
  { token: TOKEN_B, bf: scalar(0x02) },
]);

// Self-check the positive case, and derive a negative codomain (token B mapped
// to token A's proof) that must verify false.
if (
  !ct.verifySurjectionProof(
    surjectionValid.proof,
    surjectionValid.codomainGenerator,
    surjectionValid.domain.map(d => d.generator)
  )
) {
  throw new Error('surjection self-check failed: valid proof did not verify');
}

const surjectionProofs = [
  {
    label: 'valid: output token-AA is in domain {AA, BB}',
    codomainTokenUid: hex(surjectionValid.codomainToken),
    codomainTag: hex(surjectionValid.codomainTag),
    codomainBlindingFactor: hex(surjectionValid.codomainBf),
    codomainGenerator: hex(surjectionValid.codomainGenerator),
    domain: surjectionValid.domain.map(d => ({
      tokenUid: hex(d.token),
      tag: hex(d.tag),
      blindingFactor: hex(d.bf),
      generator: hex(d.generator),
    })),
    proof: hex(surjectionValid.proof),
    expected: true,
  },
  {
    // Same proof + domain, but verified against the WRONG codomain generator
    // (token-BB's). Must be rejected.
    label: 'invalid: proof checked against a mismatched codomain generator',
    codomainGenerator: hex(surjectionValid.domain[1].generator),
    domain: surjectionValid.domain.map(d => hex(d.generator)),
    proof: hex(surjectionValid.proof),
    expected: false,
  },
];

// ─── 7. balance verification cases ───────────────────────────────────────────

const htrAssetGen = ct.deriveAssetTag(HTR);

// A real, balanced 1-shielded-input / 2-shielded-output transaction. The second
// output's blinding factor is solved so the homomorphic sum is exactly zero.
const rIn = scalar(0x05);
const rOut1 = scalar(0x06);
const rOut2 = ct.computeBalancingBlindingFactor(
  40n,
  ZERO,
  [{ value: 100n, valueBlindingFactor: rIn, generatorBlindingFactor: ZERO }],
  [{ value: 60n, valueBlindingFactor: rOut1, generatorBlindingFactor: ZERO }]
);
const cIn = ct.createCommitment(100n, rIn, htrAssetGen);
const cOut1 = ct.createCommitment(60n, rOut1, htrAssetGen);
const cOut2 = ct.createCommitment(40n, rOut2, htrAssetGen);

const balance = [
  {
    label: 'transparent: 100 HTR in == 100 HTR out',
    transparentInputs: [{ amount: '100', tokenUid: hex(HTR) }],
    shieldedInputs: [],
    transparentOutputs: [{ amount: '100', tokenUid: hex(HTR) }],
    shieldedOutputs: [],
    excessBlindingFactor: null,
    expected: true,
  },
  {
    label: 'transparent: 100 HTR in != 90 HTR out',
    transparentInputs: [{ amount: '100', tokenUid: hex(HTR) }],
    shieldedInputs: [],
    transparentOutputs: [{ amount: '90', tokenUid: hex(HTR) }],
    shieldedOutputs: [],
    excessBlindingFactor: null,
    expected: false,
  },
  {
    label: 'shielded: 100 in == 60 + 40 out (balancing bf solved)',
    transparentInputs: [],
    shieldedInputs: [hex(cIn)],
    transparentOutputs: [],
    shieldedOutputs: [hex(cOut1), hex(cOut2)],
    excessBlindingFactor: null,
    expected: true,
  },
  {
    label: 'shielded: 100 in != 60 out (one output dropped)',
    transparentInputs: [],
    shieldedInputs: [hex(cIn)],
    transparentOutputs: [],
    shieldedOutputs: [hex(cOut1)],
    excessBlindingFactor: null,
    expected: false,
  },
];

// Self-check every balance case against the reference binding.
for (const b of balance) {
  const got = ct.verifyBalance(
    b.transparentInputs.map(e => ({ amount: BigInt(e.amount), tokenUid: Buffer.from(e.tokenUid, 'hex') })),
    b.shieldedInputs.map(c => Buffer.from(c, 'hex')),
    b.transparentOutputs.map(e => ({ amount: BigInt(e.amount), tokenUid: Buffer.from(e.tokenUid, 'hex') })),
    b.shieldedOutputs.map(c => Buffer.from(c, 'hex')),
    b.excessBlindingFactor ? Buffer.from(b.excessBlindingFactor, 'hex') : undefined
  );
  if (got !== b.expected) {
    throw new Error(`balance self-check failed for "${b.label}": expected ${b.expected}, got ${got}`);
  }
}

// ─── 8. commitments-sum cases ────────────────────────────────────────────────

const commitmentsSum = [
  {
    label: 'sum(in) == sum(out): 1 in vs 2 out (same balanced set)',
    positive: [hex(cIn)],
    negative: [hex(cOut1), hex(cOut2)],
    expected: true,
  },
  {
    label: 'sum mismatch: single commitment vs empty',
    positive: [hex(cIn)],
    negative: [],
    expected: false,
  },
];

for (const cs of commitmentsSum) {
  const got = ct.verifyCommitmentsSum(
    cs.positive.map(c => Buffer.from(c, 'hex')),
    cs.negative.map(c => Buffer.from(c, 'hex'))
  );
  if (got !== cs.expected) {
    throw new Error(`commitments-sum self-check failed for "${cs.label}"`);
  }
}

// ─── 9. validation cases ─────────────────────────────────────────────────────

const validate = {
  validCommitment: hex(cIn), // a real on-curve Pedersen commitment
  validGenerator: hex(htrAssetGen), // a real on-curve generator
  invalidPoint: hex(Buffer.alloc(33, 0x01)), // 33 bytes, not on the curve
};

// ─── assemble + write ────────────────────────────────────────────────────────

const fixture = {
  _meta: {
    description:
      'Canonical cross-implementation parity vectors for Hathor shielded crypto. ' +
      'REAL bytes produced by @hathor/ct-crypto-node over the shared crypto-core; ' +
      'every binding (node/wasm/mobile) must reproduce/verify them identically.',
    generator: 'test-vectors/generate-vectors.mjs',
    source: '@hathor/ct-crypto-node NAPI binding -> crypto-core (byte-compatible with hathor-core)',
    regenerate: 'node test-vectors/generate-vectors.mjs',
    consumedBy: 'test-vectors/parity.test.mjs (npm run test:parity)',
    encoding: 'byte strings are lowercase hex; u64 values are decimal strings',
    sizes: { tag: 32, generator: 33, commitment: 33, scalar: 32, pubkey: 33 },
    warning:
      'The shieldedOutputs section captures createAmountShieldedOutput, which uses a ' +
      'fresh random ephemeral key each run; regenerating changes those bytes (still valid). ' +
      'All other sections are deterministic and reproduce byte-for-byte.',
  },
  constants: { zeroTweak: hex(ZERO), htrAssetTag },
  tags,
  commitments,
  assetCommitments,
  rangeProofs,
  shieldedOutputs,
  surjectionProofs,
  balance,
  commitmentsSum,
  validate,
};

const json = JSON.stringify(fixture, null, 2) + '\n';

if (process.argv.includes('--check')) {
  // Compare deterministic sections against the committed fixture (ignore the
  // intentionally-nondeterministic shieldedOutputs bytes).
  if (!fs.existsSync(OUT_FILE)) {
    console.error('[generate-vectors] --check: no committed fixture to compare against.');
    process.exit(1);
  }
  const committed = JSON.parse(fs.readFileSync(OUT_FILE, 'utf8'));
  const strip = o => {
    const { shieldedOutputs: _drop, _meta: _m, ...rest } = o;
    return JSON.stringify(rest);
  };
  if (strip(committed) !== strip(fixture)) {
    console.error(
      '[generate-vectors] --check FAILED: deterministic vectors drifted from the committed fixture.\n' +
        'A crypto-core / binding change altered on-the-wire bytes. If intentional, regenerate:\n' +
        '  node test-vectors/generate-vectors.mjs'
    );
    process.exit(1);
  }
  console.log('[generate-vectors] --check OK: deterministic vectors match the committed fixture.');
  process.exit(0);
}

fs.writeFileSync(OUT_FILE, json);
console.log(
  `[generate-vectors] wrote ${OUT_FILE}\n` +
    `  tags=${tags.length} commitments=${commitments.length} assetCommitments=${assetCommitments.length} ` +
    `rangeProofs=${rangeProofs.length} shieldedOutputs=${shieldedOutputs.length} ` +
    `surjection=${surjectionProofs.length} balance=${balance.length} commitmentsSum=${commitmentsSum.length}`
);
