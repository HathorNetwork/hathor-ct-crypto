/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

/**
 * Cross-implementation parity harness.
 *
 * This is the fixture that guarantees @hathor/ct-crypto-node,
 * @hathor/ct-crypto-wasm and @hathor/ct-crypto-mobile stay interchangeable and
 * consensus-compatible: an artifact (commitment / range proof / surjection
 * proof) produced by one binding must reproduce byte-for-byte and verify under
 * the others, and all of them must agree with the canonical crypto-core
 * reference vectors in `shielded-parity-vectors.json`.
 *
 * What it does:
 *   1. REFERENCE — each available binding recomputes the deterministic vectors
 *      (tags, generators, commitments, asset commitments) and must match the
 *      committed fixture exactly. Because the fixture was minted by the node
 *      binding over crypto-core, node passing is a regression guard and wasm
 *      passing proves node == wasm == crypto-core on the wire.
 *   2. VERIFY — each binding that ships the verifier surface must accept the
 *      real range proofs / surjection proofs / balance cases in the fixture and
 *      reject the negative cases.
 *   3. REWIND — each binding that can rewind recovers (value, blindingFactor)
 *      from the fixture's shielded outputs.
 *   4. LIVE cross-binding — node MINTS a fresh amount-shielded output and wasm
 *      REWINDS + VERIFIES it (the direct interchangeability proof).
 *
 * Graceful degradation: a binding whose built artifact is absent locally is
 * SKIPPED with a reason (not failed) — a dev without the wasm toolchain still
 * gets the node half. Set `PARITY_REQUIRE=node,wasm` (CI does) to turn "binding
 * unavailable" into a hard failure so the CI job can't go green having exercised
 * nothing.
 *
 * Run:  node test-vectors/parity.test.mjs      (or: npm run test:parity)
 * Exit: non-zero if any check FAILS or a required binding is missing/stale.
 *
 * Mobile: @hathor/ct-crypto-mobile is a React-Native UniFFI native module with
 * no Node-loadable build, so it is skipped here by default. It wraps the SAME
 * crypto-core, and its parity is pinned by having its own platform tests load
 * THIS fixture (see test-vectors/README.md). To exercise it in Node, point
 * `MOBILE_NATIVE_MODULE` at a module exporting the UniFFI surface and it will be
 * run through the same reference/verify/rewind checks.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { Buffer } from 'node:buffer';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

const FIXTURE = path.resolve(__dirname, 'shielded-parity-vectors.json');
const vectors = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));

const REQUIRE = new Set(
  (process.env.PARITY_REQUIRE || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
);

// ─── byte helpers ────────────────────────────────────────────────────────────

const buf = h => Buffer.from(h, 'hex');
const toHex = b => Buffer.from(b).toString('hex');

// ─── tiny test framework ─────────────────────────────────────────────────────

const results = { pass: 0, fail: 0, skip: 0 };
const failures = [];
const skippedBindings = new Set();
const staleBindings = new Map(); // name -> reason (loaded but missing verifier surface)
let currentSection = '';

function section(name) {
  currentSection = name;
  process.stdout.write(`\n${name}\n`);
}

async function check(name, fn) {
  try {
    await fn();
    results.pass += 1;
    process.stdout.write(`  ok   ${name}\n`);
  } catch (err) {
    results.fail += 1;
    const msg = err && err.message ? err.message : String(err);
    failures.push(`[${currentSection}] ${name}: ${msg}`);
    process.stdout.write(`  FAIL ${name} — ${msg}\n`);
  }
}

function skip(name, reason) {
  results.skip += 1;
  process.stdout.write(`  skip ${name} — ${reason}\n`);
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'assertion failed');
}
function assertHex(actual, expectedHex, msg) {
  const got = toHex(actual);
  if (got !== expectedHex) {
    throw new Error(`${msg || 'byte mismatch'}: expected ${expectedHex}, got ${got}`);
  }
}
function assertEq(actual, expected, msg) {
  if (actual !== expected) throw new Error(`${msg || 'mismatch'}: expected ${expected}, got ${actual}`);
}

// ─── binding adapters (normalise every binding to a Buffer-in/Buffer-out API) ─

/** Load the node raw NAPI binding. Returns an adapter or null. */
function loadNode() {
  let ct;
  try {
    ct = require(path.resolve(__dirname, '../packages/ct-crypto-node/index.js'));
  } catch (err) {
    return { adapter: null, reason: `native addon not loadable: ${err.message}` };
  }
  const adapter = {
    name: 'node',
    caps: new Set([
      'deriveTag',
      'deriveAssetTag',
      'createCommitment',
      'createAssetCommitment',
      'verifyRangeProof',
      'verifySurjectionProof',
      'verifyCommitmentsSum',
      'verifyBalance',
      'validateCommitment',
      'validateGenerator',
      'rewindAmount',
      'mint',
    ]),
    deriveTag: b => ct.deriveTag(b),
    deriveAssetTag: b => ct.deriveAssetTag(b),
    createCommitment: (v, bf, g) => ct.createCommitment(v, bf, g),
    createAssetCommitment: (t, bf) => ct.createAssetCommitment(t, bf),
    verifyRangeProof: (p, c, g) => ct.verifyRangeProof(p, c, g),
    verifySurjectionProof: (p, cod, dom) => ct.verifySurjectionProof(p, cod, dom),
    verifyCommitmentsSum: (pos, neg) => ct.verifyCommitmentsSum(pos, neg),
    verifyBalance: (ti, si, to, so, ex) => ct.verifyBalance(ti, si, to, so, ex ?? undefined),
    validateCommitment: d => ct.validateCommitment(d),
    validateGenerator: d => ct.validateGenerator(d),
    rewindAmount: (pk, ep, c, rp, uid) => {
      const r = ct.rewindAmountShieldedOutput(pk, ep, c, rp, uid);
      return { value: r.value, blindingFactor: Buffer.from(r.blindingFactor) };
    },
    mint: (v, pub, uid, vbf) => {
      const o = ct.createAmountShieldedOutput(v, pub, uid, vbf);
      return {
        ephemeralPubkey: Buffer.from(o.ephemeralPubkey),
        commitment: Buffer.from(o.commitment),
        rangeProof: Buffer.from(o.rangeProof),
        blindingFactor: Buffer.from(o.blindingFactor),
      };
    },
    generateEphemeralKeypair: () => {
      const kp = ct.generateEphemeralKeypair();
      return { privateKey: Buffer.from(kp.privateKey), publicKey: Buffer.from(kp.publicKey) };
    },
  };
  return { adapter, reason: null };
}

/** Load the wasm-bindgen build from pkg/. Returns an adapter or null. */
async function loadWasm() {
  const pkgDir = path.resolve(__dirname, '../packages/ct-crypto-wasm/pkg');
  const gluePath = path.join(pkgDir, 'hathor_ct_crypto_wasm.js');
  const wasmPath = path.join(pkgDir, 'hathor_ct_crypto_wasm_bg.wasm');
  if (!fs.existsSync(gluePath) || !fs.existsSync(wasmPath)) {
    return { adapter: null, reason: `built artifact not found under ${pkgDir} (run its build)` };
  }
  // Which verifier exports the built glue actually ships — a stale local build
  // may predate the newer verifier surface. Gate per-capability on this.
  const exportNames = new Set(
    Array.from(fs.readFileSync(gluePath, 'utf8').matchAll(/export function (\w+)/g)).map(m => m[1])
  );
  let wasm;
  try {
    wasm = await import(pathToFileURL(gluePath).href);
    // Instantiate synchronously from the on-disk bytes — the wasm-pack
    // --target web loader's fetch/import.meta.url path does not work in Node.
    wasm.initSync({ module: new WebAssembly.Module(fs.readFileSync(wasmPath)) });
  } catch (err) {
    return { adapter: null, reason: `failed to instantiate wasm: ${err.message}` };
  }
  const caps = new Set(['deriveTag', 'deriveAssetTag', 'createCommitment', 'createAssetCommitment', 'rewindAmount']);
  const capFor = {
    verifyRangeProof: 'verifyRangeProof',
    verifySurjectionProof: 'verifySurjectionProof',
    verifyCommitmentsSum: 'verifyCommitmentsSum',
    verifyBalance: 'verifyBalance',
    validateCommitment: 'validateCommitment',
    validateGenerator: 'validateGenerator',
  };
  for (const [cap, exp] of Object.entries(capFor)) {
    if (exportNames.has(exp)) caps.add(cap);
  }
  const adapter = {
    name: 'wasm',
    caps,
    staleReason: caps.has('verifyBalance')
      ? null
      : 'pkg/ predates the verifier surface — rebuild @hathor/ct-crypto-wasm to run verify checks',
    deriveTag: b => Buffer.from(wasm.deriveTag(b)),
    deriveAssetTag: b => Buffer.from(wasm.deriveAssetTag(b)),
    createCommitment: (v, bf, g) => Buffer.from(wasm.createCommitment(v, bf, g)),
    createAssetCommitment: (t, bf) => Buffer.from(wasm.createAssetCommitment(t, bf)),
    verifyRangeProof: (p, c, g) => wasm.verifyRangeProof(p, c, g),
    verifySurjectionProof: (p, cod, dom) => wasm.verifySurjectionProof(p, cod, dom),
    verifyCommitmentsSum: (pos, neg) => wasm.verifyCommitmentsSum(pos, neg),
    // wasm-bindgen has no array-of-structs marshaling, so the transparent
    // entries are split into parallel amounts / tokenUids arrays.
    verifyBalance: (ti, si, to, so, ex) =>
      wasm.verifyBalance(
        ti.map(e => e.amount),
        ti.map(e => e.tokenUid),
        si,
        to.map(e => e.amount),
        to.map(e => e.tokenUid),
        so,
        ex ?? undefined
      ),
    validateCommitment: d => wasm.validateCommitment(d),
    validateGenerator: d => wasm.validateGenerator(d),
    rewindAmount: (pk, ep, c, rp, uid) => {
      const r = wasm.rewindAmountShieldedOutput(pk, ep, c, rp, uid);
      try {
        return { value: r.value, blindingFactor: Buffer.from(r.blindingFactor) };
      } finally {
        if (typeof r.free === 'function') r.free();
      }
    },
  };
  return { adapter, reason: null };
}

/**
 * Optional mobile leg: only runs when MOBILE_NATIVE_MODULE points at a module
 * exposing the UniFFI surface. The mobile provider marshals through the
 * AbstractShieldedProvider (Buffer in/out), so we adapt its async provider
 * methods to the same shape.
 */
async function loadMobile() {
  const modPath = process.env.MOBILE_NATIVE_MODULE;
  if (!modPath) return { adapter: null, reason: 'MOBILE_NATIVE_MODULE not set (RN native module has no Node build)' };
  let createMobileShieldedCryptoProvider;
  let nativeModule;
  try {
    ({ createMobileShieldedCryptoProvider } = require(
      path.resolve(__dirname, '../packages/ct-crypto-mobile/js/index.js')
    ));
    nativeModule = require(path.resolve(process.cwd(), modPath));
  } catch (err) {
    return { adapter: null, reason: `could not load mobile provider/native module: ${err.message}` };
  }
  let provider;
  try {
    provider = createMobileShieldedCryptoProvider({ nativeModule });
  } catch (err) {
    return { adapter: null, reason: `mobile provider construction failed: ${err.message}` };
  }
  const adapter = {
    name: 'mobile',
    caps: new Set(['deriveTag', 'deriveAssetTag', 'createCommitment', 'createAssetCommitment', 'rewindAmount']),
    deriveTag: b => provider.deriveTag(b),
    deriveAssetTag: b => provider.deriveAssetTag(b),
    createCommitment: (v, bf, g) => provider.createCommitment(v, bf, g),
    createAssetCommitment: (t, bf) => provider.createAssetCommitment(t, bf),
    rewindAmount: async (pk, ep, c, rp, uid) => {
      const r = await provider.rewindAmountShieldedOutput(pk, ep, c, rp, uid);
      return { value: r.value, blindingFactor: Buffer.from(r.blindingFactor) };
    },
  };
  return { adapter, reason: null };
}

// ─── check suites (run against any adapter that has the capability) ──────────

async function referenceChecks(a) {
  section(`REFERENCE — ${a.name} recomputes deterministic vectors == fixture`);

  for (const t of vectors.tags) {
    if (a.caps.has('deriveTag')) {
      await check(`deriveTag(${t.label})`, async () => assertHex(await a.deriveTag(buf(t.tokenUid)), t.deriveTag));
    }
    if (a.caps.has('deriveAssetTag')) {
      await check(`deriveAssetTag(${t.label})`, async () =>
        assertHex(await a.deriveAssetTag(buf(t.tokenUid)), t.deriveAssetTag)
      );
    }
  }

  if (a.caps.has('createCommitment')) {
    for (const c of vectors.commitments) {
      await check(`createCommitment(v=${c.value}, ${c.tokenUid.slice(0, 4)}…)`, async () =>
        assertHex(await a.createCommitment(BigInt(c.value), buf(c.blindingFactor), buf(c.generator)), c.commitment)
      );
    }
  }

  if (a.caps.has('createAssetCommitment')) {
    for (const ac of vectors.assetCommitments) {
      await check(`createAssetCommitment(${ac.tokenUid.slice(0, 4)}…)`, async () =>
        assertHex(await a.createAssetCommitment(buf(ac.tag), buf(ac.blindingFactor)), ac.assetCommitment)
      );
    }
  }
}

async function verifyChecks(a) {
  if (a.staleReason && !a.caps.has('verifyRangeProof')) {
    section(`VERIFY — ${a.name}`);
    skip(`${a.name} verifier surface`, a.staleReason);
    return;
  }
  section(`VERIFY — ${a.name} accepts real proofs / rejects negatives`);

  if (a.caps.has('verifyRangeProof')) {
    for (const rp of vectors.rangeProofs) {
      await check(`verifyRangeProof(v=${rp.value}) == true`, async () =>
        assertEq(await a.verifyRangeProof(buf(rp.proof), buf(rp.commitment), buf(rp.generator)), true)
      );
      // A different, valid, on-curve commitment (value+1) must NOT verify.
      if (a.caps.has('createCommitment')) {
        await check(`verifyRangeProof(v=${rp.value}, wrong commitment) == false`, async () => {
          const wrong = await a.createCommitment(BigInt(rp.value) + 1n, buf(rp.blindingFactor), buf(rp.generator));
          assertEq(await a.verifyRangeProof(buf(rp.proof), wrong, buf(rp.generator)), false);
        });
      }
    }
  }

  if (a.caps.has('verifySurjectionProof')) {
    for (const sp of vectors.surjectionProofs) {
      const domainGens = (sp.domain || []).map(d => buf(typeof d === 'string' ? d : d.generator));
      await check(`verifySurjectionProof(${sp.label}) == ${sp.expected}`, async () =>
        assertEq(await a.verifySurjectionProof(buf(sp.proof), buf(sp.codomainGenerator), domainGens), sp.expected)
      );
    }
  }

  if (a.caps.has('verifyBalance')) {
    for (const b of vectors.balance) {
      const ti = b.transparentInputs.map(e => ({ amount: BigInt(e.amount), tokenUid: buf(e.tokenUid) }));
      const to = b.transparentOutputs.map(e => ({ amount: BigInt(e.amount), tokenUid: buf(e.tokenUid) }));
      const si = b.shieldedInputs.map(buf);
      const so = b.shieldedOutputs.map(buf);
      const ex = b.excessBlindingFactor ? buf(b.excessBlindingFactor) : undefined;
      await check(`verifyBalance(${b.label}) == ${b.expected}`, async () =>
        assertEq(await a.verifyBalance(ti, si, to, so, ex), b.expected)
      );
    }
  }

  if (a.caps.has('verifyCommitmentsSum')) {
    for (const cs of vectors.commitmentsSum) {
      await check(`verifyCommitmentsSum(${cs.label}) == ${cs.expected}`, async () =>
        assertEq(await a.verifyCommitmentsSum(cs.positive.map(buf), cs.negative.map(buf)), cs.expected)
      );
    }
  }

  if (a.caps.has('validateCommitment')) {
    await check(`validateCommitment(valid) == true`, async () =>
      assertEq(await a.validateCommitment(buf(vectors.validate.validCommitment)), true)
    );
    await check(`validateCommitment(off-curve) == false`, async () =>
      assertEq(await a.validateCommitment(buf(vectors.validate.invalidPoint)), false)
    );
  }
  if (a.caps.has('validateGenerator')) {
    await check(`validateGenerator(valid) == true`, async () =>
      assertEq(await a.validateGenerator(buf(vectors.validate.validGenerator)), true)
    );
  }
}

async function rewindChecks(a) {
  if (!a.caps.has('rewindAmount')) return;
  section(`REWIND — ${a.name} recovers (value, blindingFactor) from fixture outputs`);
  for (const o of vectors.shieldedOutputs.filter(x => x.mode === 'amount')) {
    await check(`rewindAmountShieldedOutput(v=${o.value})`, async () => {
      const r = await a.rewindAmount(
        buf(o.recipientPrivateKey),
        buf(o.ephemeralPubkey),
        buf(o.commitment),
        buf(o.rangeProof),
        buf(o.tokenUid)
      );
      assertEq(r.value, BigInt(o.expected.value), 'recovered value');
      assertHex(r.blindingFactor, o.expected.blindingFactor, 'recovered blinding factor');
    });
  }
}

async function liveCrossRoundTrip(nodeA, wasmA) {
  section('LIVE cross-binding — node MINTS, wasm REWINDS + VERIFIES');
  if (!nodeA || !nodeA.caps.has('mint')) {
    skip('live node->wasm round-trip', 'node binding unavailable (cannot mint)');
    return;
  }
  if (!wasmA || !wasmA.caps.has('rewindAmount')) {
    skip('live node->wasm round-trip', 'wasm binding unavailable');
    return;
  }
  const tokenUid = buf(vectors.tags[0].tokenUid); // HTR
  const generator = buf(vectors.tags[0].deriveAssetTag);
  const kp = nodeA.generateEphemeralKeypair();
  const value = 987654n;
  const vbf = Buffer.alloc(32, 0x5a);
  const out = nodeA.mint(value, kp.publicKey, tokenUid, vbf);

  await check('wasm rewinds a node-minted output back to cleartext', async () => {
    const r = await wasmA.rewindAmount(kp.privateKey, out.ephemeralPubkey, out.commitment, out.rangeProof, tokenUid);
    assertEq(r.value, value, 'recovered value');
    assertHex(r.blindingFactor, toHex(out.blindingFactor), 'recovered blinding factor');
  });

  if (wasmA.caps.has('verifyRangeProof')) {
    await check("wasm verifies the node-minted output's range proof", async () =>
      assertEq(await wasmA.verifyRangeProof(out.rangeProof, out.commitment, generator), true)
    );
  } else {
    skip("wasm verifies node-minted range proof", wasmA.staleReason || 'verifyRangeProof unavailable');
  }
}

// ─── driver ──────────────────────────────────────────────────────────────────

async function main() {
  process.stdout.write(`Cross-implementation parity harness\nfixture: ${FIXTURE}\n`);
  if (REQUIRE.size) process.stdout.write(`required bindings: ${[...REQUIRE].join(', ')}\n`);

  const loaded = {};
  const node = loadNode();
  const wasm = await loadWasm();
  const mobile = await loadMobile();

  for (const [name, res] of [['node', node], ['wasm', wasm], ['mobile', mobile]]) {
    if (res.adapter) {
      loaded[name] = res.adapter;
      if (res.adapter.staleReason) staleBindings.set(name, res.adapter.staleReason);
    } else {
      skippedBindings.add(name);
      process.stdout.write(`\n[binding] ${name} SKIPPED — ${res.reason}\n`);
    }
  }

  for (const name of ['node', 'wasm', 'mobile']) {
    const a = loaded[name];
    if (!a) continue;
    await referenceChecks(a);
    // Run the verifier suite for any binding that ships it, or that shipped a
    // stale build missing it (so the reason is reported). Mobile has no verifier
    // surface by design, so it is skipped here.
    if (a.caps.has('verifyRangeProof') || a.staleReason) await verifyChecks(a);
    await rewindChecks(a);
  }

  await liveCrossRoundTrip(loaded.node, loaded.wasm);

  // ─── summary + required-binding enforcement ────────────────────────────────
  section('SUMMARY');
  process.stdout.write(`  pass=${results.pass} fail=${results.fail} skip=${results.skip}\n`);

  // A required binding is "unavailable" if it did not load, OR if it loaded but
  // shipped a stale build missing the verifier surface (CI must exercise it for
  // real, not skip it).
  const missingRequired = [...REQUIRE].filter(b => skippedBindings.has(b) || staleBindings.has(b));
  if (missingRequired.length) {
    process.stdout.write(
      `\nRequired binding(s) unavailable/stale: ${missingRequired
        .map(b => (staleBindings.has(b) ? `${b} (stale: ${staleBindings.get(b)})` : b))
        .join(', ')}. ` + `They must be built fresh for this run (PARITY_REQUIRE=${[...REQUIRE].join(',')}).\n`
    );
  }
  if (failures.length) {
    process.stdout.write(`\nFAILURES:\n${failures.map(f => `  - ${f}`).join('\n')}\n`);
  }

  const ok = results.fail === 0 && missingRequired.length === 0;
  if (!ok) {
    process.stdout.write('\nPARITY: FAIL\n');
    process.exit(1);
  }
  // A run that exercised nothing (no binding loaded, none required) is suspicious.
  if (results.pass === 0) {
    process.stdout.write('\nPARITY: no bindings available — nothing exercised (set PARITY_REQUIRE to enforce).\n');
  } else {
    process.stdout.write('\nPARITY: OK\n');
  }
}

main().catch(err => {
  process.stdout.write(`\nharness crashed: ${err && err.stack ? err.stack : err}\n`);
  process.exit(1);
});
