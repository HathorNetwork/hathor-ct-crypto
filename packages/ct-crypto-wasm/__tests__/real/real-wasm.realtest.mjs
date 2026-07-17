/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

/**
 * REAL wasm-crypto integration tests.
 *
 * These do NOT use the `__tests__/wasm-stub.js` stub — they load the actual
 * built `pkg/` artifact and run real secp256k1-zkp cryptography through the
 * WasmShieldedProvider. Run via the `test:real` npm script (needs
 * `--experimental-vm-modules`; see jest.real.config.cjs).
 *
 * Coverage:
 *   - createCommitment          (wasm-only: determinism + on-curve validation)
 *   - verifyBalance             (wasm-only: transparent balance true/false)
 *   - verifyCommitmentsSum      (wasm-only: reflexive true / mismatch false)
 *   - verifyRangeProof + rewind (round-trip: an output minted by the sibling
 *     @hathor/ct-crypto-node binding, then verified + rewound by wasm)
 *
 * The range-proof-dependent checks need a real proof, which only the signing
 * (node) binding can produce; those sub-tests skip with a clear reason when the
 * node addon isn't available for this platform.
 *
 * If the built wasm artifact is missing, the whole suite SKIPS with a clear
 * message rather than passing against a stub.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createRequire } from 'node:module';
import { Buffer } from 'node:buffer';
import { ScanMissError } from '@hathor/ct-crypto-provider';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkgDir = path.resolve(__dirname, '../../pkg');
const wasmPath = path.join(pkgDir, 'hathor_ct_crypto_wasm_bg.wasm');
const gluePath = path.join(pkgDir, 'hathor_ct_crypto_wasm.js');
const providerPath = path.join(pkgDir, 'provider.js');

const artifactPresent =
  fs.existsSync(wasmPath) && fs.existsSync(gluePath) && fs.existsSync(providerPath);

if (!artifactPresent) {
  // eslint-disable-next-line no-console
  console.warn(
    `\n[real-wasm] SKIPPING real-crypto tests: built artifact not found under ${pkgDir}.\n` +
      `These tests exercise the ACTUAL wasm build (never the stub). Build it first:\n` +
      `  npm run build      # needs the nix wasm toolchain — see README\n` +
      `or rely on CI's build-wasm job. Skipped, NOT passed against a stub.\n`
  );
}

// Which verifier exports the built glue actually ships (a stale local build may
// predate the newer functions). Read synchronously at collection time so each
// dependent test can be gated with a clear skip instead of a hard failure.
const glueExports = artifactPresent
  ? new Set(
      Array.from(fs.readFileSync(gluePath, 'utf8').matchAll(/export function (\w+)/g)).map(
        m => m[1]
      )
    )
  : new Set();

// The sibling node binding (for minting real range proofs). Optional: absent
// when the native addon isn't prebuilt for this platform.
let node = null;
try {
  const require = createRequire(import.meta.url);
  node = require(path.resolve(__dirname, '../../../ct-crypto-node/index.js'));
} catch (_) {
  node = null;
}

// A fresh build (glue + copied-in provider.js are stamped together) ships the
// new verifier surface. Older local builds predate it; gate the surface-
// specific tests on this so a stale pkg/ skips them with a clear reason instead
// of hard-failing.
const buildFresh =
  glueExports.has('verifyBalance') && glueExports.has('verifyCommitmentsSum');

if (artifactPresent && !buildFresh) {
  // eslint-disable-next-line no-console
  console.warn(
    '\n[real-wasm] pkg/ predates the verifier surface (verifyBalance/verifyCommitmentsSum ' +
      'and the fresh provider.js). Rebuild with `npm run build` to run those tests. ' +
      'Running only the primitives available in this build.\n'
  );
}

const suite = artifactPresent ? describe : describe.skip;
const fresh = buildFresh ? it : it.skip;
const withNode = node ? it : it.skip;

suite('real wasm crypto (built pkg/)', () => {
  let provider;

  beforeAll(async () => {
    const glue = await import(pathToFileURL(gluePath).href);
    // Instantiate synchronously from the on-disk bytes — avoids the loader's
    // fetch/import.meta.url path, which does not work under Node.
    glue.initSync({ module: new WebAssembly.Module(fs.readFileSync(wasmPath)) });
    const mod = await import(pathToFileURL(providerPath).href);
    // The factory calls the glue's default init again; already-initialised, so
    // it returns immediately without trying to fetch.
    provider = await mod.createBrowserShieldedCryptoProvider();
  });

  it('createCommitment: real, deterministic, on-curve', async () => {
    const htrGen = await provider.deriveAssetTag(Buffer.alloc(32));
    expect(htrGen.length).toBe(33);
    const vbf = Buffer.alloc(32, 7);
    const c1 = await provider.createCommitment(123n, vbf, htrGen);
    const c2 = await provider.createCommitment(123n, vbf, htrGen);
    expect(Buffer.isBuffer(c1)).toBe(true);
    expect(c1.length).toBe(33);
    expect(c1.equals(c2)).toBe(true); // deterministic
    const c3 = await provider.createCommitment(123n, Buffer.alloc(32, 8), htrGen);
    expect(c1.equals(c3)).toBe(false); // different vbf -> different commitment
    if (glueExports.has('validateCommitment')) {
      expect(await provider.validateCommitment(c1)).toBe(true);
      expect(await provider.validateGenerator(htrGen)).toBe(true);
    }
  });

  fresh('verifyCommitmentsSum: reflexive true, mismatch false', async () => {
    const htrGen = await provider.deriveAssetTag(Buffer.alloc(32));
    const a = await provider.createCommitment(100n, Buffer.alloc(32, 1), htrGen);
    const b = await provider.createCommitment(50n, Buffer.alloc(32, 2), htrGen);
    // Same multiset on both sides -> sums are equal.
    expect(await provider.verifyCommitmentsSum([a, b], [a, b])).toBe(true);
    // Mismatched -> not equal.
    expect(await provider.verifyCommitmentsSum([a], [b])).toBe(false);
  });

  fresh('verifyBalance: transparent balance true/false', async () => {
    const htr = Buffer.alloc(32); // HTR token uid
    // 100 in = 100 out -> balanced.
    expect(
      await provider.verifyBalance(
        [{ amount: 100n, tokenUid: htr }],
        [],
        [{ amount: 100n, tokenUid: htr }],
        []
      )
    ).toBe(true);
    // 100 in != 90 out -> unbalanced.
    expect(
      await provider.verifyBalance(
        [{ amount: 100n, tokenUid: htr }],
        [],
        [{ amount: 90n, tokenUid: htr }],
        []
      )
    ).toBe(false);
  });

  withNode(
    'rewind round-trip: node mints an output, wasm rewinds it + verifies the range proof',
    async () => {
      const kp = node.generateEphemeralKeypair();
      const tokenUid = Buffer.alloc(32); // HTR
      const vbf = node.generateRandomBlindingFactor();
      const value = 424242n;
      const out = node.createAmountShieldedOutput(value, kp.publicKey, tokenUid, vbf);

      // wasm rewinds the node-minted output back to cleartext.
      const rewound = await provider.rewindAmountShieldedOutput(
        kp.privateKey,
        out.ephemeralPubkey,
        out.commitment,
        out.rangeProof,
        tokenUid
      );
      expect(rewound.value).toBe(value);
      expect(Buffer.from(rewound.blindingFactor).equals(Buffer.from(out.blindingFactor))).toBe(
        true
      );

      if (glueExports.has('verifyRangeProof')) {
        const gen = await provider.deriveAssetTag(tokenUid);
        expect(await provider.verifyRangeProof(out.rangeProof, out.commitment, gen)).toBe(true);
        // Range proof does not open the tampered commitment.
        const badCommitment = node.createCommitment(value + 1n, vbf, gen);
        expect(await provider.verifyRangeProof(out.rangeProof, badCommitment, gen)).toBe(false);
      }

      // A foreign scan key must surface as ScanMissError (via the fresh
      // provider.js `_isScanMiss` override). Only assert when the build carries
      // that override (it is stamped in alongside the verifier surface).
      const foreign = node.generateEphemeralKeypair();
      const foreignRewind = provider.rewindAmountShieldedOutput(
        foreign.privateKey,
        out.ephemeralPubkey,
        out.commitment,
        out.rangeProof,
        tokenUid
      );
      if (buildFresh) {
        await expect(foreignRewind).rejects.toBeInstanceOf(ScanMissError);
      } else {
        // Stale build: still rejects, just not with the typed error (and, pre
        // error-shape fix, possibly with a bare string rather than an Error).
        await expect(foreignRewind).rejects.toBeDefined();
      }
    }
  );
});
