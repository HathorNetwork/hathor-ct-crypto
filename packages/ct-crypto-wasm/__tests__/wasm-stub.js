/**
 * Stub for `./hathor_ct_crypto_wasm.js` used by provider tests. Records
 * every call + returns canned Uint8Array values, so the test can verify
 * the WasmShieldedProvider does the right marshaling without needing
 * an actual WASM build.
 *
 * The real provider tests against the real WASM build live in the
 * `shielded-outputs-audit` browser app (E2E) — those are the integration
 * verification. These unit tests just lock the subclass contract.
 */
const calls = [];

function record(name, args, ret) {
  calls.push({ name, args });
  return ret;
}

// Default async init (mimics wasm-pack `--target web`).
export default async function init() {
  return {};
}

export function deriveTag(tokenUid) {
  return record('deriveTag', [tokenUid], new Uint8Array(32).fill(0xa1));
}
export function deriveAssetTag(tokenUid) {
  return record('deriveAssetTag', [tokenUid], new Uint8Array(33).fill(0xa2));
}
export function createCommitment(value, blindingFactor, generator) {
  return record(
    'createCommitment',
    [value, blindingFactor, generator],
    new Uint8Array(33).fill(0xa3)
  );
}
export function createAssetCommitment(tag, blindingFactor) {
  return record('createAssetCommitment', [tag, blindingFactor], new Uint8Array(33).fill(0xa4));
}
export function deriveEcdhSharedSecret(privateKey, peerPubkey) {
  return record(
    'deriveEcdhSharedSecret',
    [privateKey, peerPubkey],
    new Uint8Array(32).fill(0xa5)
  );
}
// The real wasm-bindgen rewind results are Rust-backed class instances with a
// `.free()`; include a stub `free` so the provider's free-after-copy path is
// exercised (and records the call) instead of no-op'd by the guard.
export function rewindAmountShieldedOutput() {
  return {
    value: 42n,
    blindingFactor: new Uint8Array(32).fill(0xa6),
    free() {
      record('rewindAmountShieldedOutput.free', []);
    },
  };
}
export function rewindFullShieldedOutput() {
  return {
    value: 99n,
    blindingFactor: new Uint8Array(32).fill(0xa7),
    tokenUid: new Uint8Array(32).fill(0xa8),
    assetBlindingFactor: new Uint8Array(32).fill(0xa9),
    free() {
      record('rewindFullShieldedOutput.free', []);
    },
  };
}

// Optional verifier surface — record args + return a canned boolean so the
// provider's marshaling (esp. verifyBalance's struct→parallel-array split) can
// be asserted without a real wasm build.
export function verifyRangeProof(proof, commitment, generator) {
  return record('verifyRangeProof', [proof, commitment, generator], true);
}
export function verifySurjectionProof(proof, codomain, domain) {
  return record('verifySurjectionProof', [proof, codomain, domain], true);
}
export function verifyBalance(
  transparentInputAmounts,
  transparentInputTokenUids,
  shieldedInputs,
  transparentOutputAmounts,
  transparentOutputTokenUids,
  shieldedOutputs,
  excessBlindingFactor
) {
  return record(
    'verifyBalance',
    [
      transparentInputAmounts,
      transparentInputTokenUids,
      shieldedInputs,
      transparentOutputAmounts,
      transparentOutputTokenUids,
      shieldedOutputs,
      excessBlindingFactor,
    ],
    true
  );
}
export function verifyCommitmentsSum(positive, negative) {
  return record('verifyCommitmentsSum', [positive, negative], true);
}
export function validateCommitment(data) {
  return record('validateCommitment', [data], true);
}
export function validateGenerator(data) {
  return record('validateGenerator', [data], true);
}

export function __getRecordedCalls() {
  return calls;
}
export function __resetRecordedCalls() {
  calls.length = 0;
}
