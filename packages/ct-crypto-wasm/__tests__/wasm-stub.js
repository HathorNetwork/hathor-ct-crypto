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
export function rewindAmountShieldedOutput() {
  return {
    value: 42n,
    blindingFactor: new Uint8Array(32).fill(0xa6),
  };
}
export function rewindFullShieldedOutput() {
  return {
    value: 99n,
    blindingFactor: new Uint8Array(32).fill(0xa7),
    tokenUid: new Uint8Array(32).fill(0xa8),
    assetBlindingFactor: new Uint8Array(32).fill(0xa9),
  };
}

export function __getRecordedCalls() {
  return calls;
}
export function __resetRecordedCalls() {
  calls.length = 0;
}
