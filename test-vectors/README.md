# Cross-implementation parity vectors

This directory is the **single fixture that guarantees the three binding
packages — `@hathor/ct-crypto-node`, `@hathor/ct-crypto-wasm`,
`@hathor/ct-crypto-mobile` — stay interchangeable and consensus-compatible.**

Before it, each package's test suite tested *disjoint* things: nothing proved
that a commitment or proof produced by one binding reproduces byte-for-byte
under another, or that all three agree with the shared `crypto-core` reference.
A silent divergence in any binding (a marshaling bug, a stale build, an
accidental serialization change) would only surface in production as a
consensus split. These vectors close that gap.

## Files

| File | Purpose |
| --- | --- |
| `shielded-parity-vectors.json` | The canonical fixture: **real** bytes minted by the node binding over `crypto-core`. Committed to git. |
| `generate-vectors.mjs` | Regenerates the fixture from `@hathor/ct-crypto-node`. The vectors are derived by *running* the crypto, not invented. |
| `parity.test.mjs` | The cross-package harness (run via `npm run test:parity`). Loads every available binding and checks it against the fixture and against the others. |

## What the harness proves

`parity.test.mjs` runs four families of checks against **every binding whose
built artifact is available**:

1. **REFERENCE** — each binding recomputes the deterministic vectors (tags,
   generators, Pedersen commitments, asset commitments) and must match the
   committed fixture **exactly**. The fixture was minted by node over
   `crypto-core`, so:
   - node matching ⇒ regression guard against any on-the-wire byte change in
     `crypto-core` or the node binding;
   - wasm/mobile matching ⇒ proof that `node == wasm == mobile == crypto-core`
     for the primitives that build a shielded output.
2. **VERIFY** — each binding that ships the verifier surface must **accept** the
   fixture's real range proofs / surjection proofs / balanced transactions and
   **reject** the negative cases.
3. **REWIND** — each binding that can rewind recovers `(value, blindingFactor)`
   from the fixture's shielded outputs.
4. **LIVE cross-binding** — node **mints a fresh** amount-shielded output and
   wasm **rewinds + verifies** it. This is the direct interchangeability proof:
   an artifact created by one binding is consumed by another, live, in the same
   run.

## Running it

```sh
npm run test:parity            # from the repo root
# or:
node test-vectors/parity.test.mjs
```

The harness **degrades gracefully**: a binding whose build is missing locally is
**skipped with a reason** (a dev without the wasm/nix toolchain still gets the
node half and the deterministic wasm checks against whatever `pkg/` exists).
Exit code is non-zero only if a check **fails** or a **required** binding is
missing/stale.

### Environment variables

| Var | Effect |
| --- | --- |
| `PARITY_REQUIRE=node,wasm` | Turn "binding unavailable **or stale**" into a hard failure for the listed bindings. CI sets this so the job can't go green having skipped the real crypto. A binding that loaded but shipped a build missing the verifier surface counts as stale. |
| `MOBILE_NATIVE_MODULE=<path>` | Run the mobile leg in Node by injecting a module that exposes the UniFFI surface (see "Mobile" below). Unset by default. |

## Regenerating the fixture

```sh
npm --workspace @hathor/ct-crypto-node run build   # ensure the native addon exists
node test-vectors/generate-vectors.mjs             # rewrites shielded-parity-vectors.json
node test-vectors/generate-vectors.mjs --check     # verify deterministic sections didn't drift
```

Every section except `shieldedOutputs` is **deterministic** — a pure function of
its inputs, or fed a fixed nonce — so regenerating reproduces byte-for-byte.
`shieldedOutputs` exercises `createAmountShieldedOutput`, which mints a fresh
random ephemeral key internally; those bytes change on regenerate but stay valid
forever (the harness only ever verifies and rewinds them). `--check` compares the
deterministic sections only and fails if a `crypto-core`/binding change altered
on-the-wire bytes — a fast, standalone consensus-drift alarm that needs no wasm
build.

> The `shieldedOutputs` entries include a **throwaway test-only private key** so
> the rewind round-trip is self-contained. It protects no real funds.

## CI wiring

- **`node` job** (already builds the native addon): add
  `PARITY_REQUIRE=node node test-vectors/parity.test.mjs` after `npm test` — or
  simply `npm run test:parity` with `PARITY_REQUIRE=node` — so every PR runs the
  node reference/verify/rewind half for real.
- **`build-wasm` job** (owned by the workflows agent — builds `pkg/` with
  `wasm-pack`): after the build, run

  ```yaml
  - name: cross-implementation parity (node + wasm)
    env:
      PARITY_REQUIRE: node,wasm
    run: npm run test:parity
  ```

  That job is the one that exercises the **live node↔wasm round-trip** and the
  wasm verifier surface for real. `PARITY_REQUIRE=node,wasm` makes a missing or
  stale wasm build fail rather than skip.

  The job needs the node prebuild staged too (same `cargo build -p
  hathor-ct-crypto-node … && cp …/libhathor_ct_crypto.so
  packages/ct-crypto-node/prebuilds/linux-x64-glibc/ct-crypto.node` steps the
  `node` job uses) so the live mint side is available; otherwise the harness
  skips the live leg with a reason.

## Mobile

`@hathor/ct-crypto-mobile` is a React-Native UniFFI native module with **no
Node-loadable build**, so this JS harness skips it by default. Its parity is
pinned two ways:

1. It wraps the **same `crypto-core`** the fixture was minted from, and the Rust
   workspace's `cargo test` (the `rust` CI job, which includes the UniFFI tests)
   exercises that core directly.
2. The mobile package's own platform tests should **load this fixture** and
   assert the same deterministic `tags` / `commitments` / `assetCommitments` /
   `rangeProofs` bytes, so the RN bridge + UniFFI marshaling is proven against
   the identical reference the node and wasm bindings pass. To dry-run that in
   Node, point `MOBILE_NATIVE_MODULE` at a module exposing the UniFFI surface and
   the harness runs mobile through the same REFERENCE/REWIND checks.

## Fixture schema (abridged)

```jsonc
{
  "_meta":   { "...": "provenance, encoding (hex bytes, decimal u64), sizes, regenerate cmd" },
  "constants": { "zeroTweak": "00…", "htrAssetTag": "…" },
  "tags":    [ { "label", "tokenUid", "deriveTag" /*32B*/, "deriveAssetTag" /*33B*/ } ],
  "commitments":      [ { "value", "blindingFactor", "tokenUid", "generator", "commitment" } ],
  "assetCommitments": [ { "tokenUid", "tag", "blindingFactor", "assetCommitment" } ],
  "rangeProofs":      [ { "value", "blindingFactor", "tokenUid", "generator", "commitment",
                          "nonce", "proof", "rewind": { "value", "blindingFactor" } } ],
  "shieldedOutputs":  [ { "mode", "value", "tokenUid", "generator",
                          "recipientPrivateKey" /*test-only*/, "recipientPubkey",
                          "ephemeralPubkey", "commitment", "rangeProof", "blindingFactor",
                          "expected": { "value", "blindingFactor" } } ],
  "surjectionProofs": [ { "label", "codomainGenerator", "domain", "proof", "expected" } ],
  "balance":          [ { "label", "transparentInputs", "shieldedInputs",
                          "transparentOutputs", "shieldedOutputs", "excessBlindingFactor",
                          "expected" } ],
  "commitmentsSum":   [ { "label", "positive", "negative", "expected" } ],
  "validate":         { "validCommitment", "validGenerator", "invalidPoint" }
}
```
