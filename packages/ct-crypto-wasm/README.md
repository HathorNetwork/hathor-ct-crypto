# `@hathor/ct-crypto-wasm`

Browser-compatible (wasm-bindgen) build of the Hathor confidential-transaction
crypto primitives — the **view/verify** sibling of
[`@hathor/ct-crypto-node`](https://github.com/HathorNetwork/hathor-ct-crypto).
Used by the explorer and other browser consumers.

What it exposes (JS names):

- Tag/generator derivation: `deriveTag`, `deriveAssetTag`, `htrAssetTag`
- Commitment recompute (cleartext-opening validation): `createCommitment`,
  `createAssetCommitment`, `createTrivialCommitment`
- Output scanning/decryption: `deriveEcdhSharedSecret`,
  `rewindAmountShieldedOutput`, `rewindFullShieldedOutput`
- On-chain data validation: `validateCommitment`, `validateGenerator`,
  `verifyRangeProof`, `verifySurjectionProof`

What it deliberately does **not** expose: output *creation* (range-proof and
surjection-proof construction), blinding-factor RNG, and balancing-factor
computation — signing flows belong to `@hathor/ct-crypto-node` (or
`@hathor/ct-crypto-mobile` on mobile). The `./provider` subpath ships a
`WasmShieldedProvider` whose signing methods throw accordingly.

## Build

The crate is consumed via npm (`npm install @hathor/ct-crypto-wasm`); to
build the artifact yourself you need:

- Rust with the `wasm32-unknown-unknown` target
- An **unwrapped** clang with the wasm32 backend (nix's wrapped clang
  injects host-only flags; emscripten's `emcc` rejects bare wasm32)
- `wasm-pack`

The repo ships a flake that wires all three:

```sh
nix develop --command ./scripts/build-wasm.sh
```

That produces the publishable artifact at `pkg/` — `build-wasm.sh` rewrites
`pkg/package.json` (scoped name, version, exports, runtime deps) on every
build, so never hand-edit files under `pkg/`. Publishing happens from `pkg/`
as part of the repo's release flow (all packages release in lockstep on a
`vX.Y.Z` tag).

## Tests

```sh
cargo test                                    # native unit tests
nix develop --command wasm-pack test --node   # wasm bindings (optional)
```

## Layout

```
src/
  lib.rs             # crate gate
  wasm_bindings.rs   # the wasm-bindgen surface
provider.js          # WasmShieldedProvider (copied into pkg/ by the build)
provider.d.ts        # types for the ./provider subpath
flake.nix            # dev shell (wasm-pack + clang-unwrapped + llvm-ar)
scripts/build-wasm.sh
```

The cryptography itself lives in the workspace's `crypto-core/` crate — this
package is only the wasm-bindgen boundary plus packaging.
