# hathor-ct-crypto

Monorepo for Hathor confidential-transaction crypto. Holds the shared Rust
primitives and the per-platform JS packages that wrap them into a uniform
shielded-output provider used by `@hathor/wallet-lib`.

## Layout

```
hathor-ct-crypto/
├── crypto-core/                   # Pure-Rust crypto primitives (not published)
└── packages/
    ├── ct-crypto-provider/        # @hathor/ct-crypto-provider — abstract class + interface (TS, pure)
    ├── ct-crypto-node/            # @hathor/ct-crypto-node — NAPI bindings + UniFFI bindings + Node provider
    └── ct-crypto-wasm/            # @hathor/ct-crypto-wasm — wasm-bindgen bindings + browser provider
```

## Packages

### `@hathor/ct-crypto-provider`

Pure TypeScript. Defines `IShieldedCryptoProvider` (the interface
wallet-lib's `setShieldedCryptoProvider` accepts) and
`AbstractShieldedProvider` (the abstract class that holds the shared
wrapping logic). Every platform-specific provider extends the abstract
class; subclasses only implement the platform-specific marshaling and
backend calls.

### `@hathor/ct-crypto-node`

NAPI native addon for Node.js (signing + verifying full surface) plus
UniFFI bindings (consumed by `hathor-wallet-mobile`'s iOS + Android
native modules). Exports a `NodeShieldedProvider` factory via the
`./provider` subpath.

### `@hathor/ct-crypto-wasm`

wasm-bindgen browser build (verifier-only — no signing, no rewind,
no RNG). Exports a `BrowserShieldedProvider` factory via the
`./provider` subpath.

## Workspace

```bash
# Rust
cargo test                # runs all crate tests
cargo check               # quick check across the workspace

# JS
npm install               # bootstraps workspaces
npm run build             # build each package that has a build script
npm test                  # run each package's tests
```

## Versioning

Lockstep: all three packages publish under the same monorepo-level
version. A breaking change to the abstract class bumps every package
simultaneously. Releases are tagged `vX.Y.Z-shielded` while the feature
is still in prerelease.

## License

MIT — see [LICENSE](LICENSE).
