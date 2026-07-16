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
    ├── ct-crypto-node/            # @hathor/ct-crypto-node — NAPI bindings + Node provider
    ├── ct-crypto-mobile/          # @hathor/ct-crypto-mobile — UniFFI (Swift/Kotlin) + RN bridge + mobile provider
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

NAPI native addon for Node.js (signing + verifying full surface).
Exports a `NodeShieldedProvider` factory via the `./provider` subpath.

### `@hathor/ct-crypto-mobile`

React Native library for iOS + Android. The Rust core compiled per
mobile target (XCFramework / jniLibs), exposed over UniFFI-generated
Swift/Kotlin, bridged as the `HathorCtCrypto` native module, and wrapped
by a `MobileShieldedProvider`. Consumed by `hathor-wallet-mobile`.

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

## Versioning & releases

Lockstep: all four packages publish under the same monorepo-level version.
A breaking change to the abstract class bumps every package simultaneously.

A release is driven by a `vX.Y.Z` tag: CI builds the native artifacts
(`build-node.yml` → the 7 NAPI prebuilds; `build-mobile.yml` → the iOS
XCFramework + Android jniLibs) and uploads ready-to-publish package
artifacts with binary checksums. A maintainer downloads those artifacts,
builds the pure-TS provider and the wasm `pkg/` locally, and publishes all
four packages to npm — so published binaries always come from CI. (Early
prereleases were published under the `shielded` dist-tag; stable versions
go to `latest`.)

## License

MIT — see [LICENSE](LICENSE).
