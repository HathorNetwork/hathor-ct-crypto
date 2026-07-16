# @hathor/ct-crypto-node

Native NAPI addon for Hathor confidential transaction cryptography.

Provides Pedersen commitments, Borromean-style range proofs (secp256k1-zkp,
40-bit range), surjection proofs, balance verification, and ECDH-based
shielded output creation/decryption. The full signing + verifying surface —
wallet-lib and wallet-headless use this package.

## Installation

```bash
npm install @hathor/ct-crypto-node
```

Prebuilt binaries are included for:

- macOS: `darwin-arm64` (Apple Silicon), `darwin-x64` (Intel)
- Linux glibc: `linux-x64-glibc`, `linux-arm64-glibc`
- Linux musl (Alpine — wallet-headless's Docker base): `linux-x64-musl`, `linux-arm64-musl`
- Windows: `win32-x64`

The loader detects the platform, architecture, and (on Linux) the C library
at require-time and picks the matching prebuild automatically.

## Usage

```js
const { createDefaultShieldedCryptoProvider } = require('@hathor/ct-crypto-node/provider');
wallet.setShieldedCryptoProvider(createDefaultShieldedCryptoProvider());
```

The `./provider` subpath exports a `NodeShieldedProvider` implementing
`@hathor/ct-crypto-provider`'s `IShieldedCryptoProvider`. The package root
exports the raw NAPI functions for advanced consumers.

## Building from source

Requires a Rust toolchain:

```bash
cargo build --features napi --release
```

## Releasing

Releases are CI-built: pushing a `vX.Y.Z` tag makes the `Build native addon`
workflow compile all seven prebuilds, assert none is missing, and upload a
ready-to-publish `npm-package` artifact (with `SHA256SUMS` for the binaries).
A maintainer downloads that artifact and runs `npm publish` from it — the
binaries that reach npm are always the CI-built ones, never a laptop build.

## License

MIT
