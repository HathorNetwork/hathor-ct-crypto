# @hathor/ct-crypto-node

Native NAPI addon for Hathor confidential transaction cryptography.

Provides Pedersen commitments, Borromean-style range proofs (secp256k1-zkp,
40-bit range), surjection proofs, balance verification, and ECDH-based
shielded output creation/decryption. The full signing + verifying surface —
wallet-lib and wallet-headless use this package.

## Installation

```bash
npm install @hathor/ct-crypto-node@shielded
```

Versions are `-shielded` prereleases on the `shielded` dist-tag; `latest`
still points at an older, incompatible line.

Each platform's binary ships as its own package, which npm installs
automatically through `optionalDependencies`:

- macOS: `@hathor/ct-crypto-node-darwin-arm64` (Apple Silicon),
  `@hathor/ct-crypto-node-darwin-x64` (Intel)
- Linux glibc: `@hathor/ct-crypto-node-linux-x64-gnu`,
  `@hathor/ct-crypto-node-linux-arm64-gnu`
- Linux musl (Alpine — wallet-headless's Docker base):
  `@hathor/ct-crypto-node-linux-x64-musl`, `@hathor/ct-crypto-node-linux-arm64-musl`
- Windows: `@hathor/ct-crypto-node-win32-x64-msvc`

The loader detects the platform, architecture, and (on Linux) the C library
at require-time and loads the matching package.

## Usage

```js
const { createDefaultShieldedCryptoProvider } = require('@hathor/ct-crypto-node/provider');
wallet.setShieldedCryptoProvider(createDefaultShieldedCryptoProvider());
```

The `./provider` subpath exports a `NodeShieldedProvider` implementing
`@hathor/ct-crypto-provider`'s `IShieldedCryptoProvider`. The package root
exports the raw NAPI functions for advanced consumers.

## Building from source

Requires a Rust toolchain. From the repository root:

```bash
npm ci
npm run build -w @hathor/ct-crypto-node   # writes ct-crypto.<platform>.node next to index.js
```

## Releasing

From 0.0.2-shielded on, every platform binary on npm is the one CI built from
the release tag, checked byte-for-byte before publishing. See
[RELEASING.md](https://github.com/HathorNetwork/hathor-ct-crypto/blob/master/RELEASING.md).

## License

MIT
