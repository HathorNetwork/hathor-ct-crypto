# @hathor/ct-crypto-node

Native NAPI addon for Hathor confidential transaction cryptography.

Provides Pedersen commitments, Bulletproof range proofs, surjection proofs, and ECDH-based shielded output creation/decryption using secp256k1-zkp.

## Installation

```bash
npm install @hathor/ct-crypto-node
```

Prebuilt binaries are included for:
- macOS ARM64 (Apple Silicon)
- macOS x64 (Intel)
- Linux x64
- Linux ARM64

## Building from source

Requires Rust toolchain:

```bash
cargo build --features napi --release
```

## Publishing

1. Push a tag to trigger CI builds: `git tag v0.3.0 && git push --tags`
2. Wait for the GitHub Actions `build` workflow to complete
3. Download the `npm-package` artifact from the workflow run
4. Extract and publish:

```bash
cd npm-package/
npm publish --access public
```

## License

MIT
