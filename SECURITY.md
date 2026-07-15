# Security Policy

`hathor-ct-crypto` produces the cryptographic primitives and key-handling
binaries used by Hathor wallets (wallet-lib, wallet-headless, wallet-mobile) and
the block explorer for confidential transactions. Vulnerabilities here can affect
user funds and privacy, so we take reports seriously.

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately via one of:

- GitHub private vulnerability reporting (Security → Report a vulnerability), or
- email **security@hathor.network** with subject `ct-crypto: <short summary>`.

Please include: affected package(s) and version(s), a description of the issue,
and a proof-of-concept or reproduction steps if available.

We aim to acknowledge reports within 3 business days and to provide a remediation
timeline after triage. Please allow coordinated disclosure before publicizing.

## Scope

In scope: `crypto-core`, the NAPI/UniFFI/WASM bindings, the TypeScript provider,
and the published npm packages (`@hathor/ct-crypto-node`, `@hathor/ct-crypto-wasm`,
`@hathor/ct-crypto-provider`).

Consensus-critical note: this library must remain byte-compatible with the
hathor-core node (the source of truth). Divergences that would let a client build
a transaction the node rejects — or verify something the node would not — are
treated as high severity even when no direct fund loss is demonstrated. See
`UPSTREAM.md` for the fork anchor and the core-sync drift check.
