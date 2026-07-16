# @hathor/ct-crypto-mobile

React Native (iOS + Android) shielded crypto provider for Hathor confidential
transactions. The cryptography is the same Rust core used by
`@hathor/ct-crypto-node` and `@hathor/ct-crypto-wasm`, compiled for mobile and
exposed over UniFFI through a React Native native module.

## What's in the box

```
src/                Rust crate (hathor-ct-crypto-mobile): UniFFI surface over crypto-core
ios/                UniFFI-generated Swift API + RN bridge module + XCFramework*
android/            UniFFI-generated Kotlin API + RN bridge module + jniLibs*
js/                 MobileShieldedProvider (implements @hathor/ct-crypto-provider)
```

`*` The compiled Rust binaries (`ios/HathorCtCrypto.xcframework`,
`android/src/main/jniLibs/<abi>/libhathor_ct_crypto_mobile.so`) are built by CI
(`.github/workflows/build-mobile.yml`) and shipped in the npm tarball — they are
not present in a plain git checkout. A release published without them would be
broken by construction; the `prepublishOnly` guard refuses to publish without
them, and releases are published from the CI artifact (see the repo's
RELEASING.md).

## Usage (in a React Native app)

```sh
npm install @hathor/ct-crypto-mobile
cd ios && pod install   # autolinking picks up hathor-ct-crypto-mobile.podspec
```

```js
import { createMobileShieldedCryptoProvider } from '@hathor/ct-crypto-mobile';

wallet.setShieldedCryptoProvider(createMobileShieldedCryptoProvider());
```

Same `IShieldedCryptoProvider` contract as the node and wasm providers — see
`@hathor/ct-crypto-provider` for the interface documentation.

## Bridge marshaling contract

The RN bridge carries neither raw bytes nor BigInt, so between JS and native:

- **bytes** cross as **base64 strings**;
- **u64 values** cross as **decimal strings** (amounts can exceed 2^53, where
  JS `Number` silently loses precision);
- records cross as objects with the provider's camelCase keys;
- native errors reject with code `InvalidInput` or `CryptoFailed`.

`js/index.js` and the two bridge modules (`ios/HathorCtCryptoModule.swift`,
`android/.../HathorCtCryptoModule.kt`) are the two ends of this contract —
change them together.

## Regenerating the FFI bindings

The Swift/Kotlin files under `ios/` and `android/.../uniffi/` are **generated**
from the Rust crate — never edit them by hand. After changing
`src/uniffi_bindings.rs`:

```sh
cargo build -p hathor-ct-crypto-mobile --release
cargo run -p hathor-ct-crypto-mobile --features uniffi-cli --bin uniffi-bindgen -- \
  generate --library target/release/libhathor_ct_crypto_mobile.dylib \
  --language swift --no-format --out-dir packages/ct-crypto-mobile/ios
cargo run -p hathor-ct-crypto-mobile --features uniffi-cli --bin uniffi-bindgen -- \
  generate --library target/release/libhathor_ct_crypto_mobile.dylib \
  --language kotlin --no-format --out-dir packages/ct-crypto-mobile/android/src/main/java
```

Always pass `--no-format` — the committed bindings are unformatted, and the
CI drift check regenerates with `--no-format` so the comparison does not
depend on whichever swiftformat/ktlint version happens to be installed.

CI fails the build if the committed bindings drift from the Rust surface.
