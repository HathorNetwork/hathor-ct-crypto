// Type declarations for the ./provider subpath of @hathor/ct-crypto-wasm.
// Copied into pkg/ by scripts/build-wasm.sh and referenced by the package's
// `./provider` export `types` condition.

import { AbstractShieldedProvider, IShieldedCryptoProvider } from '@hathor/ct-crypto-provider';

/**
 * Browser (wasm-bindgen-backed) shielded crypto provider. Verifier-only by
 * policy: signing, RNG, surjection-proof creation and balancing-blinding-factor
 * computation throw. Use @hathor/ct-crypto-node for those operations.
 *
 * Declared as an interface + construct-signature const rather than a `class`:
 * a hand-written `class ... extends AbstractShieldedProvider {}` is a
 * non-abstract class with unimplemented abstract members (TS2515). The
 * interface keeps `WasmShieldedProvider` usable as a type; the const keeps
 * `new WasmShieldedProvider()` usable as a value.
 */
export interface WasmShieldedProvider extends AbstractShieldedProvider {}
export declare const WasmShieldedProvider: new () => WasmShieldedProvider;

/**
 * Instantiate the browser provider. Async because it awaits the wasm module's
 * init (fetch + instantiate) once before returning.
 */
export function createBrowserShieldedCryptoProvider(): Promise<IShieldedCryptoProvider>;
