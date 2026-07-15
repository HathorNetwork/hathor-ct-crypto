// NEW-04: type declarations for the ./provider subpath of @hathor/ct-crypto-wasm.
// Copied into pkg/ by scripts/build-wasm.sh and referenced by the package's
// `./provider` export `types` condition.

import { AbstractShieldedProvider, IShieldedCryptoProvider } from '@hathor/ct-crypto-provider';

/**
 * Browser (wasm-bindgen-backed) shielded crypto provider. Verifier-only by
 * policy: signing, RNG, surjection-proof creation and balancing-blinding-factor
 * computation throw. Use @hathor/ct-crypto-node for those operations.
 */
export class WasmShieldedProvider extends AbstractShieldedProvider {}

/**
 * Instantiate the browser provider. Async because it awaits the wasm module's
 * init (fetch + instantiate) once before returning.
 */
export function createBrowserShieldedCryptoProvider(): Promise<IShieldedCryptoProvider>;
