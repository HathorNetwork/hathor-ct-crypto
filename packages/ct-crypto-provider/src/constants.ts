/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

/**
 * The 32-byte all-zero tweak/scalar.
 *
 * Used as the `generatorBlindingFactor` for AmountShielded outputs (the asset
 * generator is unblinded there), and anywhere a "no blinding" scalar is
 * required — mirrors `secp256k1_zkp::ZERO_TWEAK` in the native bindings.
 *
 * Previously the contract's docs referenced `ZERO_TWEAK` (e.g.
 * `computeBalancingBlindingFactor`'s `generatorBlindingFactor` param) but
 * consumers had no way to obtain it from the package. Import it from here:
 *
 * ```ts
 * import { ZERO_TWEAK } from '@hathor/ct-crypto-provider';
 * ```
 *
 * Treat this as immutable — do NOT write into the returned Buffer; it is a
 * single shared instance. Callers that need a mutable copy should
 * `Buffer.from(ZERO_TWEAK)`.
 */
export const ZERO_TWEAK: Buffer = Buffer.alloc(32);
