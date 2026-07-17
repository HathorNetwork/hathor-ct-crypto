/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

/**
 * Thrown by `rewindAmountShieldedOutput` / `rewindFullShieldedOutput` when an
 * output is simply **not addressed to the scan key being tried** — the common
 * case while scanning the chain, NOT a corruption/decode error.
 *
 * Chain scanners iterate every output against a wallet's scan keys; the vast
 * majority are foreign. Before this class the only way to tell "foreign output"
 * apart from "malformed/corrupt output" was to string-match the thrown error
 * message, which is brittle. Catch `ScanMissError` (via `instanceof`) to skip
 * foreign outputs and let any other error propagate as a real failure:
 *
 * ```ts
 * try {
 *   const rewound = await provider.rewindAmountShieldedOutput(...);
 *   // addressed to us
 * } catch (err) {
 *   if (err instanceof ScanMissError) continue; // foreign output, skip
 *   throw err;                                   // genuine corruption
 * }
 * ```
 *
 * It extends `Error`, so consumers that catch generically keep working
 * unchanged — this is a strictly additive, more-specific signal.
 *
 * The abstract provider only raises this when its `_isScanMiss(err)` hook
 * recognises the platform-native scan-miss condition; otherwise the original
 * error is re-thrown untouched, preserving existing behaviour.
 */
export class ScanMissError extends Error {
  constructor(message?: string, options?: { cause?: unknown }) {
    super(message ?? 'Shielded output is not addressed to this scan key');
    this.name = 'ScanMissError';
    // Preserve the prototype chain when compiled down to older targets so
    // `instanceof ScanMissError` keeps working for consumers.
    Object.setPrototypeOf(this, ScanMissError.prototype);
    // `cause` is set manually (rather than via super) so this stays valid
    // under an ES2020 lib, where `ErrorOptions.cause` is not yet declared.
    if (options && options.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }
  }
}
