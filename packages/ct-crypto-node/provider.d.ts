// NEW-05: type declarations for the ./provider subpath.
// Without these, TS consumers importing '@hathor/ct-crypto-node/provider' get
// implicit `any` (or a hard error under noImplicitAny), losing type checking on
// the crypto boundary where bigint-vs-number and Buffer-vs-Uint8Array mistakes
// are exactly the bugs that matter.

import { AbstractShieldedProvider, IShieldedCryptoProvider } from '@hathor/ct-crypto-provider';

/**
 * Node (NAPI-backed) implementation of the shielded crypto provider.
 * Implements the full IShieldedCryptoProvider surface.
 */
export class NodeShieldedProvider extends AbstractShieldedProvider {}

/**
 * Construct the default Node shielded crypto provider.
 *
 *   const { createDefaultShieldedCryptoProvider } = require('@hathor/ct-crypto-node/provider');
 *   wallet.setShieldedCryptoProvider(createDefaultShieldedCryptoProvider());
 */
export function createDefaultShieldedCryptoProvider(): IShieldedCryptoProvider;
