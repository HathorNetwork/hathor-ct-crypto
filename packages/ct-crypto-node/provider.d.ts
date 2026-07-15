// NEW-05: type declarations for the ./provider subpath.
// Without these, TS consumers importing '@hathor/ct-crypto-node/provider' get
// implicit `any` (or a hard error under noImplicitAny), losing type checking on
// the crypto boundary where bigint-vs-number and Buffer-vs-Uint8Array mistakes
// are exactly the bugs that matter.

import { AbstractShieldedProvider, IShieldedCryptoProvider } from '@hathor/ct-crypto-provider';

/**
 * Node (NAPI-backed) implementation of the shielded crypto provider.
 * Concrete subclass of AbstractShieldedProvider (implements every abstract
 * `_raw*`/`_encodeBytes`/`_decodeBytes` member at runtime).
 *
 * Declared as an interface + construct-signature const rather than a `class`:
 * a hand-written `class ... extends AbstractShieldedProvider {}` is a
 * non-abstract class with unimplemented abstract members (TS2515). The
 * interface keeps `NodeShieldedProvider` usable as a type; the const keeps
 * `new NodeShieldedProvider()` usable as a value.
 */
export interface NodeShieldedProvider extends AbstractShieldedProvider {}
export declare const NodeShieldedProvider: new () => NodeShieldedProvider;

/**
 * Construct the default Node shielded crypto provider.
 *
 *   const { createDefaultShieldedCryptoProvider } = require('@hathor/ct-crypto-node/provider');
 *   wallet.setShieldedCryptoProvider(createDefaultShieldedCryptoProvider());
 */
export function createDefaultShieldedCryptoProvider(): IShieldedCryptoProvider;
