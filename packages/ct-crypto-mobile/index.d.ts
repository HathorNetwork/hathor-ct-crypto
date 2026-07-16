// Type declarations for @hathor/ct-crypto-mobile.

import { AbstractShieldedProvider, IShieldedCryptoProvider } from '@hathor/ct-crypto-provider';

/**
 * Mobile (React Native) shielded crypto provider, backed by the Rust core over
 * UniFFI via the HathorCtCrypto native module. Concrete subclass of
 * AbstractShieldedProvider (implements every abstract member at runtime).
 *
 * Declared as an interface + construct-signature const rather than a `class`:
 * a hand-written `class ... extends AbstractShieldedProvider {}` is a
 * non-abstract class with unimplemented abstract members (TS2515/TS18052).
 */
export interface MobileShieldedProvider extends AbstractShieldedProvider {}
export declare const MobileShieldedProvider: new (nativeModule: unknown) => MobileShieldedProvider;

export interface CreateMobileShieldedCryptoProviderOptions {
  /** Inject the native module (tests / custom setups). Defaults to
   *  `NativeModules.HathorCtCrypto` from react-native. */
  nativeModule?: unknown;
}

/**
 * Construct the default mobile shielded crypto provider.
 *
 *   import { createMobileShieldedCryptoProvider } from '@hathor/ct-crypto-mobile';
 *   wallet.setShieldedCryptoProvider(createMobileShieldedCryptoProvider());
 */
export declare function createMobileShieldedCryptoProvider(
  options?: CreateMobileShieldedCryptoProviderOptions
): IShieldedCryptoProvider;
