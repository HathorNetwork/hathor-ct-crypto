# @hathor/ct-crypto-provider

The interface and abstract class for Hathor shielded crypto providers. This
package contains no crypto — it defines the contract that
`@hathor/ct-crypto-node`, `@hathor/ct-crypto-wasm`, and
`@hathor/ct-crypto-mobile` each implement.

## What's in here

- `IShieldedCryptoProvider` — the TS interface
- `AbstractShieldedProvider` — abstract class that pre-implements every
  interface method, delegating to a smaller set of platform-specific
  `_raw*` methods that subclasses fill in
- Result/entry interfaces: `ICreatedShieldedOutput`, `IRewoundAmountShieldedOutput`, etc.

## Why an abstract class on top of the interface

The three concrete providers all do the same wrapping work:

- Promise-wrap sync underlying calls
- Marshal Buffer ↔ platform-native byte type (Buffer / Uint8Array / number[])
- Convert recovered `tokenUid` from Buffer to hex at the rewind boundary
- Compose `openAmountShieldedCommitment` / `openFullShieldedCommitment`
  from `deriveTag` + `deriveAssetTag` + `createAssetCommitment` + `createCommitment`

Putting that in `AbstractShieldedProvider` means subclasses are small —
only platform-specific marshaling + raw backend calls.

## Usage (subclass authors)

```ts
import { AbstractShieldedProvider } from '@hathor/ct-crypto-provider';

class MyProvider extends AbstractShieldedProvider {
  protected _encodeBytes(buf: Buffer): unknown { /* … */ }
  protected _decodeBytes(raw: unknown): Buffer { /* … */ }
  protected async _rawGenerateRandomBlindingFactor(): Promise<unknown> { /* … */ }
  // … etc for every _raw* method
}
```

## Usage (wallet-lib consumers)

```ts
import { createDefaultShieldedCryptoProvider } from '@hathor/ct-crypto-node/provider';
import { HathorWallet } from '@hathor/wallet-lib';

const wallet = new HathorWallet(/* … */);
wallet.setShieldedCryptoProvider(createDefaultShieldedCryptoProvider());
await wallet.start();
```

`wallet.setShieldedCryptoProvider` accepts any `IShieldedCryptoProvider` —
structural conformance, so a subclass of `AbstractShieldedProvider` works,
as does any object that happens to match the interface shape.

## License

MIT
