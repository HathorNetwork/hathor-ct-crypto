# @hathor/ct-crypto-provider

The interface and abstract class for Hathor shielded crypto providers. This
package contains no crypto — it defines the contract that
`@hathor/ct-crypto-node`, `@hathor/ct-crypto-wasm`, and
`@hathor/ct-crypto-mobile` each implement.

## What's in here

- `IShieldedCryptoProvider` — the TS interface. Includes an OPTIONAL verifier
  surface (`verifyRangeProof?`, `verifySurjectionProof?`, `verifyBalance?`,
  `verifyCommitmentsSum?`, `validateCommitment?`, `validateGenerator?`) —
  feature-detect before calling, since not every platform ships it.
- `AbstractShieldedProvider` — abstract class that pre-implements every
  required interface method, delegating to a smaller set of platform-specific
  `_raw*` methods that subclasses fill in
- Result/entry interfaces: `ICreatedShieldedOutput`, `IRewoundAmountShieldedOutput`,
  `ITransparentBalanceEntry`, etc.
- `ScanMissError` — typed error for "output not addressed to this scan key"
  (see below)
- `ZERO_TWEAK` — the 32-byte all-zero scalar (the `generatorBlindingFactor`
  for AmountShielded outputs)

## Scan-miss handling

When scanning the chain, most outputs are not addressed to a given scan key —
`rewindAmountShieldedOutput` / `rewindFullShieldedOutput` reject in that case.
To distinguish this benign "not mine" case from genuine corruption without
string-matching messages, catch the exported `ScanMissError`:

```ts
import { ScanMissError } from '@hathor/ct-crypto-provider';

try {
  const rewound = await provider.rewindAmountShieldedOutput(/* … */);
} catch (err) {
  if (err instanceof ScanMissError) continue; // foreign output — skip
  throw err;                                   // real failure
}
```

`ScanMissError extends Error`, so code that catches generically is unaffected.
A subclass raises it only when it recognises its binding's scan-miss condition
(via the `_isScanMiss` hook); otherwise the original error propagates unchanged.

## Why an abstract class on top of the interface

The three concrete providers all do the same wrapping work:

- Promise-wrap sync underlying calls
- Marshal Buffer ↔ platform-native byte type (Buffer for Node / Uint8Array for
  WASM / base64 string for the mobile RN bridge)
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
