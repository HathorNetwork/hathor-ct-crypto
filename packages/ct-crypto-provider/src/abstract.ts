/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import {
  IBlindingEntry,
  ICreatedShieldedOutput,
  IOpenedFullShieldedCommitment,
  IRewoundAmountShieldedOutput,
  IRewoundFullShieldedOutput,
  IShieldedCryptoProvider,
  ISurjectionDomainEntry,
} from './types';
import { ScanMissError } from './errors';

/**
 * Raw blinding entry as seen by a platform binding — `unknown` byte slots
 * because each platform marshals bytes differently (Buffer for Node, Uint8Array
 * for WASM, base64 string for the RN bridge on mobile).
 */
export interface IRawBlindingEntry {
  value: bigint;
  valueBlindingFactor: unknown;
  generatorBlindingFactor: unknown;
}

export interface IRawSurjectionDomainEntry {
  generator: unknown;
  tag: unknown;
  blindingFactor: unknown;
}

export interface IRawCreatedShieldedOutput {
  ephemeralPubkey: unknown;
  commitment: unknown;
  rangeProof: unknown;
  blindingFactor: unknown;
  assetCommitment?: unknown;
  assetBlindingFactor?: unknown;
}

export interface IRawRewoundAmountShieldedOutput {
  value: bigint;
  blindingFactor: unknown;
}

export interface IRawRewoundFullShieldedOutput {
  value: bigint;
  blindingFactor: unknown;
  tokenUid: unknown;
  assetBlindingFactor: unknown;
}

/**
 * Shared implementation of the shielded crypto provider interface.
 *
 * Subclasses (NodeShieldedProvider, WasmShieldedProvider,
 * MobileShieldedProvider) only need to implement:
 *   - `_encodeBytes` / `_decodeBytes` — platform byte marshaling
 *   - one `_raw*` method per operation the platform supports
 *
 * The abstract class handles:
 *   - Promise wrapping (already returning Promise<T>)
 *   - tokenUid Buffer→hex conversion at the rewind boundary
 *   - Long-form blinding-factor naming
 *   - Composing `openAmountShieldedCommitment` / `openFullShieldedCommitment`
 *     from the lower-level primitives (deriveTag, createAssetCommitment,
 *     createCommitment), so platform bindings don't need dedicated `open*`
 *     exports.
 *   - Error context wrapping (subclasses just throw; this wraps once)
 *
 * Verifier-only subclasses (WASM) use `_unsupported(name)` to short-circuit
 * signing / RNG paths uniformly.
 */
export abstract class AbstractShieldedProvider implements IShieldedCryptoProvider {
  // ─── public surface (implements IShieldedCryptoProvider) ───────────────────

  async generateRandomBlindingFactor(): Promise<Buffer> {
    const raw = await this._rawGenerateRandomBlindingFactor();
    return this._decodeBytes(raw);
  }

  async createAmountShieldedOutput(
    value: bigint,
    recipientPubkey: Buffer,
    tokenUid: Buffer,
    valueBlindingFactor: Buffer
  ): Promise<ICreatedShieldedOutput> {
    const raw = await this._rawCreateAmountShieldedOutput(
      value,
      this._encodeBytes(recipientPubkey),
      this._encodeBytes(tokenUid),
      this._encodeBytes(valueBlindingFactor)
    );
    return this._decodeCreatedShieldedOutput(raw);
  }

  async createShieldedOutputWithBothBlindings(
    value: bigint,
    recipientPubkey: Buffer,
    tokenUid: Buffer,
    valueBlindingFactor: Buffer,
    assetBlindingFactor: Buffer
  ): Promise<ICreatedShieldedOutput> {
    const raw = await this._rawCreateShieldedOutputWithBothBlindings(
      value,
      this._encodeBytes(recipientPubkey),
      this._encodeBytes(tokenUid),
      this._encodeBytes(valueBlindingFactor),
      this._encodeBytes(assetBlindingFactor)
    );
    return this._decodeCreatedShieldedOutput(raw);
  }

  async rewindAmountShieldedOutput(
    privateKey: Buffer,
    ephemeralPubkey: Buffer,
    commitment: Buffer,
    rangeProof: Buffer,
    tokenUid: Buffer
  ): Promise<IRewoundAmountShieldedOutput> {
    let raw: IRawRewoundAmountShieldedOutput;
    try {
      raw = await this._rawRewindAmountShieldedOutput(
        this._encodeBytes(privateKey),
        this._encodeBytes(ephemeralPubkey),
        this._encodeBytes(commitment),
        this._encodeBytes(rangeProof),
        this._encodeBytes(tokenUid)
      );
    } catch (err) {
      this._rethrowRewindError(err);
    }
    return {
      value: raw.value,
      blindingFactor: this._decodeBytes(raw.blindingFactor),
    };
  }

  async rewindFullShieldedOutput(
    privateKey: Buffer,
    ephemeralPubkey: Buffer,
    commitment: Buffer,
    rangeProof: Buffer,
    assetCommitment: Buffer
  ): Promise<IRewoundFullShieldedOutput> {
    let raw: IRawRewoundFullShieldedOutput;
    try {
      raw = await this._rawRewindFullShieldedOutput(
        this._encodeBytes(privateKey),
        this._encodeBytes(ephemeralPubkey),
        this._encodeBytes(commitment),
        this._encodeBytes(rangeProof),
        this._encodeBytes(assetCommitment)
      );
    } catch (err) {
      this._rethrowRewindError(err);
    }
    return {
      value: raw.value,
      blindingFactor: this._decodeBytes(raw.blindingFactor),
      // Canonical encoding: tokenUid is hex everywhere outside this boundary.
      // wallet-lib's IUtxo.token, IHistoryShieldedOutput, etc. all expect hex.
      tokenUid: this._decodeBytes(raw.tokenUid).toString('hex'),
      assetBlindingFactor: this._decodeBytes(raw.assetBlindingFactor),
    };
  }

  async computeBalancingBlindingFactor(
    value: bigint,
    generatorBlindingFactor: Buffer,
    inputs: IBlindingEntry[],
    otherOutputs: IBlindingEntry[]
  ): Promise<Buffer> {
    const raw = await this._rawComputeBalancingBlindingFactor(
      value,
      this._encodeBytes(generatorBlindingFactor),
      inputs.map(i => this._encodeBlindingEntry(i)),
      otherOutputs.map(o => this._encodeBlindingEntry(o))
    );
    return this._decodeBytes(raw);
  }

  async deriveTag(tokenUid: Buffer): Promise<Buffer> {
    const raw = await this._rawDeriveTag(this._encodeBytes(tokenUid));
    return this._decodeBytes(raw);
  }

  async deriveAssetTag(tokenUid: Buffer): Promise<Buffer> {
    const raw = await this._rawDeriveAssetTag(this._encodeBytes(tokenUid));
    return this._decodeBytes(raw);
  }

  async createCommitment(
    value: bigint,
    blindingFactor: Buffer,
    generator: Buffer
  ): Promise<Buffer> {
    const raw = await this._rawCreateCommitment(
      value,
      this._encodeBytes(blindingFactor),
      this._encodeBytes(generator)
    );
    return this._decodeBytes(raw);
  }

  async createAssetCommitment(tag: Buffer, blindingFactor: Buffer): Promise<Buffer> {
    const raw = await this._rawCreateAssetCommitment(
      this._encodeBytes(tag),
      this._encodeBytes(blindingFactor)
    );
    return this._decodeBytes(raw);
  }

  async createSurjectionProof(
    codomainTag: Buffer,
    codomainBlindingFactor: Buffer,
    domain: ISurjectionDomainEntry[]
  ): Promise<Buffer> {
    const raw = await this._rawCreateSurjectionProof(
      this._encodeBytes(codomainTag),
      this._encodeBytes(codomainBlindingFactor),
      domain.map(d => this._encodeDomainEntry(d))
    );
    return this._decodeBytes(raw);
  }

  async deriveEcdhSharedSecret(privateKey: Buffer, peerPubkey: Buffer): Promise<Buffer> {
    const raw = await this._rawDeriveEcdhSharedSecret(
      this._encodeBytes(privateKey),
      this._encodeBytes(peerPubkey)
    );
    return this._decodeBytes(raw);
  }

  /**
   * Composed from `deriveAssetTag` + `createCommitment`. Subclasses don't
   * override this — if both primitives exist, the open works; if either
   * primitive throws (e.g. verifier-only subclass missing them), this
   * surfaces the throw.
   */
  async openAmountShieldedCommitment(
    value: bigint,
    valueBlindingFactor: Buffer,
    tokenUid: Buffer
  ): Promise<Buffer> {
    const generator = await this.deriveAssetTag(tokenUid);
    return this.createCommitment(value, valueBlindingFactor, generator);
  }

  /**
   * Composed from `deriveTag` + `createAssetCommitment` + `createCommitment`.
   */
  async openFullShieldedCommitment(
    value: bigint,
    valueBlindingFactor: Buffer,
    tokenUid: Buffer,
    assetBlindingFactor: Buffer
  ): Promise<IOpenedFullShieldedCommitment> {
    const tag = await this.deriveTag(tokenUid);
    const assetCommitment = await this.createAssetCommitment(tag, assetBlindingFactor);
    const valueCommitment = await this.createCommitment(
      value,
      valueBlindingFactor,
      assetCommitment
    );
    return { valueCommitment, assetCommitment };
  }

  // ─── helpers subclasses MAY override ─────────────────────────────────────

  /**
   * Encode a blinding entry for a platform-specific raw call. Default uses
   * long-form keys (matches NAPI's expected shape and ct-crypto-core's
   * Rust struct). Subclasses with different key conventions (e.g. older
   * mobile bridges that wanted `vbf`/`gbf`) override this.
   */
  protected _encodeBlindingEntry(entry: IBlindingEntry): IRawBlindingEntry {
    return {
      value: entry.value,
      valueBlindingFactor: this._encodeBytes(entry.valueBlindingFactor),
      generatorBlindingFactor: this._encodeBytes(entry.generatorBlindingFactor),
    };
  }

  /**
   * Encode a surjection-domain entry for a platform-specific raw call.
   */
  protected _encodeDomainEntry(entry: ISurjectionDomainEntry): IRawSurjectionDomainEntry {
    return {
      generator: this._encodeBytes(entry.generator),
      tag: this._encodeBytes(entry.tag),
      blindingFactor: this._encodeBytes(entry.blindingFactor),
    };
  }

  /**
   * Decode the raw create-output result into the typed shape, normalising
   * the optional asset fields. NAPI returns `null` for absent fields; we
   * normalise to `undefined` per TS convention.
   */
  protected _decodeCreatedShieldedOutput(raw: IRawCreatedShieldedOutput): ICreatedShieldedOutput {
    return {
      ephemeralPubkey: this._decodeBytes(raw.ephemeralPubkey),
      commitment: this._decodeBytes(raw.commitment),
      rangeProof: this._decodeBytes(raw.rangeProof),
      blindingFactor: this._decodeBytes(raw.blindingFactor),
      assetCommitment: raw.assetCommitment != null ? this._decodeBytes(raw.assetCommitment) : undefined,
      assetBlindingFactor:
        raw.assetBlindingFactor != null ? this._decodeBytes(raw.assetBlindingFactor) : undefined,
    };
  }

  /**
   * Return `true` when `err` (thrown by a `_rawRewind*` call) represents the
   * output simply **not being addressed to this scan key** — the common,
   * benign scan-miss case — rather than genuine corruption / malformed input.
   *
   * The base cannot tell the two apart from a generic platform error, so it
   * conservatively returns `false`: unrecognised errors propagate unchanged,
   * exactly as before. Subclasses that CAN recognise their binding's scan-miss
   * signal (e.g. a specific error code / message from the native/wasm layer)
   * override this to opt into `ScanMissError` translation. This is purely
   * additive — a subclass that does not override keeps today's throw behaviour.
   */
  protected _isScanMiss(_err: unknown): boolean {
    return false;
  }

  /**
   * Normalise an error thrown by a `_rawRewind*` call: convert a recognised
   * scan-miss into a typed {@link ScanMissError} (preserving the original as
   * `cause`), otherwise re-throw the original untouched. Always throws.
   */
  protected _rethrowRewindError(err: unknown): never {
    if (this._isScanMiss(err)) {
      throw new ScanMissError(undefined, { cause: err });
    }
    throw err;
  }

  /**
   * Reject the call with a descriptive error. Verifier-only subclasses use
   * this in unsupported `_raw*` methods.
   */
  protected _unsupported(name: string): Promise<never> {
    return Promise.reject(
      new Error(
        `${name} is not supported by this shielded crypto provider. ` +
          'Verifier/auditor providers (e.g. @hathor/ct-crypto-wasm) expose ' +
          'verification, commitment-recompute, and rewind, but not output ' +
          'creation, signing, or RNG; use @hathor/ct-crypto-node for those.'
      )
    );
  }

  // ─── abstract — every subclass MUST implement ────────────────────────────

  /** Convert a Buffer to the platform-native byte representation. */
  protected abstract _encodeBytes(buf: Buffer): unknown;

  /** Convert a platform-native byte value back to a Buffer. */
  protected abstract _decodeBytes(raw: unknown): Buffer;

  // Raw primitive operations — one per IShieldedCryptoProvider method.
  protected abstract _rawGenerateRandomBlindingFactor(): Promise<unknown>;

  protected abstract _rawCreateAmountShieldedOutput(
    value: bigint,
    recipientPubkey: unknown,
    tokenUid: unknown,
    valueBlindingFactor: unknown
  ): Promise<IRawCreatedShieldedOutput>;

  protected abstract _rawCreateShieldedOutputWithBothBlindings(
    value: bigint,
    recipientPubkey: unknown,
    tokenUid: unknown,
    valueBlindingFactor: unknown,
    assetBlindingFactor: unknown
  ): Promise<IRawCreatedShieldedOutput>;

  protected abstract _rawRewindAmountShieldedOutput(
    privateKey: unknown,
    ephemeralPubkey: unknown,
    commitment: unknown,
    rangeProof: unknown,
    tokenUid: unknown
  ): Promise<IRawRewoundAmountShieldedOutput>;

  protected abstract _rawRewindFullShieldedOutput(
    privateKey: unknown,
    ephemeralPubkey: unknown,
    commitment: unknown,
    rangeProof: unknown,
    assetCommitment: unknown
  ): Promise<IRawRewoundFullShieldedOutput>;

  protected abstract _rawComputeBalancingBlindingFactor(
    value: bigint,
    generatorBlindingFactor: unknown,
    inputs: IRawBlindingEntry[],
    otherOutputs: IRawBlindingEntry[]
  ): Promise<unknown>;

  protected abstract _rawDeriveTag(tokenUid: unknown): Promise<unknown>;

  protected abstract _rawDeriveAssetTag(tokenUid: unknown): Promise<unknown>;

  protected abstract _rawCreateCommitment(
    value: bigint,
    blindingFactor: unknown,
    generator: unknown
  ): Promise<unknown>;

  protected abstract _rawCreateAssetCommitment(
    tag: unknown,
    blindingFactor: unknown
  ): Promise<unknown>;

  protected abstract _rawCreateSurjectionProof(
    codomainTag: unknown,
    codomainBlindingFactor: unknown,
    domain: IRawSurjectionDomainEntry[]
  ): Promise<unknown>;

  protected abstract _rawDeriveEcdhSharedSecret(
    privateKey: unknown,
    peerPubkey: unknown
  ): Promise<unknown>;
}
