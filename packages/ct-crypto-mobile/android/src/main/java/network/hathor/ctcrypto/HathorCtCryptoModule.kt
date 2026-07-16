/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

package network.hathor.ctcrypto

import android.util.Base64
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableArray
import com.facebook.react.bridge.WritableMap
import uniffi.hathor_ct_crypto.BlindingEntry
import uniffi.hathor_ct_crypto.CreatedShieldedOutput
import uniffi.hathor_ct_crypto.CryptoException
import uniffi.hathor_ct_crypto.SurjectionDomainEntry
import uniffi.hathor_ct_crypto.computeBalancingBlindingFactorUniffi
import uniffi.hathor_ct_crypto.createAssetCommitmentUniffi
import uniffi.hathor_ct_crypto.createCommitmentUniffi
import uniffi.hathor_ct_crypto.createShieldedOutputWithBlindingUniffi
import uniffi.hathor_ct_crypto.createShieldedOutputWithBothBlindingsUniffi
import uniffi.hathor_ct_crypto.createSurjectionProofUniffi
import uniffi.hathor_ct_crypto.decryptShieldedOutputUniffi
import uniffi.hathor_ct_crypto.deriveAssetTagUniffi
import uniffi.hathor_ct_crypto.deriveEcdhSharedSecretUniffi
import uniffi.hathor_ct_crypto.deriveTagUniffi
import uniffi.hathor_ct_crypto.generateRandomBlindingFactorUniffi

/**
 * React Native bridge for the UniFFI-generated Hathor CT crypto API
 * (uniffi/hathor_ct_crypto/hathor_ct_crypto.kt, backed by the Rust cdylib in
 * src/main/jniLibs).
 *
 * Marshaling contract with js/index.js (MobileShieldedProvider):
 *   - bytes cross the bridge as base64 strings
 *   - u64 values cross as decimal strings (they can exceed 2^53)
 *   - records cross as maps with the provider's camelCase keys
 *   - errors reject with code "InvalidInput" or "CryptoFailed"
 */
class HathorCtCryptoModule(reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {

  override fun getName(): String = "HathorCtCrypto"

  // ─── marshaling helpers ───────────────────────────────────────────────────

  private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

  private fun bytes(s: String, name: String): ByteArray =
    try {
      Base64.decode(s, Base64.DEFAULT)
    } catch (e: IllegalArgumentException) {
      throw IllegalArgumentException("$name is not valid base64")
    }

  private fun u64(s: String, name: String): ULong =
    s.toULongOrNull() ?: throw IllegalArgumentException("$name is not a valid u64 decimal string")

  private fun rejectWith(promise: Promise, e: Throwable) {
    when (e) {
      is CryptoException.InvalidInput -> promise.reject("InvalidInput", e.msg, e)
      is CryptoException.CryptoFailed -> promise.reject("CryptoFailed", e.msg, e)
      is IllegalArgumentException -> promise.reject("InvalidInput", e.message, e)
      else -> promise.reject("CryptoFailed", e.message ?: e.toString(), e)
    }
  }

  private fun createdMap(o: CreatedShieldedOutput): WritableMap {
    val m = Arguments.createMap()
    m.putString("ephemeralPubkey", b64(o.ephemeralPubkey))
    m.putString("commitment", b64(o.commitment))
    m.putString("rangeProof", b64(o.rangeProof))
    m.putString("blindingFactor", b64(o.blindingFactor))
    val ac = o.assetCommitment
    if (ac != null) m.putString("assetCommitment", b64(ac)) else m.putNull("assetCommitment")
    val abf = o.assetBlindingFactor
    if (abf != null) m.putString("assetBlindingFactor", b64(abf)) else m.putNull("assetBlindingFactor")
    return m
  }

  private fun blindingEntries(arr: ReadableArray, name: String): List<BlindingEntry> =
    (0 until arr.size()).map { i ->
      val m = arr.getMap(i) ?: throw IllegalArgumentException("$name[$i] must be an object")
      BlindingEntry(
        value = u64(
          m.getString("value") ?: throw IllegalArgumentException("$name[$i].value missing"),
          "$name[$i].value"
        ),
        valueBlindingFactor = bytes(
          m.getString("valueBlindingFactor")
            ?: throw IllegalArgumentException("$name[$i].valueBlindingFactor missing"),
          "$name[$i].valueBlindingFactor"
        ),
        generatorBlindingFactor = bytes(
          m.getString("generatorBlindingFactor")
            ?: throw IllegalArgumentException("$name[$i].generatorBlindingFactor missing"),
          "$name[$i].generatorBlindingFactor"
        ),
      )
    }

  // ─── exported methods (12 — one per provider _raw* primitive) ─────────────

  @ReactMethod
  fun generateRandomBlindingFactor(promise: Promise) {
    try {
      promise.resolve(b64(generateRandomBlindingFactorUniffi()))
    } catch (e: Throwable) {
      rejectWith(promise, e)
    }
  }

  @ReactMethod
  fun createAmountShieldedOutput(
    value: String,
    recipientPubkey: String,
    tokenUid: String,
    valueBlindingFactor: String,
    promise: Promise,
  ) {
    try {
      val out = createShieldedOutputWithBlindingUniffi(
        value = u64(value, "value"),
        recipientPubkey = bytes(recipientPubkey, "recipientPubkey"),
        tokenUid = bytes(tokenUid, "tokenUid"),
        fullyShielded = false,
        blindingFactor = bytes(valueBlindingFactor, "valueBlindingFactor"),
      )
      promise.resolve(createdMap(out))
    } catch (e: Throwable) {
      rejectWith(promise, e)
    }
  }

  @ReactMethod
  fun createShieldedOutputWithBothBlindings(
    value: String,
    recipientPubkey: String,
    tokenUid: String,
    valueBlindingFactor: String,
    assetBlindingFactor: String,
    promise: Promise,
  ) {
    try {
      val out = createShieldedOutputWithBothBlindingsUniffi(
        value = u64(value, "value"),
        recipientPubkey = bytes(recipientPubkey, "recipientPubkey"),
        tokenUid = bytes(tokenUid, "tokenUid"),
        valueBlindingFactor = bytes(valueBlindingFactor, "valueBlindingFactor"),
        assetBlindingFactor = bytes(assetBlindingFactor, "assetBlindingFactor"),
      )
      promise.resolve(createdMap(out))
    } catch (e: Throwable) {
      rejectWith(promise, e)
    }
  }

  @ReactMethod
  fun rewindAmountShieldedOutput(
    privateKey: String,
    ephemeralPubkey: String,
    commitment: String,
    rangeProof: String,
    tokenUid: String,
    promise: Promise,
  ) {
    try {
      val res = decryptShieldedOutputUniffi(
        recipientPrivkey = bytes(privateKey, "privateKey"),
        ephemeralPubkey = bytes(ephemeralPubkey, "ephemeralPubkey"),
        commitment = bytes(commitment, "commitment"),
        rangeProof = bytes(rangeProof, "rangeProof"),
        tokenUid = bytes(tokenUid, "tokenUid"),
        assetCommitment = null,
      )
      val m = Arguments.createMap()
      m.putString("value", res.value.toString())
      m.putString("blindingFactor", b64(res.blindingFactor))
      promise.resolve(m)
    } catch (e: Throwable) {
      rejectWith(promise, e)
    }
  }

  @ReactMethod
  fun rewindFullShieldedOutput(
    privateKey: String,
    ephemeralPubkey: String,
    commitment: String,
    rangeProof: String,
    assetCommitment: String,
    promise: Promise,
  ) {
    try {
      val res = decryptShieldedOutputUniffi(
        recipientPrivkey = bytes(privateKey, "privateKey"),
        ephemeralPubkey = bytes(ephemeralPubkey, "ephemeralPubkey"),
        commitment = bytes(commitment, "commitment"),
        rangeProof = bytes(rangeProof, "rangeProof"),
        tokenUid = null,
        assetCommitment = bytes(assetCommitment, "assetCommitment"),
      )
      val abf = res.assetBlindingFactor
        ?: throw IllegalArgumentException("FullShielded rewind returned no assetBlindingFactor")
      val m = Arguments.createMap()
      m.putString("value", res.value.toString())
      m.putString("blindingFactor", b64(res.blindingFactor))
      m.putString("tokenUid", b64(res.tokenUid))
      m.putString("assetBlindingFactor", b64(abf))
      promise.resolve(m)
    } catch (e: Throwable) {
      rejectWith(promise, e)
    }
  }

  @ReactMethod
  fun computeBalancingBlindingFactor(
    value: String,
    generatorBlindingFactor: String,
    inputs: ReadableArray,
    otherOutputs: ReadableArray,
    promise: Promise,
  ) {
    try {
      val out = computeBalancingBlindingFactorUniffi(
        value = u64(value, "value"),
        generatorBlindingFactor = bytes(generatorBlindingFactor, "generatorBlindingFactor"),
        inputs = blindingEntries(inputs, "inputs"),
        otherOutputs = blindingEntries(otherOutputs, "otherOutputs"),
      )
      promise.resolve(b64(out))
    } catch (e: Throwable) {
      rejectWith(promise, e)
    }
  }

  @ReactMethod
  fun deriveTag(tokenUid: String, promise: Promise) {
    try {
      promise.resolve(b64(deriveTagUniffi(bytes(tokenUid, "tokenUid"))))
    } catch (e: Throwable) {
      rejectWith(promise, e)
    }
  }

  @ReactMethod
  fun deriveAssetTag(tokenUid: String, promise: Promise) {
    try {
      promise.resolve(b64(deriveAssetTagUniffi(bytes(tokenUid, "tokenUid"))))
    } catch (e: Throwable) {
      rejectWith(promise, e)
    }
  }

  @ReactMethod
  fun createCommitment(value: String, blindingFactor: String, generator: String, promise: Promise) {
    try {
      val out = createCommitmentUniffi(
        value = u64(value, "value"),
        blindingFactor = bytes(blindingFactor, "blindingFactor"),
        generator = bytes(generator, "generator"),
      )
      promise.resolve(b64(out))
    } catch (e: Throwable) {
      rejectWith(promise, e)
    }
  }

  @ReactMethod
  fun createAssetCommitment(tag: String, blindingFactor: String, promise: Promise) {
    try {
      val out = createAssetCommitmentUniffi(
        tag = bytes(tag, "tag"),
        blindingFactor = bytes(blindingFactor, "blindingFactor"),
      )
      promise.resolve(b64(out))
    } catch (e: Throwable) {
      rejectWith(promise, e)
    }
  }

  @ReactMethod
  fun createSurjectionProof(
    codomainTag: String,
    codomainBlindingFactor: String,
    domain: ReadableArray,
    promise: Promise,
  ) {
    try {
      val entries = (0 until domain.size()).map { i ->
        val m = domain.getMap(i) ?: throw IllegalArgumentException("domain[$i] must be an object")
        SurjectionDomainEntry(
          generator = bytes(
            m.getString("generator") ?: throw IllegalArgumentException("domain[$i].generator missing"),
            "domain[$i].generator"
          ),
          tag = bytes(
            m.getString("tag") ?: throw IllegalArgumentException("domain[$i].tag missing"),
            "domain[$i].tag"
          ),
          blindingFactor = bytes(
            m.getString("blindingFactor")
              ?: throw IllegalArgumentException("domain[$i].blindingFactor missing"),
            "domain[$i].blindingFactor"
          ),
        )
      }
      val out = createSurjectionProofUniffi(
        codomainTag = bytes(codomainTag, "codomainTag"),
        codomainBlindingFactor = bytes(codomainBlindingFactor, "codomainBlindingFactor"),
        domain = entries,
      )
      promise.resolve(b64(out))
    } catch (e: Throwable) {
      rejectWith(promise, e)
    }
  }

  @ReactMethod
  fun deriveEcdhSharedSecret(privateKey: String, peerPubkey: String, promise: Promise) {
    try {
      val out = deriveEcdhSharedSecretUniffi(
        privkey = bytes(privateKey, "privateKey"),
        pubkey = bytes(peerPubkey, "peerPubkey"),
      )
      promise.resolve(b64(out))
    } catch (e: Throwable) {
      rejectWith(promise, e)
    }
  }
}
