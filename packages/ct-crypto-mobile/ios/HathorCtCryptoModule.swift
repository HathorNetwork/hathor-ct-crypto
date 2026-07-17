/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import Foundation
import React

/// React Native bridge for the UniFFI-generated Hathor CT crypto API
/// (hathor_ct_crypto.swift in this directory, backed by the Rust staticlib in
/// HathorCtCrypto.xcframework).
///
/// Marshaling contract with js/index.js (MobileShieldedProvider):
///   - bytes cross the bridge as base64 strings
///   - u64 values cross as decimal strings (they can exceed 2^53)
///   - records cross as dictionaries with the provider's camelCase keys
///   - errors reject with code "InvalidInput" or "CryptoFailed"
@objc(HathorCtCrypto)
class HathorCtCrypto: NSObject {
  @objc static func requiresMainQueueSetup() -> Bool { false }

  private enum BridgeError: Error {
    case badInput(String)
  }

  // ─── marshaling helpers ───────────────────────────────────────────────────

  private func data(_ b64: String, _ name: String) throws -> Data {
    // Strict base64 by design: no `.ignoreUnknownCharacters`, so whitespace,
    // non-alphabet characters and unpadded input are rejected. The Android
    // bridge (HathorCtCryptoModule.kt) validates with a matching strict regex
    // so both native bridges accept EXACTLY the same inputs — keep them in sync.
    guard let d = Data(base64Encoded: b64) else {
      throw BridgeError.badInput("\(name) is not valid base64")
    }
    return d
  }

  private func u64(_ s: String, _ name: String) throws -> UInt64 {
    guard let v = UInt64(s) else {
      throw BridgeError.badInput("\(name) is not a valid u64 decimal string")
    }
    return v
  }

  private func rejectWith(_ reject: RCTPromiseRejectBlock, _ error: Error) {
    switch error {
    case CryptoError.InvalidInput(let msg):
      reject("InvalidInput", msg, error)
    case CryptoError.CryptoFailed(let msg):
      reject("CryptoFailed", msg, error)
    case BridgeError.badInput(let msg):
      reject("InvalidInput", msg, error)
    default:
      reject("CryptoFailed", String(describing: error), error)
    }
  }

  private func createdDict(_ o: CreatedShieldedOutput) -> [String: Any] {
    return [
      "ephemeralPubkey": o.ephemeralPubkey.base64EncodedString(),
      "commitment": o.commitment.base64EncodedString(),
      "rangeProof": o.rangeProof.base64EncodedString(),
      "blindingFactor": o.blindingFactor.base64EncodedString(),
      "assetCommitment": o.assetCommitment.map { $0.base64EncodedString() } ?? NSNull(),
      "assetBlindingFactor": o.assetBlindingFactor.map { $0.base64EncodedString() } ?? NSNull(),
    ]
  }

  private func blindingEntries(_ arr: NSArray, _ name: String) throws -> [BlindingEntry] {
    return try arr.enumerated().map { (i, el) in
      guard let m = el as? [String: Any],
            let value = m["value"] as? String,
            let vbf = m["valueBlindingFactor"] as? String,
            let gbf = m["generatorBlindingFactor"] as? String else {
        throw BridgeError.badInput("\(name)[\(i)] must have value/valueBlindingFactor/generatorBlindingFactor")
      }
      return BlindingEntry(
        value: try u64(value, "\(name)[\(i)].value"),
        valueBlindingFactor: try data(vbf, "\(name)[\(i)].valueBlindingFactor"),
        generatorBlindingFactor: try data(gbf, "\(name)[\(i)].generatorBlindingFactor")
      )
    }
  }

  // ─── exported methods (12 — one per provider _raw* primitive) ─────────────

  @objc(generateRandomBlindingFactor:rejecter:)
  func generateRandomBlindingFactor(_ resolve: @escaping RCTPromiseResolveBlock,
                                    rejecter reject: @escaping RCTPromiseRejectBlock) {
    resolve(generateRandomBlindingFactorUniffi().base64EncodedString())
  }

  @objc(createAmountShieldedOutput:recipientPubkey:tokenUid:valueBlindingFactor:resolver:rejecter:)
  func createAmountShieldedOutput(_ value: String, recipientPubkey: String, tokenUid: String,
                                  valueBlindingFactor: String,
                                  resolver resolve: @escaping RCTPromiseResolveBlock,
                                  rejecter reject: @escaping RCTPromiseRejectBlock) {
    do {
      let out = try createShieldedOutputWithBlindingUniffi(
        value: try u64(value, "value"),
        recipientPubkey: try data(recipientPubkey, "recipientPubkey"),
        tokenUid: try data(tokenUid, "tokenUid"),
        fullyShielded: false,
        blindingFactor: try data(valueBlindingFactor, "valueBlindingFactor")
      )
      resolve(createdDict(out))
    } catch { rejectWith(reject, error) }
  }

  @objc(createShieldedOutputWithBothBlindings:recipientPubkey:tokenUid:valueBlindingFactor:assetBlindingFactor:resolver:rejecter:)
  func createShieldedOutputWithBothBlindings(_ value: String, recipientPubkey: String, tokenUid: String,
                                             valueBlindingFactor: String, assetBlindingFactor: String,
                                             resolver resolve: @escaping RCTPromiseResolveBlock,
                                             rejecter reject: @escaping RCTPromiseRejectBlock) {
    do {
      let out = try createShieldedOutputWithBothBlindingsUniffi(
        value: try u64(value, "value"),
        recipientPubkey: try data(recipientPubkey, "recipientPubkey"),
        tokenUid: try data(tokenUid, "tokenUid"),
        valueBlindingFactor: try data(valueBlindingFactor, "valueBlindingFactor"),
        assetBlindingFactor: try data(assetBlindingFactor, "assetBlindingFactor")
      )
      resolve(createdDict(out))
    } catch { rejectWith(reject, error) }
  }

  @objc(rewindAmountShieldedOutput:ephemeralPubkey:commitment:rangeProof:tokenUid:resolver:rejecter:)
  func rewindAmountShieldedOutput(_ privateKey: String, ephemeralPubkey: String, commitment: String,
                                  rangeProof: String, tokenUid: String,
                                  resolver resolve: @escaping RCTPromiseResolveBlock,
                                  rejecter reject: @escaping RCTPromiseRejectBlock) {
    do {
      let res = try decryptShieldedOutputUniffi(
        recipientPrivkey: try data(privateKey, "privateKey"),
        ephemeralPubkey: try data(ephemeralPubkey, "ephemeralPubkey"),
        commitment: try data(commitment, "commitment"),
        rangeProof: try data(rangeProof, "rangeProof"),
        tokenUid: try data(tokenUid, "tokenUid"),
        assetCommitment: nil
      )
      resolve([
        "value": String(res.value),
        "blindingFactor": res.blindingFactor.base64EncodedString(),
      ])
    } catch { rejectWith(reject, error) }
  }

  @objc(rewindFullShieldedOutput:ephemeralPubkey:commitment:rangeProof:assetCommitment:resolver:rejecter:)
  func rewindFullShieldedOutput(_ privateKey: String, ephemeralPubkey: String, commitment: String,
                                rangeProof: String, assetCommitment: String,
                                resolver resolve: @escaping RCTPromiseResolveBlock,
                                rejecter reject: @escaping RCTPromiseRejectBlock) {
    do {
      let res = try decryptShieldedOutputUniffi(
        recipientPrivkey: try data(privateKey, "privateKey"),
        ephemeralPubkey: try data(ephemeralPubkey, "ephemeralPubkey"),
        commitment: try data(commitment, "commitment"),
        rangeProof: try data(rangeProof, "rangeProof"),
        tokenUid: nil,
        assetCommitment: try data(assetCommitment, "assetCommitment")
      )
      guard let abf = res.assetBlindingFactor else {
        throw BridgeError.badInput("FullShielded rewind returned no assetBlindingFactor")
      }
      resolve([
        "value": String(res.value),
        "blindingFactor": res.blindingFactor.base64EncodedString(),
        "tokenUid": res.tokenUid.base64EncodedString(),
        "assetBlindingFactor": abf.base64EncodedString(),
      ])
    } catch { rejectWith(reject, error) }
  }

  @objc(computeBalancingBlindingFactor:generatorBlindingFactor:inputs:otherOutputs:resolver:rejecter:)
  func computeBalancingBlindingFactor(_ value: String, generatorBlindingFactor: String,
                                      inputs: NSArray, otherOutputs: NSArray,
                                      resolver resolve: @escaping RCTPromiseResolveBlock,
                                      rejecter reject: @escaping RCTPromiseRejectBlock) {
    do {
      let out = try computeBalancingBlindingFactorUniffi(
        value: try u64(value, "value"),
        generatorBlindingFactor: try data(generatorBlindingFactor, "generatorBlindingFactor"),
        inputs: try blindingEntries(inputs, "inputs"),
        otherOutputs: try blindingEntries(otherOutputs, "otherOutputs")
      )
      resolve(out.base64EncodedString())
    } catch { rejectWith(reject, error) }
  }

  @objc(deriveTag:resolver:rejecter:)
  func deriveTag(_ tokenUid: String,
                 resolver resolve: @escaping RCTPromiseResolveBlock,
                 rejecter reject: @escaping RCTPromiseRejectBlock) {
    do {
      resolve(try deriveTagUniffi(tokenUid: try data(tokenUid, "tokenUid")).base64EncodedString())
    } catch { rejectWith(reject, error) }
  }

  @objc(deriveAssetTag:resolver:rejecter:)
  func deriveAssetTag(_ tokenUid: String,
                      resolver resolve: @escaping RCTPromiseResolveBlock,
                      rejecter reject: @escaping RCTPromiseRejectBlock) {
    do {
      resolve(try deriveAssetTagUniffi(tokenUid: try data(tokenUid, "tokenUid")).base64EncodedString())
    } catch { rejectWith(reject, error) }
  }

  @objc(createCommitment:blindingFactor:generator:resolver:rejecter:)
  func createCommitment(_ value: String, blindingFactor: String, generator: String,
                        resolver resolve: @escaping RCTPromiseResolveBlock,
                        rejecter reject: @escaping RCTPromiseRejectBlock) {
    do {
      let out = try createCommitmentUniffi(
        value: try u64(value, "value"),
        blindingFactor: try data(blindingFactor, "blindingFactor"),
        generator: try data(generator, "generator")
      )
      resolve(out.base64EncodedString())
    } catch { rejectWith(reject, error) }
  }

  @objc(createAssetCommitment:blindingFactor:resolver:rejecter:)
  func createAssetCommitment(_ tag: String, blindingFactor: String,
                             resolver resolve: @escaping RCTPromiseResolveBlock,
                             rejecter reject: @escaping RCTPromiseRejectBlock) {
    do {
      let out = try createAssetCommitmentUniffi(
        tag: try data(tag, "tag"),
        blindingFactor: try data(blindingFactor, "blindingFactor")
      )
      resolve(out.base64EncodedString())
    } catch { rejectWith(reject, error) }
  }

  @objc(createSurjectionProof:codomainBlindingFactor:domain:resolver:rejecter:)
  func createSurjectionProof(_ codomainTag: String, codomainBlindingFactor: String, domain: NSArray,
                             resolver resolve: @escaping RCTPromiseResolveBlock,
                             rejecter reject: @escaping RCTPromiseRejectBlock) {
    do {
      let entries: [SurjectionDomainEntry] = try domain.enumerated().map { (i, el) in
        guard let m = el as? [String: Any],
              let gen = m["generator"] as? String,
              let tag = m["tag"] as? String,
              let bf = m["blindingFactor"] as? String else {
          throw BridgeError.badInput("domain[\(i)] must have generator/tag/blindingFactor")
        }
        return SurjectionDomainEntry(
          generator: try data(gen, "domain[\(i)].generator"),
          tag: try data(tag, "domain[\(i)].tag"),
          blindingFactor: try data(bf, "domain[\(i)].blindingFactor")
        )
      }
      let out = try createSurjectionProofUniffi(
        codomainTag: try data(codomainTag, "codomainTag"),
        codomainBlindingFactor: try data(codomainBlindingFactor, "codomainBlindingFactor"),
        domain: entries
      )
      resolve(out.base64EncodedString())
    } catch { rejectWith(reject, error) }
  }

  @objc(deriveEcdhSharedSecret:peerPubkey:resolver:rejecter:)
  func deriveEcdhSharedSecret(_ privateKey: String, peerPubkey: String,
                              resolver resolve: @escaping RCTPromiseResolveBlock,
                              rejecter reject: @escaping RCTPromiseRejectBlock) {
    do {
      let out = try deriveEcdhSharedSecretUniffi(
        privkey: try data(privateKey, "privateKey"),
        pubkey: try data(peerPubkey, "peerPubkey")
      )
      resolve(out.base64EncodedString())
    } catch { rejectWith(reject, error) }
  }
}
