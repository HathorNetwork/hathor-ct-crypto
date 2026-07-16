/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 * Objective-C shim exposing the Swift HathorCtCrypto module to React Native.
 * Selectors must match the @objc(...) annotations in HathorCtCryptoModule.swift.
 */

#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(HathorCtCrypto, NSObject)

RCT_EXTERN_METHOD(generateRandomBlindingFactor:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(createAmountShieldedOutput:(NSString *)value
                  recipientPubkey:(NSString *)recipientPubkey
                  tokenUid:(NSString *)tokenUid
                  valueBlindingFactor:(NSString *)valueBlindingFactor
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(createShieldedOutputWithBothBlindings:(NSString *)value
                  recipientPubkey:(NSString *)recipientPubkey
                  tokenUid:(NSString *)tokenUid
                  valueBlindingFactor:(NSString *)valueBlindingFactor
                  assetBlindingFactor:(NSString *)assetBlindingFactor
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(rewindAmountShieldedOutput:(NSString *)privateKey
                  ephemeralPubkey:(NSString *)ephemeralPubkey
                  commitment:(NSString *)commitment
                  rangeProof:(NSString *)rangeProof
                  tokenUid:(NSString *)tokenUid
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(rewindFullShieldedOutput:(NSString *)privateKey
                  ephemeralPubkey:(NSString *)ephemeralPubkey
                  commitment:(NSString *)commitment
                  rangeProof:(NSString *)rangeProof
                  assetCommitment:(NSString *)assetCommitment
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(computeBalancingBlindingFactor:(NSString *)value
                  generatorBlindingFactor:(NSString *)generatorBlindingFactor
                  inputs:(NSArray *)inputs
                  otherOutputs:(NSArray *)otherOutputs
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deriveTag:(NSString *)tokenUid
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deriveAssetTag:(NSString *)tokenUid
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(createCommitment:(NSString *)value
                  blindingFactor:(NSString *)blindingFactor
                  generator:(NSString *)generator
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(createAssetCommitment:(NSString *)tag
                  blindingFactor:(NSString *)blindingFactor
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(createSurjectionProof:(NSString *)codomainTag
                  codomainBlindingFactor:(NSString *)codomainBlindingFactor
                  domain:(NSArray *)domain
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(deriveEcdhSharedSecret:(NSString *)privateKey
                  peerPubkey:(NSString *)peerPubkey
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
