//
//  ZPEcKeyPair.h
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/9.
//

#import <Foundation/Foundation.h>
#import "ZPKeyPair.h"

NS_ASSUME_NONNULL_BEGIN

/**
 *  Provide Elliptic Curve Cryptography Key Pair Management.
 *  提供 EC 金鑰對管理。
 *  - Generate EC Key Pair in Keychain.
 *  - Create EC key from PEM file format.
 *  - Create EC key from coordinates x and y.
 */
@interface ZPEcKeyPair : ZPKeyPair

/// Generate EC Key Pair in Keychain.
/// @param name Key Pair Label
/// @param keySizeInBits kSecp256r1, kSecp384r1, kSecp521r1
+ (ZPEcKeyPair*) generateWithName:(NSString*) name KeySize:(SecKeySizes) keySizeInBits;

/// Create EC private key from PEM file format.
+ (SecKeyRef) createPrivateKeyFromPEM:(NSString*) pemFilePath;

/// Create EC public key from ANSI X9.63 format (04 || X || Y [ || K]).
+ (SecKeyRef) createPublicKeyWithData:(NSData*) data;

/// Create EC public key from coordinates x and y.
+ (SecKeyRef) createPublicKeyWithSize:(SecKeySizes) keySizeInBits X:(NSData* _Nonnull) x Y:(NSData* _Nonnull) y;

- (uint32_t) getPublicKeyComponentLength;

/// Export Public Key to coordinates x and y.
- (NSUInteger) exportPublicX:(NSMutableData*) xBuf Y:(NSMutableData*) yBuf;
- (uint32_t) exportPublicKeyBufferSize:(uint32_t) bufSize X:(uint8_t*) xBuf Y:(uint8_t*) yBuf;

/// Export DER (ASN.1) Format Public Key
- (NSData* _Nullable) exportAsn1PublicKey;

#pragma mark - ASN1 Decode
+ (NSData* _Nullable) decodeAsn1PrivateKey:(NSData*) asn1Data;
+ (NSData* _Nullable) decodeAsn1PublicKey:(NSData*) dataAsn1PublicKey;
+ (BOOL) decodeAsn1PublicKey:(NSData*) dataPublicKey ToX:(NSMutableData*) xBuf Y:(NSMutableData*) yBuf;

@end

NS_ASSUME_NONNULL_END
