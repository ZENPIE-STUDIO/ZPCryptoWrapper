//
//  ZPEcKeyPair.h
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/9.
//

#import <Foundation/Foundation.h>
#import "ZPKeyPair.h"

NS_ASSUME_NONNULL_BEGIN

@interface ZPEcKeyPair : ZPKeyPair

/// 產生 EC Key Pair
/// @param name Key Pair Label
/// @param keySizeInBits kSecp256r1, kSecp384r1, kSecp521r1
+ (ZPEcKeyPair*) generateWithName:(NSString*) name KeySize:(SecKeySizes) keySizeInBits;

+ (SecKeyRef) createPrivateKey:(NSString*) base64 KeySize:(SecKeySizes) keySizeInBits;

+ (SecKeyRef) createPrivateKeyFromPEM:(NSString*) pemFilePath;
+ (SecKeyRef) createPublicKeyWithData:(NSData*) data;
+ (SecKeyRef) createPublicKeyWithSize:(SecKeySizes) keySizeInBits X:(NSData* _Nonnull) x Y:(NSData* _Nonnull) y;

- (uint32_t) getPublicKeyComponentLength;

// Export Public X, Y
- (NSUInteger) exportPublicX:(NSMutableData*) xBuf Y:(NSMutableData*) yBuf;
- (uint32_t) exportPublicKeyBufferSize:(uint32_t) bufSize X:(uint8_t*) xBuf Y:(uint8_t*) yBuf;

- (NSData* _Nullable) exportAsn1PublicKey;
#pragma mark - ASN1 Decode
+ (NSData* _Nullable) decodeAsn1PrivateKey:(NSData*) asn1Data;
+ (NSData* _Nullable) decodeAsn1PublicKey:(NSData*) dataAsn1PublicKey;
+ (BOOL) decodeAsn1PublicKey:(NSData*) dataPublicKey ToX:(NSMutableData*) xBuf Y:(NSMutableData*) yBuf;

@end

NS_ASSUME_NONNULL_END
