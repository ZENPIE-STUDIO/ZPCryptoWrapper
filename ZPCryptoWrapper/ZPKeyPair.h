//
//  ZPKeyPair.h
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/5.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, KeyType) {
    KeyTypeUnknow = 0,
    KeyTypeRSA,
    KeyTypeECSECPrimeRandom
};

@class ZPRsaKeyPair;
@class ZPEcKeyPair;

/**
 *  Key Pair Management.
 *  金鑰對管理
 */
@interface ZPKeyPair : NSObject

@property (nonatomic, readonly) KeyType type;
@property (nonatomic, readonly) NSString* name;
@property (nonatomic, readonly) SecKeySizes keySizes;
@property (nonatomic, readonly) _Nullable SecKeyRef publicKey;
@property (nonatomic, readonly) _Nullable SecKeyRef privateKey;

#pragma mark - in keychain
+ (boolean_t) generatePublicKey:(SecKeyRef * _Nullable CF_RETURNS_RETAINED) pPublicKey
                     PrivateKey:(SecKeyRef * _Nullable CF_RETURNS_RETAINED) pPrivateKey
                       WithType:(CFStringRef) keyType
                           Name:(NSString*) name
                           Size:(SecKeySizes) keySizeInBits;
+ (instancetype) getInstanceFromKeychain:(NSString*) name;
+ (KeyType) getKeyType:(SecKeyRef) key;
+ (SecKeySizes) getKeySizes:(SecKeyRef) key;

- (instancetype) initWithName:(NSString*) name PublicKey:(SecKeyRef) publicKey PrivateKey:(SecKeyRef) privateKey;
- (void) deleteFromKeychain;

#pragma mark -
- (NSData* _Nullable) exportPrivateKey;
- (NSData* _Nullable) exportPublicKey;

+ (SecKeyRef) getPublicCertFromX509Data:(NSData*) certData;
#pragma mark - TEST ONLY
+ (void) deleteAllKeyCreatedByMe;

@end

NS_ASSUME_NONNULL_END
