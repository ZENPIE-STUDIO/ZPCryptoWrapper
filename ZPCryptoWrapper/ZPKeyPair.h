//
//  ZPKeyPair.h
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/5.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#if TARGET_OS_IPHONE
//#define SecKeySizes uint32_t
//#define kSecp256r1 256
typedef NS_ENUM(uint32_t, SecKeySizes)
{
    //kSecDefaultKeySize  = 0,

    // Symmetric Keysizes - default is currently kSecAES128 for AES.
    //kSec3DES192         = 192,
    kSecAES128          = 128,
    kSecAES192          = 192,
    kSecAES256          = 256,

    // Supported ECC Keys for Suite-B from RFC 4492 section 5.1.1.
    // default is currently kSecp256r1
    kSecp192r1          = 192,
    kSecp256r1          = 256,
    kSecp384r1          = 384,
    kSecp521r1          = 521,  // Yes, 521

    // Boundaries for RSA KeySizes - default is currently 2048
    // RSA keysizes must be multiples of 8
    //kSecRSAMin          = 1024,
    //kSecRSAMax          = 4096
};
#endif

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
