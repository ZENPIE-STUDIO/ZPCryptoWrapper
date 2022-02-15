//
//  ZPEcCryptor.h
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/10.
//

#import <Foundation/Foundation.h>
#import "ZPEcKeyPair.h"
#import "ZPCryptoConstants.h"

NS_ASSUME_NONNULL_BEGIN

/**
 *  Provide Elliptic Curve Cryptography Function and Key Management.
 *  提供 EC 加解密功能 及 金鑰管理。
 *  - Generate EC Key Pair in Keychain.
 *  - ECDSA - Sign / Verify Signature
 *  - ECDH
 */
@interface ZPEcCryptor : NSObject

/**
 *  Generate EC Key Pair. If Key Pair with the same name exists, it cannot be generated.
 *
 *  @param name key name in keychain
 *
 *  @param keySizeInBits kSecp192r1, kSecp256r1, kSecp384r1, kSecp521r1
 *
 *  @return EC Key Pair.
 */
+ (ZPEcKeyPair*) generateKeyPair:(NSString*) name KeySize:(SecKeySizes) keySizeInBits;

/**
 *  Generate EC Key Pair.
 *
 *  @param name key name in keychain
 *
 *  @param keySizeInBits kSecp192r1, kSecp256r1, kSecp384r1, kSecp521r1
 *
 *  @param overwrite YES: Delete the Key of the same name.
 *
 *  @return EC Key Pair.
 */
+ (ZPEcKeyPair*) generateKeyPair:(NSString*) name KeySize:(SecKeySizes) keySizeInBits Overwrite:(BOOL) overwrite;

/// ECDSA - Signature (Message)
+ (NSData*) signMessage:(NSData*) message withPrivateKey:(SecKeyRef) privateKey CoseAlgorithm:(COSE_ALG) coseAlg Error:(NSError**) pError;
/// ECDSA - Signature (Digest)
+ (NSData*) signDigest:(NSData*) digest withPrivateKey:(SecKeyRef) privateKey Algorithm:(SecKeyAlgorithm) algorithm Error:(NSError**) pError;

/// ECDSA - Verify Signature (Message)
+ (BOOL) verifySignature:(NSData*) signature withPublicKey:(SecKeyRef) publicKey CoseAlgorithm:(COSE_ALG) coseAlg Message:(NSData*) message Error:(NSError**) pError;

/// ECDSA - Verify Signature (Digest)
+ (BOOL) verifySignature:(NSData*) signature withPublicKey:(SecKeyRef) publicKey Algorithm:(SecKeyAlgorithm) algorithm Digest:(NSData*) digest Error:(NSError**) pError;

/// ECDH Standard key derivation - compute shared secret using ECDH algorithm without cofactor.
+ (NSData*) sharedSecretForPrivateKey:(SecKeyRef) privateKey PublicKey:(SecKeyRef) publicKey;

@end

NS_ASSUME_NONNULL_END
