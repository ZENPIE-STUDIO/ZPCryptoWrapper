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

@interface ZPEcCryptor : NSObject

+ (ZPEcKeyPair*) generateKeyPair:(NSString*) name KeySize:(SecKeySizes) keySizeInBits;
+ (ZPEcKeyPair*) generateKeyPair:(NSString*) name KeySize:(SecKeySizes) keySizeInBits Overwrite:(BOOL) overwrite;
// Sign
+ (NSData*) signMessage:(NSData*) message withPrivateKey:(SecKeyRef) privateKey CoseAlgorithm:(COSE_ALG) coseAlg Error:(NSError**) pError;
+ (NSData*) signDigest:(NSData*) digest withPrivateKey:(SecKeyRef) privateKey Algorithm:(SecKeyAlgorithm) algorithm Error:(NSError**) pError;

// Verify
+ (BOOL) verifySignature:(NSData*) signature withPublicKey:(SecKeyRef) publicKey CoseAlgorithm:(COSE_ALG) coseAlg Message:(NSData*) message Error:(NSError**) pError;
+ (BOOL) verifySignature:(NSData*) signature withPublicKey:(SecKeyRef) publicKey Algorithm:(SecKeyAlgorithm) algorithm Digest:(NSData*) digest Error:(NSError**) pError;

// ECDH - calculate Shared Secret
+ (NSData*) sharedSecretForPrivateKey:(SecKeyRef) privateKey PublicKey:(SecKeyRef) publicKey;

@end

NS_ASSUME_NONNULL_END
