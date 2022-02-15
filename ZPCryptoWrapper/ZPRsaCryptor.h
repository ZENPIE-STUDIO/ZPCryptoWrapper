//
//  ZPRsaCryptor.h
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/10.
//

#import <Foundation/Foundation.h>
#import "ZPRsaKeyPair.h"
#import "ZPCryptoConstants.h"

NS_ASSUME_NONNULL_BEGIN

/**
 *  Provide RSA Cryptography Function and Key Management.
 *  提供 RSA 金鑰對管理。
 *  - Generate RSA Key Pair in Keychain.
 *  - PKCS1 & OAEP Encrypt / Decrypt
 *  - Sign / Verify Signature
 */
@interface ZPRsaCryptor : NSObject

// PKCS1 : plainData 沒有限制 length，內部會自行切塊
+ (NSError*) pkcs1_encryptData:(NSData*) plainData withPublicKey:(SecKeyRef) publicKey ToCipherData:(NSMutableData*) cipherData;
+ (NSError*) pkcs1_decryptData:(NSData*) cipherData withPrivateKey:(SecKeyRef) privateKey ToPlainData:(NSMutableData*) plainData;

+ (NSUInteger) calculateOaepMaxEncryptDataSizeFromKeySize:(SecKeySizes) keySizes;

// OAEP : plainData 沒有限制 length，內部會自行切塊
+ (NSError*) oaep_encryptData:(NSData*) plainData withPublicKey:(SecKeyRef) publicKey ToCipherData:(NSMutableData*) cipherData;
+ (NSError*) oaep_decryptData:(NSData*) cipherData withPrivateKey:(SecKeyRef) privateKey ToPlainData:(NSMutableData*) plainData;

// Sign
+ (NSData*) signMessage:(NSData*) message withPrivateKey:(SecKeyRef) privateKey CoseAlgorithm:(COSE_ALG) coseAlg Error:(NSError**) pError;
+ (NSData*) signDigest:(NSData*) digest withPrivateKey:(SecKeyRef) privateKey Algorithm:(SecKeyAlgorithm) algorithm Error:(NSError**) pError;

// Verify
+ (BOOL) verifySignature:(NSData*) signature withPublicKey:(SecKeyRef) publicKey CoseAlgorithm:(COSE_ALG) coseAlg Message:(NSData*) message Error:(NSError**) pError;
+ (BOOL) verifySignature:(NSData*) signature withPublicKey:(SecKeyRef) publicKey Algorithm:(SecKeyAlgorithm) algorithm Digest:(NSData*) digest Error:(NSError**) pError;

@end

NS_ASSUME_NONNULL_END
