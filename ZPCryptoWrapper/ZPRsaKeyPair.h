//
//  ZPRsaKeyPair.h
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/9.
//

#import <Foundation/Foundation.h>
#import "ZPKeyPair.h"

NS_ASSUME_NONNULL_BEGIN

/**
 *  Provide RSA Cryptography Key Pair Management.
 *  提供 RSA 金鑰對管理。
 *  - Generate RSA Key Pair in Keychain.
 */
@interface ZPRsaKeyPair : ZPKeyPair

/// Generate RSA Key Pair in Keychain.
/// @param name Key Pair Label
/// @param keySizeInBits RSA KeySizes (1024~4096) - default is currently 2048
+ (ZPRsaKeyPair* _Nullable) generateWithName:(NSString* _Nonnull) name KeySize:(SecKeySizes) keySizeInBits;

/// Create Private Key from PKCS1 data (not in Keychain)
+ (SecKeyRef _Nullable) createPrivateKeyFromPKCS1:(NSString* _Nonnull) base64 KeySize:(SecKeySizes) keySizeInBits;

/// Export Public Key to Modulus and Exponent.
+ (BOOL) exportPublicKey:(SecKeyRef _Nonnull) publicKey ToModulus:(NSMutableData* _Nonnull) modulus Exponent:(NSMutableData* _Nonnull) exponent;
- (BOOL) exportPublicModulus:(NSMutableData* _Nonnull) modulus Exponent:(NSMutableData* _Nonnull) exponent;

/// Export DER (ASN.1) Format Public Key
- (NSData* _Nullable) exportAsn1PublicKey;

/// Export DER (ASN.1) Format Private Key
+ (NSDictionary* _Nullable) exportAsn1PrivateKey:(SecKeyRef _Nonnull) privateKey;

// 用匯出的 Asn1 Public Key 建立 Public Key
+ (SecKeyRef _Nullable) createPublicKeyFromAsn1PublicKey:(NSData* _Nonnull) dataPublicKey;

/// Create public key from Modulus, Exponent.
+ (SecKeyRef _Nullable) createPublicKeyFromModulus:(NSData* _Nonnull) modulus Exponent:(NSData* _Nonnull) exponent;

// Decode Asn1 Public Key，取得 Modulus, Exponent
+ (BOOL) decodeAsn1PublicKey:(NSData* _Nonnull) dataPublicKey ToModulus:(NSMutableData* _Nonnull) modulus Exponent:(NSMutableData* _Nonnull) exponent;

@end

NS_ASSUME_NONNULL_END
