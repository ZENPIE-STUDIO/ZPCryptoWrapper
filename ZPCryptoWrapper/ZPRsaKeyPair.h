//
//  ZPRsaKeyPair.h
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/9.
//

#import <Foundation/Foundation.h>
#import "ZPKeyPair.h"

NS_ASSUME_NONNULL_BEGIN

@interface ZPRsaKeyPair : ZPKeyPair

// gen完會出現在 Keychain 中
+ (ZPRsaKeyPair* _Nullable) generateWithName:(NSString* _Nonnull) name KeySize:(SecKeySizes) keySizeInBits;

// 從 PKCS1 的資料建立 Private Key (不會出現在 Keychain中)
+ (SecKeyRef _Nullable) createPrivateKeyFromPKCS1:(NSString* _Nonnull) base64 KeySize:(SecKeySizes) keySizeInBits;
+ (BOOL) exportPublicKey:(SecKeyRef _Nonnull) publicKey ToModulus:(NSMutableData* _Nonnull) modulus Exponent:(NSMutableData* _Nonnull) exponent;
- (BOOL) exportPublicModulus:(NSMutableData* _Nonnull) modulus Exponent:(NSMutableData* _Nonnull) exponent;

- (NSData* _Nullable) exportAsn1PublicKey;
+ (NSDictionary* _Nullable) exportAsn1PrivateKey:(SecKeyRef _Nonnull) privateKey;

// 用匯出的 Asn1 Public Key 建立 Public Key
+ (SecKeyRef _Nullable) createPublicKeyFromAsn1PublicKey:(NSData* _Nonnull) dataPublicKey;
// 從 Modulus, Exponent 建立 Public Key (不會出現在 Keychain中)
+ (SecKeyRef _Nullable) createPublicKeyFromModulus:(NSData* _Nonnull) modulus Exponent:(NSData* _Nonnull) exponent;
// 用匯出的 Asn1 Public Key 得到 Modulus, Exponent
+ (BOOL) decodeAsn1PublicKey:(NSData* _Nonnull) dataPublicKey ToModulus:(NSMutableData* _Nonnull) modulus Exponent:(NSMutableData* _Nonnull) exponent;

@end

NS_ASSUME_NONNULL_END
