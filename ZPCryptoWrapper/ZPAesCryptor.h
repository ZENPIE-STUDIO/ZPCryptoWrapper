//
//  ZPAesCryptor.h
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/10.
//

///TODO: 更保密
/// - 不將AES Key內容從Keychain中取出
/// - Encrypt/Decrypt 使用 KeyName 來指定 AES Key

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 *  Provide AES encryption and decryption function and key management.
 *  提供 AES 加解密功能 及 金鑰管理。
 *  - Generate AES Key to NSData (bytes array).
 *  - Generate AES Key in Keychain.
 *  - AES CBC Encrypt / Decrypt
 *  - AES GCM Encrypt / Decrypt
 */
@interface ZPAesCryptor : NSObject

/**
 *  Generate AES256 Key.
 *
 *  @return AES Key (bytes array).
 */
+ (NSData* _Nullable) generateAES256Key;

/**
 *  Generate AES Key.
 *
 *  @param keySizeBytes 16, 24, kCCKeySizeAES256(32)
 *
 *  @return AES Key (bytes array).
 */
+ (NSData* _Nullable) generateKeyWithSizeBytes:(NSInteger) keySizeBytes;

#pragma mark - keychain
/**
 *  Generate AES Key.
 *
 *  @param keySizeBytes kCCKeySizeAES128(16), kCCKeySizeAES192(24), kCCKeySizeAES256(32)
 *
 *  @return AES Key (bytes array).
 */
+ (OSStatus) keychainQueryKeyWithName:(NSString*) name ExportData:(NSMutableData*) buffer;

/**
 *  Generate AES 256 Key.
 *
 *  @param name key name in keychain
 *
 *  @param buffer 會將產生的 AES Key bytes array放入buffer
 *
 *  @return AES Key (bytes array).
 */
+ (OSStatus) keychainGenerateKeyWithName:(NSString*) name ExportData:(NSMutableData*) buffer;
+ (void) keychainDeleteKeyWithName:(NSString*) name;

#pragma mark - CBC
/// AES Encrypt (CBC)
+ (NSData* _Nullable) encryptCBC:(NSData*) plainData withKey:(NSData* _Nonnull) aesKey;

/// AES Decrypt (CBC)
+ (NSData* _Nullable) decryptCBC:(NSData*) cipherData withKey:(NSData* _Nonnull) aesKey;

#pragma mark - GCM
/// Easy - AES Encrypt (GCM)，差異有：
///   + AAD = nil
///   + Tag(16bytes) 附在 CipherData 之前
+ (NSData* _Nullable) easyEncryptGCM:(NSData* _Nonnull) plainData withKey:(NSData* _Nonnull) aesKey;
/// Easy - AES Decrypt (GCM)
///   + AAD = nil
///   + Tag(16bytes) 附在 CipherData 之前
+ (NSData* _Nullable) easyDecryptGCM:(NSData* _Nonnull) cipherData withKey:(NSData* _Nonnull) aesKey;
/// AES Encrypt (GCM)
///  Additional Authenticated Data (AAD)
+ (NSData* _Nullable) encryptGCM:(NSData* _Nonnull) plainData withKey:(NSData* _Nonnull) aesKey AAD:(NSData* _Nullable) aad outTAG:(NSMutableData* _Nonnull) tagOut;

/// AES Decrypt (GCM)
+ (NSData* _Nullable) decryptGCM:(NSData* _Nonnull) cipherData withKey:(NSData* _Nonnull) aesKey AAD:(NSData* _Nullable) aad inTAG:(NSData* _Nonnull) tagIn;

@end

NS_ASSUME_NONNULL_END
