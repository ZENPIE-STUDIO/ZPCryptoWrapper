//
//  ZPAesCryptor.h
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/10.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
// Use AES256
@interface ZPAesCryptor : NSObject

+ (NSData* _Nullable) generateAES256Key;
+ (NSData* _Nullable) generateKeyWithSizeBytes:(NSInteger) keySizeBytes;

#pragma mark - keychain
+ (OSStatus) keychainQueryKeyWithName:(NSString*) name ExportData:(NSMutableData*) buffer;
// Use Key Size = AES256
+ (OSStatus) keychainGenerateKeyWithName:(NSString*) name ExportData:(NSMutableData*) buffer;
+ (void) keychainDeleteKeyWithName:(NSString*) name;

#pragma mark - CBC
// AES Encrypt (CBC)
+ (NSData* _Nullable) encryptCBC:(NSData*) plainData withKey:(NSData* _Nonnull) aesKey;

// AES Decrypt (CBC)
+ (NSData* _Nullable) decryptCBC:(NSData*) cipherData withKey:(NSData* _Nonnull) aesKey;

#pragma mark - GCM
// Easy - AES Encrypt (GCM)，差異有：
//   + AAD = nil
//   + Tag(16bytes) 附在 CipherData 之前
+ (NSData* _Nullable) easyEncryptGCM:(NSData* _Nonnull) plainData withKey:(NSData* _Nonnull) aesKey;
// Easy - AES Decrypt (GCM)
//   + AAD = nil
//   + Tag(16bytes) 附在 CipherData 之前
+ (NSData* _Nullable) easyDecryptGCM:(NSData* _Nonnull) cipherData withKey:(NSData* _Nonnull) aesKey;
// AES Encrypt (GCM)
//  Additional Authenticated Data (AAD)
+ (NSData* _Nullable) encryptGCM:(NSData* _Nonnull) plainData withKey:(NSData* _Nonnull) aesKey AAD:(NSData* _Nullable) aad outTAG:(NSMutableData* _Nonnull) tagOut;

// AES Decrypt (GCM)
+ (NSData* _Nullable) decryptGCM:(NSData* _Nonnull) cipherData withKey:(NSData* _Nonnull) aesKey AAD:(NSData* _Nullable) aad inTAG:(NSData* _Nonnull) tagIn;

@end

NS_ASSUME_NONNULL_END
