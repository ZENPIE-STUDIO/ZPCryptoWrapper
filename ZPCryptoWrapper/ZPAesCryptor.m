//
//  ZPAesCryptor.m
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/10.
//

#import "ZPAesCryptor.h"
#import <CommonCrypto/CommonCrypto.h>

// Private API
CCCryptorStatus CCCryptorGCMOneshotEncrypt(CCAlgorithm alg, const void  *key,    size_t keyLength, /* raw key material */
                                        const void  *iv,     size_t ivLength,
                                        const void  *aData,  size_t aDataLength,
                                        const void  *dataIn, size_t dataInLength,
                                        void        *cipherOut,
                                        void        *tagOut, size_t tagLength);
    
CCCryptorStatus CCCryptorGCMOneshotDecrypt(CCAlgorithm alg, const void  *key,    size_t keyLength,
                                       const void  *iv,     size_t ivLen,
                                       const void  *aData,  size_t aDataLen,
                                       const void  *dataIn, size_t dataInLength,
                                       void        *dataOut,
                                       const void  *tagIn,  size_t tagLength);

//MARK: IV
const static Byte IV16[16] = {
    (Byte)'z', (Byte)'e', (Byte)'n', (Byte)'p', (Byte)'i', (Byte)'e', (Byte)'.', (Byte)'.',
    (Byte)'s', (Byte)'t', (Byte)'u', (Byte)'d', (Byte)'i', (Byte)'o', (Byte)'.', (Byte)'.'
};


@implementation ZPAesCryptor

// AES256, 32Bytes
+ (NSData* _Nullable) generateAES256Key {
    return [ZPAesCryptor generateKeyWithSizeBytes:kCCKeySizeAES256];
}

+ (NSData* _Nullable) generateKeyWithSizeBytes:(NSInteger) keySizeBytes {
    unsigned char buf[keySizeBytes];
    int result = SecRandomCopyBytes(kSecRandomDefault, keySizeBytes, buf);
    if (result != 0) {
        NSLog(@"SecRandomCopyBytes failed");
        return nil;
    }
    NSData* data = [[NSData alloc] initWithBytes:buf length:keySizeBytes];
    return data;
}

#pragma mark - keychain
// 從 Keychain 裡面尋找
+ (OSStatus) keychainQueryKeyWithName:(NSString*) name ExportData:(NSMutableData*) buffer {
    SecKeyRef seckey = NULL;
    CFMutableDictionaryRef parameters = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(parameters, kSecClass, kSecClassKey);
    CFDictionaryAddValue(parameters, kSecAttrLabel, (__bridge const void *) name);
    OSStatus status = SecItemCopyMatching(parameters, (CFTypeRef *)&seckey);
    CFRelease(parameters);
    if (errSecSuccess != status) {
        //NSLog(@"%@",secKey);
        NSLog(@"Not found!");
        seckey = NULL;
    }
    if (seckey != NULL) {
        status = [ZPAesCryptor exportSymmetricKey:seckey ToData:buffer];
        CFRelease(seckey);
        NSLog(@"found - export : %@", buffer);
    }
    return status;
}

+ (OSStatus) keychainGenerateKeyWithName:(NSString*) name ExportData:(NSMutableData*) buffer {
    SecKeyRef seckey = NULL;
    CFErrorRef error = NULL;
    // Create the dictionary of key parameters
    CFMutableDictionaryRef parameters = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(parameters, kSecAttrKeyType, kSecAttrKeyTypeAES);
    CFDictionaryAddValue(parameters, kSecAttrKeySizeInBits, (__bridge const void *) @(kCCKeySizeAES256 * 8));
    CFDictionaryAddValue(parameters, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionaryAddValue(parameters, kSecAttrLabel, (__bridge const void *) name);
    //CFDictionaryAddValue(parameters, kSecAttrAccess, [ZPAesCryptor createSecAccess]);
    //kSecAttrKeyClassSymmetric
    // 用了就生不出來@@
    //NSString* bundleId = [[NSBundle mainBundle] bundleIdentifier]; // 加 Application Tag : 為了方便大量刪除
    //CFDictionaryAddValue(parameters, kSecAttrApplicationTag, (__bridge const void *) [bundleId dataUsingEncoding:NSUTF8StringEncoding]);
    seckey = SecKeyGenerateSymmetric(parameters, &error);
    CFRelease(parameters);
    OSStatus status = errSecSuccess;
    if (error != NULL) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"failed > %@", err.localizedDescription);
        status = (int) err.code;
    }
    
    if (seckey != NULL) {
        status = [ZPAesCryptor exportSymmetricKey:seckey ToData:buffer];
        CFRelease(seckey);
    }
    return status;
}

+ (void) keychainDeleteKeyWithName:(NSString*) name {
    CFMutableDictionaryRef parameters = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(parameters, kSecClass, kSecClassKey);
    CFDictionaryAddValue(parameters, kSecAttrLabel, (__bridge const void *) name);
    OSStatus errStatus = noErr;
    NSUInteger count = 0;
    do {
        errStatus = SecItemDelete(parameters);
        switch (errStatus) {
            case errSecItemNotFound: // (-25300)
                //NSLog(@"%@ (%lu) : NotFound", applicationTag, count);
                break;
            case noErr: NSLog(@"%@ (%lu) : OK", name, count); break;
            default: NSLog(@"%@ (%lu) : Error = %d", name, count, (int) errStatus); break;
        }
        count++;
    } while (errStatus == noErr);
    CFRelease(parameters);
}

#pragma mark - CBC
// AES Encrypt (CBC)
+ (NSData*) encryptCBC:(NSData*) plainData withKey:(NSData*) aesKey {
    return [ZPAesCryptor cbc_operation:kCCEncrypt InData:plainData withKey:aesKey];
}

// AES Decrypt (CBC)
+ (NSData*) decryptCBC:(NSData*) cipherData withKey:(NSData*) aesKey {
    return [ZPAesCryptor cbc_operation:kCCDecrypt InData:cipherData withKey:aesKey];
}
#pragma mark - GCM
// Easy - AES Encrypt (GCM)，差異有：
//   + AAD = nil
//   + Tag(16bytes) 附在 CipherData 之前
+ (NSData*) easyEncryptGCM:(NSData*) plainData withKey:(NSData*) aesKey {
    NSMutableData* tag = [NSMutableData new];
    NSData* cipherData = [ZPAesCryptor encryptGCM:plainData withKey:aesKey AAD:nil outTAG:tag];
    if (cipherData != nil) {
        [tag appendData:cipherData];
        return tag;
    }
    return nil;
}
// Easy - AES Decrypt (GCM)
//   + AAD = nil
//   + Tag(16bytes) 附在 CipherData 之前
+ (NSData*) easyDecryptGCM:(NSData*) cipherData withKey:(NSData*) aesKey {
    const NSUInteger TagLength = 16;
    if (cipherData.length < TagLength) {
        return nil;
    }
    NSData* tag = [cipherData subdataWithRange:NSMakeRange(0, TagLength)];
    NSData* realCipherData = [cipherData subdataWithRange:NSMakeRange(TagLength, cipherData.length - TagLength)];
    return [ZPAesCryptor decryptGCM:realCipherData withKey:aesKey AAD:nil inTAG:tag];
}
// AES Encrypt (GCM)
+ (NSData*) encryptGCM:(NSData*) plainData withKey:(NSData*) aesKey AAD:(NSData*) aad outTAG:(NSMutableData*) tagOut {
    size_t tagLength = kCCBlockSizeAES128; // 8 ~ 16
    Byte tagBuffer[tagLength];
    size_t bufferSize = plainData.length; // IN = OUT
    void *buffer = malloc(bufferSize);
    NSData* encData = nil;
    if (buffer != NULL) {
        const void* aadBytes = NULL;
        NSUInteger aadLength = 0;
        if (aad != nil) {
            aadBytes = aad.bytes;
            aadLength = aad.length;
        }
        CCCryptorStatus ccStatus = CCCryptorGCMOneshotEncrypt(kCCAlgorithmAES, aesKey.bytes, kCCKeySizeAES256,
                                   IV16, 16,
                                   aadBytes, aadLength,
                                   plainData.bytes, plainData.length,
                                   buffer,
                                   tagBuffer, tagLength);
        if (ccStatus == kCCSuccess) {
            [tagOut appendBytes:tagBuffer length:tagLength];
            encData = [NSData dataWithBytes:buffer length:bufferSize];
        }
        free(buffer);
    }
    return encData;
}
// AES Decrypt (GCM)
+ (NSData*) decryptGCM:(NSData*) cipherData withKey:(NSData*) aesKey AAD:(NSData*) aad inTAG:(NSData*) tagIn {
    //size_t tagLength = kCCBlockSizeAES128; // 8 ~ 16
    size_t bufferSize = cipherData.length; // IN = OUT
    void *buffer = malloc(bufferSize);
    if (buffer != NULL) {
        const void* aadBytes = NULL;
        NSUInteger aadLength = 0;
        if (aad != nil) {
            aadBytes = aad.bytes;
            aadLength = aad.length;
        }
        CCCryptorStatus ccStatus = CCCryptorGCMOneshotDecrypt(kCCAlgorithmAES, aesKey.bytes, kCCKeySizeAES256,
                                   IV16, 16,
                                   aadBytes, aadLength,
                                   cipherData.bytes, cipherData.length,
                                   buffer,
                                   tagIn.bytes, tagIn.length);
        if (ccStatus == kCCSuccess) {
            return [NSData dataWithBytesNoCopy:buffer length:bufferSize];
        }
        free(buffer);
    }
    return nil;
}
#pragma mark - Inner
// AES Encrypt (CBC)
+ (NSData*) cbc_operation:(uint32_t) operation InData:(NSData*) inData withKey:(NSData*) aesKey {
    // 'key' should be 32 bytes for AES256, will be null-padded otherwise
    if (aesKey == nil || aesKey.length != kCCKeySizeAES256) {
        NSLog(@"Wrong AES KEY");
        return nil;
    }
    NSUInteger dataLength = inData.length;
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    if (buffer != NULL) {
        size_t dataOutMoved = 0;
        CCCryptorStatus cryptStatus = CCCrypt(operation, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                                              aesKey.bytes, kCCKeySizeAES256,
                                              IV16 /* initialization vector (optional) */,
                                              inData.bytes, dataLength, /* input */
                                              buffer, bufferSize, /* output */
                                              &dataOutMoved);
        if (cryptStatus == kCCSuccess) {
            //the returned NSData takes ownership of the buffer and will free it on deallocation
            return [NSData dataWithBytesNoCopy:buffer length:dataOutMoved];
        }
        free(buffer);
    }
    return nil;
}

+ (OSStatus) exportSymmetricKey:(SecKeyRef) cryptoKey ToData:(NSMutableData*) buffer {
    SecItemImportExportKeyParameters params;
    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    params.flags = 0;
    params.passphrase = NULL;
    params.alertTitle = NULL;
    params.alertPrompt = NULL;
    params.accessRef = NULL;
    // Create and populate the key usage array
    params.keyUsage = (__bridge CFMutableArrayRef)[NSMutableArray arrayWithObjects:(id)kSecAttrCanEncrypt, kSecAttrCanDecrypt, nil];
    // Create and populate the key attributes array
    params.keyAttributes = (__bridge CFMutableArrayRef)[NSMutableArray array];
    // Set the external format and flag values appropriately
    SecExternalFormat externalFormat = kSecFormatRawKey; // Should result in the default appropriate external format for the given key.
    int flags = 0;
    // Export the CFData Key
    CFShow(cryptoKey);
    CFDataRef keyData = NULL;
    OSStatus oserr = SecItemExport(cryptoKey, externalFormat, flags, &params, &keyData);
    if (oserr == errSecSuccess) {
        NSData* data = CFBridgingRelease(keyData);
        [buffer appendData:data];
        NSLog(@"Exported Symmetric Key Data: %@", data);
    } else {
        //errSecInteractionNotAllowed
        NSLog(@"SecItemExport failed (oserr= %d)", oserr);
    }
    return oserr;
}

// 目前沒呼叫
+ (SecAccessRef) createSecAccess {
    CFErrorRef error = NULL;
    SecAccessRef accRef = SecAccessCreateWithOwnerAndACL(0, 0, 0, NULL, &error);
    NSLog(@"SecAccessCreateWithOwnerAndACL Error = %@", (__bridge NSError*) error);
    //SecAccessRef accRef;
    //OSStatus status = SecAccessCreate((__bridge CFStringRef)@"", NULL, &accRef);
    //NSLog(@"SecAccessCreate = %ld", status);
    SecKeychainPromptSelector promptSelector = 0;
    SecACLRef newACL;
    NSArray* applicationList = @[];
    OSStatus status = SecACLCreateWithSimpleContents(accRef, (__bridge CFArrayRef) applicationList, (__bridge CFStringRef)@"", promptSelector, &newACL);
    NSLog(@"SecACLCreateWithSimpleContents = %d", status);
    NSArray* array = @[(__bridge id)kSecACLAuthorizationAny];
    status = SecACLUpdateAuthorizations(newACL, (__bridge CFArrayRef) array);
    NSLog(@"SecACLUpdateAuthorizations = %d", status);
    return accRef;
}
@end
