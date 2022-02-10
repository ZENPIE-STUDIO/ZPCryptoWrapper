//
//  ZPEcCryptor.m
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/10.
//

#import "ZPEcCryptor.h"
#import "ZPMessageDigest.h"


@implementation ZPEcCryptor

+ (ZPEcKeyPair*) generateKeyPair:(NSString*) name KeySize:(SecKeySizes) keySizeInBits {
    return [ZPEcCryptor generateKeyPair:name KeySize:keySizeInBits Overwrite:NO];
}

+ (ZPEcKeyPair*) generateKeyPair:(NSString*) name KeySize:(SecKeySizes) keySizeInBits Overwrite:(BOOL) overwrite {
    if (overwrite) {
        // 有同名的要先刪除
        ZPEcKeyPair* oldKeyPair = [ZPEcKeyPair getInstanceFromKeychain:name];
        if (oldKeyPair != nil) {
            [oldKeyPair deleteFromKeychain];
        }
    }
    return [ZPEcKeyPair generateWithName:name KeySize:keySizeInBits];
}

+ (SecKeyAlgorithm) algorithmFromCoseAlg:(COSE_ALG) coseAlg {
    SecKeyAlgorithm secKeyAlgorithm = nil;
    // 要sign的內容是 Message，用這個
//    switch (coseAlg) {
//        case COSE_ALG_ES256: secKeyAlgorithm = kSecKeyAlgorithmECDSASignatureMessageX962SHA256; break;
//        case COSE_ALG_ES384: secKeyAlgorithm = kSecKeyAlgorithmECDSASignatureMessageX962SHA384; break;
//        case COSE_ALG_ES512: secKeyAlgorithm = kSecKeyAlgorithmECDSASignatureMessageX962SHA512; break;
//        default: break;
//    }
    // 要sign的內容是 digest，用這個
    switch (coseAlg) {
        case COSE_ALG_ES256: secKeyAlgorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA256; break;
        case COSE_ALG_ES384: secKeyAlgorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA384; break;
        case COSE_ALG_ES512: secKeyAlgorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA512; break;
        default: break;
    }
    return secKeyAlgorithm;
}

+ (NSData*) digestFromMessage:(NSData*) message ByCoseAlg:(COSE_ALG) coseAlg {
    NSData* digest = nil;
    switch (coseAlg) {
        case COSE_ALG_ES256: digest = [ZPMessageDigest sha256:message]; break;
        case COSE_ALG_ES384: digest = [ZPMessageDigest sha384:message]; break;
        case COSE_ALG_ES512: digest = [ZPMessageDigest sha512:message]; break;
        default:break;
    }
    return digest;
}

+ (NSData*) signMessage:(NSData*) message withPrivateKey:(SecKeyRef) privateKey CoseAlgorithm:(COSE_ALG) coseAlg Error:(NSError**) pError {
    SecKeyAlgorithm secKeyAlgorithm = [ZPEcCryptor algorithmFromCoseAlg:coseAlg];
    if (secKeyAlgorithm == nil) {
        NSLog(@"%ld SecKeyAlgorithm is nil!", coseAlg);
        return nil;
    }
    NSData* digest = [ZPEcCryptor digestFromMessage:message ByCoseAlg:coseAlg];
    if (digest == nil) {
        NSLog(@"");
        return nil;
    }
    return [ZPEcCryptor signDigest:digest withPrivateKey:privateKey Algorithm:secKeyAlgorithm Error:pError];
}

+ (NSData*) signDigest:(NSData*) digest withPrivateKey:(SecKeyRef) privateKey Algorithm:(SecKeyAlgorithm) algorithm Error:(NSError**) pError {
    if (!SecKeyIsAlgorithmSupported(privateKey, kSecKeyOperationTypeSign, algorithm)) {
        NSLog(@"%@ : NO SUPPORT!", algorithm);
        *pError = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFeatureUnsupportedError userInfo:nil];
        return nil;
    }
    NSData* signature = nil;
    CFErrorRef error = NULL;
    CFDataRef signatureData = SecKeyCreateSignature(privateKey, algorithm, (__bridge CFDataRef) digest, &error);
    if (signatureData != NULL) {
        signature = (__bridge NSData*) signatureData;
    } else {
        *pError = CFBridgingRelease(error);
        NSLog(@"failed > %@", (*pError).localizedDescription);
    }
    return signature;
}

+ (BOOL) verifySignature:(NSData *)signature withPublicKey:(SecKeyRef) publicKey CoseAlgorithm:(COSE_ALG) coseAlg Message:(NSData*) message Error:(NSError**) pError {
    SecKeyAlgorithm secKeyAlgorithm = [ZPEcCryptor algorithmFromCoseAlg:coseAlg];
    if (secKeyAlgorithm == nil) {
        NSLog(@"%ld SecKeyAlgorithm is nil!", coseAlg);
        *pError = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFeatureUnsupportedError userInfo:nil];
        return NO;
    }
    NSData* digest = [ZPEcCryptor digestFromMessage:message ByCoseAlg:coseAlg];
    if (digest == nil) {
        NSLog(@"digest is nil");
        *pError = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFeatureUnsupportedError userInfo:nil];
        return NO;
    }
    return [ZPEcCryptor verifySignature:signature withPublicKey:publicKey Algorithm:secKeyAlgorithm Digest:digest Error:pError];
}

+ (BOOL) verifySignature:(NSData*) signature withPublicKey:(SecKeyRef) publicKey Algorithm:(SecKeyAlgorithm) algorithm Digest:(NSData*) digest Error:(NSError**) pError {
    if (!SecKeyIsAlgorithmSupported(publicKey, kSecKeyOperationTypeVerify, algorithm)) {
        NSLog(@"%@ : NO SUPPORT!", algorithm);
        *pError = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFeatureUnsupportedError userInfo:nil];
        return NO;
    }
    CFErrorRef error = NULL;
    Boolean ret = SecKeyVerifySignature(publicKey, algorithm, (__bridge CFDataRef) digest, (__bridge CFDataRef) signature, &error);
    if (!ret) {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"failed > %@", err.localizedDescription);
        *pError = err;
        return NO;
    }
    return YES;
}
// ECDH - calculate Shared Secret，目前是指定輸出 32 bytes (For AES)
+ (NSData*) sharedSecretForPrivateKey:(SecKeyRef) privateKey PublicKey:(SecKeyRef) publicKey {
    //const NSInteger kRequestedSize = 32;
    const SecKeyAlgorithm algorithm = kSecKeyAlgorithmECDHKeyExchangeStandard;
    CFErrorRef error = nil;
    CFMutableDictionaryRef params = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDataRef exDataRef = SecKeyCopyKeyExchangeResult(privateKey, algorithm, publicKey, params, &error);
    NSData* exData = nil;
    if (exDataRef != nil) {
        exData = (__bridge NSData*) exDataRef;
    } else {
        NSError *err = CFBridgingRelease(error);
        NSLog(@"failed > %@", err.localizedDescription);
    }
    CFRelease(params);
    return exData;
}

@end
