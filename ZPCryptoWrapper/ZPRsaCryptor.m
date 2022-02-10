//
//  ZPRsaCryptor.m
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/10.
//

#import "ZPRsaCryptor.h"
#import "ZPMessageDigest.h"

@implementation ZPRsaCryptor

#pragma mark - PKCS1 enc/dec -
// Encrypt data with public key (PKCS1): PlainData length < (KeySize/8 - 11)
//  加密完會得到 (keySize / 8) 的 data length
//  例如：Key 2048 - Encrypt PlainData must < 245 bytes；Output 256 bytes
+ (NSError*) pkcs1_encryptData:(NSData*) plainData withPublicKey:(SecKeyRef) publicKey ToCipherData:(NSMutableData*) cipherData {
    const SecKeySizes keySize = [ZPKeyPair getKeySizes:publicKey];
    const NSUInteger MaxDataSize = (keySize / 8) - 11;
    return [ZPRsaCryptor encryptData:plainData withPublicKey:publicKey Algorithm:kSecKeyAlgorithmRSAEncryptionPKCS1 MaxDataSize:MaxDataSize ToCipherData:cipherData];
}

+ (NSError*) pkcs1_decryptData:(NSData*) cipherData withPrivateKey:(SecKeyRef) privateKey ToPlainData:(NSMutableData*) plainData {
    return [ZPRsaCryptor decryptData:cipherData withPrivateKey:privateKey Algorithm:kSecKeyAlgorithmRSAEncryptionPKCS1 ToPlainData:plainData];
}

#pragma mark - OAEP enc/dec -
+ (SecKeyAlgorithm) getOaepAlgorithmFromKeySize:(SecKeySizes) keySizes {
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSAEncryptionOAEPSHA256;
    switch (keySizes) {
        case 2048: break;
        case 3072: algorithm = kSecKeyAlgorithmRSAEncryptionOAEPSHA384; break;
        case 4096: algorithm = kSecKeyAlgorithmRSAEncryptionOAEPSHA512; break;
        default: NSLog(@"Unknown Key Size = %u", keySizes); break;
    }
    return algorithm;
}

// 搭配如下 - 直接把 KeySize / 8 當作 HashLenBits
//  [Ref]https://crypto.stackexchange.com/questions/42097/what-is-the-maximum-size-of-the-plaintext-message-for-rsa-oaep
// - RSA2048 & SHA256 => 190
// - RSA3072 & SHA384 => 286
// - RSA4096 & SHA512 => 382
+ (NSUInteger) calculateOaepMaxEncryptDataSizeFromKeySize:(SecKeySizes) keySizes {
    const NSUInteger HashLenBits = keySizes / 8;
    NSUInteger maxAllowDataSize = (keySizes / 8) - (2 * HashLenBits / 8) - 2;
    NSLog(@"[OAEP] %u , maxAllowDataSize = %lu", keySizes, (unsigned long)maxAllowDataSize);
    return maxAllowDataSize;
}

//+ (NSUInteger) calculateOaepMaxEncryptDataSizeFromKeySize:(SecKeySizes) keySizes HashLenBit:(NSUInteger) HashLenBits {
//    NSUInteger maxAllowDataSize = (keySizes / 8) - (2 * HashLenBits / 8) - 2;
//    LOGD(@"[OAEP] %lu , maxAllowDataSize = %u", keySizes, maxAllowDataSize);
//    return maxAllowDataSize;
//}

+ (NSError*) oaep_encryptData:(NSData*) plainData withPublicKey:(SecKeyRef) publicKey ToCipherData:(NSMutableData*) cipherData {
    SecKeySizes keySize = [ZPKeyPair getKeySizes:publicKey];
    NSUInteger MaxDataSize = [ZPRsaCryptor calculateOaepMaxEncryptDataSizeFromKeySize:keySize];
    SecKeyAlgorithm algorithm = [ZPRsaCryptor getOaepAlgorithmFromKeySize:keySize];
    return [ZPRsaCryptor encryptData:plainData withPublicKey:publicKey Algorithm:algorithm MaxDataSize:MaxDataSize ToCipherData:cipherData];
}

+ (NSError*) oaep_decryptData:(NSData*) cipherData withPrivateKey:(SecKeyRef) privateKey ToPlainData:(NSMutableData*) plainData {
    SecKeySizes keySize = [ZPKeyPair getKeySizes:privateKey];
    NSLog(@"keySize = %u", keySize);
    SecKeyAlgorithm algorithm = [ZPRsaCryptor getOaepAlgorithmFromKeySize:keySize];
    return [ZPRsaCryptor decryptData:cipherData withPrivateKey:privateKey Algorithm:algorithm ToPlainData:plainData];
}

#pragma mark - inner enc/dec -
// maxDataSize : 每次加密最大的 size
+ (NSError*) encryptData:(NSData*) plainData withPublicKey:(SecKeyRef) publicKey Algorithm:(SecKeyAlgorithm) algorithm MaxDataSize:(NSUInteger) maxDataSize ToCipherData:(NSMutableData*) cipherData {
    NSError *err = nil;
    NSUInteger offset = 0;
    NSUInteger length = 0;
    do {
        length = MIN(plainData.length - offset, maxDataSize);
        CFErrorRef error = NULL;
        NSData* subData = [plainData subdataWithRange:NSMakeRange(offset, length)];
        CFDataRef cipherDataRef = SecKeyCreateEncryptedData(publicKey, algorithm,
                                                            (__bridge CFDataRef) subData, &error);
        if (cipherDataRef) {
            NSData* tmpData = (NSData*) CFBridgingRelease(cipherDataRef); // ARC takes ownership
            [cipherData appendData:tmpData];
        } else {
            err = CFBridgingRelease(error);  // ARC takes ownership
            NSLog(@"error = %@", err);
            [cipherData setLength:0];
            break;
        }
        offset += length;
    } while (offset < plainData.length);
    return err;
}

+ (NSError*) decryptData:(NSData*) cipherData withPrivateKey:(SecKeyRef) privateKey Algorithm:(SecKeyAlgorithm) algorithm ToPlainData:(NSMutableData*) plainData {
    NSError *err = nil;
    size_t blockSize = SecKeyGetBlockSize(privateKey);
    unsigned long segNo = cipherData.length / blockSize;
        
    for (size_t i = 0; i < segNo; i++) {
        CFErrorRef error = NULL;
        NSData *subData = [cipherData subdataWithRange:NSMakeRange(i * blockSize, blockSize)];
        CFDataRef plainDataRef = SecKeyCreateDecryptedData(privateKey, algorithm, (__bridge CFDataRef) subData, &error);
        if (plainDataRef) {
            NSData* tmpData = (NSData*) CFBridgingRelease(plainDataRef);      // ARC takes ownership
            [plainData appendData:tmpData];
            NSLog(@"%lu/%lu: %@", i+1, segNo, tmpData);
        } else {
            err = CFBridgingRelease(error);  // ARC takes ownership
            NSLog(@"error = %@", err);
            [plainData setLength:0];
            break;
        }
    }
    return err;
}

// kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256 = 先SHA取digest，再傳給 kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256 處理
+ (SecKeyAlgorithm) algorithmFromCoseAlg:(COSE_ALG) coseAlg {
    SecKeyAlgorithm secKeyAlgorithm = nil;
    switch (coseAlg) {
        case COSE_ALG_PS256: secKeyAlgorithm = kSecKeyAlgorithmRSASignatureDigestPSSSHA256; break;
        case COSE_ALG_PS384: secKeyAlgorithm = kSecKeyAlgorithmRSASignatureDigestPSSSHA384; break;
        case COSE_ALG_PS512: secKeyAlgorithm = kSecKeyAlgorithmRSASignatureDigestPSSSHA512; break;
        case COSE_ALG_RS256: secKeyAlgorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256; break;
        case COSE_ALG_RS384: secKeyAlgorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384; break;
        case COSE_ALG_RS512: secKeyAlgorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512; break;
        case COSE_ALG_RS1:   secKeyAlgorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1; break;
        default: break;
    }
    return secKeyAlgorithm;
}

+ (NSData*) digestFromMessage:(NSData*) message ByCoseAlg:(COSE_ALG) coseAlg {
    NSData* digest = nil;
    switch (coseAlg) {
        case COSE_ALG_PS256:
        case COSE_ALG_RS256: digest = [ZPMessageDigest sha256:message]; break;
        case COSE_ALG_PS384:
        case COSE_ALG_RS384: digest = [ZPMessageDigest sha384:message]; break;
        case COSE_ALG_PS512:
        case COSE_ALG_RS512: digest = [ZPMessageDigest sha512:message]; break;
        case COSE_ALG_RS1: digest = [ZPMessageDigest sha1:message]; break;
        default:break;
    }
    return digest;
}
+ (NSData*) signMessage:(NSData*) message withPrivateKey:(SecKeyRef) privateKey CoseAlgorithm:(COSE_ALG) coseAlg Error:(NSError**) pError {
    SecKeyAlgorithm secKeyAlgorithm = [ZPRsaCryptor algorithmFromCoseAlg:coseAlg];
    if (secKeyAlgorithm == nil) {
        NSLog(@"%ld SecKeyAlgorithm is nil!", coseAlg);
        return nil;
    }
    NSData* digest = [ZPRsaCryptor digestFromMessage:message ByCoseAlg:coseAlg];
    if (digest == nil) {
        NSLog(@"");
        return nil;
    }
    return [ZPRsaCryptor signDigest:digest withPrivateKey:privateKey Algorithm:secKeyAlgorithm Error:pError];
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
        NSError *err = CFBridgingRelease(error);
        NSLog(@"failed > %@", err.localizedDescription);
    }
    return signature;
}

+ (BOOL) verifySignature:(NSData *)signature withPublicKey:(SecKeyRef) publicKey CoseAlgorithm:(COSE_ALG) coseAlg Message:(NSData*) message Error:(NSError**) pError {
    SecKeyAlgorithm secKeyAlgorithm = [ZPRsaCryptor algorithmFromCoseAlg:coseAlg];
    if (secKeyAlgorithm == nil) {
        NSLog(@"secKeyAlgorithm is nil");
        *pError = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFeatureUnsupportedError userInfo:nil];
        return NO;
    }
    NSData* digest = [ZPRsaCryptor digestFromMessage:message ByCoseAlg:coseAlg];
    if (digest == nil) {
        NSLog(@"digest is nil");
        *pError = [NSError errorWithDomain:NSCocoaErrorDomain code:NSFeatureUnsupportedError userInfo:nil];
        return NO;
    }
    return [ZPRsaCryptor verifySignature:signature withPublicKey:publicKey Algorithm:secKeyAlgorithm Digest:digest Error:pError];
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
@end
