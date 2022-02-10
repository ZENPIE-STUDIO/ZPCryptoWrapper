//
//  ZPEcKeyPair.m
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/9.
//

#import "ZPEcKeyPair.h"
#import "ZPUtils.h"
#import <Security/Security.h>
#import <Security/SecAsn1Coder.h>
#import <Security/SecAsn1Templates.h>


// EC256: 25 bytes
static const Byte kByHeaderEC256[] = {0x30, 0x59, 0x30, 0x13,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
    0x07, 0x03, 0x42};

// EC384: 22 bytes
static const Byte kByHeaderEC384[] = {0x30, 0x76, 0x30, 0x10,
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
    0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62};

// EC521: 24 bytes
static const Byte kByHeaderEC521[] = {0x30, 0x81, 0x9B, 0x30, 0x10,
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23, 0x03, 0x81, 0x86};


#pragma mark - From keyTemplates.h

// Eddie - EC Private Key
typedef struct {
    SecAsn1Item         version;        // INTEGER
    SecAsn1Item         algorithm;      // OCTETSTRING
    SecAsn1Oid          objId;          // OBJECTIDENTIFIER     OID > 1.2.840.10045.3.1.7 (prime256v1)
    SecAsn1Item         privateKey;     // BITSTRING
} EC_PrivateKey;

/* EC Private key */
const SecAsn1Template kSecAsn1ECPrivateKeyInfoTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(EC_PrivateKey) },
    { SEC_ASN1_INTEGER, offsetof(EC_PrivateKey, version) },
    { SEC_ASN1_OCTET_STRING, offsetof(EC_PrivateKey, algorithm) },
    { SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT | SEC_ASN1_CONTEXT_SPECIFIC | 0, offsetof(EC_PrivateKey, objId), kSecAsn1AnyTemplate},
    { SEC_ASN1_OPTIONAL | SEC_ASN1_CONSTRUCTED | SEC_ASN1_EXPLICIT | SEC_ASN1_CONTEXT_SPECIFIC | 1, offsetof(EC_PrivateKey, privateKey), kSecAsn1BitStringTemplate },
    { 0, }
};

// EC Public Key
typedef struct {
    SecAsn1Item     algorithm;
    SecAsn1Item     namedCurve;
} ASN1_EC_ALGORITHM_IDENTIFIER;

const SecAsn1Template kEcAlgorithmIdTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_EC_ALGORITHM_IDENTIFIER)},
    {SEC_ASN1_OBJECT_ID, offsetof(ASN1_EC_ALGORITHM_IDENTIFIER, algorithm)},
    {SEC_ASN1_OBJECT_ID, offsetof(ASN1_EC_ALGORITHM_IDENTIFIER, namedCurve)},
    {0}
};

typedef struct {
    ASN1_EC_ALGORITHM_IDENTIFIER    algorithm;
    SecAsn1Item                     publicKey;
} ASN1_EC_PUBLIC_KEY_TEMPLATE;

const SecAsn1Template kEcPublicKeyTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_EC_PUBLIC_KEY_TEMPLATE)},
    {SEC_ASN1_INLINE, offsetof(ASN1_EC_PUBLIC_KEY_TEMPLATE, algorithm), kEcAlgorithmIdTemplate},
    {SEC_ASN1_BIT_STRING , offsetof(ASN1_EC_PUBLIC_KEY_TEMPLATE, publicKey)},
    {0}
};

#pragma mark - ZPEcKeyPair
@implementation ZPEcKeyPair


- (uint32_t) getPublicKeyComponentLength {
    NSData* publicKeyRawData = [self exportPublicKey];
    uint32_t ecXYLength = 0;
    if (publicKeyRawData != nil) {
        ecXYLength = (uint32_t) ((publicKeyRawData.length - 1) / 2);
    }
    return ecXYLength;
}

- (NSUInteger) exportPublicX:(NSMutableData*) xBuf Y:(NSMutableData*) yBuf {
    NSData* publicKeyRawData = [self exportPublicKey];
    NSLog(@"publicKeyRawData = %@", publicKeyRawData);
    NSUInteger ecXYLength = 0;
    if (publicKeyRawData != nil) {
        ecXYLength = (publicKeyRawData.length - 1) / 2;
        Byte buffer[ecXYLength];
        // X
        [publicKeyRawData getBytes:buffer range:NSMakeRange(1, ecXYLength)];
        [xBuf setLength:0];
        [xBuf appendBytes:buffer length:ecXYLength];
        // Y
        [publicKeyRawData getBytes:buffer range:NSMakeRange(1 + ecXYLength, ecXYLength)];
        [yBuf setLength:0];
        [yBuf appendBytes:buffer length:ecXYLength];
    }
    return ecXYLength;
}

- (uint32_t) exportPublicKeyBufferSize:(uint32_t) bufSize X:(uint8_t*) xBuf Y:(uint8_t*) yBuf {
    NSData* publicKeyRawData = [self exportPublicKey];
    NSLog(@"publicKeyRawData = %@", publicKeyRawData);
    // 依 type 不同
    // es256 > 32
    // es384 > 48
    uint32_t ecXYLength = 0;
    if (publicKeyRawData != nil) {
        ecXYLength = (uint32_t) ((publicKeyRawData.length - 1) / 2);
        if (ecXYLength <= bufSize) {
            [publicKeyRawData getBytes:xBuf range:NSMakeRange(1, ecXYLength)];
            [publicKeyRawData getBytes:yBuf range:NSMakeRange(1 + ecXYLength, ecXYLength)];
        } else {
            // buffer to small
            NSLog(@"X, Y Buffer to small");
        }
    }
    return ecXYLength;
}

/// 產生 EC Key Pair
/// @param name Key Pair Label
/// @param keySizeInBits kSecp256r1, kSecp384r1, kSecp521r1
+ (ZPEcKeyPair*) generateWithName:(NSString*) name KeySize:(SecKeySizes) keySizeInBits {
    SecKeyRef publicKey, privateKey;
    if (![ZPKeyPair generatePublicKey:&publicKey PrivateKey:&privateKey
                          WithType:kSecAttrKeyTypeECSECPrimeRandom Name:name Size:keySizeInBits]) {
        return nil;
    }
    NSLog(@"%@, %d", name, keySizeInBits);
    return [[ZPEcKeyPair alloc] initWithName:name PublicKey:publicKey PrivateKey:privateKey];
}

+ (SecKeyRef) createPrivateKey:(NSString*) base64 KeySize:(SecKeySizes) keySizeInBits {
    SecKeyRef privateKey = NULL;
    
    NSData* asn1Data = [ZPUtils base64DecodeUrl:base64];
    NSData* keyData = [ZPEcKeyPair decodeAsn1PrivateKey:asn1Data];
    CFMutableDictionaryRef params = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (params) {
        CFDictionaryAddValue(params, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
        CFDictionaryAddValue(params, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
        CFDictionaryAddValue(params, kSecAttrKeySizeInBits, (__bridge const void *)(@(keySizeInBits)));
        CFErrorRef error = NULL;
        privateKey = SecKeyCreateWithData((__bridge CFDataRef) keyData, params, &error);
        if (error != NULL) {
            NSError *err = CFBridgingRelease(error);
            NSLog(@"failed > %@", err.localizedDescription);
        }
        CFRelease(params);
    }
    return privateKey;
}
// 256: 65bytes(含0x04)
+ (SecKeyRef) createPublicKeyWithData:(NSData*) data {
    SecKeyRef publicKey = NULL;
    NSMutableData* keyData = [NSMutableData new];
    if (data.length == 64) {
        unsigned char header[1] = {0x04};
        [keyData appendBytes:header length:1];
    }
    [keyData appendData:data];
    CFMutableDictionaryRef params = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (params) {
        CFDictionaryAddValue(params, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
        CFDictionaryAddValue(params, kSecAttrKeyClass, kSecAttrKeyClassPublic);
        CFErrorRef error = NULL;
        publicKey = SecKeyCreateWithData((__bridge CFDataRef) keyData, params, &error);
        if (error != NULL) {
            NSError *err = CFBridgingRelease(error);
            NSLog(@"failed > %@", err.localizedDescription);
        }
        CFRelease(params);
    }
    return publicKey;
}

+ (SecKeyRef) createPublicKeyWithSize:(SecKeySizes) keySizeInBits X:(NSData* _Nonnull) x Y:(NSData* _Nonnull) y {
    SecKeyRef publicKey = NULL;
    NSMutableData* keyData = [NSMutableData new];
    Byte tmpByte = 0x04; // uncompressed point
    [keyData appendBytes:&tmpByte length:1];
    [keyData appendData:x]; // X
    [keyData appendData:y]; // Y
    
    CFMutableDictionaryRef params = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (params) {
        CFDictionaryAddValue(params, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
        CFDictionaryAddValue(params, kSecAttrKeyClass, kSecAttrKeyClassPublic);
        CFDictionaryAddValue(params, kSecAttrKeySizeInBits, (__bridge const void *)(@(keySizeInBits)));
        CFErrorRef error = NULL;
        publicKey = SecKeyCreateWithData((__bridge CFDataRef) keyData, params, &error);
        if (error != NULL) {
            NSError *err = CFBridgingRelease(error);
            NSLog(@"failed > %@", err.localizedDescription);
        }
        CFRelease(params);
    }
    return publicKey;
}
// 目前只支援 kSecp256r1, 384, 521
+ (SecKeyRef) createPrivateKeyFromPEM:(NSString*) pemFilePath {
    SecKeyRef priKey = NULL;
    NSError* error = nil;
    NSString* strPemData = [NSString stringWithContentsOfFile:pemFilePath encoding:NSUTF8StringEncoding error:&error];
    if (strPemData == nil) {
        return NULL;
    }
    // 取出 Curve 的種類 (還不知道怎麼解析，因為是固定值 所以偷懶一下)
    SecKeySizes keySizes = 0;
    if (NSNotFound != [strPemData rangeOfString:@"BggqhkjOPQMBBw=="].location) {
        keySizes = kSecp256r1;  // BggqhkjOPQMBBw==  : prime256v1
    } else if (NSNotFound != [strPemData rangeOfString:@"BgUrgQQAIg=="].location) {
        keySizes = kSecp384r1;  // BgUrgQQAIg==      : secp384r1
    } else if (NSNotFound != [strPemData rangeOfString:@"BgUrgQQAIw=="].location) {
        keySizes = kSecp521r1;  // BgUrgQQAIw==      : secp521r1
    } else {
        NSLog(@"Not support!");
        return NULL;
    }
    
    // 取出 Private Key
    NSRange beginPrk = [strPemData rangeOfString:@"-----BEGIN EC PRIVATE KEY-----"];
    NSRange endPrk = [strPemData rangeOfString:@"-----END EC PRIVATE KEY-----"];
    if (beginPrk.location != NSNotFound && endPrk.location != NSNotFound) {
        NSInteger nSubStrLength = endPrk.location - (beginPrk.location + beginPrk.length);
        NSString* base64Prk = [strPemData substringWithRange:NSMakeRange(beginPrk.location + beginPrk.length, nSubStrLength)];
        base64Prk = [base64Prk stringByReplacingOccurrencesOfString:@"\r" withString:@""];
        base64Prk = [base64Prk stringByReplacingOccurrencesOfString:@"\n" withString:@""];
        NSLog(@"KeySizes = %u,  base64Prk (%ld) = %@", keySizes, base64Prk.length, base64Prk);
        priKey = [ZPEcKeyPair createPrivateKey:base64Prk KeySize:keySizes];
    }
    return priKey;
}
// Export DER (ASN.1) Format Public Key
- (NSData* _Nullable) exportAsn1PublicKey {
    NSMutableData* dataPublicKey = [NSMutableData new];
    switch (self.keySizes) {
        case kSecp256r1: [dataPublicKey appendBytes:kByHeaderEC256 length:sizeof(kByHeaderEC256)]; break;
        case kSecp384r1: [dataPublicKey appendBytes:kByHeaderEC384 length:sizeof(kByHeaderEC384)]; break;
        case kSecp521r1: [dataPublicKey appendBytes:kByHeaderEC521 length:sizeof(kByHeaderEC521)]; break;
        default:
            NSLog(@"Unknown KeySize: %u", self.keySizes);
            return NULL;
    }
    NSData* data = [self exportPublicKey];  // ANSI X9.63 format (04 || X || Y [ || K])
    // add leading zero
    const Byte LeadingZero = 0x00;
    [dataPublicKey appendBytes:&LeadingZero length:1];
    [dataPublicKey appendData:data];
    return dataPublicKey;
}
#pragma mark - ASN1 Decode
+ (NSData* _Nullable) decodeAsn1PrivateKey:(NSData*) asn1Data {
    NSMutableData* keyData = nil;
    SecAsn1CoderRef asn1Decoder = NULL;
    OSStatus status = SecAsn1CoderCreate(&asn1Decoder);
//    NSS_ECDSA_PrivateKey ecdsaPayload = { 0 };
//    status = SecAsn1Decode(asn1Decoder, asn1Data.bytes, asn1Data.length, kSecAsn1ECDSAPrivateKeyInfoTemplate, &ecdsaPayload);
    
    EC_PrivateKey payload = { 0 };
    status = SecAsn1Decode(asn1Decoder, asn1Data.bytes, asn1Data.length, kSecAsn1ECPrivateKeyInfoTemplate, &payload);
    
    if (status == errSecSuccess) {
        // 因為直接從 ECKeyPair export 的 private key size 是 97bytes (可用 SecKeyCreateWithData 產生 Private KEY)
        // Parse 完 ASN.1 後的Payload 得到的 Private Key 是 65bytes，還差32bytes
        // 剛好是
        keyData = [NSMutableData new];
        // Bit String > 65bytes = 520/8
        NSUInteger privateKeyByteLength = payload.privateKey.Length / 8;
        NSData* prkData = [NSData dataWithBytes:payload.privateKey.Data length:privateKeyByteLength];
        [keyData appendData: prkData];
        //
        NSData* algData = [NSData dataWithBytes:payload.algorithm.Data length:payload.algorithm.Length];
        [keyData appendData:algData];
        //NSLog(@"Private Key Length = %ld", privateKeyByteLength);
        //NSLog(@"Private keyData = %@", keyData);
    } else if (status == errSecDecode) {
        NSLog(@"SecAsn1Decode Failed > Unable to decode the provided data");
    } else {
        NSLog(@"SecAsn1Decode Failed > %d", status);
    }
    return keyData;
}

+ (NSData* _Nullable) decodeAsn1PublicKey:(NSData*) dataAsn1PublicKey {
    NSData* dataPubKey = nil;
    ASN1_EC_PUBLIC_KEY_TEMPLATE asn1PublicKey;
    SecAsn1CoderRef decoder = NULL;
    OSStatus status = SecAsn1CoderCreate(&decoder);
    if (decoder != NULL) {
        status = SecAsn1Decode(decoder, dataAsn1PublicKey.bytes, dataAsn1PublicKey.length, kEcPublicKeyTemplate, &asn1PublicKey);
        if (errSecSuccess == status) {
            // Bit String > 65bytes = 520/8
            size_t keyLength = asn1PublicKey.publicKey.Length / 8;
            dataPubKey = [NSData dataWithBytes:asn1PublicKey.publicKey.Data length:keyLength];
        }
        SecAsn1CoderRelease(decoder);
    }
    return dataPubKey;
}

+ (BOOL) decodeAsn1PublicKey:(NSData*) dataAsn1PublicKey ToX:(NSMutableData*) xBuf Y:(NSMutableData*) yBuf {
    BOOL succ = NO;
    NSData* dataPubKey = [ZPEcKeyPair decodeAsn1PublicKey:dataAsn1PublicKey];
    if (dataPubKey != nil) {
        size_t dataLength = dataPubKey.length;
        size_t ecKeyLen = (dataLength - 1) / 2;  // 跳過最前面的 04
        [xBuf appendBytes:[dataPubKey bytes] + 1 length:ecKeyLen];
        [yBuf appendBytes:[dataPubKey bytes] + 1 + ecKeyLen length:ecKeyLen];
        succ = YES;
    }
    return succ;
}

@end
