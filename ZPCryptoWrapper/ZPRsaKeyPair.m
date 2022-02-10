//
//  ZPRsaKeyPair.m
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/9.
//

#import "ZPRsaKeyPair.h"
#import "ZPUtils.h"
#import "ZPMessageDigest.h"
#import <Security/SecAsn1Coder.h>
#import <Security/SecAsn1Templates.h>
#import <Security/SecAsn1Types.h>

// RSA Private Key
typedef struct {
    SecAsn1Item version;
    SecAsn1Item modulus;
    SecAsn1Item publicExponent;
    SecAsn1Item privateExponent;
    SecAsn1Item prime1;
    SecAsn1Item prime2;
    SecAsn1Item exponent1;
    SecAsn1Item exponent2;
    SecAsn1Item coefficient;
} ASN1_RSA_PRIVATE_KEY;

const SecAsn1Template kRsaPrivateKeyTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_RSA_PRIVATE_KEY) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, version) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, modulus) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, publicExponent) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, privateExponent) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, prime1) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, prime2) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, exponent1) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, exponent2) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, coefficient) },
    { 0 },
};
// RSA Public Key
typedef struct {
    SecAsn1Item modulus;
    SecAsn1Item publicExponent;
} ASN1_RSA_PUBLIC_KEY;

const SecAsn1Template kRsaPublicKeyTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_RSA_PUBLIC_KEY) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PUBLIC_KEY, modulus) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PUBLIC_KEY, publicExponent) },
    { 0 },
};
//typedef struct {
//    SecAsn1Oid algorithm;
//    SecAsn1Item parameters;
//} SecAsn1AlgId;
/* AlgorithmIdentifier : SecAsn1AlgId */
const SecAsn1Template kSecAsn1AlgorithmIDTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(SecAsn1AlgId) },
    { SEC_ASN1_OBJECT_ID, offsetof(SecAsn1AlgId, algorithm), },
    { SEC_ASN1_OPTIONAL | SEC_ASN1_ANY, offsetof(SecAsn1AlgId, parameters), },
    { 0, }
};

//typedef struct {
//    SecAsn1AlgId algorithm;
//    SecAsn1Item subjectPublicKey;
//} SecAsn1PubKeyInfo;
const SecAsn1Template kSubjectPublicKeyInfoTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(SecAsn1PubKeyInfo) },
    { SEC_ASN1_INLINE, offsetof(SecAsn1PubKeyInfo, algorithm), kSecAsn1AlgorithmIDTemplate },
    { SEC_ASN1_BIT_STRING, offsetof(SecAsn1PubKeyInfo, subjectPublicKey), kRsaPublicKeyTemplate },
    { 0 }
};

@implementation ZPRsaKeyPair

/// 產生 RSA Key Pair
/// @param name Key Pair Label
/// @param keySizeInBits
/// RSA keysizes must be multiples of 8, kSecRSAMin = 1024, kSecRSAMax = 4096
+ (ZPRsaKeyPair*) generateWithName:(NSString*) name KeySize:(SecKeySizes) keySizeInBits {
    // create dict which actually saves key into keychain
    if (keySizeInBits < kSecRSAMin || keySizeInBits > kSecRSAMax || keySizeInBits % 8) {
        NSLog(@"keySize error : %d", keySizeInBits);
        return nil;
    }
    SecKeyRef publicKey, privateKey;
    if (![ZPKeyPair generatePublicKey:&publicKey PrivateKey:&privateKey
                          WithType:kSecAttrKeyTypeRSA Name:name Size:keySizeInBits]) {
        return nil;
    }
    NSLog(@"%@, %d", name, keySizeInBits);
    return [[ZPRsaKeyPair alloc] initWithName:name PublicKey:publicKey PrivateKey:privateKey];
}

+ (SecKeyRef) createPrivateKeyFromPKCS1:(NSString*) base64 KeySize:(SecKeySizes) keySizeInBits {
    if (keySizeInBits < kSecRSAMin || keySizeInBits > kSecRSAMax || keySizeInBits % 8) {
        NSLog(@"keySize error : %d", keySizeInBits);
        return nil;
    }
    SecKeyRef privateKey = NULL;
    NSData* keyData = [ZPUtils base64DecodeUrl:base64];
    CFMutableDictionaryRef params = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (params) {
        CFDictionaryAddValue(params, kSecAttrKeyType, kSecAttrKeyTypeRSA); // PKCS1
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

//// ConvertCoseToBlob
//+ (NSData*) convertCoseToBlob:(NSData*) dataCose {
//    // 解析 CBOR
//    return nil;
//}
+ (BOOL) exportPublicKey:(SecKeyRef) publicKey ToModulus:(NSMutableData* _Nonnull) modulus Exponent:(NSMutableData* _Nonnull) exponent {
    if (publicKey == nil) {
        return NO;
    }
    CFErrorRef error = nil;
    CFDataRef cfKeyData = SecKeyCopyExternalRepresentation(publicKey, &error);
    if (cfKeyData == NULL) {
        return NO;
    }
    // ----
    BOOL succ = NO;
    SecAsn1CoderRef coder = NULL;
    SecAsn1CoderCreate(&coder);
    if (coder != NULL) {
        ASN1_RSA_PUBLIC_KEY asn1PublicKey;
        OSStatus status = SecAsn1Decode(coder,
                                        CFDataGetBytePtr(cfKeyData),
                                        CFDataGetLength(cfKeyData),
                                        kRsaPublicKeyTemplate,
                                        &asn1PublicKey);
        if (errSecSuccess == status) {
            [exponent appendBytes:asn1PublicKey.publicExponent.Data length:asn1PublicKey.publicExponent.Length];
            [modulus appendBytes:asn1PublicKey.modulus.Data length:asn1PublicKey.modulus.Length];
            succ = YES;
        }
        SecAsn1CoderRelease(coder);
    }
    return succ;
}

- (BOOL) exportPublicModulus:(NSMutableData* _Nonnull) modulus Exponent:(NSMutableData* _Nonnull) exponent {
    return [ZPRsaKeyPair exportPublicKey:self.publicKey ToModulus:modulus Exponent:exponent];
}

- (NSData*) exportAsn1PublicKey {
    NSData* dataPublicKey = nil;
    NSMutableData* exponent = [NSMutableData new];
    NSMutableData* modulus = [NSMutableData new];
    if ([self exportPublicModulus:modulus Exponent:exponent]) {
        ASN1_RSA_PUBLIC_KEY asn1RsaPubKey;
        asn1RsaPubKey.modulus.Length = modulus.length;
        asn1RsaPubKey.modulus.Data = (uint8_t*) [modulus bytes];
        asn1RsaPubKey.publicExponent.Length = exponent.length;
        asn1RsaPubKey.publicExponent.Data = (uint8_t*) [exponent bytes];
        
        SecAsn1Item asn1ItemPubKey;
        SecAsn1CoderRef coder = NULL;
        SecAsn1CoderCreate(&coder);
        if (coder != NULL) {
            OSStatus status = SecAsn1EncodeItem(coder, &asn1RsaPubKey, kRsaPublicKeyTemplate, &asn1ItemPubKey);
            if (status == errSecSuccess) {
                dataPublicKey = [NSData dataWithBytes:asn1ItemPubKey.Data length:asn1ItemPubKey.Length];
            }
            SecAsn1CoderRelease(coder);
        }
    }
    return dataPublicKey;
}

+ (NSData*) dataFromSecAsn1Item:(SecAsn1Item*) item {
    return [NSData dataWithBytes:item->Data length:item->Length];
}

+ (NSDictionary*) exportAsn1PrivateKey:(SecKeyRef) privateKey {
    CFErrorRef error = nil;
    CFDataRef cfKeyData = SecKeyCopyExternalRepresentation(privateKey, &error);
    if (cfKeyData == NULL) {
        return nil;
    }
    NSMutableDictionary* privateKeyDict = nil;
    ASN1_RSA_PRIVATE_KEY asn1PrivateKey;
    SecAsn1CoderRef coder = NULL;
    SecAsn1CoderCreate(&coder);
    if (coder) {
        OSStatus status = SecAsn1Decode(coder,
                                        CFDataGetBytePtr(cfKeyData),
                                        CFDataGetLength(cfKeyData),
                                        kRsaPrivateKeyTemplate,
                                        &asn1PrivateKey);
        if (status == errSecSuccess) {
            //privateKeyDict
            privateKeyDict = [NSMutableDictionary new];
            //NSData* version = [RSAKeyPair dataFromSecAsn1Item:&(asn1PrivateKey.version)];
            //NSLog(@"version = %@", version);
            privateKeyDict[@"modulus"] = [ZPRsaKeyPair dataFromSecAsn1Item:&(asn1PrivateKey.modulus)];
            privateKeyDict[@"publicExponent"] = [ZPRsaKeyPair dataFromSecAsn1Item:&(asn1PrivateKey.publicExponent)];
            privateKeyDict[@"privateExponent"] = [ZPRsaKeyPair dataFromSecAsn1Item:&(asn1PrivateKey.privateExponent)];
            privateKeyDict[@"prime1"] = [ZPRsaKeyPair dataFromSecAsn1Item:&(asn1PrivateKey.prime1)];
            privateKeyDict[@"prime2"] = [ZPRsaKeyPair dataFromSecAsn1Item:&(asn1PrivateKey.prime2)];
            privateKeyDict[@"exponent1"] = [ZPRsaKeyPair dataFromSecAsn1Item:&(asn1PrivateKey.exponent1)];
            privateKeyDict[@"exponent2"] = [ZPRsaKeyPair dataFromSecAsn1Item:&(asn1PrivateKey.exponent2)];
            privateKeyDict[@"coefficient"] = [ZPRsaKeyPair dataFromSecAsn1Item:&(asn1PrivateKey.coefficient)];
        }
    }
    return privateKeyDict;
}


+ (SecKeyRef) createPublicKeyFromAsn1PublicKey:(NSData*) dataPublicKey {
    NSMutableData* modulus = [NSMutableData new];
    NSMutableData* exponent = [NSMutableData new];
    if ([ZPRsaKeyPair decodeAsn1PublicKey:dataPublicKey ToModulus:modulus Exponent:exponent]) {
        return [ZPRsaKeyPair createPublicKeyFromModulus:modulus Exponent:exponent];
    }
    return NULL;
}

+ (SecKeyRef) createPublicKeyFromModulus:(NSData* _Nonnull) modulus Exponent:(NSData* _Nonnull) exponent {
    SecKeyRef publicKey = NULL;

    SecKeySizes keySizeInBits = (SecKeySizes) modulus.length * 8;
    Byte tmpValue;
    NSMutableData* modulusX = [NSMutableData new];
    tmpValue = 0x00;    // Prefix 0x00
    [modulusX appendBytes:&tmpValue length:1];
    [modulusX appendData:modulus];
    // Modulus
    NSMutableData* modulusEncoded = [NSMutableData new];
    tmpValue = 0x02;    // INTEGER
    [modulusEncoded appendBytes:&tmpValue length:1];
    NSData* lengthModulus = [ZPRsaKeyPair newLengthByteArrayFromData:modulusX];
    [modulusEncoded appendData:lengthModulus];
    [modulusEncoded appendData:modulusX];
    
    // Exponent
    NSMutableData* exponentEncoded = [NSMutableData new];
    tmpValue = 0x02;    // INTEGER
    [exponentEncoded appendBytes:&tmpValue length:1];
    NSData* lengthExponent = [ZPRsaKeyPair newLengthByteArrayFromData:exponent];
    [exponentEncoded appendData:lengthExponent];
    [exponentEncoded appendData:exponent];
    
    // 先把 modulus + exponent
    [modulusEncoded appendData:exponentEncoded];
    // Sequence
    NSMutableData* sequenceEncoded = [NSMutableData new];
    tmpValue = 0x30;
    [sequenceEncoded appendBytes:&tmpValue length:1];
    NSData* lengthMandE = [ZPRsaKeyPair newLengthByteArrayFromData:modulusEncoded];
    [sequenceEncoded appendData:lengthMandE];
    [sequenceEncoded appendData:modulusEncoded];
    
    CFMutableDictionaryRef params = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (params) {
        CFDictionaryAddValue(params, kSecAttrKeyType, kSecAttrKeyTypeRSA); // PKCS1
        CFDictionaryAddValue(params, kSecAttrKeyClass, kSecAttrKeyClassPublic);
        CFDictionaryAddValue(params, kSecAttrKeySizeInBits, (__bridge const void *)(@(keySizeInBits)));
        CFErrorRef error = NULL;
        publicKey = SecKeyCreateWithData((__bridge CFDataRef) sequenceEncoded, params, &error);
        if (error != NULL) {
            NSError *err = CFBridgingRelease(error);
            NSLog(@"failed > %@", err.localizedDescription);
        }
        CFRelease(params);
    }
    return publicKey;
}

+ (BOOL) decodeAsn1PublicKey:(NSData*) dataPublicKey ToModulus:(NSMutableData* _Nonnull) modulus Exponent:(NSMutableData* _Nonnull) exponent {
    BOOL succ = NO;
    ASN1_RSA_PUBLIC_KEY asn1PublicKey;
    SecAsn1CoderRef decoder = NULL;
    OSStatus status = SecAsn1CoderCreate(&decoder);
    if (decoder != NULL) {
        status = SecAsn1Decode(decoder, dataPublicKey.bytes, dataPublicKey.length, kRsaPublicKeyTemplate, &asn1PublicKey);
        if (errSecSuccess == status) {
            [modulus appendBytes:asn1PublicKey.modulus.Data length:asn1PublicKey.modulus.Length];
            [exponent appendBytes:asn1PublicKey.publicExponent.Data length:asn1PublicKey.publicExponent.Length];
            succ = YES;
        }
        SecAsn1CoderRelease(decoder);
    }
    return succ;
}

// 用來計算 DER 長度
+ (NSData*) newLengthByteArrayFromData:(NSData*) data {
    NSMutableData* lenArray = [NSMutableData new];
    NSUInteger count = data.length;
    uint8_t tmpValue = 0;
    if (count < 128) {
        tmpValue = (uint8_t) count;
        [lenArray appendBytes:&tmpValue length:1];
        return lenArray;
    }
    // The number of bytes needed to encode count.
    NSInteger lengthBytesCount = (NSInteger) (log2((double)count) / 8) + 1;

    // The first byte in the length field encoding the number of remaining bytes.
    uint8_t firstLengthFieldByte = (uint8_t) (128 + lengthBytesCount);

    for (NSInteger i = 0; i < lengthBytesCount; i++) {
        // Take the last 8 bits of count.
        tmpValue = (uint8_t)(count & 0xff);
        // Add them to the length field.
        [lenArray replaceBytesInRange:NSMakeRange(0, 0) withBytes:&tmpValue length:1];
        // Delete the last 8 bits of count.
        count = count >> 8;
    }
    // Include the first byte.
    [lenArray replaceBytesInRange:NSMakeRange(0, 0) withBytes:&firstLengthFieldByte length:1];
    return lenArray;
}
@end
