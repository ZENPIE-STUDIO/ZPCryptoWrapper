//
//  ZPCryptoWrapperTests.m
//  ZPCryptoWrapperTests
//
//  Created by EddieHua on 2022/2/9.
//

#import <XCTest/XCTest.h>
#import "ZPUtils.h"
#import "ZPMessageDigest.h"
#import "ZPKeyPair.h"
#import "ZPRsaKeyPair.h"
#import "ZPEcKeyPair.h"
#import "ZPRsaCryptor.h"
#import "ZPEcCryptor.h"
#import "ZPAesCryptor.h"

@interface ZPCryptoWrapperTests : XCTestCase

@end

@implementation ZPCryptoWrapperTests

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
        //[self testEC];
    }];
}

- (void) testBase64 {
    NSString* base64urlAnswer = @"aHR0cHM6Ly9jcnlwdGlpLmNvbS8";
    NSString* base64Answer =    @"aHR0cHM6Ly9jcnlwdGlpLmNvbS8=";
    NSData* data = [ZPUtils dataFromUtf8String:@"https://cryptii.com/"];
    NSString* base64 = [ZPUtils base64Encode:data]; // Encode
    NSLog(@"Base64 = %@", base64);
    XCTAssertEqualObjects(base64Answer, base64);
    NSData* dataChk = [ZPUtils base64Decode:base64];
    XCTAssertEqualObjects(data, dataChk);
    
    // base64 url
    NSString* base64url = [ZPUtils base64EncodeUrl:data];
    XCTAssertEqualObjects(base64urlAnswer, base64url);
    NSData* dataUrlChk = [ZPUtils base64DecodeUrl:base64url];
    XCTAssertEqualObjects(data, dataUrlChk);
}

- (void) testMessageDigest {
    // SHA1
    NSData* dataSha1Answer = [ZPUtils dataFromHexString:@"01b307acba4f54f55aafc33bb06bbbf6ca803e9a"];
    NSData* dataSha1Result = [ZPMessageDigest sha1msg:@"1234567890"];
    XCTAssertEqualObjects(dataSha1Answer, dataSha1Result);
    // SHA256
    NSData* dataSha256Answer = [ZPUtils dataFromHexString:@"c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646"];
    NSData* dataSha256Result = [ZPMessageDigest sha256msg:@"1234567890"];
    XCTAssertEqualObjects(dataSha256Answer, dataSha256Result);
    // SHA384
    NSData* dataSha384Answer = [ZPUtils dataFromHexString:@"ed845f8b4f2a6d5da86a3bec90352d916d6a66e3420d720e16439adf238f129182c8c64fc4ec8c1e6506bc2b4888baf9"];
    NSData* dataSha384Result = [ZPMessageDigest sha384msg:@"1234567890"];
    XCTAssertEqualObjects(dataSha384Answer, dataSha384Result);
    // SHA512
    NSData* dataSha512Answer = [ZPUtils dataFromHexString:@"12b03226a6d8be9c6e8cd5e55dc6c7920caaa39df14aab92d5e3ea9340d1c8a4d3d0b8e4314f1f6ef131ba4bf1ceb9186ab87c801af0d5c95b1befb8cedae2b9"];
    NSData* dataSha512Result = [ZPMessageDigest sha512msg:@"1234567890"];
    XCTAssertEqualObjects(dataSha512Answer, dataSha512Result);
}


static const NSString* kPlainText = @"1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";

- (void) testRSA {
    ZPRsaKeyPair* rsaKeyPair = [ZPRsaKeyPair generateWithName:@"testCryptoRSA" KeySize:2048];
    XCTAssertNotNil(rsaKeyPair);
    if (rsaKeyPair == nil) {
        return;
    }
    // PKCS1 Encrypt / Decrypt
    NSData* plainData = [kPlainText dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData* cipherData = [NSMutableData new];
    NSMutableData* decryptedData = [NSMutableData new];
    NSError* encError = [ZPRsaCryptor pkcs1_encryptData:plainData withPublicKey:rsaKeyPair.publicKey ToCipherData:cipherData];
    NSLog(@"pkcs1_encryptData error = %@", encError);
    NSLog(@"pkcs1_encryptData = %@", cipherData);
    // -----
    NSError* decError = [ZPRsaCryptor pkcs1_decryptData:cipherData withPrivateKey:rsaKeyPair.privateKey ToPlainData:decryptedData];
    NSLog(@"pkcs1_decryptData error = %@", decError);
    NSString* chkPlainText = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    NSLog(@"plainText = %@", kPlainText);
    NSLog(@"pkcs1 Chk PlainText = %@", chkPlainText);
    NSAssert([chkPlainText isEqualToString:kPlainText], @"PKCS1 Enc/Dec Failed!");
    // OAEP Encrypt / Decrypt
    NSMutableData* oaepCipherData = [NSMutableData new];
    NSMutableData* oaepDecryptedData = [NSMutableData new];
    NSError* oaepEncError = [ZPRsaCryptor oaep_encryptData:plainData withPublicKey:rsaKeyPair.publicKey ToCipherData:oaepCipherData];
    NSLog(@"oaep_encryptData error = %@", oaepEncError);
    NSError* oaepDecError = [ZPRsaCryptor oaep_decryptData:oaepCipherData withPrivateKey:rsaKeyPair.privateKey ToPlainData:oaepDecryptedData];
    NSLog(@"oaep_decryptData error = %@", oaepDecError);
    NSString* chkOaepPlainText = [[NSString alloc] initWithData:oaepDecryptedData encoding:NSUTF8StringEncoding];
    NSLog(@"Oaep Chk PlainText = %@", chkOaepPlainText);
    NSAssert([chkOaepPlainText isEqualToString:kPlainText], @"OAEP Enc/Dec Failed!");
    
    // ----------- Test Sign/Verify ----------
    //SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256;
    //NSData* shaPlainData = [Digest getSHA256:plainData];
    NSError* error = nil;
    COSE_ALG coseAlg = COSE_ALG_RS256;
    
    NSData* signature = [ZPRsaCryptor signMessage:plainData withPrivateKey:rsaKeyPair.privateKey CoseAlgorithm:coseAlg Error:&error];
    if (signature != nil) {
        NSError* verifyError = nil;
        BOOL isVerifyOK = [ZPRsaCryptor verifySignature:signature withPublicKey:rsaKeyPair.publicKey CoseAlgorithm:coseAlg Message:plainData Error:&verifyError];
        if (isVerifyOK) {
            NSLog(@"Verify ✅");
        } else {
            NSLog(@"Verify ❌");
        }
    }
    // ---
    NSMutableData* exponent = [NSMutableData new];
    NSMutableData* modulus = [NSMutableData new];
    [rsaKeyPair exportPublicModulus:modulus Exponent:exponent];
    NSLog(@"exponent = %@", exponent);
    NSLog(@"modulus = %@", modulus);
    NSData* asn1Data = [rsaKeyPair exportAsn1PublicKey];
    if (asn1Data != nil) {
        NSMutableData* exponent2 = [NSMutableData new];
        NSMutableData* modulus2 = [NSMutableData new];
        [ZPRsaKeyPair decodeAsn1PublicKey:asn1Data ToModulus:modulus2 Exponent:exponent2];
        NSLog(@"exponent2 = %@", exponent2);
        NSLog(@"modulus2 = %@", modulus2);
    }
    [rsaKeyPair deleteFromKeychain];
}

- (void) testEC {
    const SecKeySizes ecKeySize = kSecp256r1;
    ZPEcKeyPair* ecKeyPair = [ZPEcKeyPair generateWithName:@"tmpEcKeyPair" KeySize:ecKeySize];
    
    XCTAssertNotNil(ecKeyPair);
    if (ecKeyPair == nil) {
        return;
    }
    NSError* err = nil;
    NSData* plainData = [ZPUtils dataFromUtf8String:kPlainText];
    NSData* dataSign = [ZPEcCryptor signMessage:plainData withPrivateKey:ecKeyPair.privateKey CoseAlgorithm:COSE_ALG_ES256 Error:&err];
    if (err != nil) {
        NSLog(@"EC Signature Error = %@", err);
    } else {
        NSLog(@"EC Signature %lu > %@", dataSign.length, [ZPUtils debugHexStringFromData:dataSign]);
        NSError* verifyErr = nil;
        if ([ZPEcCryptor verifySignature:dataSign withPublicKey:ecKeyPair.publicKey CoseAlgorithm:COSE_ALG_ES256 Message:plainData Error:&verifyErr]) {
            NSLog(@"ES256 Verify Signature OK");
        } else {
            NSLog(@"ES256 Verify Signature Error : %@", verifyErr);
        }
    }
    // ---- TEST ECDH ----
    ZPEcKeyPair* keyPairEcdh = [ZPEcKeyPair generateWithName:@"tmpEcdh" KeySize:ecKeySize];
    if (keyPairEcdh != nil) {
        NSData* ex1 = [ZPEcCryptor sharedSecretForPrivateKey:keyPairEcdh.privateKey PublicKey:ecKeyPair.publicKey];
        NSData* ex2 = [ZPEcCryptor sharedSecretForPrivateKey:ecKeyPair.privateKey PublicKey:keyPairEcdh.publicKey];
        NSLog(@"Key Ex1 : %@", ex1);
        NSLog(@"Key Ex2 : %@", ex2);
        if ([ex1 isEqualToData:ex2]) {
            NSLog(@"ECDH ✅");
        } else {
            NSLog(@"ECDH ❌");
        }
        [keyPairEcdh deleteFromKeychain];
    }
    [ecKeyPair deleteFromKeychain];
}

- (void) testAES {
    NSString* plainText = @"abcde12345edcba54321abcde12345edcba54321";
    NSData* plainData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    NSString* testAESname = @"testAESkey";
    NSMutableData* aesKey = [NSMutableData new];
    if (0 != [ZPAesCryptor keychainGenerateKeyWithName:testAESname ExportData:aesKey]) {
        [ZPAesCryptor keychainGenerateKeyWithName:testAESname ExportData:aesKey];
    }
    NSMutableData* tag = [NSMutableData new];
    NSData* cipherData = [ZPAesCryptor encryptGCM:plainData withKey:aesKey AAD:nil outTAG:tag];
    NSLog(@"tag = %@", tag);
    NSData* decryptedData = [ZPAesCryptor decryptGCM:cipherData withKey:aesKey AAD:nil inTAG:tag];
    NSString* decryptdText = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    NSLog(@"decryptdText = %@", decryptdText);
    NSAssert([decryptdText isEqualToString:plainText], @"AES GCM Failed!");
    
    // Test Wrong Tag
    NSData* wrongTag = [ZPAesCryptor generateAES256Key];
    NSData* wrongDecryptedData = [ZPAesCryptor decryptGCM:cipherData withKey:aesKey AAD:nil inTAG:wrongTag];
    NSLog(@"wrongDecryptedData = %@", wrongDecryptedData);
    XCTAssertNil(wrongDecryptedData);
    
    // Easy Version
    NSData* easyCipherData = [ZPAesCryptor easyEncryptGCM:plainData withKey:aesKey];
    NSData* easyDecData = [ZPAesCryptor easyDecryptGCM:easyCipherData withKey:aesKey];
    NSString* easyDecText = [[NSString alloc] initWithData:easyDecData encoding:NSUTF8StringEncoding];
    NSAssert([easyDecText isEqualToString:plainText], @"Easy AES GCM Failed!");
    
    [ZPAesCryptor keychainDeleteKeyWithName:testAESname];
}
@end
