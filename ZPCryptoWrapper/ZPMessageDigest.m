//
//  ZPMessageDigest.m
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/5.
//

#import "ZPMessageDigest.h"
#import <CommonCrypto/CommonDigest.h>

@implementation ZPMessageDigest


//+ (NSString*) md5:(NSString*) message {
//    NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
//    const char *cStr = [data bytes];
//    unsigned char digest[CC_MD5_DIGEST_LENGTH];
//    CC_MD5( cStr, (CC_LONG) data.length, digest ); // This is the md5 call
//    
//    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
//    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
//        [output appendFormat:@"%02x", digest[i]];
//    return  output;
//}

// =========================================
// UTF8 String
+ (NSData*) sha256msg: (NSString*) message {
    return [ZPMessageDigest sha256:[message dataUsingEncoding:NSUTF8StringEncoding]];
}

+ (NSData*) sha384msg:(NSString*) message {
    return [ZPMessageDigest sha384:[message dataUsingEncoding:NSUTF8StringEncoding]];
}

+ (NSData*) sha512msg:(NSString*) message {
    return [ZPMessageDigest sha512:[message dataUsingEncoding:NSUTF8StringEncoding]];
}

+ (NSData*) sha1msg:(NSString*) message {
    return [ZPMessageDigest sha1:[message dataUsingEncoding:NSUTF8StringEncoding]];
}

// Bytes Data
+ (NSData*) sha256: (NSData*) input {
    unsigned char buf[CC_SHA256_DIGEST_LENGTH];
    unsigned char* result = CC_SHA256(input.bytes, (unsigned int)input.length, buf);
    if (result) {
        NSData* data = [[NSData alloc] initWithBytes:buf length:CC_SHA256_DIGEST_LENGTH];
        return data;
    }
    return nil;
}

+ (NSData*) sha384: (NSData*) input {
    unsigned char buf[CC_SHA384_DIGEST_LENGTH];
    unsigned char* result = CC_SHA384(input.bytes, (unsigned int)input.length, buf);
    if (result) {
        NSData* data = [[NSData alloc] initWithBytes:buf length:CC_SHA384_DIGEST_LENGTH];
        return data;
    }
    return nil;
}

+ (NSData*) sha512: (NSData*) input {
    unsigned char buf[CC_SHA512_DIGEST_LENGTH];
    unsigned char* result = CC_SHA512(input.bytes, (unsigned int)input.length, buf);
    if (result) {
        NSData* data = [[NSData alloc] initWithBytes:buf length:CC_SHA512_DIGEST_LENGTH];
        return data;
    }
    return nil;
}

+ (NSData*) sha1:(NSData*) input {
    unsigned char buf[CC_SHA1_DIGEST_LENGTH];
    unsigned char* result = CC_SHA1(input.bytes, (unsigned int)input.length, buf);
    if (result) {
        NSData* data = [[NSData alloc] initWithBytes:buf length:CC_SHA1_DIGEST_LENGTH];
        return data;
    }
    return nil;
}

@end
