//
//  ZPUtils.m
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/9.
//

#import "ZPUtils.h"

@implementation ZPUtils

// NSString(Utf8) <==> NSData
+ (NSData*) dataFromUtf8String:(NSString*) str {
    return [str dataUsingEncoding:NSUTF8StringEncoding];
}

+ (NSString*) utf8StringFromData:(NSData*) data {
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

#pragma mark - Hex String
// Hex String <==> Data
// 有空白也會處理掉
+ (NSData* _Nullable) dataFromHexString:(NSString *) strHex {
    strHex = [strHex stringByReplacingOccurrencesOfString:@" " withString:@""];
    const NSUInteger length = strHex.length;
    if (length < 2 || length % 2 != 0) {
        return nil;
    }
    NSMutableData *hexData = [[NSMutableData alloc] initWithCapacity:length/2];
    NSRange range = NSMakeRange(0, 2);
    for (NSInteger i = range.location; i < length; i += 2) {
        unsigned int anInt;
        NSString *hexCharStr = [strHex substringWithRange:range];
        NSScanner *scanner = [[NSScanner alloc] initWithString:hexCharStr];
        [scanner scanHexInt:&anInt];
        [hexData appendBytes:&anInt length:1];
        range.location += range.length;
        range.length = 2;
    }
    return hexData;
}
//
+ (NSString*) hexStringFromData:(NSData*) data {
    NSMutableString* result = [[NSMutableString alloc] initWithCapacity:(data.length*3)];
    unsigned char* ptr = (unsigned char*) data.bytes;
    for(int i = 0; i < data.length; i++) {
        [result appendFormat:@"%02X", *(ptr+i)];
    }
    return result;
}
// Debug 用，byte 之間會有 " "
+ (NSString*) debugHexStringFromData:(NSData*) data {
    NSMutableString* result = [[NSMutableString alloc] initWithCapacity:(data.length*3)];
    unsigned char* ptr = (unsigned char*) data.bytes;
    for(int i = 0; i < data.length; i++) {
        [result appendFormat:@"%02X ", *(ptr+i)];
    }
    return result;
}

#pragma mark - Base64
+ (NSString*) base64Encode: (NSData*) data {
    NSString* base64 = [data base64EncodedStringWithOptions:0];
    return base64;
}

+ (NSData*) base64Decode: (NSString*) base64 {
    NSData* nsdata = nil;
    if (base64 != nil)
        nsdata = [[NSData alloc] initWithBase64EncodedString:base64 options:0];
    return nsdata;
}

+ (NSString*) base64EncodeUrl: (NSData*) data {
    NSString* base64 = [ZPUtils base64Encode:data];
    base64 = [base64 stringByReplacingOccurrencesOfString:@"=" withString:@""];
    base64 = [base64 stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    base64 = [base64 stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    return base64;
}

+ (NSData*) base64DecodeUrl: (NSString*) base64url {
    int padLen = (4 - (base64url.length % 4)) % 4;
    NSString* padded = [base64url stringByPaddingToLength:(base64url.length+padLen) withString:@"=" startingAtIndex:0];
    padded = [padded stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
    padded = [padded stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
    return [ZPUtils base64Decode:padded];
}
@end
