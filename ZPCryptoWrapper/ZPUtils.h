//
//  ZPUtils.h
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/9.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 *  集合常用的一些 function
 *  - Hex String
 *  - Base64
 */
@interface ZPUtils : NSObject
// NSString(Utf8) <==> NSData
+ (NSData*) dataFromUtf8String:(NSString*) str;
+ (NSString*) utf8StringFromData:(NSData*) data;

#pragma mark - Hex String

+ (NSData* _Nullable) dataFromHexString:(NSString *) strHex;

+ (NSString*) hexStringFromData:(NSData*) data;

+ (NSString*) debugHexStringFromData:(NSData*) data;

#pragma mark - Base64
+ (NSString*) base64Encode: (NSData*) data;

+ (NSData* _Nullable) base64Decode: (NSString*) base64;

+ (NSString*) base64EncodeUrl: (NSData*) data;

+ (NSData* _Nullable) base64DecodeUrl: (NSString*) base64url;
@end

NS_ASSUME_NONNULL_END
