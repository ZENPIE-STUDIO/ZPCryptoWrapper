//
//  ZPMessageDigest.h
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/5.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZPMessageDigest : NSObject

//+ (NSString*) md5:(NSString *) message;

// UTF8 String
+ (NSData*) sha256msg:(NSString*) message;
+ (NSData*) sha384msg:(NSString*) message;
+ (NSData*) sha512msg:(NSString*) message;
+ (NSData*) sha1msg:(NSString*) message;

// Bytes Data
+ (NSData*) sha256:(NSData*) input;
+ (NSData*) sha384:(NSData*) input;
+ (NSData*) sha512:(NSData*) input;
+ (NSData*) sha1:(NSData*) input;

@end

NS_ASSUME_NONNULL_END
