//
//  ZPMessageDigest.h
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/5.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 *  Some cryptographic hash functions used to generate message digests.
 *  一些密碼雜湊函式，用來產生訊息摘要。
 */
@interface ZPMessageDigest : NSObject

//MARK: - Secure Hash Algorithm
/**
 *  SHA-256
 *
 *  @param message UTF8 String message.
 *
 *  @return Digest. (Length 32bytes)
 */
+ (NSData*) sha256msg:(NSString*) message;

/**
 *  SHA-256
 *
 *  @param input Bytes Data.
 *
 *  @return Digest. (Length 32bytes)
 */
+ (NSData*) sha256:(NSData*) input;

/**
 *  SHA-384
 *
 *  @param message UTF8 String message.
 *
 *  @return Digest. (Length 48bytes)
 */
+ (NSData*) sha384msg:(NSString*) message;

/**
 *  SHA-384
 *
 *  @param input Bytes Data.
 *
 *  @return Digest. (Length 48bytes)
 */
+ (NSData*) sha384:(NSData*) input;


/**
 *  SHA-512
 *
 *  @param message UTF8 String message.
 *
 *  @return Digest. (Length 64bytes)
 */
+ (NSData*) sha512msg:(NSString*) message;

/**
 *  SHA-512
 *
 *  @param input Bytes Data.
 *
 *  @return Digest. (Length 64bytes)
 */
+ (NSData*) sha512:(NSData*) input;

/**
 *  SHA-1
 *
 *  @param message UTF8 String message.
 *
 *  @return Digest. (Length 20bytes)
 */
+ (NSData*) sha1msg:(NSString*) message;

/**
 *  SHA-1
 *
 *  @param input Bytes Data.
 *
 *  @return Digest. (Length 20bytes)
 */
+ (NSData*) sha1:(NSData*) input;

// =========================================
//MARK: - MD5 Message-Digest Algorithm
/**
 *  MD5
 *
 *  @param message UTF8 String message.
 *
 *  @return Digest. (Length 16bytes)
 */
+ (NSString*) md5:(NSString *) message;

@end

NS_ASSUME_NONNULL_END
