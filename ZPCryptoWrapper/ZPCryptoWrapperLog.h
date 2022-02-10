//
//  ZPCryptoWrapperLog.h
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/9.
//

#import <Foundation/Foundation.h>

#ifdef DEBUG
#   define NSLog(fmt, ...) NSLog((@"ZPCryptoWrapper %s" fmt), __PRETTY_FUNCTION__, ##__VA_ARGS__);
#else
#   define NSLog(...)
#endif

