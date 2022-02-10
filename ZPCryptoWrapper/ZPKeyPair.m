//
//  ZPKeyPair.m
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/5.
//

#import "ZPKeyPair.h"
#import "ZPRsaKeyPair.h"
#import "ZPEcKeyPair.h"
#import "ZPCryptoWrapperLog.h"


@implementation ZPKeyPair


+ (SecAccessControlRef) newAccessControl {
    CFErrorRef error = NULL;
    SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(
      kCFAllocatorDefault,
      kSecAttrAccessibleAfterFirstUnlock,
      0, &error
    );
    //kSecAttrAccessibleAlways - apple 不建議用了
    //kSecAttrAccessibleAlwaysThisDeviceOnly
    //SecACLCreateWithSimpleContents
    //SecAccessCreateWithOwnerAndACL
    return sacObject;
}

+ (SecAccessRef) createSecAccess {
    CFErrorRef error = NULL;
    SecAccessRef accRef = SecAccessCreateWithOwnerAndACL(0, 0, 0, NULL, &error);
    //NSLog(@"SecAccessCreateWithOwnerAndACL Error = %@", (__bridge NSError*) error);
    //SecAccessRef accRef;
    //OSStatus status = SecAccessCreate((__bridge CFStringRef)@"", NULL, &accRef);
    //NSLog(@"SecAccessCreate = %d", status);
    SecKeychainPromptSelector promptSelector = 0;
    SecACLRef newACL;
    NSArray* applicationList = @[];
    OSStatus status = SecACLCreateWithSimpleContents(accRef, (__bridge CFArrayRef) applicationList, (__bridge CFStringRef)@"", promptSelector, &newACL);
    //NSLog(@"SecACLCreateWithSimpleContents = %ld", status);
    NSArray* array = @[(__bridge id)kSecACLAuthorizationAny];
    status = SecACLUpdateAuthorizations(newACL, (__bridge CFArrayRef) array);
    //NSLog(@"SecACLUpdateAuthorizations = %ld", status);
    return accRef;
}

#pragma mark - keychain

+ (boolean_t) generatePublicKey:(SecKeyRef*) pPublicKey
                     PrivateKey:(SecKeyRef*) pPrivateKey
                       WithType:(CFStringRef) keyType
                           Name:(NSString*) name
                           Size:(SecKeySizes) keySizeInBits {
    NSString* bundleId = [[NSBundle mainBundle] bundleIdentifier]; // 加 Application Tag : 為了方便大量刪除
    CFMutableDictionaryRef params = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    // PrivateKey ACL
    CFMutableDictionaryRef privateKeyParams = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(privateKeyParams, kSecClass, kSecClassKey);
    //CFDictionaryAddValue(privateKeyParams, kSecAttrLabel, (__bridge const void *) name);
    // kSecAttrAccess 與 kSecAttrAccessControl 互斥
    CFDictionaryAddValue(privateKeyParams, kSecAttrAccess, [ZPKeyPair createSecAccess]);
    //CFDictionaryAddValue(privateKeyParams, kSecAttrAccessControl, [ZPKeyPair newAccessControl]);
    //CFDictionaryAddValue(privateKeyParams, kSecAttrApplicationTag, (__bridge const void *) [bundleId dataUsingEncoding:NSUTF8StringEncoding]);
    CFDictionaryAddValue(params, kSecPrivateKeyAttrs, privateKeyParams);
    
    // Public key
    CFMutableDictionaryRef publicKeyParams = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(publicKeyParams, kSecClass, kSecClassKey);
    //CFDictionaryAddValue(publicKeyParams, kSecAttrLabel, (__bridge const void *) name);
    //CFDictionaryAddValue(publicKeyParams, kSecAttrApplicationTag, (__bridge const void *) [bundleId dataUsingEncoding:NSUTF8StringEncoding]);
    CFDictionaryAddValue(params, kSecPublicKeyAttrs, publicKeyParams);
    // ---------------
    CFDictionaryAddValue(params, kSecClass, kSecClassKey);
    CFDictionaryAddValue(params, kSecAttrKeyType, keyType);
    CFDictionaryAddValue(params, kSecAttrKeySizeInBits, (__bridge const void *)@(keySizeInBits));
    CFDictionaryAddValue(params, kSecAttrLabel, (__bridge const void *) name);
    CFDictionaryAddValue(params, kSecAttrApplicationTag, (__bridge const void *) [bundleId dataUsingEncoding:NSUTF8StringEncoding]);
    OSStatus status = SecKeyGeneratePair(params, pPublicKey, pPrivateKey);
    CFRelease(params);
    while (status != errSecSuccess) {
        NSLog(@"SecKeyGeneratePair = %d", status);
        return false;
    }
    return true;
}

+ (SecKeyRef) queryKeyWithName:(NSString*) name KeyClass:(CFStringRef) keyClass {
    SecKeyRef seckey = NULL;
    //kSecAttrKeyClassPrivate, kSecAttrKeyClassPublic
    CFMutableDictionaryRef queryParams = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(queryParams, kSecClass, kSecClassKey);
    CFDictionaryAddValue(queryParams, kSecAttrKeyClass, keyClass);
    CFDictionaryAddValue(queryParams, kSecReturnRef, kCFBooleanTrue);
    CFDictionaryAddValue(queryParams, kSecAttrLabel, (__bridge const void *) name);
    OSStatus status = SecItemCopyMatching(queryParams, (CFTypeRef *)&seckey);
    CFRelease(queryParams);
    if (errSecSuccess != status) {
        //NSLog(@"%@",secKey);
        seckey = NULL;
    }
    return seckey;
}

+ (KeyType) getKeyType:(SecKeyRef) key {
    KeyType keyType = KeyTypeUnknow;
    NSDictionary* keyAttr = (__bridge_transfer NSDictionary*) SecKeyCopyAttributes(key);
    NSString* strKeyType = keyAttr[(__bridge NSString *) kSecAttrKeyType];
    if (strKeyType != nil) {
        if ([strKeyType isEqualToString:(__bridge NSString *) kSecAttrKeyTypeRSA]) {
            //NSLog(@"RSA(%@)", strKeyType);
            keyType = KeyTypeRSA;
        } else if ([strKeyType isEqualToString:(__bridge NSString *) kSecAttrKeyTypeECSECPrimeRandom]) {
            //NSLog(@"ECSECPrimeRandom(%@)", strKeyType);
            keyType = KeyTypeECSECPrimeRandom;
        }
    }
    return keyType;
}

+ (SecKeySizes) getKeySizes:(SecKeyRef) key {
    NSDictionary* keyAttr = (__bridge_transfer NSDictionary*) SecKeyCopyAttributes(key);
    NSNumber* keySize = keyAttr[(__bridge NSString *) kSecAttrKeySizeInBits];
    //NSLog(@"b keySize = %@", keySize);
    //NSNumber* ekeySize = keyAttr[(__bridge NSString *) kSecAttrEffectiveKeySize];
    //NSLog(@"e keySize = %@", ekeySize);
    //extern const CFStringRef kSecAttrKeySizeInBits > bsiz
    //extern const CFStringRef kSecAttrEffectiveKeySize > esiz
    return (SecKeySizes) keySize.intValue;
}

// 用名稱取出 Key Pair
+ (instancetype) getInstanceFromKeychain:(NSString*) name {
    SecKeyRef publicKey = [ZPKeyPair queryKeyWithName:name KeyClass:kSecAttrKeyClassPublic];
    SecKeyRef privateKey = [ZPKeyPair queryKeyWithName:name KeyClass:kSecAttrKeyClassPrivate];
    ZPKeyPair* keyPair = nil;
    // 只要有一把key 就可以
    //if (publicKey != NULL && privateKey != NULL) {
    if (publicKey != NULL || privateKey != NULL) {
        SecKeyRef key = (publicKey != NULL) ? publicKey : privateKey;   // 盡量用 public key 判別，才不會要求提權
        KeyType type = [ZPKeyPair getKeyType:key];
        if (type == KeyTypeRSA) {
            keyPair = [[ZPRsaKeyPair alloc] initWithName:name PublicKey:publicKey PrivateKey:privateKey];
        } else if (type == KeyTypeECSECPrimeRandom) {
            keyPair = [[ZPEcKeyPair alloc] initWithName:name PublicKey:publicKey PrivateKey:privateKey];
        }
    } else {
        if (publicKey != NULL) {
            CFRelease(publicKey);
        }
        if (privateKey != NULL) {
            CFRelease(privateKey);
        }
    }
    NSLog(@"%@ => %@", name, keyPair);
    return keyPair;
}


- (void) dealloc {
    NSLog(@"%@", _name);
    [self releaseAllKey];
}

- (void) releaseAllKey {
    if (_publicKey != NULL) {
        CFRelease(_publicKey);
        _publicKey = NULL;
    }
    if (_privateKey != NULL) {
        CFRelease(_privateKey);
        _privateKey = NULL;
    }
}

// private init
- (instancetype) initWithName:(NSString*) name PublicKey: (SecKeyRef) publicKey PrivateKey:(SecKeyRef) privateKey {
    if (self = [super init]) {
        _name = name;
        _publicKey = publicKey;
        _privateKey = privateKey;
        SecKeyRef key = (publicKey != NULL) ? publicKey : privateKey;
        _type = [ZPKeyPair getKeyType:key];
        _keySizes = [ZPKeyPair getKeySizes:key];
    }
    return self;
}

- (void) deleteFromKeychain {
    [self releaseAllKey];
    CFMutableDictionaryRef queryParams = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(queryParams, kSecClass, kSecClassKey);
    CFDictionaryAddValue(queryParams, kSecAttrLabel, (__bridge const void *) _name);
    
    OSStatus errStatus = noErr;
    NSUInteger count = 0;
    do {
        errStatus = SecItemDelete(queryParams);
        switch (errStatus) {
            case errSecItemNotFound: // (-25300)
                //NSLog(@"%@ (%lu) : NotFound", applicationTag, count);
                break;
            case noErr: NSLog(@"%@ (%lu) : OK", _name, count); break;
            default: NSLog(@"%@ (%lu) : Error = %d", _name, count, errStatus); break;
        }
        count++;
    } while (errStatus == noErr);
    CFRelease(queryParams);
}

#pragma mark -
- (NSData* _Nullable) exportPrivateKey {
    if (_privateKey != NULL) {
        CFErrorRef error = nil;
        CFDataRef data = SecKeyCopyExternalRepresentation(_privateKey, &error);
        if (data != nil) {
            return (__bridge NSData*) data;
        }
    }
    return nil;
}

- (NSData* _Nullable) exportPublicKey {
    if (_publicKey != NULL) {
        CFErrorRef error = nil;
        CFDataRef data = SecKeyCopyExternalRepresentation(_publicKey, &error);
        if (data != nil) {
            return (__bridge NSData*) data;
        }
    }
    return nil;
}

+ (SecKeyRef) getPublicCertFromX509Data:(NSData*) certData {
    //CFDataRef cfRef = CFDataCreate(NULL, [certData bytes], [certData length]);
    SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef) certData);
    SecKeyRef key = NULL;
    SecTrustRef trust = NULL;
    SecPolicyRef policy = NULL;
    
    if (cert != NULL) {
        policy = SecPolicyCreateBasicX509();
        if (policy) {
            if (SecTrustCreateWithCertificates((CFTypeRef)cert, policy, &trust) == noErr) {
                SecTrustResultType result;
                if (SecTrustEvaluate(trust, &result) == noErr) {
                    key = SecTrustCopyPublicKey(trust);
                }
            }
        }
    }
    if (policy) CFRelease(policy);
    if (trust) CFRelease(trust);
    if (cert) CFRelease(cert);
    return key;
}

+ (void) deleteAllKeyCreatedByMe {
    NSLog(@"");
    CFMutableDictionaryRef queryParams = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(queryParams, kSecClass, kSecClassKey);
    // 加 Application Tag : 為了方便大量刪除
    NSString* bundleId = [[NSBundle mainBundle] bundleIdentifier];
    CFDictionaryAddValue(queryParams, kSecAttrApplicationTag, (__bridge const void *) [bundleId dataUsingEncoding:NSUTF8StringEncoding]);
    OSStatus errStatus = noErr;
    NSUInteger count = 0;
    do {
        errStatus = SecItemDelete(queryParams);
        switch (errStatus) {
            case errSecItemNotFound: // (-25300)
                //NSLog(@"%@ (%lu) : NotFound", applicationTag, count);
                break;
            case errSecWrPerm: // (-61)
                NSLog(@"must run as root.");
                break;
            case noErr: NSLog(@"(%lu) : OK", count); break;
            default: NSLog(@"(%lu) : Error = %d", count, errStatus); break;
        }
        count++;
    } while (errStatus == noErr);
    CFRelease(queryParams);
}
@end
