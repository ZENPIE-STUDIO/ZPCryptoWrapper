//
//  ZPCryptoConstants.h
//  ZPCryptoWrapper
//
//  Created by EddieHua on 2022/2/10.
//

#ifndef ZPCryptoConstants_h
#define ZPCryptoConstants_h

// CBOR Object Signing and Encryption (COSE)
// https://www.iana.org/assignments/cose/cose.xhtml
typedef NS_ENUM(NSInteger, COSE_ALG) {
    COSE_ALG_UNKNOWN = 0,
    // ES
    COSE_ALG_ES256 = -7,    // ECDSA using P-256 and SHA-256
    COSE_ALG_ES384 = -35,   // ECDSA using P-384 and SHA-384
    COSE_ALG_ES512 = -36,   // ECDSA using P-521 and SHA-512
    // PS
    COSE_ALG_PS256 = -37,   // RSASSA-PSS with SHA-256
    COSE_ALG_PS384 = -38,   // RSASSA-PSS with SHA-384
    COSE_ALG_PS512 = -39,   // RSASSA-PSS with SHA-512
    // RS
    COSE_ALG_RS256 = -257,  // RSASSA-PKCS1-v1_5 w/ SHA-256
    COSE_ALG_RS384 = -258,  // RSASSA-PKCS1-v1_5 w/ SHA-384
    COSE_ALG_RS512 = -259,  // RSASSA-PKCS1-v1_5 w/ SHA-512
    COSE_ALG_RS1 = -65535   // RSASSA-PKCS1-v1_5 w/ SHA-1
};

#endif /* ZPCryptoConstants_h */
