# ZPCryptoWrapper


### Description

CommonCrypto wrapper for ObjC, macOS

整理近年開發macOS軟體時，用到的加解密功能。都是呼叫 Apple 官方的 CommonCrypto，主要是包裝成自己方便使用的介面。

#### Requirements

- macOS 10.13 or higher
- ARC enabled
- (TODO) iOS



### Features

#### Message Digest (ZPMessageDigest)

- SHA512, SHA384, SHA256, SHA1
- MD5



#### AES Encryption (ZPAesCryptor)

- Provide AES encryption and decryption function and key management. 
- Generate AES Key to NSData (bytes array).
- Generate AES Key in Keychain.

- AES CBC Encrypt / Decrypt

- AES GCM Encrypt / Decrypt



#### Elliptic Curve Cryptography (ZPEcKeyPair & ZPEcCryptor)

- Generate EC Key Pair in Keychain.
- ECDSA - Sign / Verify Signature
- ECDH



#### RSA Cryptography (ZPRsaKeyPair & ZPRsaCryptor)

- Generate RSA Key Pair in Keychain.

- PKCS1 & OAEP Encrypt / Decrypt

- Sign / Verify Signature



### License

**ZPCryptoWrapper** is available under the MIT license. See the [LICENSE](LICENSE) file for more info.  



### Author

- 花瀅智（[Eddie Hua](https://www.linkedin.com/in/eddie-hua-856b2538/)）
