# ZPCryptoWrapper
CommonCrypto wrapper for ObjC, macOS



### Requirements

- macOS 10.13 or higher
- ARC enabled



### Overview



### Message Digest (ZPMessageDigest)

- SHA512, SHA384, SHA256, SHA1
- MD5



### AES encryption (ZPAesCryptor)

- Provide AES encryption and decryption function and key management. (提供 AES 加解密功能 及 金鑰管理。)
- Generate AES Key to NSData (bytes array).
- Generate AES Key in Keychain.

- AES CBC Encrypt / Decrypt

- AES GCM Encrypt / Decrypt



### Elliptic Curve cryptography (ZPEcKeyPair & ZPEcCryptor)

- Generate EC Key Pair in Keychain.
- ECDSA - Sign / Verify Signature
- ECDH
