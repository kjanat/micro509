# Algorithm Support

## Signature algorithms

| Algorithm       | Certificate / CSR signing | Chain verification |
| --------------- | :-----------------------: | :----------------: |
| RSA PKCS#1 v1.5 |            yes            |        yes         |
| RSA-PSS         |            yes            |        yes         |
| ECDSA P-256     |            yes            |        yes         |
| ECDSA P-384     |            yes            |        yes         |
| ECDSA P-521     |            yes            |        yes         |
| Ed25519         |            yes            |        yes         |

## Key formats

| Format       | Import | Export |        Encrypted         |
| ------------ | :----: | :----: | :----------------------: |
| PKCS#8       |  yes   |  yes   | PBES2 (AES-CBC + PBKDF2) |
| SPKI         |  yes   |  yes   |            —             |
| JWK          |  yes   |  yes   |            —             |
| PKCS#1 (RSA) |  yes   |  yes   |   Legacy PEM (AES-CBC)   |
| SEC1 (EC)    |  yes   |  yes   |   Legacy PEM (AES-CBC)   |

## Encryption

| Context              | Schemes                                              |
| -------------------- | ---------------------------------------------------- |
| Encrypted PKCS#8     | PBES2 with AES-CBC + PBKDF2 HMAC-SHA1 or HMAC-SHA256 |
| Encrypted PFX        | PBES2 with AES-CBC + PBKDF2 HMAC-SHA1 or HMAC-SHA256 |
| Legacy encrypted PEM | AES-128-CBC, AES-192-CBC, AES-256-CBC                |
| PKCS#12 MAC          | PKCS#12 KDF + HMAC-SHA-256                           |

## Not supported

micro509 does not try to mirror every primitive some WebCrypto runtimes expose:

- DSA
- Ed448
- RSA-OAEP
- ECDH / X25519 / X448
- Generic symmetric-crypto APIs
- Brainpool curves
