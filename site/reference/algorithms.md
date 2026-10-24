# Algorithm Support

Certificate parsing, certificate issuance, key operations, and signature
verification have separate support. Certificate issuance takes a caller supplied
WebCrypto public key and a signing private key. The signing key must use a
signature algorithm supported by micro509.

## Certificate and key capabilities

| Algorithm / key type    | Certificate parsing | Certificate issuance as subject key | Generate / import through micro509 | Sign / verify signatures | Key agreement | Key encapsulation |
| ----------------------- | :-----------------: | :---------------------------------: | :--------------------------------: | :----------------------: | :-----------: | :---------------: |
| RSA signatures          |         yes         |                 yes                 |                yes                 |           yes            |      no       |        no         |
| RSA-OAEP                |         yes         |                 yes                 |                yes                 |            no            |      no       |        yes        |
| ECDSA P-256/P-384/P-521 |         yes         |                 yes                 |                yes                 |           yes            |      no       |        no         |
| Ed25519                 |         yes         |                 yes                 |                yes                 |           yes            |      no       |        no         |
| X25519                  |         yes         | yes, with an exportable caller key  |                 no                 |            no            |      no       |        no         |
| Ed448                   |         yes         |   runtime dependent[^runtime-key]   |                 no                 |            no            |      no       |        no         |
| X448                    |         yes         |   runtime dependent[^runtime-key]   |                 no                 |            no            |      no       |        no         |

RSA signature support covers PKCS#1 v1.5 and RSA-PSS. RSA-OAEP supports
SHA-256/384/512 hashes and an optional label. Explicit OAEP key imports also accept
`hash: 'SHA-1'` for legacy envelopes. SHA-256 is the default. SHA-1 is unavailable
for key generation and RSA signature imports. The `yes` values for ECDSA and
Ed25519 cover those signature algorithms. `verifySignatureWithKey` verifies with an
existing WebCrypto public key, including a non-extractable key. Certificate
verification uses the same supported signature algorithms. Ed25519, Ed448, X25519 and X448 certificate
key-usage rules follow [RFC 9295][rfc9295]. A certificate using a key type
without a supported signature operation can still be issued with that subject
key when the runtime can export it and a supported CA signs it. An X25519
certificate can participate in `verifyCertificateChain`: path verification
checks the issuer signature and certificate rules, without performing X25519.

Generic SPKI and PKCS#8 export functions delegate to WebCrypto and can export
other key types when the supplied `CryptoKey` is extractable and its runtime
supports the format. micro509 key import and generation are narrower.

DSA and Brainpool signing and verification are unsupported. micro509 also
has no ECDH key generation/import or key-agreement API.

## Key formats

| Format       | Import through micro509 | Export through micro509 |
| ------------ | :---------------------: | :---------------------: |
| PKCS#8       |           yes           |           yes           |
| SPKI         |           yes           |           yes           |
| JWK          |           yes           |           yes           |
| PKCS#1 (RSA) |           yes           |           yes           |
| SEC1 (EC)    |           yes           |           yes           |

## Packaged symmetric operations

micro509 has no general-purpose symmetric encryption, MAC, or KDF API. These
primitives are available only inside higher-level format workflows:

| Workflow                     | Packaged operations                                  |
| ---------------------------- | ---------------------------------------------------- |
| Encrypted PKCS#8 / PFX       | PBES2, AES-CBC, PBKDF2 with HMAC-SHA1 or HMAC-SHA256 |
| Legacy encrypted PEM         | AES-128-CBC, AES-192-CBC, AES-256-CBC                |
| PKCS#12 MAC                  | PKCS#12 KDF and HMAC-SHA-256                         |
| PBMAC1 ([RFC 9879][rfc9879]) | PBKDF2 HMAC-SHA-256/384/512 and HMAC-SHA-256/384/512 |

PBMAC1 creation uses SHA-256.

[rfc9295]: https://www.rfc-editor.org/rfc/rfc9295.html
[rfc9879]: https://www.rfc-editor.org/rfc/rfc9879.html

[^runtime-key]: Issuance depends on the WebCrypto runtime providing an exportable key.
    micro509 enforces the certificate key-usage rules. micro509 has no generation
    or import API for these algorithms. It does not perform X25519/X448 agreement.
