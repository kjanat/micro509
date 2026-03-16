[micro509](modules.md) / keys

# keys

Canonical key generation and import/export domain surface.
Owns the stable `micro509/keys` entrypoint.

## Interfaces

### EcKeyAlgorithmInput

Defined in: [keys/keys.ts:60](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L60)

ECDSA variant of [`KeyAlgorithmInput`](#keyalgorithminput).

#### Properties

##### kind

> `readonly` **kind**: `"ecdsa"`

Defined in: [keys/keys.ts:62](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L62)

Discriminant selecting ECDSA key generation.

##### namedCurve?

> `readonly` `optional` **namedCurve**: [`EcNamedCurve`](#ecnamedcurve)

Defined in: [keys/keys.ts:64](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L64)

NIST curve. Defaults to `'P-256'`.

---

### Ed25519KeyAlgorithmInput

Defined in: [keys/keys.ts:68](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L68)

Ed25519 variant of [`KeyAlgorithmInput`](#keyalgorithminput).

#### Properties

##### kind

> `readonly` **kind**: `"ed25519"`

Defined in: [keys/keys.ts:70](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L70)

Discriminant selecting Ed25519 key generation.

---

### ImportEcPublicKeyInput

Defined in: [keys/keys.ts:110](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L110)

ECDSA variant of [`PublicKeyImportInput`](#publickeyimportinput).

#### Properties

##### kind

> `readonly` **kind**: `"ecdsa"`

Defined in: [keys/keys.ts:112](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L112)

Discriminant selecting ECDSA import.

##### namedCurve

> `readonly` **namedCurve**: [`EcNamedCurve`](#ecnamedcurve)

Defined in: [keys/keys.ts:114](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L114)

NIST curve the key belongs to. Required for EC import.

---

### ImportEd25519PublicKeyInput

Defined in: [keys/keys.ts:118](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L118)

Ed25519 variant of [`PublicKeyImportInput`](#publickeyimportinput).

#### Properties

##### kind

> `readonly` **kind**: `"ed25519"`

Defined in: [keys/keys.ts:120](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L120)

Discriminant selecting Ed25519 import.

---

### ImportRsaPublicKeyInput

Defined in: [keys/keys.ts:100](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L100)

RSA variant of [`PublicKeyImportInput`](#publickeyimportinput).

#### Properties

##### hash?

> `readonly` `optional` **hash**: [`RsaHash`](#rsahash)

Defined in: [keys/keys.ts:104](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L104)

Hash algorithm. Defaults to `'SHA-256'`.

##### kind

> `readonly` **kind**: `"rsa"`

Defined in: [keys/keys.ts:102](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L102)

Discriminant selecting RSA import.

##### scheme?

> `readonly` `optional` **scheme**: [`RsaScheme`](#rsascheme)

Defined in: [keys/keys.ts:106](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L106)

Signature padding scheme. Defaults to `'pkcs1-v1_5'`.

---

### KeyPairMaterial

Defined in: [keys/keys.ts:80](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L80)

Key pair with convenience export helpers. Returned by [`generateKeyPair`](#generatekeypair).

#### Properties

##### privateKey

> `readonly` **privateKey**: `CryptoKey`

Defined in: [keys/keys.ts:84](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L84)

The WebCrypto private key (extractable, `sign` usage).

##### publicKey

> `readonly` **publicKey**: `CryptoKey`

Defined in: [keys/keys.ts:82](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L82)

The WebCrypto public key (extractable, `verify` usage).

#### Methods

##### exportPkcs8Der()

> **exportPkcs8Der**(): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Defined in: [keys/keys.ts:90](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L90)

Export the private key as DER-encoded PKCS#8 PrivateKeyInfo.

###### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

##### exportPkcs8Pem()

> **exportPkcs8Pem**(): `Promise`\<`string`\>

Defined in: [keys/keys.ts:92](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L92)

Export the private key as PEM-encoded PKCS#8 PrivateKeyInfo.

###### Returns

`Promise`\<`string`\>

##### exportPrivateJwk()

> **exportPrivateJwk**(): `Promise`\<`JsonWebKey`\>

Defined in: [keys/keys.ts:96](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L96)

Export the private key as a JSON Web Key.

###### Returns

`Promise`\<`JsonWebKey`\>

##### exportPublicJwk()

> **exportPublicJwk**(): `Promise`\<`JsonWebKey`\>

Defined in: [keys/keys.ts:94](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L94)

Export the public key as a JSON Web Key.

###### Returns

`Promise`\<`JsonWebKey`\>

##### exportSpkiDer()

> **exportSpkiDer**(): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Defined in: [keys/keys.ts:86](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L86)

Export the public key as DER-encoded SubjectPublicKeyInfo.

###### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

##### exportSpkiPem()

> **exportSpkiPem**(): `Promise`\<`string`\>

Defined in: [keys/keys.ts:88](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L88)

Export the public key as PEM-encoded SubjectPublicKeyInfo.

###### Returns

`Promise`\<`string`\>

---

### LegacyPemEncryptionOptions

Defined in: [keys/keys.ts:136](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L136)

Options for OpenSSL-style `Proc-Type: 4,ENCRYPTED` PEM encryption (PKCS#1/SEC1).

#### Properties

##### cipher?

> `readonly` `optional` **cipher**: `"AES-128-CBC"` \| `"AES-192-CBC"` \| `"AES-256-CBC"`

Defined in: [keys/keys.ts:142](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L142)

AES-CBC cipher. Defaults to `'AES-256-CBC'`.

##### iv?

> `readonly` `optional` **iv**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [keys/keys.ts:140](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L140)

16-byte initialization vector. Random when omitted.

##### password

> `readonly` **password**: `string`

Defined in: [keys/keys.ts:138](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L138)

Passphrase used to derive the encryption key.

---

### Pbes2EncryptionOptions

Defined in: [internal/crypto/pbes2.ts:33](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/crypto/pbes2.ts#L33)

Input for `encryptPbes2`.

#### Properties

##### encryption?

> `readonly` `optional` **encryption**: [`Pbes2EncryptionScheme`](#pbes2encryptionscheme)

Defined in: [internal/crypto/pbes2.ts:43](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/crypto/pbes2.ts#L43)

AES key size. Default: `'aes256-cbc'`.

##### iterations?

> `readonly` `optional` **iterations**: `number`

Defined in: [internal/crypto/pbes2.ts:37](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/crypto/pbes2.ts#L37)

PBKDF2 iteration count. Default: `100_000`.

##### iv?

> `readonly` `optional` **iv**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [internal/crypto/pbes2.ts:41](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/crypto/pbes2.ts#L41)

AES-CBC initialization vector. Default: 16 cryptographically random bytes.

##### password

> `readonly` **password**: `string`

Defined in: [internal/crypto/pbes2.ts:35](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/crypto/pbes2.ts#L35)

Password fed to PBKDF2 for key derivation.

##### prf?

> `readonly` `optional` **prf**: [`Pbes2Prf`](#pbes2prf)

Defined in: [internal/crypto/pbes2.ts:45](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/crypto/pbes2.ts#L45)

PBKDF2 PRF. Default: `'hmac-sha256'`.

##### salt?

> `readonly` `optional` **salt**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [internal/crypto/pbes2.ts:39](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/crypto/pbes2.ts#L39)

PBKDF2 salt. Default: 16 cryptographically random bytes.

---

### RsaKeyAlgorithmInput

Defined in: [keys/keys.ts:48](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L48)

RSA variant of [`KeyAlgorithmInput`](#keyalgorithminput).

#### Properties

##### hash?

> `readonly` `optional` **hash**: [`RsaHash`](#rsahash)

Defined in: [keys/keys.ts:54](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L54)

Hash algorithm for the key. Defaults to `'SHA-256'`.

##### kind

> `readonly` **kind**: `"rsa"`

Defined in: [keys/keys.ts:50](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L50)

Discriminant selecting RSA key generation.

##### modulusLength?

> `readonly` `optional` **modulusLength**: `2048` \| `3072` \| `4096`

Defined in: [keys/keys.ts:52](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L52)

RSA modulus size in bits. Defaults to `2048`.

##### scheme?

> `readonly` `optional` **scheme**: [`RsaScheme`](#rsascheme)

Defined in: [keys/keys.ts:56](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L56)

Signature padding scheme. Defaults to `'pkcs1-v1_5'`.

## Type Aliases

### EcNamedCurve

> **EcNamedCurve** = `"P-256"` \| `"P-384"` \| `"P-521"`

Defined in: [keys/keys.ts:45](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L45)

NIST elliptic curve for ECDSA keys.

---

### EncryptedPkcs8Options

> **EncryptedPkcs8Options** = [`Pbes2EncryptionOptions`](#pbes2encryptionoptions)

Defined in: [keys/keys.ts:133](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L133)

PBES2 encryption options for [`exportEncryptedPkcs8Der`](#exportencryptedpkcs8der) and [`exportEncryptedPkcs8Pem`](#exportencryptedpkcs8pem).

---

### KeyAlgorithmInput

> **KeyAlgorithmInput** = [`RsaKeyAlgorithmInput`](#rsakeyalgorithminput) \| [`EcKeyAlgorithmInput`](#eckeyalgorithminput) \| [`Ed25519KeyAlgorithmInput`](#ed25519keyalgorithminput)

Defined in: [keys/keys.ts:74](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L74)

Input for [`generateKeyPair`](#generatekeypair). Selects algorithm family and parameters.

---

### Pbes2EncryptionScheme

> **Pbes2EncryptionScheme** = `"aes128-cbc"` \| `"aes192-cbc"` \| `"aes256-cbc"`

Defined in: [internal/crypto/pbes2.ts:27](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/crypto/pbes2.ts#L27)

AES-CBC key sizes supported by this PBES2 implementation.

---

### Pbes2Prf

> **Pbes2Prf** = `"hmac-sha1"` \| `"hmac-sha256"`

Defined in: [internal/crypto/pbes2.ts:30](https://github.com/kjanat/ts-x509/blob/vitepress/src/internal/crypto/pbes2.ts#L30)

PBKDF2 pseudo-random function choices. `hmac-sha1` is the RFC default; `hmac-sha256` is preferred.

---

### PrivateKeyImportInput

> **PrivateKeyImportInput** = [`PublicKeyImportInput`](#publickeyimportinput)

Defined in: [keys/keys.ts:130](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L130)

Algorithm descriptor for private key import functions. Same shape as [`PublicKeyImportInput`](#publickeyimportinput).

---

### PublicKeyImportInput

> **PublicKeyImportInput** = [`ImportRsaPublicKeyInput`](#importrsapublickeyinput) \| [`ImportEcPublicKeyInput`](#importecpublickeyinput) \| [`ImportEd25519PublicKeyInput`](#imported25519publickeyinput)

Defined in: [keys/keys.ts:124](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L124)

Algorithm descriptor for public key import functions.

---

### RsaHash

> **RsaHash** = `"SHA-256"` \| `"SHA-384"` \| `"SHA-512"`

Defined in: [keys/keys.ts:39](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L39)

Hash algorithm paired with an RSA key.

---

### RsaScheme

> **RsaScheme** = `"pkcs1-v1_5"` \| `"pss"`

Defined in: [keys/keys.ts:42](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L42)

RSA signature padding scheme.

## Functions

### exportBinaryBase64()

> **exportBinaryBase64**(`key`): `Promise`\<`string`\>

Defined in: [keys/keys.ts:311](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L311)

Export a key as raw base64: SPKI for public keys, PKCS#8 for private keys.

#### Parameters

##### key

`CryptoKey`

#### Returns

`Promise`\<`string`\>

---

### exportEncryptedPkcs1Pem()

> **exportEncryptedPkcs1Pem**(`privateKey`, `options`): `Promise`\<`string`\>

Defined in: [keys/keys.ts:267](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L267)

Export an RSA private key as legacy `Proc-Type: 4,ENCRYPTED` PEM (PKCS#1).

#### Parameters

##### privateKey

`CryptoKey`

##### options

[`LegacyPemEncryptionOptions`](#legacypemencryptionoptions)

#### Returns

`Promise`\<`string`\>

---

### exportEncryptedPkcs8Der()

> **exportEncryptedPkcs8Der**(`privateKey`, `options`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Defined in: [keys/keys.ts:234](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L234)

Export a private key as DER-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.

#### Parameters

##### privateKey

`CryptoKey`

##### options

[`Pbes2EncryptionOptions`](#pbes2encryptionoptions)

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

---

### exportEncryptedPkcs8Pem()

> **exportEncryptedPkcs8Pem**(`privateKey`, `options`): `Promise`\<`string`\>

Defined in: [keys/keys.ts:244](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L244)

Export a private key as PEM-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.

#### Parameters

##### privateKey

`CryptoKey`

##### options

[`Pbes2EncryptionOptions`](#pbes2encryptionoptions)

#### Returns

`Promise`\<`string`\>

---

### exportEncryptedSec1Pem()

> **exportEncryptedSec1Pem**(`privateKey`, `options`): `Promise`\<`string`\>

Defined in: [keys/keys.ts:290](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L290)

Export an EC private key as legacy `Proc-Type: 4,ENCRYPTED` PEM (SEC 1).

#### Parameters

##### privateKey

`CryptoKey`

##### options

[`LegacyPemEncryptionOptions`](#legacypemencryptionoptions)

#### Returns

`Promise`\<`string`\>

---

### exportPkcs1Der()

> **exportPkcs1Der**(`privateKey`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Defined in: [keys/keys.ts:252](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L252)

Export an RSA private key as DER-encoded PKCS#1 RSAPrivateKey. Throws for non-RSA keys.

#### Parameters

##### privateKey

`CryptoKey`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

---

### exportPkcs1Pem()

> **exportPkcs1Pem**(`privateKey`): `Promise`\<`string`\>

Defined in: [keys/keys.ts:262](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L262)

Export an RSA private key as PEM-encoded PKCS#1 RSAPrivateKey. Throws for non-RSA keys.

#### Parameters

##### privateKey

`CryptoKey`

#### Returns

`Promise`\<`string`\>

---

### exportPkcs8Der()

> **exportPkcs8Der**(`privateKey`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Defined in: [keys/keys.ts:206](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L206)

Export a private key as DER-encoded PKCS#8 PrivateKeyInfo.

#### Parameters

##### privateKey

`CryptoKey`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

---

### exportPkcs8Pem()

> **exportPkcs8Pem**(`privateKey`): `Promise`\<`string`\>

Defined in: [keys/keys.ts:229](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L229)

Export a private key as a PEM-encoded PKCS#8 PrivateKeyInfo.

#### Parameters

##### privateKey

`CryptoKey`

#### Returns

`Promise`\<`string`\>

---

### exportPrivateJwk()

> **exportPrivateJwk**(`privateKey`): `Promise`\<`JsonWebKey`\>

Defined in: [keys/keys.ts:224](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L224)

Export a private key as a JSON Web Key.

#### Parameters

##### privateKey

`CryptoKey`

#### Returns

`Promise`\<`JsonWebKey`\>

---

### exportPublicJwk()

> **exportPublicJwk**(`publicKey`): `Promise`\<`JsonWebKey`\>

Defined in: [keys/keys.ts:219](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L219)

Export a public key as a JSON Web Key.

#### Parameters

##### publicKey

`CryptoKey`

#### Returns

`Promise`\<`JsonWebKey`\>

#### Example

```ts
const keys = await generateKeyPair({
  kind: 'ecdsa',
  namedCurve: 'P-256',
});
const jwk = await exportPublicJwk(keys.publicKey);
```

---

### exportSec1Der()

> **exportSec1Der**(`privateKey`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Defined in: [keys/keys.ts:275](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L275)

Export an EC private key as DER-encoded SEC 1 ECPrivateKey. Throws for non-EC keys.

#### Parameters

##### privateKey

`CryptoKey`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

---

### exportSec1Pem()

> **exportSec1Pem**(`privateKey`): `Promise`\<`string`\>

Defined in: [keys/keys.ts:285](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L285)

Export an EC private key as PEM-encoded SEC 1 ECPrivateKey.

#### Parameters

##### privateKey

`CryptoKey`

#### Returns

`Promise`\<`string`\>

---

### exportSpkiDer()

> **exportSpkiDer**(`publicKey`): `Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

Defined in: [keys/keys.ts:201](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L201)

Export a public key as DER-encoded SubjectPublicKeyInfo.

#### Parameters

##### publicKey

`CryptoKey`

#### Returns

`Promise`\<`Uint8Array`\<`ArrayBufferLike`\>\>

---

### exportSpkiPem()

> **exportSpkiPem**(`publicKey`): `Promise`\<`string`\>

Defined in: [keys/keys.ts:306](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L306)

Export a public key as PEM-encoded SubjectPublicKeyInfo.

#### Parameters

##### publicKey

`CryptoKey`

#### Returns

`Promise`\<`string`\>

#### Example

```ts
const keys = await generateKeyPair();
const pem = await exportSpkiPem(keys.publicKey);
```

---

### generateKeyPair()

> **generateKeyPair**(`algorithm?`): `Promise`\<[`KeyPairMaterial`](#keypairmaterial)\>

Defined in: [keys/keys.ts:159](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L159)

Generate an asymmetric key pair for signing and verification.

#### Parameters

##### algorithm?

[`KeyAlgorithmInput`](#keyalgorithminput) = `...`

#### Returns

`Promise`\<[`KeyPairMaterial`](#keypairmaterial)\>

#### Example

```ts
const ecKeys = await generateKeyPair({
  kind: 'ecdsa',
  namedCurve: 'P-384',
});
const rsaKeys = await generateKeyPair({
  kind: 'rsa',
  modulusLength: 4096,
});
const edKeys = await generateKeyPair({ kind: 'ed25519' });

// Default: ECDSA P-256
const keys = await generateKeyPair();
const pem = await keys.exportPkcs8Pem();
```

---

### importEncryptedPkcs1Pem()

> **importEncryptedPkcs1Pem**(`pem`, `password`, `algorithm?`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:459](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L459)

Import an RSA private key from legacy `Proc-Type: 4,ENCRYPTED` PEM (PKCS#1).

#### Parameters

##### pem

`string`

##### password

`string`

##### algorithm?

[`ImportRsaPublicKeyInput`](#importrsapublickeyinput) = `...`

#### Returns

`Promise`\<`CryptoKey`\>

---

### importEncryptedPkcs8Der()

> **importEncryptedPkcs8Der**(`der`, `password`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:394](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L394)

Import a private key from DER-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.

#### Parameters

##### der

`Uint8Array`

##### password

`string`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### importEncryptedPkcs8Pem()

> **importEncryptedPkcs8Pem**(`pem`, `password`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:434](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L434)

Import a private key from PEM-encoded PBES2-encrypted PKCS#8 EncryptedPrivateKeyInfo.

#### Parameters

##### pem

`string`

##### password

`string`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

#### Example

```ts
const key = await importEncryptedPkcs8Pem(pem, 'secret', {
  kind: 'rsa',
});
```

---

### importEncryptedSec1Pem()

> **importEncryptedSec1Pem**(`pem`, `password`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:500](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L500)

Import an EC private key from legacy `Proc-Type: 4,ENCRYPTED` PEM (SEC 1).

#### Parameters

##### pem

`string`

##### password

`string`

##### algorithm

[`ImportEcPublicKeyInput`](#importecpublickeyinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### importPkcs1Der()

> **importPkcs1Der**(`der`, `algorithm?`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:443](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L443)

Import an RSA private key from DER-encoded PKCS#1 RSAPrivateKey.

#### Parameters

##### der

`Uint8Array`

##### algorithm?

[`ImportRsaPublicKeyInput`](#importrsapublickeyinput) = `...`

#### Returns

`Promise`\<`CryptoKey`\>

---

### importPkcs1Pem()

> **importPkcs1Pem**(`pem`, `algorithm?`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:451](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L451)

Import an RSA private key from PEM-encoded PKCS#1 RSAPrivateKey (`RSA PRIVATE KEY` label).

#### Parameters

##### pem

`string`

##### algorithm?

[`ImportRsaPublicKeyInput`](#importrsapublickeyinput) = `...`

#### Returns

`Promise`\<`CryptoKey`\>

---

### importPkcs8Base64()

> **importPkcs8Base64**(`base64`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:469](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L469)

Import a private key from base64-encoded PKCS#8 PrivateKeyInfo (no PEM headers).

#### Parameters

##### base64

`string`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### importPkcs8Der()

> **importPkcs8Der**(`der`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:360](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L360)

Import a private key from DER-encoded PKCS#8 PrivateKeyInfo.

#### Parameters

##### der

`Uint8Array`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### importPkcs8Pem()

> **importPkcs8Pem**(`pem`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:386](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L386)

Import a private key from PEM-encoded PKCS#8 PrivateKeyInfo.

#### Parameters

##### pem

`string`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

#### Example

```ts
const key = await importPkcs8Pem(pemString, {
  kind: 'ecdsa',
  namedCurve: 'P-256',
});
```

---

### importPrivateJwk()

> **importPrivateJwk**(`jwk`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:526](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L526)

Import a private signing key from a JSON Web Key.

#### Parameters

##### jwk

`JsonWebKey`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

#### Example

```ts
const jwk = {
  kty: 'EC',
  crv: 'P-256',
  x: '...',
  y: '...',
  d: '...',
};
const key = await importPrivateJwk(jwk, {
  kind: 'ecdsa',
  namedCurve: 'P-256',
});
```

---

### importPublicJwk()

> **importPublicJwk**(`jwk`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:510](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L510)

Import a public verification key from a JSON Web Key.

#### Parameters

##### jwk

`JsonWebKey`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### importSec1Der()

> **importSec1Der**(`der`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:484](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L484)

Import an EC private key from DER-encoded SEC 1 ECPrivateKey.

#### Parameters

##### der

`Uint8Array`

##### algorithm

[`ImportEcPublicKeyInput`](#importecpublickeyinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### importSec1Pem()

> **importSec1Pem**(`pem`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:492](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L492)

Import an EC private key from PEM-encoded SEC 1 ECPrivateKey (`EC PRIVATE KEY` label).

#### Parameters

##### pem

`string`

##### algorithm

[`ImportEcPublicKeyInput`](#importecpublickeyinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### importSpkiBase64()

> **importSpkiBase64**(`base64`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:345](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L345)

Import a public key from base64-encoded SubjectPublicKeyInfo (no PEM headers).

#### Parameters

##### base64

`string`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### importSpkiDer()

> **importSpkiDer**(`der`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:322](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L322)

Import a public key from DER-encoded SubjectPublicKeyInfo.

#### Parameters

##### der

`Uint8Array`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>

---

### importSpkiPem()

> **importSpkiPem**(`pem`, `algorithm`): `Promise`\<`CryptoKey`\>

Defined in: [keys/keys.ts:337](https://github.com/kjanat/ts-x509/blob/vitepress/src/keys/keys.ts#L337)

Import a public key from PEM-encoded SubjectPublicKeyInfo.

#### Parameters

##### pem

`string`

##### algorithm

[`PublicKeyImportInput`](#publickeyimportinput)

#### Returns

`Promise`\<`CryptoKey`\>
