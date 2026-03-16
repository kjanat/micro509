[micro509](modules.md) / pkcs

# pkcs

PKCS container APIs: PFX/PKCS#12 and PKCS#7/CMS.

Owns PFX archive creation and parsing, PKCS#7 certificate bags and SignedData,
and PKCS#12 MAC integrity helpers.

## Interfaces

### CreatePfxInput

Defined in: [pkcs/pfx.ts:79](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L79)

Input for [`createPfx`](#createpfx).

#### Properties

##### certificates?

> `readonly` `optional` **certificates**: readonly [`PfxCertificateBagInput`](#pfxcertificatebaginput)[]

Defined in: [pkcs/pfx.ts:81](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L81)

Certificates to include as certBag entries.

##### encryption?

> `readonly` `optional` **encryption**: [`Pbes2EncryptionOptions`](keys.md#pbes2encryptionoptions)

Defined in: [pkcs/pfx.ts:85](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L85)

PBES2 encryption settings for the key-bag ContentInfo. Omit for unencrypted.

##### mac?

> `readonly` `optional` **mac**: [`Pkcs12MacOptions`](#pkcs12macoptions)

Defined in: [pkcs/pfx.ts:87](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L87)

PKCS#12 MAC integrity settings. Omit to skip MAC generation.

##### privateKeys?

> `readonly` `optional` **privateKeys**: readonly [`PfxPrivateKeyBagInput`](#pfxprivatekeybaginput)[]

Defined in: [pkcs/pfx.ts:83](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L83)

Private keys to include as keyBag entries.

---

### ParsedPfx

Defined in: [pkcs/pfx.ts:167](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L167)

Fully decoded PFX container returned by [`parsePfxDer`](#parsepfxder) / [`parsePfxPem`](#parsepfxpem).

#### Properties

##### bags

> `readonly` **bags**: readonly [`ParsedPfxBag`](#parsedpfxbag)[]

Defined in: [pkcs/pfx.ts:169](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L169)

All SafeBags in the PFX, including unknown types.

##### certificates

> `readonly` **certificates**: readonly [`ParsedCertificate`](x509.md#parsedcertificate)\<`Record`\<`never`, `never`\>\>[]

Defined in: [pkcs/pfx.ts:171](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L171)

Convenience: only the parsed certificates extracted from certBag entries.

##### macData?

> `readonly` `optional` **macData**: [`ParsedPkcs12MacData`](#parsedpkcs12macdata)

Defined in: [pkcs/pfx.ts:175](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L175)

MAC verification metadata, present when the PFX includes a MacData block.

##### privateKeys

> `readonly` **privateKeys**: readonly `Uint8Array`\<`ArrayBufferLike`\>[]

Defined in: [pkcs/pfx.ts:173](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L173)

Convenience: raw PKCS#8 DER of each private key extracted from keyBag entries.

---

### ParsedPfxAttribute

Defined in: [pkcs/pfx.ts:112](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L112)

A single PKCS#12 bag attribute as decoded by [`parsePfxDer`](#parsepfxder).

#### Properties

##### oid

> `readonly` **oid**: `string`

Defined in: [pkcs/pfx.ts:114](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L114)

Dotted-decimal OID identifying this attribute type.

##### valuesHex

> `readonly` **valuesHex**: readonly `string`[]

Defined in: [pkcs/pfx.ts:116](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L116)

Hex-encoded DER of each attribute value.

---

### ParsedPfxBagAttributes

Defined in: [pkcs/pfx.ts:120](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L120)

Decoded bag attributes for a single SafeBag inside a PFX.

#### Properties

##### entries

> `readonly` **entries**: readonly [`ParsedPfxAttribute`](#parsedpfxattribute)[]

Defined in: [pkcs/pfx.ts:122](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L122)

All raw attributes as OID + hex-encoded values.

##### friendlyName?

> `readonly` `optional` **friendlyName**: `string`

Defined in: [pkcs/pfx.ts:124](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L124)

Decoded BMPString friendly-name attribute, if present.

##### localKeyId?

> `readonly` `optional` **localKeyId**: `string`

Defined in: [pkcs/pfx.ts:126](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L126)

Hex-encoded localKeyId attribute, if present.

---

### ParsedPkcs12MacData

Defined in: [pkcs/pkcs12-mac.ts:40](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs12-mac.ts#L40)

Decoded PKCS#12 MacData block returned by [`parsePkcs12MacData`](#parsepkcs12macdata).

#### Properties

##### digestAlgorithmName

> `readonly` **digestAlgorithmName**: `string`

Defined in: [pkcs/pkcs12-mac.ts:44](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs12-mac.ts#L44)

Human-readable digest algorithm name (currently `"SHA-256"`).

##### digestAlgorithmOid

> `readonly` **digestAlgorithmOid**: `string`

Defined in: [pkcs/pkcs12-mac.ts:42](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs12-mac.ts#L42)

OID of the digest algorithm (currently always SHA-256).

##### digestHex

> `readonly` **digestHex**: `string`

Defined in: [pkcs/pkcs12-mac.ts:46](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs12-mac.ts#L46)

Hex-encoded MAC digest value.

##### iterations

> `readonly` **iterations**: `number`

Defined in: [pkcs/pkcs12-mac.ts:50](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs12-mac.ts#L50)

Number of PKCS#12 KDF iterations.

##### saltHex

> `readonly` **saltHex**: `string`

Defined in: [pkcs/pkcs12-mac.ts:48](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs12-mac.ts#L48)

Hex-encoded salt bytes used during key derivation.

##### valid?

> `readonly` `optional` **valid**: `boolean`

Defined in: [pkcs/pkcs12-mac.ts:52](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs12-mac.ts#L52)

MAC verification outcome. Present only when a password was supplied during parsing.

---

### ParsedPkcs7SignedData

Defined in: [pkcs/pkcs7.ts:95](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L95)

Decoded PKCS#7 SignedData content, including certificates and signer info.

#### Properties

##### certificates

> `readonly` **certificates**: readonly [`ParsedCertificate`](x509.md#parsedcertificate)\<`Record`\<`never`, `never`\>\>[]

Defined in: [pkcs/pkcs7.ts:109](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L109)

Certificates included in the SignedData certificate set.

##### contentTypeOid

> `readonly` **contentTypeOid**: `string`

Defined in: [pkcs/pkcs7.ts:97](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L97)

Outer ContentInfo type OID (always `pkcs7-signedData`).

##### digestAlgorithmNames

> `readonly` **digestAlgorithmNames**: readonly `string`[]

Defined in: [pkcs/pkcs7.ts:103](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L103)

Human-readable digest algorithm names declared in `digestAlgorithms`.

##### digestAlgorithmOids

> `readonly` **digestAlgorithmOids**: readonly `string`[]

Defined in: [pkcs/pkcs7.ts:101](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L101)

OIDs of digest algorithms declared in `digestAlgorithms`.

##### encapsulatedContent?

> `readonly` `optional` **encapsulatedContent**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [pkcs/pkcs7.ts:107](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L107)

Raw encapsulated content bytes. Absent in degenerate (certs-only) bags.

##### encapsulatedContentTypeOid

> `readonly` **encapsulatedContentTypeOid**: `string`

Defined in: [pkcs/pkcs7.ts:105](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L105)

OID of the encapsulated content type (e.g. `pkcs7-data`).

##### signerInfos

> `readonly` **signerInfos**: readonly [`ParsedPkcs7SignerInfo`](#parsedpkcs7signerinfo)[]

Defined in: [pkcs/pkcs7.ts:111](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L111)

Decoded signer info entries. Empty for degenerate cert bags.

##### version

> `readonly` **version**: `number`

Defined in: [pkcs/pkcs7.ts:99](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L99)

SignedData version number.

---

### ParsedPkcs7SignerInfo

Defined in: [pkcs/pkcs7.ts:65](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L65)

A single SignerInfo decoded from a PKCS#7 SignedData structure.

#### Properties

##### digestAlgorithmName

> `readonly` **digestAlgorithmName**: `string`

Defined in: [pkcs/pkcs7.ts:77](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L77)

Human-readable digest algorithm name (e.g. `"SHA-256"`).

##### digestAlgorithmOid

> `readonly` **digestAlgorithmOid**: `string`

Defined in: [pkcs/pkcs7.ts:75](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L75)

OID of the digest algorithm used to hash the content.

##### hasSignedAttrs

> `readonly` **hasSignedAttrs**: `boolean`

Defined in: [pkcs/pkcs7.ts:89](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L89)

Whether this SignerInfo includes authenticated (signed) attributes.

##### issuer?

> `readonly` `optional` **issuer**: [`ParsedName`](x509.md#parsedname)

Defined in: [pkcs/pkcs7.ts:69](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L69)

Parsed issuer distinguished name, if present (issuerAndSerialNumber signer identifier).

##### serialNumberHex?

> `readonly` `optional` **serialNumberHex**: `string`

Defined in: [pkcs/pkcs7.ts:71](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L71)

Hex-encoded serial number used to locate the signer certificate, if present.

##### signature

> `readonly` **signature**: `Uint8Array`

Defined in: [pkcs/pkcs7.ts:87](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L87)

Raw signature bytes.

##### signatureAlgorithmName

> `readonly` **signatureAlgorithmName**: `string`

Defined in: [pkcs/pkcs7.ts:81](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L81)

Human-readable signature algorithm name.

##### signatureAlgorithmOid

> `readonly` **signatureAlgorithmOid**: `string`

Defined in: [pkcs/pkcs7.ts:79](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L79)

OID of the algorithm used to produce the signature.

##### signatureAlgorithmParametersDer?

> `readonly` `optional` **signatureAlgorithmParametersDer**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [pkcs/pkcs7.ts:83](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L83)

Raw DER of the signature AlgorithmIdentifier parameters, if present.

##### signatureHex

> `readonly` **signatureHex**: `string`

Defined in: [pkcs/pkcs7.ts:85](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L85)

Hex-encoded raw signature bytes.

##### signedAttrsDer?

> `readonly` `optional` **signedAttrsDer**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [pkcs/pkcs7.ts:91](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L91)

Raw DER of signedAttrs with original IMPLICIT [0] tag (0xa0). Present only when `hasSignedAttrs` is true.

##### subjectKeyIdentifier?

> `readonly` `optional` **subjectKeyIdentifier**: `string`

Defined in: [pkcs/pkcs7.ts:73](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L73)

Hex-encoded SubjectKeyIdentifier used to locate the signer certificate, if present.

##### version

> `readonly` **version**: `number`

Defined in: [pkcs/pkcs7.ts:67](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L67)

CMS SignerInfo version (typically 1 for issuerAndSerialNumber).

---

### ParsePfxFailure

Defined in: [pkcs/pfx.ts:186](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L186)

Error payload for a failed PFX parse.

#### Extends

- [`Micro509Error`](result.md#micro509error)\<[`ParsePfxErrorCode`](#parsepfxerrorcode)\>

#### Properties

##### code

> `readonly` **code**: [`ParsePfxErrorCode`](#parsepfxerrorcode)

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`code`](result.md#code-3)

##### details?

> `readonly` `optional` **details**: `Record`\<`never`, `never`\>

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`details`](result.md#details-3)

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`message`](result.md#message-3)

##### ok

> `readonly` **ok**: `false`

Defined in: [pkcs/pfx.ts:188](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L188)

Always `false` for failures.

---

### ParsePfxOptions

Defined in: [pkcs/pfx.ts:94](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L94)

Options for [`parsePfxDer`](#parsepfxder) and [`parsePfxPem`](#parsepfxpem).

#### Properties

##### macPassword?

> `readonly` `optional` **macPassword**: `string`

Defined in: [pkcs/pfx.ts:98](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L98)

Separate password for MAC verification. Falls back to `password` when omitted.

##### password?

> `readonly` `optional` **password**: `string`

Defined in: [pkcs/pfx.ts:96](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L96)

Password used to decrypt PBES2-encrypted ContentInfo entries. Also used for MAC verification when `macPassword` is omitted.

---

### ParsePkcs7Failure

Defined in: [pkcs/pkcs7.ts:122](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L122)

Error payload for a failed PKCS#7 parse.

#### Extends

- [`Micro509Error`](result.md#micro509error)\<[`ParsePkcs7ErrorCode`](#parsepkcs7errorcode)\>

#### Properties

##### code

> `readonly` **code**: [`ParsePkcs7ErrorCode`](#parsepkcs7errorcode)

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`code`](result.md#code-3)

##### details?

> `readonly` `optional` **details**: `Record`\<`never`, `never`\>

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`details`](result.md#details-3)

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`message`](result.md#message-3)

##### ok

> `readonly` **ok**: `false`

Defined in: [pkcs/pkcs7.ts:124](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L124)

Always `false` for failures.

---

### PfxBagAttributesInput

Defined in: [pkcs/pfx.ts:55](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L55)

Optional metadata attached to a certificate or key bag inside a PFX.

#### Properties

##### friendlyName?

> `readonly` `optional` **friendlyName**: `string`

Defined in: [pkcs/pfx.ts:57](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L57)

Human-readable label stored as a BMPString attribute.

##### localKeyId?

> `readonly` `optional` **localKeyId**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [pkcs/pfx.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L59)

Opaque identifier linking a certificate bag to its corresponding key bag.

---

### PfxCertificateBagInput

Defined in: [pkcs/pfx.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L63)

A certificate to embed in a PFX container. Input for [`createPfx`](#createpfx).

#### Properties

##### attributes?

> `readonly` `optional` **attributes**: [`PfxBagAttributesInput`](#pfxbagattributesinput)

Defined in: [pkcs/pfx.ts:67](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L67)

Optional bag-level attributes (friendly name, local key ID).

##### certificate

> `readonly` **certificate**: [`PfxCertificateSource`](#pfxcertificatesource)

Defined in: [pkcs/pfx.ts:65](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L65)

Certificate as PEM text or DER bytes.

---

### PfxMaterial

Defined in: [pkcs/pfx.ts:102](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L102)

DER, PEM, and base64 encodings of a PFX container produced by [`createPfx`](#createpfx).

#### Properties

##### base64

> `readonly` **base64**: `string`

Defined in: [pkcs/pfx.ts:108](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L108)

Base64-encoded DER (no PEM armor).

##### der

> `readonly` **der**: `Uint8Array`

Defined in: [pkcs/pfx.ts:104](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L104)

Raw DER-encoded PFX bytes.

##### pem

> `readonly` **pem**: `string`

Defined in: [pkcs/pfx.ts:106](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L106)

PEM-armored PFX (`-----BEGIN PKCS12-----`).

---

### PfxPrivateKeyBagInput

Defined in: [pkcs/pfx.ts:71](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L71)

A private key to embed in a PFX container. Input for [`createPfx`](#createpfx).

#### Properties

##### attributes?

> `readonly` `optional` **attributes**: [`PfxBagAttributesInput`](#pfxbagattributesinput)

Defined in: [pkcs/pfx.ts:75](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L75)

Optional bag-level attributes (friendly name, local key ID).

##### privateKey

> `readonly` **privateKey**: [`PfxPrivateKeySource`](#pfxprivatekeysource)

Defined in: [pkcs/pfx.ts:73](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L73)

Private key as a WebCrypto `CryptoKey` or raw PKCS#8 DER bytes.

---

### Pkcs12MacOptions

Defined in: [pkcs/pkcs12-mac.ts:30](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs12-mac.ts#L30)

Input for [`createPkcs12MacData`](#createpkcs12macdata).

#### Properties

##### iterations?

> `readonly` `optional` **iterations**: `number`

Defined in: [pkcs/pkcs12-mac.ts:34](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs12-mac.ts#L34)

PKCS#12 KDF iteration count. Default: `2048`.

##### password

> `readonly` **password**: `string`

Defined in: [pkcs/pkcs12-mac.ts:32](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs12-mac.ts#L32)

Password used to derive the HMAC key via the PKCS#12 KDF.

##### salt?

> `readonly` `optional` **salt**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [pkcs/pkcs12-mac.ts:36](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs12-mac.ts#L36)

Random salt. Default: 16 cryptographically random bytes.

---

### Pkcs7CertBag

Defined in: [pkcs/pkcs7.ts:55](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L55)

DER, PEM, and base64 encodings of a PKCS#7 certificate bag.

#### Properties

##### base64

> `readonly` **base64**: `string`

Defined in: [pkcs/pkcs7.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L61)

Base64-encoded DER (no PEM armor).

##### der

> `readonly` **der**: `Uint8Array`

Defined in: [pkcs/pkcs7.ts:57](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L57)

Raw DER-encoded PKCS#7 structure.

##### pem

> `readonly` **pem**: `string`

Defined in: [pkcs/pkcs7.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L59)

PEM-armored PKCS#7 (`-----BEGIN PKCS7-----`).

---

### VerifyPkcs7SignedDataFailure

Defined in: [pkcs/pkcs7.ts:148](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L148)

Error payload for a failed [`verifyPkcs7SignedData`](#verifypkcs7signeddata) call.

#### Extends

- [`Micro509Error`](result.md#micro509error)\<`"signer_not_found"` \| `"signature_invalid"` \| `"message_digest_mismatch"` \| `"content_missing"` \| [`ParsePkcs7ErrorCode`](#parsepkcs7errorcode)\>

#### Properties

##### code

> `readonly` **code**: [`ParsePkcs7ErrorCode`](#parsepkcs7errorcode) \| `"signer_not_found"` \| `"signature_invalid"` \| `"message_digest_mismatch"` \| `"content_missing"`

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`code`](result.md#code-3)

##### details?

> `readonly` `optional` **details**: `Record`\<`never`, `never`\>

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`details`](result.md#details-3)

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](result.md#micro509error).[`message`](result.md#message-3)

##### ok

> `readonly` **ok**: `false`

Defined in: [pkcs/pkcs7.ts:157](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L157)

Always `false` for failures.

## Type Aliases

### ParsedPfxBag

> **ParsedPfxBag** = \{ `attributes`: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes); `bagId`: `string`; `certificate`: [`ParsedCertificate`](x509.md#parsedcertificate); `kind`: `"certificate"`; \} \| \{ `attributes`: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes); `bagId`: `string`; `kind`: `"privateKey"`; `pkcs8Der`: `Uint8Array`; \} \| \{ `attributes`: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes); `bagId`: `string`; `kind`: `"unknown"`; `valueDer`: `Uint8Array`; \}

Defined in: [pkcs/pfx.ts:134](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L134)

Discriminated union of SafeBag types decoded from a PFX container.

Use `kind` to narrow: `'certificate'` | `'privateKey'` | `'unknown'`.

#### Type Declaration

\{ `attributes`: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes); `bagId`: `string`; `certificate`: [`ParsedCertificate`](x509.md#parsedcertificate); `kind`: `"certificate"`; \}

##### attributes

> `readonly` **attributes**: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes)

Decoded bag-level attributes.

##### bagId

> `readonly` **bagId**: `string`

Dotted-decimal OID of the bag type.

##### certificate

> `readonly` **certificate**: [`ParsedCertificate`](x509.md#parsedcertificate)

Parsed certificate from the certBag.

##### kind

> `readonly` **kind**: `"certificate"`

Bag contains an X.509 certificate.

\{ `attributes`: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes); `bagId`: `string`; `kind`: `"privateKey"`; `pkcs8Der`: `Uint8Array`; \}

##### attributes

> `readonly` **attributes**: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes)

Decoded bag-level attributes.

##### bagId

> `readonly` **bagId**: `string`

Dotted-decimal OID of the bag type.

##### kind

> `readonly` **kind**: `"privateKey"`

Bag contains a PKCS#8 private key.

##### pkcs8Der

> `readonly` **pkcs8Der**: `Uint8Array`

Raw DER-encoded PKCS#8 PrivateKeyInfo.

\{ `attributes`: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes); `bagId`: `string`; `kind`: `"unknown"`; `valueDer`: `Uint8Array`; \}

##### attributes

> `readonly` **attributes**: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes)

Decoded bag-level attributes.

##### bagId

> `readonly` **bagId**: `string`

Dotted-decimal OID of the bag type.

##### kind

> `readonly` **kind**: `"unknown"`

Bag type not recognized by this library.

##### valueDer

> `readonly` **valueDer**: `Uint8Array`

Raw DER of the unrecognized bag value.

---

### ParsePfxErrorCode

> **ParsePfxErrorCode** = `"malformed"` \| `"invalid_password"` \| `"password_required"`

Defined in: [pkcs/pfx.ts:183](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L183)

Error codes returned by [`parsePfxDer`](#parsepfxder) and [`parsePfxPem`](#parsepfxpem).

---

### ParsePfxResult

> **ParsePfxResult** = \{ `ok`: `true`; `value`: [`ParsedPfx`](#parsedpfx); \} \| [`ErrorResult`](result.md#errorresult)\<[`ParsePfxErrorCode`](#parsepfxerrorcode), `Record`\<`never`, `never`\>, [`ParsePfxFailure`](#parsepfxfailure)\>

Defined in: [pkcs/pfx.ts:192](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L192)

Success-or-failure result from [`parsePfxDer`](#parsepfxder) / [`parsePfxPem`](#parsepfxpem).

#### Type Declaration

\{ `ok`: `true`; `value`: [`ParsedPfx`](#parsedpfx); \}

##### ok

> `readonly` **ok**: `true`

Parse succeeded.

##### value

> `readonly` **value**: [`ParsedPfx`](#parsedpfx)

Decoded PFX container.

[`ErrorResult`](result.md#errorresult)\<[`ParsePfxErrorCode`](#parsepfxerrorcode), `Record`\<`never`, `never`\>, [`ParsePfxFailure`](#parsepfxfailure)\>

---

### ParsePkcs7CertBagResult

> **ParsePkcs7CertBagResult** = \{ `ok`: `true`; `value`: readonly [`ParsedCertificate`](x509.md#parsedcertificate)[]; \} \| [`ErrorResult`](result.md#errorresult)\<[`ParsePkcs7ErrorCode`](#parsepkcs7errorcode), `Record`\<`never`, `never`\>, [`ParsePkcs7Failure`](#parsepkcs7failure)\>

Defined in: [pkcs/pkcs7.ts:138](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L138)

Success-or-failure result from [`parsePkcs7CertBagDer`](#parsepkcs7certbagder) / [`parsePkcs7CertBagPem`](#parsepkcs7certbagpem).

#### Type Declaration

\{ `ok`: `true`; `value`: readonly [`ParsedCertificate`](x509.md#parsedcertificate)[]; \}

##### ok

> `readonly` **ok**: `true`

Parse succeeded.

##### value

> `readonly` **value**: readonly [`ParsedCertificate`](x509.md#parsedcertificate)[]

Parsed certificates from the cert bag.

[`ErrorResult`](result.md#errorresult)\<[`ParsePkcs7ErrorCode`](#parsepkcs7errorcode), `Record`\<`never`, `never`\>, [`ParsePkcs7Failure`](#parsepkcs7failure)\>

---

### ParsePkcs7ErrorCode

> **ParsePkcs7ErrorCode** = `"malformed"` \| `"not_signed_data"`

Defined in: [pkcs/pkcs7.ts:119](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L119)

Error codes for PKCS#7 parse failures.

---

### ParsePkcs7SignedDataResult

> **ParsePkcs7SignedDataResult** = \{ `ok`: `true`; `value`: [`ParsedPkcs7SignedData`](#parsedpkcs7signeddata); \} \| [`ErrorResult`](result.md#errorresult)\<[`ParsePkcs7ErrorCode`](#parsepkcs7errorcode), `Record`\<`never`, `never`\>, [`ParsePkcs7Failure`](#parsepkcs7failure)\>

Defined in: [pkcs/pkcs7.ts:128](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L128)

Success-or-failure result from [`parsePkcs7SignedDataDer`](#parsepkcs7signeddatader) / [`parsePkcs7SignedDataPem`](#parsepkcs7signeddatapem).

#### Type Declaration

\{ `ok`: `true`; `value`: [`ParsedPkcs7SignedData`](#parsedpkcs7signeddata); \}

##### ok

> `readonly` **ok**: `true`

Parse succeeded.

##### value

> `readonly` **value**: [`ParsedPkcs7SignedData`](#parsedpkcs7signeddata)

Decoded SignedData.

[`ErrorResult`](result.md#errorresult)\<[`ParsePkcs7ErrorCode`](#parsepkcs7errorcode), `Record`\<`never`, `never`\>, [`ParsePkcs7Failure`](#parsepkcs7failure)\>

---

### PfxCertificateSource

> **PfxCertificateSource** = `string` \| `Uint8Array`

Defined in: [pkcs/pfx.ts:50](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L50)

PEM string or DER bytes for a certificate to include in a PFX bag.

---

### PfxEncryptionOptions

> **PfxEncryptionOptions** = [`Pbes2EncryptionOptions`](keys.md#pbes2encryptionoptions)

Defined in: [pkcs/pfx.ts:91](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L91)

PBES2 encryption settings for PFX key-bag protection. Alias of [`Pbes2EncryptionOptions`](keys.md#pbes2encryptionoptions).

---

### PfxPrivateKeySource

> **PfxPrivateKeySource** = `CryptoKey` \| `Uint8Array`

Defined in: [pkcs/pfx.ts:52](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L52)

A WebCrypto private key or raw PKCS#8 DER bytes for a PFX key bag.

---

### Pkcs7CertificateSource

> **Pkcs7CertificateSource** = `string` \| `Uint8Array`

Defined in: [pkcs/pkcs7.ts:52](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L52)

PEM text (may contain multiple CERTIFICATE blocks) or raw DER bytes.

---

### VerifyPkcs7SignedDataResult

> **VerifyPkcs7SignedDataResult** = \{ `ok`: `true`; `value`: [`ParsedPkcs7SignedData`](#parsedpkcs7signeddata); \} \| [`ErrorResult`](result.md#errorresult)\<`"signer_not_found"` \| `"signature_invalid"` \| `"message_digest_mismatch"` \| `"content_missing"` \| [`ParsePkcs7ErrorCode`](#parsepkcs7errorcode), `Record`\<`never`, `never`\>, [`VerifyPkcs7SignedDataFailure`](#verifypkcs7signeddatafailure)\>

Defined in: [pkcs/pkcs7.ts:161](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L161)

Success-or-failure result from [`verifyPkcs7SignedData`](#verifypkcs7signeddata).

#### Type Declaration

\{ `ok`: `true`; `value`: [`ParsedPkcs7SignedData`](#parsedpkcs7signeddata); \}

##### ok

> `readonly` **ok**: `true`

Verification succeeded.

##### value

> `readonly` **value**: [`ParsedPkcs7SignedData`](#parsedpkcs7signeddata)

The verified SignedData structure.

[`ErrorResult`](result.md#errorresult)\<`"signer_not_found"` \| `"signature_invalid"` \| `"message_digest_mismatch"` \| `"content_missing"` \| [`ParsePkcs7ErrorCode`](#parsepkcs7errorcode), `Record`\<`never`, `never`\>, [`VerifyPkcs7SignedDataFailure`](#verifypkcs7signeddatafailure)\>

## Functions

### createPfx()

> **createPfx**(`input`): `Promise`\<[`PfxMaterial`](#pfxmaterial)\>

Defined in: [pkcs/pfx.ts:224](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L224)

Builds a PKCS#12/PFX archive containing certificates and/or private keys.

When `encryption` is provided, the key-bag ContentInfo is PBES2-encrypted.
When `mac` is provided, a PKCS#12 MAC integrity block is appended.

#### Parameters

##### input

[`CreatePfxInput`](#createpfxinput)

#### Returns

`Promise`\<[`PfxMaterial`](#pfxmaterial)\>

#### Example

```ts
import { createPfx } from 'micro509';

const pfx = await createPfx({
  certificates: [{ certificate: certPem }],
  privateKeys: [{ privateKey: keyPair.privateKey }],
  encryption: { password: 's3cret' },
  mac: { password: 's3cret' },
});
// pfx.der, pfx.pem, pfx.base64
```

---

### createPkcs12MacData()

> **createPkcs12MacData**(`authenticatedSafe`, `options`): `Promise`\<\{ `der`: `Uint8Array`; `parsed`: [`ParsedPkcs12MacData`](#parsedpkcs12macdata); \}\>

Defined in: [pkcs/pkcs12-mac.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs12-mac.ts#L59)

Computes a PKCS#12 HMAC-SHA-256 MAC over the AuthenticatedSafe and returns
the DER-encoded MacData block alongside its parsed representation.

#### Parameters

##### authenticatedSafe

`Uint8Array`

##### options

[`Pkcs12MacOptions`](#pkcs12macoptions)

#### Returns

`Promise`\<\{ `der`: `Uint8Array`; `parsed`: [`ParsedPkcs12MacData`](#parsedpkcs12macdata); \}\>

---

### createPkcs7CertBagDer()

> **createPkcs7CertBagDer**(`certificates`): `Uint8Array`

Defined in: [pkcs/pkcs7.ts:187](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L187)

Creates a degenerate PKCS#7 SignedData structure containing only certificates (no signers).

Returns the raw DER encoding. Use [`createPkcs7CertBagPem`](#createpkcs7certbagpem) for PEM + base64.

#### Parameters

##### certificates

readonly [`Pkcs7CertificateSource`](#pkcs7certificatesource)[]

#### Returns

`Uint8Array`

---

### createPkcs7CertBagPem()

> **createPkcs7CertBagPem**(`certificates`): [`Pkcs7CertBag`](#pkcs7certbag)

Defined in: [pkcs/pkcs7.ts:202](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L202)

Creates a degenerate PKCS#7 SignedData certificate bag and returns DER, PEM, and base64 forms.

#### Parameters

##### certificates

readonly [`Pkcs7CertificateSource`](#pkcs7certificatesource)[]

#### Returns

[`Pkcs7CertBag`](#pkcs7certbag)

---

### parsePfxDer()

> **parsePfxDer**(`der`, `options?`): `Promise`\<[`ParsePfxResult`](#parsepfxresult)\>

Defined in: [pkcs/pfx.ts:285](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L285)

Decodes a DER-encoded PKCS#12/PFX container into its constituent bags.

Returns a result union — check `ok` before accessing `value`.
Encrypted containers require `options.password`. MAC verification uses
`options.macPassword` (falls back to `options.password`).

#### Parameters

##### der

`Uint8Array`

##### options?

[`ParsePfxOptions`](#parsepfxoptions)

#### Returns

`Promise`\<[`ParsePfxResult`](#parsepfxresult)\>

#### Example

```ts
import { parsePfxDer } from 'micro509';

const result = await parsePfxDer(pfxBytes, {
  password: 's3cret',
});
if (result.ok) {
  console.log(result.value.certificates.length);
}
```

---

### parsePfxPem()

> **parsePfxPem**(`pem`, `options?`): `Promise`\<[`ParsePfxResult`](#parsepfxresult)\>

Defined in: [pkcs/pfx.ts:359](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L359)

Decodes a PEM-armored PKCS#12/PFX container. Expects exactly one `PKCS12` block.

Delegates to [`parsePfxDer`](#parsepfxder) after PEM decoding.

#### Parameters

##### pem

`string`

##### options?

[`ParsePfxOptions`](#parsepfxoptions)

#### Returns

`Promise`\<[`ParsePfxResult`](#parsepfxresult)\>

#### Example

```ts
import { parsePfxPem } from 'micro509';

const result = await parsePfxPem(pfxPemString, {
  password: 's3cret',
});
if (result.ok) {
  console.log(result.value.privateKeys.length);
}
```

---

### parsePkcs12MacData()

> **parsePkcs12MacData**(`der`, `authenticatedSafe`, `password?`): `Promise`\<[`ParsedPkcs12MacData`](#parsedpkcs12macdata)\>

Defined in: [pkcs/pkcs12-mac.ts:93](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs12-mac.ts#L93)

Decodes a DER-encoded MacData block. When `password` is provided, verifies
the MAC and sets the `valid` flag on the returned structure.

#### Parameters

##### der

`Uint8Array`

##### authenticatedSafe

`Uint8Array`

##### password?

`string`

#### Returns

`Promise`\<[`ParsedPkcs12MacData`](#parsedpkcs12macdata)\>

---

### parsePkcs7CertBagDer()

> **parsePkcs7CertBagDer**(`der`): [`ParsePkcs7CertBagResult`](#parsepkcs7certbagresult)

Defined in: [pkcs/pkcs7.ts:218](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L218)

Parses a DER-encoded PKCS#7 cert bag, returning the contained certificates.

#### Parameters

##### der

`Uint8Array`

#### Returns

[`ParsePkcs7CertBagResult`](#parsepkcs7certbagresult)

---

### parsePkcs7CertBagPem()

> **parsePkcs7CertBagPem**(`pem`): [`ParsePkcs7CertBagResult`](#parsepkcs7certbagresult)

Defined in: [pkcs/pkcs7.ts:227](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L227)

Parses a PEM-armored PKCS#7 cert bag. Expects exactly one `PKCS7` PEM block.

#### Parameters

##### pem

`string`

#### Returns

[`ParsePkcs7CertBagResult`](#parsepkcs7certbagresult)

---

### parsePkcs7SignedDataDer()

> **parsePkcs7SignedDataDer**(`der`): [`ParsePkcs7SignedDataResult`](#parsepkcs7signeddataresult)

Defined in: [pkcs/pkcs7.ts:248](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L248)

Decodes a DER-encoded PKCS#7 ContentInfo expecting `signedData` content type.

#### Parameters

##### der

`Uint8Array`

#### Returns

[`ParsePkcs7SignedDataResult`](#parsepkcs7signeddataresult)

---

### parsePkcs7SignedDataPem()

> **parsePkcs7SignedDataPem**(`pem`): [`ParsePkcs7SignedDataResult`](#parsepkcs7signeddataresult)

Defined in: [pkcs/pkcs7.ts:309](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L309)

Decodes a PEM-armored PKCS#7 SignedData. Expects exactly one `PKCS7` PEM block.

#### Parameters

##### pem

`string`

#### Returns

[`ParsePkcs7SignedDataResult`](#parsepkcs7signeddataresult)

---

### verifyPkcs7SignedData()

> **verifyPkcs7SignedData**(`input`): `Promise`\<[`VerifyPkcs7SignedDataResult`](#verifypkcs7signeddataresult)\>

Defined in: [pkcs/pkcs7.ts:343](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L343)

Verifies all signer signatures in a PKCS#7 SignedData structure.

Accepts PEM text, raw DER, or an already-parsed [`ParsedPkcs7SignedData`](#parsedpkcs7signeddata).
For each signer, locates the matching certificate in the embedded set and
verifies the signature (including signed-attribute digest checks per RFC 5652 Section 5.4).

#### Parameters

##### input

`string` | `Uint8Array`\<`ArrayBufferLike`\> | [`ParsedPkcs7SignedData`](#parsedpkcs7signeddata)

#### Returns

`Promise`\<[`VerifyPkcs7SignedDataResult`](#verifypkcs7signeddataresult)\>

#### Example

```ts
import { verifyPkcs7SignedData } from 'micro509';

const result = await verifyPkcs7SignedData(pkcs7Pem);
if (result.ok) {
  console.log('all signers verified');
}
```
