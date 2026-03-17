[micro509](modules.md) / pkcs

# pkcs

PKCS container APIs: PFX/PKCS#12 and PKCS#7/CMS.

Owns PFX archive creation and parsing, PKCS#7 certificate bags and SignedData,
and PKCS#12 MAC integrity helpers.

## Interfaces

### CreatePfxInput

Defined in: [pkcs/pfx.ts:84](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L84)

Input for [`createPfx`](#createpfx).

#### Properties

##### certificates?

> `readonly` `optional` **certificates**: readonly [`PfxCertificateBagInput`](#pfxcertificatebaginput)[]

Defined in: [pkcs/pfx.ts:86](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L86)

Certificates to include as certBag entries.

##### encryption?

> `readonly` `optional` **encryption**: [`Pbes2EncryptionOptions`](keys.md#pbes2encryptionoptions)

Defined in: [pkcs/pfx.ts:90](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L90)

PBES2 encryption settings for the key-bag ContentInfo. Omit for unencrypted.

##### mac?

> `readonly` `optional` **mac**: [`Pkcs12MacOptions`](#pkcs12macoptions)

Defined in: [pkcs/pfx.ts:92](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L92)

PKCS#12 MAC integrity settings. Omit to skip MAC generation.

##### privateKeys?

> `readonly` `optional` **privateKeys**: readonly [`PfxPrivateKeyBagInput`](#pfxprivatekeybaginput)[]

Defined in: [pkcs/pfx.ts:88](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L88)

Private keys to include as keyBag entries.

---

### ParsedPfx

Defined in: [pkcs/pfx.ts:172](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L172)

Fully decoded PFX container returned by [`parsePfxDer`](#parsepfxder) / [`parsePfxPem`](#parsepfxpem).

#### Properties

##### bags

> `readonly` **bags**: readonly [`ParsedPfxBag`](#parsedpfxbag)[]

Defined in: [pkcs/pfx.ts:174](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L174)

All SafeBags in the PFX, including unknown types.

##### certificates

> `readonly` **certificates**: readonly [`ParsedCertificate`](x509.md#parsedcertificate)\<`Record`\<`never`, `never`\>\>[]

Defined in: [pkcs/pfx.ts:176](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L176)

Convenience: only the parsed certificates extracted from certBag entries.

##### macData?

> `readonly` `optional` **macData**: [`ParsedPkcs12MacData`](#parsedpkcs12macdata)

Defined in: [pkcs/pfx.ts:180](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L180)

MAC verification metadata, present when the PFX includes a MacData block.

##### privateKeys

> `readonly` **privateKeys**: readonly `Uint8Array`\<`ArrayBufferLike`\>[]

Defined in: [pkcs/pfx.ts:178](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L178)

Convenience: raw PKCS#8 DER of each private key extracted from keyBag entries.

---

### ParsedPfxAttribute

Defined in: [pkcs/pfx.ts:117](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L117)

A single PKCS#12 bag attribute as decoded by [`parsePfxDer`](#parsepfxder).

#### Properties

##### oid

> `readonly` **oid**: `string`

Defined in: [pkcs/pfx.ts:119](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L119)

Dotted-decimal OID identifying this attribute type.

##### valuesHex

> `readonly` **valuesHex**: readonly `string`[]

Defined in: [pkcs/pfx.ts:121](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L121)

Hex-encoded DER of each attribute value.

---

### ParsedPfxBagAttributes

Defined in: [pkcs/pfx.ts:125](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L125)

Decoded bag attributes for a single SafeBag inside a PFX.

#### Properties

##### entries

> `readonly` **entries**: readonly [`ParsedPfxAttribute`](#parsedpfxattribute)[]

Defined in: [pkcs/pfx.ts:127](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L127)

All raw attributes as OID + hex-encoded values.

##### friendlyName?

> `readonly` `optional` **friendlyName**: `string`

Defined in: [pkcs/pfx.ts:129](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L129)

Decoded BMPString friendly-name attribute, if present.

##### localKeyId?

> `readonly` `optional` **localKeyId**: `string`

Defined in: [pkcs/pfx.ts:131](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L131)

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

Defined in: [pkcs/pkcs7.ts:96](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L96)

Decoded PKCS#7 SignedData content, including certificates and signer info.

#### Properties

##### certificates

> `readonly` **certificates**: readonly [`ParsedCertificate`](x509.md#parsedcertificate)\<`Record`\<`never`, `never`\>\>[]

Defined in: [pkcs/pkcs7.ts:112](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L112)

Certificates included in the SignedData certificate set.

##### contentTypeOid

> `readonly` **contentTypeOid**: `string`

Defined in: [pkcs/pkcs7.ts:100](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L100)

Outer ContentInfo type OID (always `pkcs7-signedData`).

##### der?

> `readonly` `optional` **der**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [pkcs/pkcs7.ts:98](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L98)

Original DER bytes when this object came from [`parsePkcs7SignedDataDer`](#parsepkcs7signeddatader) or PEM parsing.

##### digestAlgorithmNames

> `readonly` **digestAlgorithmNames**: readonly `string`[]

Defined in: [pkcs/pkcs7.ts:106](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L106)

Human-readable digest algorithm names declared in `digestAlgorithms`.

##### digestAlgorithmOids

> `readonly` **digestAlgorithmOids**: readonly `string`[]

Defined in: [pkcs/pkcs7.ts:104](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L104)

OIDs of digest algorithms declared in `digestAlgorithms`.

##### encapsulatedContent?

> `readonly` `optional` **encapsulatedContent**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [pkcs/pkcs7.ts:110](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L110)

Raw encapsulated content bytes. Absent in degenerate (certs-only) bags.

##### encapsulatedContentTypeOid

> `readonly` **encapsulatedContentTypeOid**: `string`

Defined in: [pkcs/pkcs7.ts:108](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L108)

OID of the encapsulated content type (e.g. `pkcs7-data`).

##### signerInfos

> `readonly` **signerInfos**: readonly [`ParsedPkcs7SignerInfo`](#parsedpkcs7signerinfo)[]

Defined in: [pkcs/pkcs7.ts:114](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L114)

Decoded signer info entries. Empty for degenerate cert bags.

##### version

> `readonly` **version**: `number`

Defined in: [pkcs/pkcs7.ts:102](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L102)

SignedData version number.

---

### ParsedPkcs7SignerInfo

Defined in: [pkcs/pkcs7.ts:66](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L66)

A single SignerInfo decoded from a PKCS#7 SignedData structure.

#### Properties

##### digestAlgorithmName

> `readonly` **digestAlgorithmName**: `string`

Defined in: [pkcs/pkcs7.ts:78](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L78)

Human-readable digest algorithm name (e.g. `"SHA-256"`).

##### digestAlgorithmOid

> `readonly` **digestAlgorithmOid**: `string`

Defined in: [pkcs/pkcs7.ts:76](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L76)

OID of the digest algorithm used to hash the content.

##### hasSignedAttrs

> `readonly` **hasSignedAttrs**: `boolean`

Defined in: [pkcs/pkcs7.ts:90](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L90)

Whether this SignerInfo includes authenticated (signed) attributes.

##### issuer?

> `readonly` `optional` **issuer**: [`ParsedName`](x509.md#parsedname)

Defined in: [pkcs/pkcs7.ts:70](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L70)

Parsed issuer distinguished name, if present (issuerAndSerialNumber signer identifier).

##### serialNumberHex?

> `readonly` `optional` **serialNumberHex**: `string`

Defined in: [pkcs/pkcs7.ts:72](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L72)

Hex-encoded serial number used to locate the signer certificate, if present.

##### signature

> `readonly` **signature**: `Uint8Array`

Defined in: [pkcs/pkcs7.ts:88](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L88)

Raw signature bytes.

##### signatureAlgorithmName

> `readonly` **signatureAlgorithmName**: `string`

Defined in: [pkcs/pkcs7.ts:82](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L82)

Human-readable signature algorithm name.

##### signatureAlgorithmOid

> `readonly` **signatureAlgorithmOid**: `string`

Defined in: [pkcs/pkcs7.ts:80](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L80)

OID of the algorithm used to produce the signature.

##### signatureAlgorithmParametersDer?

> `readonly` `optional` **signatureAlgorithmParametersDer**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [pkcs/pkcs7.ts:84](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L84)

Raw DER of the signature AlgorithmIdentifier parameters, if present.

##### signatureHex

> `readonly` **signatureHex**: `string`

Defined in: [pkcs/pkcs7.ts:86](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L86)

Hex-encoded raw signature bytes.

##### signedAttrsDer?

> `readonly` `optional` **signedAttrsDer**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [pkcs/pkcs7.ts:92](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L92)

Raw DER of signedAttrs with original IMPLICIT [0] tag (0xa0). Present only when `hasSignedAttrs` is true.

##### subjectKeyIdentifier?

> `readonly` `optional` **subjectKeyIdentifier**: `string`

Defined in: [pkcs/pkcs7.ts:74](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L74)

Hex-encoded SubjectKeyIdentifier used to locate the signer certificate, if present.

##### version

> `readonly` **version**: `number`

Defined in: [pkcs/pkcs7.ts:68](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L68)

CMS SignerInfo version (typically 1 for issuerAndSerialNumber).

---

### ParsePfxFailure

Defined in: [pkcs/pfx.ts:191](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L191)

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

Defined in: [pkcs/pfx.ts:193](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L193)

Always `false` for failures.

---

### ParsePfxOptions

Defined in: [pkcs/pfx.ts:99](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L99)

Options for [`parsePfxDer`](#parsepfxder) and [`parsePfxPem`](#parsepfxpem).

#### Properties

##### macPassword?

> `readonly` `optional` **macPassword**: `string`

Defined in: [pkcs/pfx.ts:103](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L103)

Separate password for MAC verification. Falls back to `password` when omitted.

##### password?

> `readonly` `optional` **password**: `string`

Defined in: [pkcs/pfx.ts:101](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L101)

Password used to decrypt PBES2-encrypted ContentInfo entries. Also used for MAC verification when `macPassword` is omitted.

---

### ParsePkcs7Failure

Defined in: [pkcs/pkcs7.ts:125](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L125)

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

Defined in: [pkcs/pkcs7.ts:127](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L127)

Always `false` for failures.

---

### PfxBagAttributesInput

Defined in: [pkcs/pfx.ts:60](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L60)

Optional metadata attached to a certificate or key bag inside a PFX.

#### Properties

##### friendlyName?

> `readonly` `optional` **friendlyName**: `string`

Defined in: [pkcs/pfx.ts:62](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L62)

Human-readable label stored as a BMPString attribute.

##### localKeyId?

> `readonly` `optional` **localKeyId**: `Uint8Array`\<`ArrayBufferLike`\>

Defined in: [pkcs/pfx.ts:64](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L64)

Opaque identifier linking a certificate bag to its corresponding key bag.

---

### PfxCertificateBagInput

Defined in: [pkcs/pfx.ts:68](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L68)

A certificate to embed in a PFX container. Input for [`createPfx`](#createpfx).

#### Properties

##### attributes?

> `readonly` `optional` **attributes**: [`PfxBagAttributesInput`](#pfxbagattributesinput)

Defined in: [pkcs/pfx.ts:72](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L72)

Optional bag-level attributes (friendly name, local key ID).

##### certificate

> `readonly` **certificate**: [`PfxCertificateSource`](#pfxcertificatesource)

Defined in: [pkcs/pfx.ts:70](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L70)

Certificate as PEM text or DER bytes.

---

### PfxMaterial

Defined in: [pkcs/pfx.ts:107](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L107)

DER, PEM, and base64 encodings of a PFX container produced by [`createPfx`](#createpfx).

#### Properties

##### base64

> `readonly` **base64**: `string`

Defined in: [pkcs/pfx.ts:113](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L113)

Base64-encoded DER (no PEM armor).

##### der

> `readonly` **der**: `Uint8Array`

Defined in: [pkcs/pfx.ts:109](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L109)

Raw DER-encoded PFX bytes.

##### pem

> `readonly` **pem**: `string`

Defined in: [pkcs/pfx.ts:111](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L111)

PEM-armored PFX (`-----BEGIN PKCS12-----`).

---

### PfxPrivateKeyBagInput

Defined in: [pkcs/pfx.ts:76](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L76)

A private key to embed in a PFX container. Input for [`createPfx`](#createpfx).

#### Properties

##### attributes?

> `readonly` `optional` **attributes**: [`PfxBagAttributesInput`](#pfxbagattributesinput)

Defined in: [pkcs/pfx.ts:80](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L80)

Optional bag-level attributes (friendly name, local key ID).

##### privateKey

> `readonly` **privateKey**: [`PfxPrivateKeySource`](#pfxprivatekeysource)

Defined in: [pkcs/pfx.ts:78](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L78)

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

Defined in: [pkcs/pkcs7.ts:56](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L56)

DER, PEM, and base64 encodings of a PKCS#7 certificate bag.

#### Properties

##### base64

> `readonly` **base64**: `string`

Defined in: [pkcs/pkcs7.ts:62](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L62)

Base64-encoded DER (no PEM armor).

##### der

> `readonly` **der**: `Uint8Array`

Defined in: [pkcs/pkcs7.ts:58](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L58)

Raw DER-encoded PKCS#7 structure.

##### pem

> `readonly` **pem**: `string`

Defined in: [pkcs/pkcs7.ts:60](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L60)

PEM-armored PKCS#7 (`-----BEGIN PKCS7-----`).

---

### VerifyPkcs7SignedDataFailure

Defined in: [pkcs/pkcs7.ts:151](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L151)

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

Defined in: [pkcs/pkcs7.ts:160](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L160)

Always `false` for failures.

## Type Aliases

### ParsedPfxBag

> **ParsedPfxBag** = \{ `attributes`: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes); `bagId`: `string`; `certificate`: [`ParsedCertificate`](x509.md#parsedcertificate); `kind`: `"certificate"`; \} \| \{ `attributes`: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes); `bagId`: `string`; `kind`: `"privateKey"`; `pkcs8Der`: `Uint8Array`; \} \| \{ `attributes`: [`ParsedPfxBagAttributes`](#parsedpfxbagattributes); `bagId`: `string`; `kind`: `"unknown"`; `valueDer`: `Uint8Array`; \}

Defined in: [pkcs/pfx.ts:139](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L139)

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

Defined in: [pkcs/pfx.ts:188](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L188)

Error codes returned by [`parsePfxDer`](#parsepfxder) and [`parsePfxPem`](#parsepfxpem).

---

### ParsePfxResult

> **ParsePfxResult** = \{ `ok`: `true`; `value`: [`ParsedPfx`](#parsedpfx); \} \| [`ErrorResult`](result.md#errorresult)\<[`ParsePfxErrorCode`](#parsepfxerrorcode), `Record`\<`never`, `never`\>, [`ParsePfxFailure`](#parsepfxfailure)\>

Defined in: [pkcs/pfx.ts:197](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L197)

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

Defined in: [pkcs/pkcs7.ts:141](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L141)

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

Defined in: [pkcs/pkcs7.ts:122](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L122)

Error codes for PKCS#7 parse failures.

---

### ParsePkcs7SignedDataResult

> **ParsePkcs7SignedDataResult** = \{ `ok`: `true`; `value`: [`ParsedPkcs7SignedData`](#parsedpkcs7signeddata); \} \| [`ErrorResult`](result.md#errorresult)\<[`ParsePkcs7ErrorCode`](#parsepkcs7errorcode), `Record`\<`never`, `never`\>, [`ParsePkcs7Failure`](#parsepkcs7failure)\>

Defined in: [pkcs/pkcs7.ts:131](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L131)

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

Defined in: [pkcs/pfx.ts:55](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L55)

PEM string or DER bytes for a certificate to include in a PFX bag.

---

### PfxEncryptionOptions

> **PfxEncryptionOptions** = [`Pbes2EncryptionOptions`](keys.md#pbes2encryptionoptions)

Defined in: [pkcs/pfx.ts:96](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L96)

PBES2 encryption settings for PFX key-bag protection. Alias of [`Pbes2EncryptionOptions`](keys.md#pbes2encryptionoptions).

---

### PfxPrivateKeySource

> **PfxPrivateKeySource** = `CryptoKey` \| `Uint8Array`

Defined in: [pkcs/pfx.ts:57](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L57)

A WebCrypto private key or raw PKCS#8 DER bytes for a PFX key bag.

---

### Pkcs7CertificateSource

> **Pkcs7CertificateSource** = `string` \| `Uint8Array`

Defined in: [pkcs/pkcs7.ts:53](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L53)

PEM text (may contain multiple CERTIFICATE blocks) or raw DER bytes.

---

### VerifyPkcs7SignedDataResult

> **VerifyPkcs7SignedDataResult** = \{ `ok`: `true`; `value`: [`ParsedPkcs7SignedData`](#parsedpkcs7signeddata); \} \| [`ErrorResult`](result.md#errorresult)\<`"signer_not_found"` \| `"signature_invalid"` \| `"message_digest_mismatch"` \| `"content_missing"` \| [`ParsePkcs7ErrorCode`](#parsepkcs7errorcode), `Record`\<`never`, `never`\>, [`VerifyPkcs7SignedDataFailure`](#verifypkcs7signeddatafailure)\>

Defined in: [pkcs/pkcs7.ts:164](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L164)

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

Defined in: [pkcs/pfx.ts:229](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L229)

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

Defined in: [pkcs/pkcs7.ts:190](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L190)

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

Defined in: [pkcs/pkcs7.ts:205](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L205)

Creates a degenerate PKCS#7 SignedData certificate bag and returns DER, PEM, and base64 forms.

#### Parameters

##### certificates

readonly [`Pkcs7CertificateSource`](#pkcs7certificatesource)[]

#### Returns

[`Pkcs7CertBag`](#pkcs7certbag)

---

### parsePfxDer()

> **parsePfxDer**(`der`, `options?`): `Promise`\<[`ParsePfxResult`](#parsepfxresult)\>

Defined in: [pkcs/pfx.ts:290](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L290)

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

Defined in: [pkcs/pfx.ts:371](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pfx.ts#L371)

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

Defined in: [pkcs/pkcs7.ts:221](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L221)

Parses a DER-encoded PKCS#7 cert bag, returning the contained certificates.

#### Parameters

##### der

`Uint8Array`

#### Returns

[`ParsePkcs7CertBagResult`](#parsepkcs7certbagresult)

---

### parsePkcs7CertBagPem()

> **parsePkcs7CertBagPem**(`pem`): [`ParsePkcs7CertBagResult`](#parsepkcs7certbagresult)

Defined in: [pkcs/pkcs7.ts:230](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L230)

Parses a PEM-armored PKCS#7 cert bag. Expects exactly one `PKCS7` PEM block.

#### Parameters

##### pem

`string`

#### Returns

[`ParsePkcs7CertBagResult`](#parsepkcs7certbagresult)

---

### parsePkcs7SignedDataDer()

> **parsePkcs7SignedDataDer**(`der`): [`ParsePkcs7SignedDataResult`](#parsepkcs7signeddataresult)

Defined in: [pkcs/pkcs7.ts:251](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L251)

Decodes a DER-encoded PKCS#7 ContentInfo expecting `signedData` content type.

#### Parameters

##### der

`Uint8Array`

#### Returns

[`ParsePkcs7SignedDataResult`](#parsepkcs7signeddataresult)

---

### parsePkcs7SignedDataPem()

> **parsePkcs7SignedDataPem**(`pem`): [`ParsePkcs7SignedDataResult`](#parsepkcs7signeddataresult)

Defined in: [pkcs/pkcs7.ts:345](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L345)

Decodes a PEM-armored PKCS#7 SignedData. Expects exactly one `PKCS7` PEM block.

#### Parameters

##### pem

`string`

#### Returns

[`ParsePkcs7SignedDataResult`](#parsepkcs7signeddataresult)

---

### verifyPkcs7SignedData()

> **verifyPkcs7SignedData**(`input`): `Promise`\<[`VerifyPkcs7SignedDataResult`](#verifypkcs7signeddataresult)\>

Defined in: [pkcs/pkcs7.ts:379](https://github.com/kjanat/ts-x509/blob/vitepress/src/pkcs/pkcs7.ts#L379)

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
