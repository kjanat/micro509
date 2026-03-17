[micro509](modules.md) / pkcs

# pkcs

PKCS container APIs: PFX/PKCS#12 and PKCS#7/CMS.

Owns PFX archive creation and parsing, PKCS#7 certificate bags and SignedData,
and PKCS#12 MAC integrity helpers.

## Interfaces

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

## Functions

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
