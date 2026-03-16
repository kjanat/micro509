[micro509](modules.md) / pem

# pem

Canonical PEM boundary surface.
Owns the stable `micro509/pem` entrypoint.

## Interfaces

### CategorizedPemBlocks

Defined in: [pem/pem.ts:26](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L26)

PEM blocks grouped by their label into well-known PKI categories.
Blocks that don't match any known label land in [`others`](#others).

#### Properties

##### certificateRequests

> `readonly` **certificateRequests**: readonly [`PemBlock`](#pemblock)[]

Defined in: [pem/pem.ts:30](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L30)

Blocks with label `CERTIFICATE REQUEST`.

##### certificates

> `readonly` **certificates**: readonly [`PemBlock`](#pemblock)[]

Defined in: [pem/pem.ts:28](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L28)

Blocks with label `CERTIFICATE`.

##### others

> `readonly` **others**: readonly [`PemBlock`](#pemblock)[]

Defined in: [pem/pem.ts:36](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L36)

Blocks whose label doesn't match any of the above categories.

##### privateKeys

> `readonly` **privateKeys**: readonly [`PemBlock`](#pemblock)[]

Defined in: [pem/pem.ts:32](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L32)

Blocks with label `PRIVATE KEY`, `RSA PRIVATE KEY`, or `EC PRIVATE KEY`.

##### publicKeys

> `readonly` **publicKeys**: readonly [`PemBlock`](#pemblock)[]

Defined in: [pem/pem.ts:34](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L34)

Blocks with label `PUBLIC KEY`.

---

### PemBlock

Defined in: [pem/pem.ts:13](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L13)

A single decoded PEM block with its label, decoded DER bytes, and original PEM text.

#### Properties

##### bytes

> `readonly` **bytes**: `Uint8Array`

Defined in: [pem/pem.ts:17](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L17)

Decoded DER content of this block.

##### label

> `readonly` **label**: `string`

Defined in: [pem/pem.ts:15](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L15)

RFC 7468 label between the `BEGIN` / `END` markers (e.g. `"CERTIFICATE"`).

##### pem

> `readonly` **pem**: `string`

Defined in: [pem/pem.ts:19](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L19)

The original PEM text including `BEGIN`/`END` lines.

## Functions

### categorizePemBlocks()

> **categorizePemBlocks**(`input`): [`CategorizedPemBlocks`](#categorizedpemblocks)

Defined in: [pem/pem.ts:115](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L115)

Groups PEM blocks by label into well-known PKI categories
(certificates, CSRs, private keys, public keys, and everything else).
Accepts either raw PEM text or pre-split [`PemBlock`](#pemblock) entries.

#### Parameters

##### input

`string` | readonly [`PemBlock`](#pemblock)[]

#### Returns

[`CategorizedPemBlocks`](#categorizedpemblocks)

---

### pemDecode()

> **pemDecode**(`label`, `pem`): `Uint8Array`

Defined in: [pem/pem.ts:58](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L58)

Extracts and base64-decodes the DER content from a PEM string.
Throws if the `BEGIN`/`END` markers don't match `label`.

#### Parameters

##### label

`string`

Expected PEM type label.

##### pem

`string`

PEM-encoded text (may contain `\r`).

#### Returns

`Uint8Array`

---

### pemEncode()

> **pemEncode**(`label`, `der`): `string`

Defined in: [pem/pem.ts:45](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L45)

Wraps DER bytes in a PEM envelope with 64-character base64 lines.

#### Parameters

##### label

`string`

PEM type label (e.g. `"CERTIFICATE"`, `"PRIVATE KEY"`).

##### der

`Uint8Array`

Raw DER-encoded content.

#### Returns

`string`

---

### splitPemBlocks()

> **splitPemBlocks**(`input`): readonly [`PemBlock`](#pemblock)[]

Defined in: [pem/pem.ts:82](https://github.com/kjanat/ts-x509/blob/vitepress/src/pem/pem.ts#L82)

Finds all `BEGIN`/`END`-delimited PEM blocks in a string and returns
them as parsed [`PemBlock`](#pemblock) entries. Handles concatenated PEM files
and ignores non-PEM text between blocks.

#### Parameters

##### input

`string`

#### Returns

readonly [`PemBlock`](#pemblock)[]
