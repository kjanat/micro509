[micro509](modules.md) / result

# result

Canonical shared result surface.
Owns the stable `micro509/result` entrypoint.

## Interfaces

### ErrorResult

Defined in: [result/result.ts:29](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L29)

Failed result with a flattened code/message/details surface for ergonomic matching.

#### Extended by

- [`IndexedErrorResult`](#indexederrorresult)

#### Type Parameters

##### TCode

`TCode` *extends* `string`

##### TDetails

`TDetails`

##### TError

`TError` *extends* [`Micro509Error`](#micro509error)\<`TCode`, `TDetails`\>

#### Properties

##### code

> `readonly` **code**: `TCode`

Defined in: [result/result.ts:39](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L39)

Machine-readable failure reason, mirrored from `error.code`.

##### details?

> `readonly` `optional` **details**: `TDetails`

Defined in: [result/result.ts:43](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L43)

Optional structured context for the failure.

##### error

> `readonly` **error**: `TError`

Defined in: [result/result.ts:37](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L37)

Structured error payload.

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:41](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L41)

Human-readable diagnostic, mirrored from `error.message`.

##### ok

> `readonly` **ok**: `false`

Defined in: [result/result.ts:35](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L35)

Always `false` for failures.

***

### IndexedErrorResult

Defined in: [result/result.ts:47](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L47)

Like [ErrorResult](#errorresult) but also carries an index into the collection that was being processed.

#### Extends

- [`ErrorResult`](#errorresult)\<`TCode`, `TDetails`, `TError`\>

#### Type Parameters

##### TCode

`TCode` *extends* `string`

##### TDetails

`TDetails`

##### TError

`TError` *extends* [`IndexedMicro509Error`](#indexedmicro509error)\<`TCode`, `TDetails`\>

#### Properties

##### code

> `readonly` **code**: `TCode`

Defined in: [result/result.ts:39](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L39)

Machine-readable failure reason, mirrored from `error.code`.

###### Inherited from

[`ErrorResult`](#errorresult).[`code`](#code)

##### details?

> `readonly` `optional` **details**: `TDetails`

Defined in: [result/result.ts:43](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L43)

Optional structured context for the failure.

###### Inherited from

[`ErrorResult`](#errorresult).[`details`](#details)

##### error

> `readonly` **error**: `TError`

Defined in: [result/result.ts:37](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L37)

Structured error payload.

###### Inherited from

[`ErrorResult`](#errorresult).[`error`](#error)

##### index?

> `readonly` `optional` **index**: `number`

Defined in: [result/result.ts:53](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L53)

Zero-based position of the failing item in the input collection.

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:41](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L41)

Human-readable diagnostic, mirrored from `error.message`.

###### Inherited from

[`ErrorResult`](#errorresult).[`message`](#message)

##### ok

> `readonly` **ok**: `false`

Defined in: [result/result.ts:35](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L35)

Always `false` for failures.

###### Inherited from

[`ErrorResult`](#errorresult).[`ok`](#ok)

***

### IndexedMicro509Error

Defined in: [result/result.ts:67](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L67)

Like [Micro509Error](#micro509error) but includes a positional index for collection-processing APIs.

#### Extends

- [`Micro509Error`](#micro509error)\<`TCode`, `TDetails`\>

#### Extended by

- [`VerifyChainFailure`](verify.md#verifychainfailure)

#### Type Parameters

##### TCode

`TCode` *extends* `string`

##### TDetails

`TDetails` = `Record`\<`never`, `never`\>

#### Properties

##### code

> `readonly` **code**: `TCode`

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

###### Inherited from

[`Micro509Error`](#micro509error).[`code`](#code-3)

##### details?

> `readonly` `optional` **details**: `TDetails`

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

###### Inherited from

[`Micro509Error`](#micro509error).[`details`](#details-3)

##### index?

> `readonly` `optional` **index**: `number`

Defined in: [result/result.ts:70](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L70)

Zero-based position of the failing item in the input collection.

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

###### Inherited from

[`Micro509Error`](#micro509error).[`message`](#message-3)

***

### Micro509Error

Defined in: [result/result.ts:57](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L57)

Base error shape carried by all failure results in the library.

#### Extended by

- [`VerifyCertificateRevocationListFailure`](revocation.md#verifycertificaterevocationlistfailure)
- [`ValidateCertificateRevocationListFailure`](revocation.md#validatecertificaterevocationlistfailure)
- [`CheckCertificateRevocationAgainstCrlFailure`](revocation.md#checkcertificaterevocationagainstcrlfailure)
- [`VerifyOcspResponseFailure`](revocation.md#verifyocspresponsefailure)
- [`ValidateOcspResponseFailure`](revocation.md#validateocspresponsefailure)
- [`ParsePfxFailure`](pkcs.md#parsepfxfailure)
- [`ParsePkcs7Failure`](pkcs.md#parsepkcs7failure)
- [`VerifyPkcs7SignedDataFailure`](pkcs.md#verifypkcs7signeddatafailure)
- [`IndexedMicro509Error`](#indexedmicro509error)
- [`MatchServiceIdentityFailure`](verify.md#matchserviceidentityfailure)
- [`EkuCheckFailure`](verify.md#ekucheckfailure)
- [`VerifyRequestFailure`](verify.md#verifyrequestfailure)

#### Type Parameters

##### TCode

`TCode` *extends* `string`

##### TDetails

`TDetails` = `Record`\<`never`, `never`\>

#### Properties

##### code

> `readonly` **code**: `TCode`

Defined in: [result/result.ts:59](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L59)

Machine-readable failure reason (e.g. `'malformed'`, `'expired'`).

##### details?

> `readonly` `optional` **details**: `TDetails`

Defined in: [result/result.ts:63](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L63)

Optional structured context for the failure.

##### message

> `readonly` **message**: `string`

Defined in: [result/result.ts:61](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L61)

Human-readable diagnostic message.

## Type Aliases

### Result

> **Result**\<`TValue`, `TError`\> = \{ `ok`: `true`; `value`: `TValue`; \} \| \{ `error`: `TError`; `ok`: `false`; \}

Defined in: [result/result.ts:14](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L14)

Discriminated `ok` union: either `{ ok: true; value }` or `{ ok: false; error }`.

Every fallible public API in micro509 returns a specialization of this type.

#### Type Parameters

##### TValue

`TValue`

##### TError

`TError`

#### Type Declaration

\{ `ok`: `true`; `value`: `TValue`; \}

##### ok

> `readonly` **ok**: `true`

Operation succeeded.

##### value

> `readonly` **value**: `TValue`

Successful payload.

\{ `error`: `TError`; `ok`: `false`; \}

##### error

> `readonly` **error**: `TError`

Structured error payload.

##### ok

> `readonly` **ok**: `false`

Operation failed.

## Functions

### errorResult()

> **errorResult**\<`TCode`, `TDetails`, `TError`\>(`error`): [`ErrorResult`](#errorresult)\<`TCode`, `TDetails`, `TError`\>

Defined in: [result/result.ts:110](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L110)

Wraps a [Micro509Error](#micro509error) in a flattened [ErrorResult](#errorresult).

#### Type Parameters

##### TCode

`TCode` *extends* `string`

##### TDetails

`TDetails`

##### TError

`TError` *extends* [`Micro509Error`](#micro509error)\<`TCode`, `TDetails`\>

#### Parameters

##### error

`TError`

#### Returns

[`ErrorResult`](#errorresult)\<`TCode`, `TDetails`, `TError`\>

***

### indexedErrorResult()

> **indexedErrorResult**\<`TCode`, `TDetails`, `TError`\>(`error`): [`IndexedErrorResult`](#indexederrorresult)\<`TCode`, `TDetails`, `TError`\>

Defined in: [result/result.ts:125](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L125)

Wraps an [IndexedMicro509Error](#indexedmicro509error) in a flattened [IndexedErrorResult](#indexederrorresult).

#### Type Parameters

##### TCode

`TCode` *extends* `string`

##### TDetails

`TDetails`

##### TError

`TError` *extends* [`IndexedMicro509Error`](#indexedmicro509error)\<`TCode`, `TDetails`\>

#### Parameters

##### error

`TError`

#### Returns

[`IndexedErrorResult`](#indexederrorresult)\<`TCode`, `TDetails`, `TError`\>

***

### indexedMicro509Error()

> **indexedMicro509Error**\<`TCode`, `TDetails`\>(`code`, `message`, `index?`, `details?`): [`IndexedMicro509Error`](#indexedmicro509error)\<`TCode`, `TDetails`\>

Defined in: [result/result.ts:95](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L95)

Constructs an [IndexedMicro509Error](#indexedmicro509error) payload with an optional collection index.

#### Type Parameters

##### TCode

`TCode` *extends* `string`

##### TDetails

`TDetails` = `Record`\<`never`, `never`\>

#### Parameters

##### code

`TCode`

##### message

`string`

##### index?

`number`

##### details?

`TDetails`

#### Returns

[`IndexedMicro509Error`](#indexedmicro509error)\<`TCode`, `TDetails`\>

***

### micro509Error()

> **micro509Error**\<`TCode`, `TDetails`\>(`code`, `message`, `details?`): [`Micro509Error`](#micro509error)\<`TCode`, `TDetails`\>

Defined in: [result/result.ts:82](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L82)

Constructs a [Micro509Error](#micro509error) payload.

#### Type Parameters

##### TCode

`TCode` *extends* `string`

##### TDetails

`TDetails` = `Record`\<`never`, `never`\>

#### Parameters

##### code

`TCode`

##### message

`string`

##### details?

`TDetails`

#### Returns

[`Micro509Error`](#micro509error)\<`TCode`, `TDetails`\>

***

### successResult()

> **successResult**\<`TValue`\>(`value`): `object`

Defined in: [result/result.ts:74](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L74)

Wraps a value in a success result (`{ ok: true, value }`).

#### Type Parameters

##### TValue

`TValue`

#### Parameters

##### value

`TValue`

#### Returns

`object`

##### ok

> `readonly` **ok**: `true`

##### value

> `readonly` **value**: `TValue`
