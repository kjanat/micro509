[micro509](modules.md) / result

# result

Canonical shared result surface.
Owns the stable `micro509/result` entrypoint.

## Functions

### errorResult()

> **errorResult**\<`TCode`, `TDetails`, `TError`\>(`error`): [`ErrorResult`](micro509.md#errorresult)\<`TCode`, `TDetails`, `TError`\>

Defined in: [result/result.ts:110](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L110)

Wraps a [Micro509Error](micro509.md#micro509error) in a flattened [ErrorResult](micro509.md#errorresult).

#### Type Parameters

##### TCode

`TCode` _extends_ `string`

##### TDetails

`TDetails`

##### TError

`TError` _extends_ [`Micro509Error`](micro509.md#micro509error)\<`TCode`, `TDetails`\>

#### Parameters

##### error

`TError`

#### Returns

[`ErrorResult`](micro509.md#errorresult)\<`TCode`, `TDetails`, `TError`\>

---

### indexedErrorResult()

> **indexedErrorResult**\<`TCode`, `TDetails`, `TError`\>(`error`): [`IndexedErrorResult`](micro509.md#indexederrorresult)\<`TCode`, `TDetails`, `TError`\>

Defined in: [result/result.ts:125](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L125)

Wraps an [IndexedMicro509Error](micro509.md#indexedmicro509error) in a flattened [IndexedErrorResult](micro509.md#indexederrorresult).

#### Type Parameters

##### TCode

`TCode` _extends_ `string`

##### TDetails

`TDetails`

##### TError

`TError` _extends_ [`IndexedMicro509Error`](micro509.md#indexedmicro509error)\<`TCode`, `TDetails`\>

#### Parameters

##### error

`TError`

#### Returns

[`IndexedErrorResult`](micro509.md#indexederrorresult)\<`TCode`, `TDetails`, `TError`\>

---

### indexedMicro509Error()

> **indexedMicro509Error**\<`TCode`, `TDetails`\>(`code`, `message`, `index?`, `details?`): [`IndexedMicro509Error`](micro509.md#indexedmicro509error)\<`TCode`, `TDetails`\>

Defined in: [result/result.ts:95](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L95)

Constructs an [IndexedMicro509Error](micro509.md#indexedmicro509error) payload with an optional collection index.

#### Type Parameters

##### TCode

`TCode` _extends_ `string`

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

[`IndexedMicro509Error`](micro509.md#indexedmicro509error)\<`TCode`, `TDetails`\>

---

### micro509Error()

> **micro509Error**\<`TCode`, `TDetails`\>(`code`, `message`, `details?`): [`Micro509Error`](micro509.md#micro509error)\<`TCode`, `TDetails`\>

Defined in: [result/result.ts:82](https://github.com/kjanat/ts-x509/blob/vitepress/src/result/result.ts#L82)

Constructs a [Micro509Error](micro509.md#micro509error) payload.

#### Type Parameters

##### TCode

`TCode` _extends_ `string`

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

[`Micro509Error`](micro509.md#micro509error)\<`TCode`, `TDetails`\>

---

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
