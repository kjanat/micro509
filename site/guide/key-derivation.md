---
sidebarTitle: Argon2
outline: [2, 3]
---

# Derive encryption keys with Argon2

Use `micro509/kdf` to turn a password into key bytes with Argon2id or Argon2d.
This guide derives an AES key, encrypts a message, saves the derivation parameters,
and derives the key again to decrypt it.

For a new application, use Argon2id. When opening an existing format, use its
recorded variant, version and parameters exactly.

The same `deriveArgon2` API works in Node, Bun, Deno, browsers, and Cloudflare
Workers. Argon2d and Argon2id support versions `0x10` and `0x13`.

## Encrypt and decrypt a message

The example uses a disposable demo password and RFC 9106's 64 MiB Argon2id
parameter set. `memoryKiB` is measured in **KiB**, `passes` is the number of passes
through that memory, and `parallelism` is the number of lanes. The 32-byte output
becomes an AES-256-GCM key.

Each run prints a compact encrypted record with base64url-encoded binary fields.
It serializes and reloads that JSON, validates its fields, derives the key again,
and verifies the recovered message. It also modifies the ciphertext to demonstrate
AES-GCM authentication. Neither the password nor derived key is printed or saved.

<LiveCode>

```ts
import { deriveArgon2 } from 'micro509/kdf';

const password = new TextEncoder().encode('demo password');
const parameters = {
  algorithm: 'argon2id',
  version: 0x13,
  memoryKiB: 64 * 1024,
  passes: 3,
  parallelism: 4,
  outputBytes: 32,
} as const;
const limits = {
  maxMemoryKiB: 64 * 1024,
  maxPasses: 3,
  maxParallelism: 4,
  maxOutputBytes: 32,
};
const message = 'A message recovered from the saved parameters.';

function encode(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replace(/=+$/, '');
}

function decode(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error('Invalid base64url');
  }
  return Uint8Array.from(
    atob(value.replaceAll('-', '+').replaceAll('_', '/')),
    (char) => char.charCodeAt(0),
  );
}

function loadRecord(json: string) {
  const record: unknown = JSON.parse(json);
  if (
    typeof record !== 'object' ||
    record === null ||
    !('format' in record) ||
    record.format !== 1 ||
    !('cipher' in record) ||
    record.cipher !== 'AES-256-GCM' ||
    !('passwordEncoding' in record) ||
    record.passwordEncoding !== 'UTF-8' ||
    !('salt' in record) ||
    typeof record.salt !== 'string' ||
    !('iv' in record) ||
    typeof record.iv !== 'string' ||
    !('ciphertext' in record) ||
    typeof record.ciphertext !== 'string' ||
    !('kdf' in record) ||
    typeof record.kdf !== 'object' ||
    record.kdf === null
  )
    throw new Error('Invalid encrypted record');
  const kdf = record.kdf;
  if (
    !('algorithm' in kdf) ||
    kdf.algorithm !== 'argon2id' ||
    !('version' in kdf) ||
    kdf.version !== 0x13 ||
    !('memoryKiB' in kdf) ||
    typeof kdf.memoryKiB !== 'number' ||
    !('passes' in kdf) ||
    typeof kdf.passes !== 'number' ||
    !('parallelism' in kdf) ||
    typeof kdf.parallelism !== 'number' ||
    !('outputBytes' in kdf) ||
    kdf.outputBytes !== 32
  )
    throw new Error('Invalid derivation parameters');
  const salt = decode(record.salt);
  const iv = decode(record.iv);
  const ciphertext = decode(record.ciphertext);
  if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 16) {
    throw new Error('Invalid binary field lengths');
  }
  return {
    kdf: {
      algorithm: kdf.algorithm,
      version: kdf.version,
      memoryKiB: kdf.memoryKiB,
      passes: kdf.passes,
      parallelism: kdf.parallelism,
      outputBytes: kdf.outputBytes,
    },
    salt,
    iv,
    ciphertext,
  } as const;
}

try {
  console.log('Argon2id v0x13: 64 MiB, 3 passes, 4 lanes');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const start = performance.now();
  const derived = await deriveArgon2(
    { ...parameters, password, salt },
    { limits },
  );
  if (!derived.ok) throw new Error(derived.error.code);
  console.log('Derived key: ' + derived.value.length + ' bytes');
  console.log(
    'Derivation time: ' + Math.round(performance.now() - start) + ' ms',
  );
  const key = await crypto.subtle
    .importKey('raw', derived.value.slice(), 'AES-GCM', false, ['encrypt'])
    .finally(() => derived.value.fill(0));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(message),
  );
  const saved = JSON.stringify({
    format: 1,
    kdf: parameters,
    passwordEncoding: 'UTF-8',
    salt: encode(salt),
    cipher: 'AES-256-GCM',
    iv: encode(iv),
    ciphertext: encode(new Uint8Array(ciphertext)),
  });
  console.log('Saved record:', saved);

  // Later: reload the saved JSON and use the same password.
  const record = loadRecord(saved);
  const restored = await deriveArgon2(
    { ...record.kdf, password, salt: record.salt },
    { limits },
  );
  if (!restored.ok) throw new Error(restored.error.code);
  const decryptionKey = await crypto.subtle
    .importKey('raw', restored.value.slice(), 'AES-GCM', false, ['decrypt'])
    .finally(() => restored.value.fill(0));
  console.log('Record serialized, reloaded and validated.');
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: record.iv },
    decryptionKey,
    record.ciphertext,
  );
  const recovered = new TextDecoder().decode(plaintext);
  if (recovered !== message) throw new Error('Round trip failed');
  console.log('Recovered message:', recovered);
  console.log('Round trip: PASS');

  const modified = record.ciphertext.slice();
  modified[0] = (modified[0] ?? 0) ^ 1;
  let rejected = false;
  try {
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: record.iv },
      decryptionKey,
      modified,
    );
  } catch (error) {
    if (!(error instanceof Error) || error.name !== 'OperationError')
      throw error;
    rejected = true;
  }
  if (!rejected) throw new Error('Modified ciphertext was accepted');
  console.log('Modified ciphertext: REJECTED');
} finally {
  password.fill(0);
}
```

</LiveCode>

Generate a fresh random salt when creating a new record. To open that record,
reuse its salt and every KDF parameter. A new salt, a different password encoding
or different parameters produces a different key. AES-GCM decryption rejects a
wrong key or modified ciphertext.

Store the salt and derivation parameters with the ciphertext. Validate the record
and apply your resource limits when loading it. Your application owns the record
format.

## Bound work from stored parameters

The record describes the derivation. The second argument to `deriveArgon2`
describes how much work your application permits. A record requesting too much
memory or too many passes returns `limit_exceeded` before derivation starts.

| Limit            | Default                                                   |
| ---------------- | --------------------------------------------------------- |
| `maxMemoryKiB`   | 262144 (256 MiB)                                          |
| `maxPasses`      | 16                                                        |
| `maxParallelism` | 16                                                        |
| `maxOutputBytes` | 1024                                                      |
| `maxInputBytes`  | 1048576 across password, salt, secret and associated data |

Limits apply per call. Four simultaneous 64 MiB derivations can use about
256 MiB for Argon2 alone. Set a separate concurrency limit for your application.

| Result code          | What to do                                                                                                         |
| -------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `invalid_parameters` | Check input types, integer ranges and parameter relationships. Memory must be at least eight times the lane count. |
| `limit_exceeded`     | Reject the record or explicitly approve a higher resource budget.                                                  |
| `unsupported`        | Check the runtime, variant and version, or choose a backend that implements them.                                  |
| `derivation_failed`  | Report a derivation failure. Backend exception text is omitted from the result.                                    |

## Open an existing format

The format defines the password preprocessing and parameters. Applying the demo's
parameters to an existing file will derive a different key.

| Format                  | Inputs to prepare                                                                                                                                                                                            |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Bitwarden / Vaultwarden | Apply the format's account-identifier normalization and SHA-256 salt preprocessing. Convert its memory setting from MiB to KiB.                                                                              |
| KDBX                    | Supply the precomputed composite key as `password`, the recorded salt and Argon2 version, and convert its memory value from bytes to KiB. Both recorded versions are supported.                              |
| PKCS#8 / PFX            | Use the existing [encrypted-key](./keys.md#encrypted-pkcs8) and [PKCS](./pkcs.md) APIs for their container-specific KDFs and encryption. `deriveArgon2` does not add an Argon2 encoding to those containers. |

For format vectors and preprocessing examples, see the
[Argon2 implementation notes](https://github.com/kjanat/micro509/blob/master/docs/ARGON2.md).

## Use another backend

Choose an implementation with `options.backend`:

| Value        | Implementation                                       |
| ------------ | ---------------------------------------------------- |
| Omitted      | Automatic selection                                  |
| `'native'`   | Native WebCrypto, version `0x13`                     |
| `'portable'` | Bundled WASM, versions `0x10` and `0x13`             |
| Callback     | Your [`Argon2Backend`](../api/kdf.md) implementation |

Automatic selection tries native WebCrypto and uses the bundled implementation
for `unsupported` requests. Other errors are returned directly. An explicit
selection uses only the chosen implementation.

A callback receives the exact requested variant and version and returns an owned
byte array of `outputBytes` length.

<details>
<summary>Backend buffer ownership and execution</summary>

micro509 validates parameters and resource limits before invoking the backend.
The backend receives private input copies. micro509 wipes those copies when the
callback settles, and copies and wipes the backend's successful output array.
Finish using the copies before resolving. If you transfer an input buffer to a
worker, erase it in that worker.

Caller-owned buffers are untouched. Erase your password and derived output when
you have finished with them. JavaScript cannot erase copies inside the runtime or
native key storage. Native WebCrypto calls cannot be cancelled once dispatched.
An external backend determines its own scheduling and cancellation behavior.

Both bundled backends require at least eight salt bytes. The portable backend
uses private WASM memory, wipes it on success and failure, and yields between
segments. Its total memory, inputs, output and overhead must fit below 2 GiB.
Native output lengths must fit a WebCrypto unsigned 32-bit bit count. Requests
beyond these limits return `unsupported`. See [runtime requirements](../reference/runtimes.md#requirements)
for browser and Workers setup.

</details>

Continue with the [KDF API reference](../api/kdf.md),
[key import and export](./keys.md), or [error-code reference](../reference/errors.md#argon2errorcode).
