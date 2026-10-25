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

## Before you run

The default backend needs native Argon2 support in WebCrypto. On a runtime without
it, `deriveArgon2` returns `unsupported`. This includes browsers without an Argon2
implementation: the live example prints that result and stops before encryption.
Run the same code in a supported Node or Deno runtime, or supply an
[external backend](#use-another-backend). See [runtime support](../reference/runtimes.md)
for the project's runtime coverage.

## Encrypt and decrypt a message

The example uses a disposable demo password and RFC 9106's 64 MiB Argon2id
parameter set. `memoryKiB` is measured in **KiB**, `passes` is the number of passes
through that memory, and `parallelism` is the number of lanes. The 32-byte output
becomes an AES-256-GCM key.

Each run prints a JSON record containing the salt, derivation parameters, IV and
ciphertext. It then derives the key again from that record and prints the recovered
message. The password and derived key are separate from the saved record.

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
const salt = crypto.getRandomValues(new Uint8Array(16));
const limits = { maxMemoryKiB: 64 * 1024, maxPasses: 3, maxParallelism: 4 };

try {
  const derived = await deriveArgon2(
    { ...parameters, password, salt },
    { limits },
  );
  if (!derived.ok) {
    console.log('Derivation:', derived.error);
  } else {
    // Print disposable demo material so this derivation can be reproduced.
    console.log('Derived key bytes:', Array.from(derived.value));
    const key = await crypto.subtle.importKey(
      'raw',
      derived.value.slice(),
      'AES-GCM',
      false,
      ['encrypt'],
    );
    derived.value.fill(0);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(
        'A message recovered from the saved parameters.',
      ),
    );
    const record = {
      kdf: parameters,
      passwordEncoding: 'UTF-8',
      salt: Array.from(salt),
      cipher: 'AES-256-GCM',
      iv: Array.from(iv),
      ciphertext: Array.from(new Uint8Array(ciphertext)),
    };
    console.log('Save this record:', JSON.stringify(record, null, 2));

    // Later: use the saved salt and parameters with the same password bytes.
    const restored = await deriveArgon2(
      {
        ...record.kdf,
        password,
        salt: new Uint8Array(record.salt),
      },
      { limits },
    );
    if (!restored.ok) throw new Error(restored.error.code);
    const decryptionKey = await crypto.subtle.importKey(
      'raw',
      restored.value.slice(),
      'AES-GCM',
      false,
      ['decrypt'],
    );
    restored.value.fill(0);
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(record.iv) },
      decryptionKey,
      new Uint8Array(record.ciphertext),
    );
    console.log('Recovered message:', new TextDecoder().decode(plaintext));
  }
} finally {
  password.fill(0);
}
```

</LiveCode>

Generate a fresh random salt when creating a new record. To open that record,
reuse its salt and every KDF parameter. A new salt, a different password encoding
or different parameters produces a different key. AES-GCM decryption rejects a
wrong key or modified ciphertext.

The JSON above illustrates an application-owned record. When loading one from
storage, validate its fields and apply your own resource limits before deriving.
Salt and parameters can be stored with ciphertext. Production applications should
omit the demo's derived-key logging. Argon2 derives bytes here, so this API does
not create a password-verifier string or an encrypted-file format for you.

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
| KDBX                    | Supply the precomputed composite key as `password`, the recorded salt and Argon2 version, and convert its memory value from bytes to KiB. Version `0x10` needs an external backend.                          |
| PKCS#8 / PFX            | Use the existing [encrypted-key](./keys.md#encrypted-pkcs8) and [PKCS](./pkcs.md) APIs for their container-specific KDFs and encryption. `deriveArgon2` does not add an Argon2 encoding to those containers. |

For format vectors and preprocessing examples, see the
[Argon2 implementation notes](https://github.com/kjanat/micro509/blob/master/docs/ARGON2.md).

## Use another backend

Pass an [`Argon2Backend`](../api/kdf.md) as `options.backend` to use a separately
installed implementation. The default WebCrypto backend supports version `0x13`.
An external backend can also implement `0x10` or run on a platform without native
Argon2. It must honor the requested variant and version and return an owned byte
array of exactly `outputBytes` length.

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

The native backend requires at least eight salt bytes. Its output length must fit
a WebCrypto unsigned 32-bit bit count. Requests beyond those capabilities return
`unsupported`.

</details>

Continue with the [KDF API reference](../api/kdf.md),
[key import and export](./keys.md), or [error-code reference](../reference/errors.md#argon2errorcode).
