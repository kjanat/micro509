# Key derivation

Import `deriveArgon2` from `micro509/kdf` for byte-oriented Argon2id and
Argon2d derivation. The default adapter uses the runtime's native WebCrypto
implementation. The KDF module has no dependencies and is loaded through its
own entrypoint.

## Derive raw bytes

Choose the exact algorithm, version, memory in **KiB**, passes, lanes, and
output length. Argon2id is the recommended variant for new applications.
The following uses RFC 9106's second recommended parameter set: 64 MiB,
three passes, and four lanes.

<LiveCode>

```ts
import { deriveArgon2 } from 'micro509/kdf';

const password = new TextEncoder().encode('demo password');
const salt = crypto.getRandomValues(new Uint8Array(16));
console.log('Salt:', Array.from(salt));

const result = await deriveArgon2({
  algorithm: 'argon2id',
  version: 0x13,
  password,
  salt,
  memoryKiB: 64 * 1024,
  passes: 3,
  parallelism: 4,
  outputBytes: 32,
});
password.fill(0);

if (result.ok) {
  console.log('Derived key:', Array.from(result.value));
  result.value.fill(0);
} else {
  console.log('Derivation:', result.error.code);
}
```

</LiveCode>

The browser demo reports `unsupported` when its WebCrypto implementation
does not expose Argon2. Node and Deno builds with native Argon2 derive the
requested bytes. The module does not switch algorithms or versions.

## Apply resource limits

Resource limits are checked before copying inputs or invoking a backend.
Caller-supplied limits replace the corresponding defaults:

| Limit            | Default                                                           |
| ---------------- | ----------------------------------------------------------------- |
| `maxMemoryKiB`   | 262144 (256 MiB)                                                  |
| `maxPasses`      | 16                                                                |
| `maxParallelism` | 16                                                                |
| `maxOutputBytes` | 1024                                                              |
| `maxInputBytes`  | 1048576, summed across password, salt, secret and associated data |

Pass a second argument such as
`{ limits: { maxMemoryKiB: 65536, maxPasses: 4 } }` when reading parameters
from an external file or server. Invalid integers return `invalid_parameters`.
Valid requests above the ceilings return `limit_exceeded`. Operational failures
return `derivation_failed`, without backend exception contents or input bytes.

Limits apply to each call. Four concurrent 64 MiB derivations can need about
256 MiB for Argon2 memory alone, plus runtime and application overhead. Bound
concurrency at the application boundary.

## Runtime and backend selection

The default adapter requests `Argon2id` or `Argon2d` and version `0x13` from
WebCrypto. Native calls are asynchronous. JavaScript does not perform the
memory-hard computation, although runtime thread-pool saturation can delay
other work. No cancellation API is exposed because native WebCrypto offers
no way to cancel an Argon2 operation already dispatched.

The shared runtime smoke test exercises RFC 9106 vectors where native import
is available and checks the `unsupported` result elsewhere. Node 26.12.0 and
the project-installed Deno 2.9.6 produced both vectors. Bun 1.4.3's WebCrypto rejected Argon2.
Availability depends on the deployed runtime, so handle `unsupported`.

Supply a trusted `Argon2Backend` through the second argument's `backend`
property to use a separately installed implementation. The callback receives
validated input copies and returns `Argon2Result`. It must implement the exact
requested variant and version or return `unsupported`. It must return an owned
output array of the requested length. micro509 copies and wipes that array.
It also wipes its input copies when the callback settles. A backend must finish
using those buffers before resolving its promise.

The bundled adapter supports version `0x13` only. Version `0x10` requires an
external backend. No portable Argon2 implementation is bundled. Backend
providers determine their own event-loop behavior, native/WASM dependencies,
temporary-memory handling, and supported runtimes.

## Format-specific preprocessing

- **Bitwarden/Vaultwarden:** normalize the account identifier and hash the salt
  with SHA-256 in the caller. Convert the format's memory value from MiB to KiB.
- **KDBX:** pass the precomputed composite key as the password. Convert the
  format's byte-based memory value to KiB and pass the recorded version. The
  native adapter rejects `0x10`. This API derives raw key material and does not
  parse or decrypt a KDBX file.
- **PKCS#8 and PFX:** this API defines no Argon2 container encoding. Existing
  container APIs continue to use their documented KDFs.

Optional `secret` and `associatedData` are separate byte inputs. The native
backend accepts salts of at least eight bytes and output lengths expressible
as a WebCrypto unsigned 32-bit bit count. Smaller salts or larger outputs
return `unsupported`, so an external provider can implement a broader range.

Caller buffers are never modified. Owned temporary arrays are zeroed after
use, but JavaScript cannot erase native key storage or copies held by a
runtime. The caller owns and should erase the successful output after use.

## Reproduce performance measurements

After `bun run build`, run `node scripts/benchmark-argon2.mjs native 1` or
replace `native` with `node` to compare the adapter against `node:crypto`.
The last argument controls concurrent calls. Each invocation uses its own
process and reports latency, process peak RSS, and event-loop timer delay.
Both native routes can use the same runtime crypto implementation. These
numbers measure adapter overhead and scheduling, not independent algorithm
performance. `docs/ARGON2.md` records the sample measurements and vector sources.

References: [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html),
[Node WebCrypto](https://nodejs.org/api/webcrypto.html#class-argon2params),
[KDBX KDF parameters](https://keepass.info/help/kb/kdbx.html).
