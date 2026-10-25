# Runtime Support

micro509 is ESM-only, side-effect-free, and has zero dependencies.

## Compatibility

| Runtime            | Status    | Notes                                                            |
| ------------------ | --------- | ---------------------------------------------------------------- |
| Node.js            | supported | Modern Node with WebCrypto globals (tested on 24+)               |
| Bun                | supported | Bun 1.3+                                                         |
| Deno               | supported | Requires WebCrypto and web text/base64 globals                   |
| Browser            | supported | Modern browsers only                                             |
| Cloudflare Workers | supported | Full WebCrypto available                                         |
| Edge runtimes      | supported | Any runtime with WebCrypto + TextEncoder/TextDecoder + atob/btoa |

[`micro509/kdf`](../guide/key-derivation.md) supports Argon2d and Argon2id versions
`0x10` and `0x13` across these runtimes.

## Requirements

micro509 requires these global APIs:

- `crypto.subtle` (WebCrypto)
- `TextEncoder` / `TextDecoder`
- `atob` / `btoa`

Argon2's portable implementation requires WebAssembly, timers, `performance.now`,
and `WeakRef`. Browser CSP must permit WASM compilation (`wasm-unsafe-eval`).
Cloudflare Workers use the package's `workerd` export and static WASM import;
import `micro509/kdf` so the bundler selects that export.

_No_ Node.js builtins (`crypto`, `buffer`, `fs`, etc.) are used in library code.

## Tree-shaking

Import from domain entrypoints to minimize bundle size. Certificate and key-format
imports do not load Argon2:

```ts
// Only pulls in verification code
import { verifyCertificateChain } from 'micro509/verify';

// Only pulls in key handling code
import { generateKeyPair } from 'micro509/keys';
```
