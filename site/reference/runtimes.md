# Runtime Support

micro509 is ESM-only, side-effect-free, and uses only WebCrypto APIs.

## Compatibility

| Runtime            | Status    | Notes                                                            |
| ------------------ | --------- | ---------------------------------------------------------------- |
| Node.js            | supported | Modern Node with WebCrypto globals (tested on 24+)               |
| Bun                | supported | Bun 1.3+                                                         |
| Deno               | supported | Requires WebCrypto and web text/base64 globals                   |
| Browser            | supported | Modern browsers only                                             |
| Cloudflare Workers | supported | Full WebCrypto available                                         |
| Edge runtimes      | supported | Any runtime with WebCrypto + TextEncoder/TextDecoder + atob/btoa |

## Requirements

micro509 requires these global APIs:

- `crypto.subtle` (WebCrypto)
- `TextEncoder` / `TextDecoder`
- `atob` / `btoa`

No Node.js builtins (`crypto`, `buffer`, `fs`, etc.) are used in library code.

## Tree-shaking

micro509 is fully tree-shakeable. Import from domain entrypoints to minimize bundle size:

```ts
// Only pulls in verification code
import { verifyCertificateChain } from 'micro509/verify';

// Only pulls in key handling code
import { generateKeyPair } from 'micro509/keys';
```
