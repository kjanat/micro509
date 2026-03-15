# micro509

The TypeScript PKI library that tells you _why_ verification failed, not just that it did.

Zero dependencies. Pure WebCrypto. Runs everywhere: Node, Bun, Deno, browsers, Cloudflare Workers.

## Install

```bash
npm install micro509
```

## Why micro509

Other JS X.509 libraries return a boolean from chain verification.
micro509 returns a discriminated union with 13 typed error codes, the
failing certificate's index, and structured failure details — so your
code can _handle_ the failure, not just log it.

```ts
if (!result.ok) {
  // result.error.code: 'SIGNATURE_INVALID' | 'EXPIRED' | 'NAME_CONSTRAINTS_VIOLATED' | ...
  // result.error.index: which certificate in the chain failed
  // result.error.details: { expected, actual } for identity mismatches
}
```

Beyond verification, micro509 covers PKI surface that no other
zero-dependency JS package ships:

- **OCSP** — build requests, parse and validate responses, verify responder authorization
- **PFX / PKCS#12** — create and parse password-protected key+cert bundles
- **PKCS#7 / CMS** — parse SignedData, verify signer signatures, extract cert bags
- **CRLs** — create, parse, verify, and check revocation status
- **Encrypted keys** — PBES2 PKCS#8, legacy OpenSSL encrypted PEM, PKCS#1, SEC1
- **Service identity** — wildcard DNS, IPv6 normalization, URI-ID, SRV-ID, explicit CN opt-in

All with no `any`, no type assertions, no non-null assertions, and
no runtime DI frameworks that break edge runtimes.

## Quick start

Create a self-signed certificate:

```ts
import { createSelfSignedCertificate } from 'micro509';

const { certificate, keyPair } = await createSelfSignedCertificate({
  subject: {
    commonName: 'example.com',
    organization: 'Acme',
    country: 'US',
  },
  validity: { days: 30 },
  extensions: {
    keyUsage: ['digitalSignature', 'keyEncipherment'],
    subjectAltNames: [
      { type: 'dns', value: 'example.com' },
      { type: 'dns', value: 'www.example.com' },
    ],
  },
});

console.log(certificate.pem);
console.log(await keyPair.exportPkcs8Pem());
```

Create a CSR:

```ts
import { createCertificateSigningRequest, generateKeyPair } from 'micro509';

const keyPair = await generateKeyPair({ kind: 'ed25519' });
const csr = await createCertificateSigningRequest({
  subject: { commonName: 'csr.example' },
  publicKey: keyPair.publicKey,
  signerPrivateKey: keyPair.privateKey,
  extensions: {
    subjectAltNames: [{ type: 'dns', value: 'csr.example' }],
  },
});

console.log(csr.pem);
```

Parse a certificate:

```ts
import { parseCertificatePem } from 'micro509';

const parsed = parseCertificatePem(certificate.pem);
console.log(parsed.subject.values.commonName);
console.log(parsed.extendedKeyUsage);
console.log(parsed.authorityInfoAccess);
```

Verify a chain:

```ts
import { verifyCertificateChain } from 'micro509';

const result = await verifyCertificateChain({
  leaf: leaf.pem,
  intermediates: [intermediate.pem],
  roots: [root.pem],
  purpose: 'serverAuth',
  serviceIdentity: { type: 'dns', value: 'api.local' },
});

if (result.ok) {
  console.log(result.value.chain.length);
} else {
  console.log(result.error.code);
}
```

## Runtime support

| Runtime | Status    | Notes                                              |
| ------- | --------- | -------------------------------------------------- |
| Node    | supported | modern Node with WebCrypto globals (tested on 24+) |
| Bun     | supported | Bun 1.3+                                           |
| Deno    | supported | requires WebCrypto and web text/base64 globals     |
| Browser | supported | modern browsers only                               |
| Worker  | supported | same WebCrypto and text/base64 globals required    |

The core stays ESM-only and side-effect-free.

## Algorithm support

| Area                           | Shipped support                                                      |
| ------------------------------ | -------------------------------------------------------------------- |
| Certificate and CSR signatures | RSA PKCS#1 v1.5, RSA-PSS, ECDSA `P-256` / `P-384` / `P-521`, Ed25519 |
| RSA key APIs                   | `scheme: 'pkcs1-v1_5'`                                               |
| ECDSA key APIs                 | `P-256`, `P-384`, `P-521`                                            |
| Encrypted PKCS#8 and PFX       | PBES2 with AES-CBC plus PBKDF2 HMAC-SHA1/HMAC-SHA256                 |
| Encrypted traditional PEM      | AES-128-CBC, AES-192-CBC, AES-256-CBC for RSA and EC private keys    |

`micro509` does not try to mirror every primitive some WebCrypto runtimes expose.\
It does not add `DSA`, `Ed448`, `RSA-OAEP`, `ECDH`, `X25519`, or generic symmetric-crypto APIs just because they may exist elsewhere.

## Standards status

| Area                       | Status  |
| -------------------------- | ------- |
| RFC 5280 path validation   | partial |
| RFC 6960 OCSP              | partial |
| RFC 6125 service identity  | partial |
| RFC 9618 policy validation | partial |

See [`docs/PKIX-SCOPE.md`](./docs/PKIX-SCOPE.md) for the detailed scope boundary
and [`docs/API.md`](./docs/API.md) for the public module surface.

## Imports

Use the root package for most applications:

```ts
import { createCertificate, parseCertificatePem, verifyCertificateChain } from 'micro509';
```

Use domain entrypoints when you want exhaustive advanced types or a narrower
workflow surface:

```ts
import { parseCertificatePem } from 'micro509/x509';
import { verifyCertificateChain, matchServiceIdentity } from 'micro509/verify';
import { createOcspRequest, checkCertificateRevocation } from 'micro509/revocation';
import { createPfx } from 'micro509/pkcs';
import { generateKeyPair } from 'micro509/keys';
import { pemDecode, pemEncode } from 'micro509/pem';
import type { Micro509Error } from 'micro509/result';
```

The full stable subpath list lives in [`docs/API.md`](./docs/API.md).

## More docs

- API reference: [`docs/API.md`](./docs/API.md)
- Standards scope: [`docs/PKIX-SCOPE.md`](./docs/PKIX-SCOPE.md)
- PKITS harness notes: [`docs/PKITS-HARNESS.md`](./docs/PKITS-HARNESS.md)
- Differential harness notes: [`docs/DIFF-HARNESS.md`](./docs/DIFF-HARNESS.md)
- Contributing: [`CONTRIBUTING.md`](./CONTRIBUTING.md)

## License

[MIT](./LICENSE)
