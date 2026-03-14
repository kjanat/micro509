# micro509

Small, typed X.509 and PKI tooling for modern TypeScript.

- create certificates, CSRs, CRLs, OCSP requests, PKCS#7 cert bags, and PFX bundles
- parse DER, PEM, and base64 inputs back to typed metadata
- verify certificate chains and CSR signatures with typed results
- import and export PKCS#8, SPKI, JWK, PKCS#1, and SEC1 keys
- stay WebCrypto-first, ESM-only, and browser-safe

## Install

```bash
npm install micro509
```

## Why use it

- WebCrypto-first: no Node builtins in library code
- typed outcomes: verification APIs return structured success or failure objects
- modern PKI surface: certificates, CSRs, revocation, OCSP, PFX, PKCS#7
- narrow defaults, explicit escape hatches

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

| Runtime | Status      | Notes                                                                        |
| ------- | ----------- | ---------------------------------------------------------------------------- |
| Node    | `supported` | use modern Node with WebCrypto globals; package metadata targets Node `>=24` |
| Bun     | `supported` | use Bun `>=1.3`                                                              |
| Deno    | `supported` | requires WebCrypto and web text/base64 globals                               |
| Browser | `supported` | modern browsers only                                                         |
| Worker  | `supported` | same WebCrypto and text/base64 globals required                              |

The core stays ESM-only and side-effect-free.

## Algorithm support

| Area                           | Shipped support                                                      |
| ------------------------------ | -------------------------------------------------------------------- |
| Certificate and CSR signatures | RSA PKCS#1 v1.5, RSA-PSS, ECDSA `P-256` / `P-384` / `P-521`, Ed25519 |
| RSA key APIs                   | `scheme: 'pkcs1-v1_5'                                                |
| ECDSA key APIs                 | `P-256`, `P-384`, `P-521`                                            |
| Encrypted PKCS#8 and PFX       | PBES2 with AES-CBC plus PBKDF2 HMAC-SHA1/HMAC-SHA256                 |
| Encrypted traditional PEM      | AES-128-CBC, AES-192-CBC, AES-256-CBC for RSA and EC private keys    |

`micro509` does not try to mirror every primitive some WebCrypto runtimes expose. It does not add `DSA`, `Ed448`, `RSA-OAEP`, `ECDH`, `X25519`, or generic symmetric-crypto APIs just because they may exist elsewhere.

## Standards status

| Area                       | Status    |
| -------------------------- | --------- |
| RFC 5280 path validation   | `partial` |
| RFC 6960 OCSP              | `partial` |
| RFC 6125 service identity  | `partial` |
| RFC 9618 policy validation | `partial` |

See `docs/PKIX-SCOPE.md` for the detailed scope boundary and `docs/API.md` for the public module surface.

## Imports

Use the root package for most applications:

```ts
import { createCertificate, parseCertificatePem, verifyCertificateChain } from 'micro509';
```

Use subpaths when you want a narrower surface:

```ts
import { verifyCertificateChain } from 'micro509/verify';
import { matchServiceIdentity } from 'micro509/identity';
import { parseCertificatePem } from 'micro509/parse';
import { generateKeyPair } from 'micro509/keys';
```

The full stable subpath list lives in `docs/API.md`.

## More docs

- API reference: `docs/API.md`
- Standards scope: `docs/PKIX-SCOPE.md`
- PKITS harness notes: `docs/PKITS-HARNESS.md`
- Differential harness notes: `docs/DIFF-HARNESS.md`
- Contributing: `CONTRIBUTING.md`

## Contributing

See `CONTRIBUTING.md`.
