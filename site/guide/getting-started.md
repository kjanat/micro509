# Getting Started

::: warning Prerelease
micro509 is `0.x` — API may change before 1.0.
:::

## Install

```bash
npm install micro509
```

```bash
bun add micro509
```

## Quick Start

### Create a self-signed certificate

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

### Create a CSR

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

### Parse a certificate

```ts
import { parseCertificatePem } from 'micro509';

const parsed = parseCertificatePem(certificate.pem);
console.log(parsed.subject.values.commonName);
console.log(parsed.extendedKeyUsage);
console.log(parsed.authorityInfoAccess);
```

### Verify a chain

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

## Imports

Use the root package for most applications:

```ts
import { createCertificate, parseCertificatePem, verifyCertificateChain } from 'micro509';
```

Use domain entrypoints for exhaustive advanced types or a narrower workflow surface:

```ts
import { parseCertificatePem } from 'micro509/x509';
import { verifyCertificateChain, matchServiceIdentity } from 'micro509/verify';
import { createOcspRequest, checkCertificateRevocation } from 'micro509/revocation';
import { createPfx } from 'micro509/pkcs';
import { generateKeyPair } from 'micro509/keys';
import { pemDecode, pemEncode } from 'micro509/pem';
import type { Micro509Error } from 'micro509/result';
```
