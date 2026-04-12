# Getting Started

::: warning Prerelease
micro509 is `0.x` — API may change before 1.0.
:::

## Install

```bash
npm install micro509
```

### Bun

```bash
bun add micro509
```

### Deno

```bash
deno add jsr:@kjanat/micro509
```

```ts
import * as micro509 from '@kjanat/micro509';

// or import directly in code:
import * as micro509 from 'jsr:@kjanat/micro509';
```

## Quick Start

### Create a self-signed certificate

<LiveCode>

```ts
import { createSelfSignedCertificate } from 'micro509';

const { certificate, keyPair } =
  await createSelfSignedCertificate({
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

console.log(certificate.pem, '\n');
console.log(await keyPair.exportPkcs8Pem());
```

</LiveCode>

### Create a CSR

<LiveCode>

```ts
import {
  createCertificateSigningRequest,
  generateKeyPair,
} from 'micro509';

const keyPair = await generateKeyPair({ kind: 'ed25519' });
const csr = await createCertificateSigningRequest({
  subject: { commonName: 'csr.example' },
  publicKey: keyPair.publicKey,
  signerPrivateKey: keyPair.privateKey,
  extensions: {
    subjectAltNames: [
      { type: 'dns', value: 'csr.example' },
    ],
  },
});

console.log(csr.pem);
```

</LiveCode>

### Parse a certificate

<LiveCode>

```ts
import {
  parseCertificatePem,
  createSelfSignedCertificate,
} from 'micro509';

const { certificate } = await createSelfSignedCertificate({
  subject: {
    commonName: 'example.com',
    organization: 'Acme',
  },
  validity: { days: 365 },
  extensions: {
    keyUsage: ['digitalSignature', 'keyEncipherment'],
    subjectAltNames: [
      { type: 'dns', value: 'example.com' },
      { type: 'dns', value: '*.example.com' },
    ],
  },
});

const parsed = parseCertificatePem(certificate.pem);
console.log(`\
subject:   ${parsed.subject.values.commonName}
org:       ${parsed.subject.values.organization}
sig algo:  ${parsed.signatureAlgorithmName}
pubkey:    ${parsed.publicKeyAlgorithmName}
key usage: ${parsed.keyUsage.flags.join(', ')}
SANs:      ${parsed.subjectAltNames.map((name) => name.value).join(', ')}`);
```

</LiveCode>

### Verify a chain

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  createCertificate,
  generateKeyPair,
  verifyCertificateChain,
} from 'micro509';

// Create a CA root
const ca = await createSelfSignedCertificate({
  subject: { commonName: 'Demo Root CA' },
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});

// Issue a leaf signed by the CA
const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
  issuer: { commonName: 'Demo Root CA' },
  subject: { commonName: 'app.example.com' },
  publicKey: leafKeys.publicKey,
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
  extensions: {
    subjectAltNames: [
      { type: 'dns', value: 'app.example.com' },
    ],
  },
});

// Verify the CA → leaf chain
const result = await verifyCertificateChain({
  leaf: leaf.pem,
  roots: [ca.certificate.pem],
  serviceIdentity: {
    type: 'dns',
    value: 'app.example.com',
  },
});

if (result.ok) {
  const { leaf: parsed } = result.value;
  console.log(`verified ${parsed.subject.values.commonName}
  issuer:       ${parsed.issuer.values.commonName}
  chain length: ${result.value.chain.length}`);
}
```

</LiveCode>

### Reject a self-signed leaf

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  verifyCertificateChain,
} from 'micro509';

const { certificate } = await createSelfSignedCertificate({
  subject: { commonName: 'rogue.example' },
});

// Self-signed leaf is rejected even when listed as a root
const trusted = await verifyCertificateChain({
  leaf: certificate.pem,
  roots: [certificate.pem],
});

// Explicit opt-in allows it for development use
const selfSigned = await verifyCertificateChain({
  leaf: certificate.pem,
  roots: [certificate.pem],
  /** When `true`, allows a self-signed leaf. @default false */
  allowSelfSignedLeaf: true,
});

console.log(`\
trusted: ${trusted.ok} (${!trusted.ok && trusted.error.code})
opt-in:  ${selfSigned.ok}`);
```

</LiveCode>

## Imports

Use the root package for most applications:

```ts
import {
  createCertificate,
  parseCertificatePem,
  verifyCertificateChain,
} from 'micro509';
```

Use domain entrypoints for exhaustive advanced types or a narrower workflow surface:

```ts
import { parseCertificatePem } from 'micro509/x509';
import {
  verifyCertificateChain,
  matchServiceIdentity,
} from 'micro509/verify';
import {
  createOcspRequest,
  checkCertificateRevocation,
} from 'micro509/revocation';
import { createPfx } from 'micro509/pkcs';
import { generateKeyPair } from 'micro509/keys';
import { pemDecode, pemEncode } from 'micro509/pem';
import type { Micro509Error } from 'micro509/result';
```
