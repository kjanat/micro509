# Getting Started

::: warning Prerelease
micro509 is `0.x` — API may change before 1.0.
:::

## Install

::: code-group

```bash [npm]
npm install micro509
```

```bash [pnpm]
pnpm add micro509
```

```bash [yarn]
yarn add micro509
```

```bash [bun]
bun add micro509
```

```bash [deno]
deno add jsr:@kjanat/micro509
```

:::

### Browser

No build step: micro509 is WebCrypto and nothing else, so a module script can
import it straight from a CDN.

```html
<script type="module">
  import { createSelfSignedCertificate } from 'https://esm.run/micro509';

  const { certificate } = await createSelfSignedCertificate(
    {
      subject: { commonName: 'example.com' },
      validity: { days: 30 },
    },
  );
  console.log(certificate.pem);
</script>
```

Subpaths work the same way — `https://esm.run/micro509/x509` — and pinning a
version (`https://esm.run/micro509@0.11.0`) is what you want in production, so
a release cannot change under you.

[`examples/browser`][browser-example] is that, in full: one HTML file that issues
a certificate and parses it back, with nothing installed and nothing built. For the
same demo with types and a dev server, see [`examples/vite`][vite-example].

[browser-example]: https://github.com/kjanat/micro509/tree/HEAD/examples/browser/README.md
[vite-example]: https://github.com/kjanat/micro509/tree/HEAD/examples/vite/README.md

### Deno

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

console.log(certificate.pem);
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

const result = parseCertificatePem(certificate.pem);
if (!result.ok) {
  console.log(`parse failed: ${result.error.code}`);
} else {
  const parsed = result.value;
  const sans = (parsed.subjectAltNames ?? [])
    .filter((name) => name.type !== 'directoryName')
    .map((name) => name.value)
    .join(', ');
  console.log(`\
subject:   ${parsed.subject.values.commonName}
org:       ${parsed.subject.values.organization}
sig algo:  ${parsed.signatureAlgorithmName}
pubkey:    ${parsed.publicKeyAlgorithmName}
key usage: ${parsed.keyUsage?.flags.join(', ') ?? 'none'}
SANs:      ${sans}
`);
}
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
  console.log(`\
verified ${parsed.subject.values.commonName}
  issuer:       ${parsed.issuer.values.commonName}
  serial:       ${parsed.serialNumberHex}
  chain length: ${result.value.chain.length}
`);
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
  /** Allow a self-signed leaf. @default false */
  allowSelfSignedLeaf: true,
});

console.log(`\
trusted: ${trusted.ok} (${!trusted.ok && trusted.error.code})
opt-in:  ${selfSigned.ok}
`);
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
