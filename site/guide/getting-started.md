---
outline: [2, 3]
---

# Getting Started

::: warning Prerelease
micro509 is `0.x` — API may change before 1.0.
:::

## Usage

### Install

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

  const { certificate } = await createSelfSignedCertificate({
    subject: { commonName: 'example.com' },
    validity: { days: 30 },
  });
  console.log(certificate.pem);
</script>
```

Subpaths work the same way — `https://esm.run/micro509/x509` — and pinning a
version (`https://esm.run/micro509@{{ $frontmatter.packageVersion }}`) is what
you want in production, so a release cannot change under you.

- [`examples/browser`][browser-example] is that, in full: one HTML file that issues a certificate and parses it back, with nothing installed and nothing built. [open in stackblitz][browser-example:stackblitz]
- [`examples/vite`][vite-example]: the same demo with types and a dev server. [open in stackblitz][vite-example:stackblitz]

[browser-example]: https://github.com/kjanat/micro509/tree/master/examples/browser/README.md "GitHub"
[browser-example:stackblitz]: https://stackblitz.com/github/kjanat/micro509/tree/master/examples/browser?title=micro509%20in%20the%20browser "Stackblitz"
[vite-example]: https://github.com/kjanat/micro509/tree/master/examples/vite/README.md "GitHub"
[vite-example:stackblitz]: https://stackblitz.com/github/kjanat/micro509/tree/master/examples/vite?title=micro509%20with%20Vite "Stackblitz"

### Deno

```ts
import * as micro509 from '@kjanat/micro509';

// or import directly in code:
import * as micro509 from 'jsr:@kjanat/micro509';
```

## Choose a task

| I want to…                          | Start here                          |
| ----------------------------------- | ----------------------------------- |
| Verify a certificate for a server   | [Verify a chain](#verify-a-chain)   |
| Issue a certificate or create a CSR | [Certificates](./certificates.md)   |
| Check CRL or OCSP evidence          | [Revocation](./revocation.md)       |
| Import a private key                | [Keys](./keys.md#import-and-export) |
| Read or create a PFX bundle         | [PKCS](./pkcs.md#pfx-pkcs12)        |

## Quick Start

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
  issuerCertificate: ca.certificate.pem,
  extensions: {
    extendedKeyUsage: ['serverAuth'],
    subjectAltNames: [{ type: 'dns', value: 'app.example.com' }],
  },
});

// Verify the CA → leaf chain
const verificationInput = {
  at: new Date(),
  leaf: leaf.pem,
  roots: [ca.certificate.pem],
  purpose: 'serverAuth',
  serviceIdentity: {
    type: 'dns',
    value: 'app.example.com',
  },
} as const;

console.log('Trusted root PEM (save as root.pem):\n' + ca.certificate.pem);
console.log('Leaf PEM (save as leaf.pem):\n' + leaf.pem);
console.log('Verification inputs:', {
  at: verificationInput.at.toISOString(),
  unixTime: Math.floor(verificationInput.at.getTime() / 1000),
  purpose: verificationInput.purpose,
  serviceIdentity: verificationInput.serviceIdentity,
  revocation: 'not configured',
});

const result = await verifyCertificateChain(verificationInput);
if (result.ok) {
  console.log(
    'Validated chain (leaf to root):',
    result.value.chain.map((cert) => ({
      subject: cert.subject.values,
      issuer: cert.issuer.values,
      serial: cert.serialNumberHex,
      notBefore: cert.notBefore.toISOString(),
      notAfter: cert.notAfter.toISOString(),
      subjectAltNames: cert.subjectAltNames,
      signatureAlgorithm: cert.signatureAlgorithmName,
    })),
  );
} else {
  console.log('Verification failure:', result.error);
}

// Use the same certificates and time, but ask for a different identity.
const mismatch = await verifyCertificateChain({
  ...verificationInput,
  serviceIdentity: { type: 'dns', value: 'wrong.example.com' },
});
console.log('Wrong-hostname result (expected rejection):', mismatch);
```

</LiveCode>

To check the same material independently, save the two PEM blocks as `root.pem`
and `leaf.pem`. Replace `UNIX_TIME_FROM_OUTPUT` with the printed `unixTime`:

```bash
openssl verify -CAfile root.pem -purpose sslserver -verify_hostname app.example.com -attime UNIX_TIME_FROM_OUTPUT leaf.pem
openssl verify -CAfile root.pem -purpose sslserver -verify_hostname wrong.example.com -attime UNIX_TIME_FROM_OUTPUT leaf.pem
```

The first command should accept the leaf; the second should reject its hostname.
Each run generates new certificates. Keep the printed PEMs and time to repeat
that run's checks.

This example creates its own CA so it runs without external files. In your
application, supply the leaf and intermediates you received and roots you
already trust. Do not make a certificate trusted merely because it arrived
with the leaf. `purpose` and `serviceIdentity` select the application checks;
this example does not supply revocation evidence.

See [the verification contract](./verification.md#what-verification-establishes)
for what a successful result establishes and what your application supplies.

### Create a self-signed certificate

<LiveCode>

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

</LiveCode>

### Create a CSR

<LiveCode>

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

</LiveCode>

### Parse a certificate

<LiveCode>

```ts
import {
  parseCertificatePem,
  createSelfSignedCertificate,
  subjectAltNameToString,
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
    .map((name) => subjectAltNameToString(name))
    .join(', ');
  console.log(`\
subject:   ${parsed.subject.values.commonName}
org:       ${parsed.subject.values.organization}
serial:    ${parsed.serialNumberHex}
sig algo:  ${parsed.signatureAlgorithmName}
pubkey:    ${parsed.publicKeyAlgorithmName}
key usage: ${parsed.keyUsage?.flags.join(', ') ?? 'none'}
SANs:      ${sans}`);
}
```

</LiveCode>

### Reject a self-signed leaf

<LiveCode>

```ts
import { createSelfSignedCertificate, verifyCertificateChain } from 'micro509';

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
serial:  ${selfSigned.ok ? selfSigned.value.leaf.serialNumberHex : ''}`);
```

</LiveCode>

## Working with results

Anything that parses untrusted input returns a `Result`: `{ ok: true, value }`
or `{ ok: false, error }` with a stable machine-readable `error.code`. Builders
taking developer-supplied config throw instead, and the thrown error carries
the same kind of code.

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  parseCertificatePem,
  unwrap,
  unwrapOr,
} from 'micro509';
import { isResultError } from 'micro509/result';

const { certificate } = await createSelfSignedCertificate({
  subject: { commonName: 'results.example' },
});

// Branch on ok for full control...
const parsed = parseCertificatePem(certificate.pem);
if (parsed.ok) {
  console.log(
    `subject:     ${parsed.value.subject.values.commonName}, serial ${parsed.value.serialNumberHex}`,
  );
}

// ...unwrap() to throw on failure...
const known = unwrap(parseCertificatePem(certificate.pem));

// ...or unwrapOr() for a fallback value.
const fallback = unwrapOr(parseCertificatePem('not a pem'), known);
console.log(`fallback:    ${fallback.subject.values.commonName}`);

// An unwrap() throw still carries the typed code.
try {
  unwrap(parseCertificatePem('not a pem'));
} catch (error) {
  if (isResultError(error)) {
    console.log(`caught code: ${error.code}`);
  }
}
```

</LiveCode>

When wrapping a throwing operation into your own `Result`-returning code,
`rethrowIfInvariant(error)` keeps the library's discipline: it rethrows
programmer bugs (`TypeError`, `RangeError`, …) so they are never flattened
into a "malformed input" failure, and returns for everything else.

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
import { verifyCertificateChain, matchServiceIdentity } from 'micro509/verify';
import {
  createOcspRequest,
  checkCertificateRevocation,
} from 'micro509/revocation';
import { createPfx } from 'micro509/pkcs';
import { signData, verifySignature } from 'micro509/crypto';
import { generateKeyPair } from 'micro509/keys';
import { pemDecode, pemEncode } from 'micro509/pem';
import { readDerRoot, decodeDerOid } from 'micro509/der';
import type { Micro509Error } from 'micro509/result';
```
