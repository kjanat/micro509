# Certificates

## Create a self-signed certificate

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
    validity: { days: 365 },
    extensions: {
      keyUsage: ['digitalSignature', 'keyEncipherment'],
      subjectAltNames: [
        { type: 'dns', value: 'example.com' },
        { type: 'dns', value: '*.example.com' },
      ],
    },
  });

console.log(certificate.pem.split('\n')[0]);
console.log(await keyPair.exportPkcs8Pem());
```

</LiveCode>

## Create a CA-signed certificate

<LiveCode>

```ts
import {
  createCertificate,
  createSelfSignedCertificate,
  generateKeyPair,
  parseCertificatePem,
} from 'micro509';

// Create a CA
const ca = await createSelfSignedCertificate({
  subject: { commonName: 'My CA' },
  validity: { days: 3650 },
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});

// Generate a key pair for the leaf certificate
const leafKeyPair = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});

// Issue a leaf certificate
const leaf = await createCertificate({
  issuer: { commonName: 'My CA' },
  subject: { commonName: 'leaf.example.com' },
  validity: { days: 90 },
  publicKey: leafKeyPair.publicKey,
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
  extensions: {
    keyUsage: ['digitalSignature'],
    subjectAltNames: [
      { type: 'dns', value: 'leaf.example.com' },
    ],
  },
});

const parsed = parseCertificatePem(leaf.pem);
console.log('leaf:  ', parsed.subject.values.commonName);
console.log('issuer:', parsed.issuer.values.commonName);
```

</LiveCode>

## Create a CSR

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

console.log(csr.pem.split('\n')[0]);
```

</LiveCode>

## Parse a certificate

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  parseCertificatePem,
} from 'micro509';

// Build a certificate inline, then parse it back
const { certificate } = await createSelfSignedCertificate({
  subject: {
    commonName: 'example.com',
    organization: 'Acme',
    country: 'US',
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

// Typed metadata
const sans = parsed.subjectAltNames ?? [];
console.log(`\
subject:   ${parsed.subject.values.commonName}
org:       ${parsed.subject.values.organization}
issuer:    ${parsed.issuer.values.commonName}
notBefore: ${parsed.notBefore.toISOString()}
notAfter:  ${parsed.notAfter.toISOString()}
sig algo:  ${parsed.signatureAlgorithmName}
ca:        ${parsed.basicConstraints?.ca ?? false}
key usage: ${parsed.keyUsage?.flags.join(', ')}
SANs:      ${sans.map((n) => n.value).join(', ')}`);
```

</LiveCode>

## Parse a CSR

<LiveCode>

```ts
import {
  createCertificateSigningRequest,
  generateKeyPair,
  parseCertificateSigningRequestPem,
} from 'micro509';

// Build a CSR inline, then parse it back
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

const parsed = parseCertificateSigningRequestPem(csr.pem);
const sans = parsed.subjectAltNames ?? [];
console.log(`\
subject:  ${parsed.subject.values.commonName}
sig algo: ${parsed.signatureAlgorithmName}
SANs:     ${sans.map((n) => n.value).join(', ')}`);
```

</LiveCode>
