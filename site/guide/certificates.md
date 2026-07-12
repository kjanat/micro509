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

console.log(certificate.pem);
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
  unwrap,
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

const parsed = unwrap(parseCertificatePem(leaf.pem));
console.log(`\
leaf:    ${parsed.subject.values.commonName}
issuer:  ${parsed.issuer.values.commonName}
serial:  ${parsed.serialNumberHex}
expires: ${parsed.notAfter.toISOString()}
sig:     ${parsed.signatureAlgorithmName}`);
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

console.log(csr.pem);
```

</LiveCode>

## Parse a certificate

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  parseCertificatePem,
  unwrap,
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

const parsed = unwrap(parseCertificatePem(certificate.pem));

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

## Get the subject public key

A parsed certificate (or CSR) exposes its SubjectPublicKeyInfo as raw DER plus
algorithm OIDs. `getSubjectPublicKey` turns that into a usable WebCrypto
`CryptoKey` directly — the algorithm, and for EC keys the curve, is inferred
from the SPKI itself, so there is no OID mapping to hand-roll. The returned
key is extractable with `verify` usage, ready for `exportSpkiPem`/
`exportSpkiDer` or signature checks.

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  exportSpkiPem,
  getSubjectPublicKey,
  parseCertificatePem,
  unwrap,
} from 'micro509';

const { certificate } = await createSelfSignedCertificate({
  subject: { commonName: 'spki.example' },
});

const parsed = unwrap(parseCertificatePem(certificate.pem));

// Algorithm and curve are inferred from the certificate's own SPKI
const publicKey = unwrap(await getSubjectPublicKey(parsed));

console.log(
  `${parsed.publicKeyAlgorithmName} -> ${publicKey.algorithm.name}`,
);
console.log(await exportSpkiPem(publicKey));
```

</LiveCode>

## Parse a CSR

<LiveCode>

```ts
import {
  createCertificateSigningRequest,
  generateKeyPair,
  parseCertificateSigningRequestPem,
  unwrap,
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

const parsed = unwrap(
  parseCertificateSigningRequestPem(csr.pem),
);
const sans = parsed.subjectAltNames ?? [];
console.log(`\
subject:  ${parsed.subject.values.commonName}
sig algo: ${parsed.signatureAlgorithmName}
SANs:     ${sans.map((n) => n.value).join(', ')}`);
```

</LiveCode>
