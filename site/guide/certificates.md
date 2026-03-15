# Certificates

## Create a self-signed certificate

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
```

## Create a CA-signed certificate

```ts
import {
  createCertificate,
  createSelfSignedCertificate,
  generateKeyPair,
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
  namedCurve: 'P-256',
});

// Issue a leaf certificate
const leaf = await createCertificate({
  subject: { commonName: 'leaf.example.com' },
  validity: { days: 90 },
  issuerCertificate: ca.certificate,
  signerPrivateKey: ca.keyPair.privateKey,
  subjectPublicKey: leafKeyPair.publicKey,
  extensions: {
    keyUsage: ['digitalSignature'],
    subjectAltNames: [
      { type: 'dns', value: 'leaf.example.com' },
    ],
  },
});
```

## Create a CSR

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
```

## Parse a certificate

```ts
import { parseCertificatePem } from 'micro509';

const parsed = parseCertificatePem(pem);

// Typed metadata
parsed.subject.values.commonName;
parsed.issuer.values.organizationName;
parsed.validity.notBefore;
parsed.validity.notAfter;

// Typed extensions
parsed.basicConstraints; // { ca: boolean, pathLenConstraint?: number }
parsed.keyUsage; // readonly KeyUsageFlag[]
parsed.extendedKeyUsage; // readonly string[]
parsed.subjectAltNames; // readonly SubjectAltName[]
parsed.authorityInfoAccess; // readonly AuthorityInformationAccess[]
```

## Parse a CSR

```ts
import { parseCertificateSigningRequestPem } from 'micro509';

const parsed = parseCertificateSigningRequestPem(pem);
parsed.subject.values.commonName;
```
