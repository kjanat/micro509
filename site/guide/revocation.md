# Revocation

The examples below build their own `ca`, `leaf`, CRL, and OCSP material
inline so each one runs on its own.

## CRL lifecycle

### Create a CRL

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  createCertificateRevocationList,
} from 'micro509';

const ca = await createSelfSignedCertificate({
  subject: { commonName: 'My CA' },
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});

const crl = await createCertificateRevocationList({
  issuer: { commonName: 'My CA' },
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
  thisUpdate: new Date(),
  nextUpdate: new Date(
    Date.now() + 7 * 24 * 60 * 60 * 1000,
  ),
  revokedCertificates: [
    {
      serialNumber: Uint8Array.of(0x01),
      revocationDate: new Date(),
      reasonCode: 'keyCompromise',
    },
  ],
});

console.log(crl.pem.split('\n')[0]);
```

</LiveCode>

### Parse and verify a CRL

<LiveCode>

```ts
import { createSelfSignedCertificate } from 'micro509';
import {
  createCertificateRevocationList,
  isCertificateRevoked,
  parseCertificateRevocationListPem,
  verifyCertificateRevocationList,
} from 'micro509/revocation';

const ca = await createSelfSignedCertificate({
  subject: { commonName: 'My CA' },
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});

const crl = await createCertificateRevocationList({
  issuer: { commonName: 'My CA' },
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
  revokedCertificates: [
    {
      serialNumber: Uint8Array.of(0x01),
      reasonCode: 'keyCompromise',
    },
  ],
});

const parsed = parseCertificateRevocationListPem(crl.pem);

const verifyResult = await verifyCertificateRevocationList(
  crl.pem,
  ca.certificate.pem,
);

console.log('verified:', verifyResult.ok);
if (verifyResult.ok) {
  console.log(
    'revoked 01:',
    isCertificateRevoked('01', parsed),
  );
}
```

</LiveCode>

## OCSP

### Build a request

<LiveCode>

```ts
import {
  createCertificate,
  createSelfSignedCertificate,
  generateKeyPair,
} from 'micro509';
import { createOcspRequest } from 'micro509/revocation';

const ca = await createSelfSignedCertificate({
  subject: { commonName: 'Demo CA' },
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});

const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
  issuer: { commonName: 'Demo CA' },
  subject: { commonName: 'app.example.com' },
  publicKey: leafKeys.publicKey,
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
});

const request = await createOcspRequest({
  requests: [
    {
      certificate: leaf.pem,
      issuerCertificate: ca.certificate.pem,
    },
  ],
});

console.log(request.pem.split('\n')[0]);
```

</LiveCode>

### Parse and validate a response

<LiveCode>

```ts
import {
  createCertificate,
  createSelfSignedCertificate,
  generateKeyPair,
} from 'micro509';
import {
  createOcspRequest,
  createOcspResponse,
  parseOcspResponseDer,
  validateOcspResponse,
} from 'micro509/revocation';

const ca = await createSelfSignedCertificate({
  subject: { commonName: 'Demo CA' },
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});

const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
  issuer: { commonName: 'Demo CA' },
  subject: { commonName: 'app.example.com' },
  publicKey: leafKeys.publicKey,
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
});

const request = await createOcspRequest({
  requests: [
    {
      certificate: leaf.pem,
      issuerCertificate: ca.certificate.pem,
    },
  ],
});

// Responder signs an OCSP response for the leaf
const ocsp = await createOcspResponse({
  signerPrivateKey: ca.keyPair.privateKey,
  signerCertificate: ca.certificate.pem,
  responses: [
    {
      certificate: leaf.pem,
      issuerCertificate: ca.certificate.pem,
      certStatus: 'good',
    },
  ],
});

const response = parseOcspResponseDer(ocsp.der);

const result = await validateOcspResponse({
  response,
  request: request.der,
  issuerCertificate: ca.certificate.pem,
});

console.log('valid:', result.ok);
if (result.ok) {
  const entry = result.value.responses?.[0];
  console.log(entry?.certStatus);
}
```

</LiveCode>

## Orchestrated revocation check

<LiveCode>

```ts
import {
  createCertificate,
  createSelfSignedCertificate,
  generateKeyPair,
  parseCertificatePem,
} from 'micro509';
import {
  checkCertificateRevocation,
  createCertificateRevocationList,
  createOcspResponse,
} from 'micro509/revocation';

const ca = await createSelfSignedCertificate({
  subject: { commonName: 'Demo CA' },
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});

const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
  issuer: { commonName: 'Demo CA' },
  subject: { commonName: 'app.example.com' },
  publicKey: leafKeys.publicKey,
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
});

// Leaf serial as bytes for the CRL entry
const parsedLeaf = parseCertificatePem(leaf.pem);
const serialHex = parsedLeaf.serialNumberHex;
const leafSerial = Uint8Array.from(
  serialHex.match(/.{2}/g) ?? [],
  (byte) => parseInt(byte, 16),
);

// CRL evidence that revokes the leaf
const crl = await createCertificateRevocationList({
  issuer: { commonName: 'Demo CA' },
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
  revokedCertificates: [
    {
      serialNumber: leafSerial,
      revocationDate: new Date(),
      reasonCode: 'keyCompromise',
    },
  ],
});

// OCSP evidence that also reports revoked
const ocsp = await createOcspResponse({
  signerPrivateKey: ca.keyPair.privateKey,
  signerCertificate: ca.certificate.pem,
  responses: [
    {
      certificate: leaf.pem,
      issuerCertificate: ca.certificate.pem,
      certStatus: 'revoked',
      revokedAt: new Date(),
    },
  ],
});

const result = await checkCertificateRevocation({
  certificate: leaf.pem,
  issuerCertificate: ca.certificate.pem,
  evidence: [
    { kind: 'crl', crl: crl.pem },
    { kind: 'ocsp', response: ocsp.der },
  ],
});

// Always succeeds — check status discriminator
console.log('status:', result.value.status);
if (result.value.status === 'revoked') {
  console.log('revoked at:', result.value.revokedAt);
}
```

</LiveCode>
