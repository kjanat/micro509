# Revocation

The examples below build their own `ca`, `leaf`, CRL, and OCSP material
inline so each one runs on its own.

::: warning Revocation checking defaults to hard-fail
Revocation checking only runs when you supply evidence — and once you do,
`RevocationPolicy.mode` defaults to `'hard-fail'`: certificates whose
revocation status is **indeterminate** (no applicable CRL/OCSP evidence,
expired evidence, untrusted signer) are **denied**. If availability matters
more than strictness — partial evidence is normal in your setup — opt out
explicitly with `policy: { mode: 'soft-fail' }`, which allows indeterminate
status and denies only on a confirmed `revoked` verdict.
:::

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

console.log(crl.pem);
```

</LiveCode>

### Parse and verify a CRL

<LiveCode>

```ts
import { createSelfSignedCertificate } from 'micro509';
import {
  createCertificateRevocationList,
  isCertificateRevoked,
  parseCertificateRevocationListPemOrThrow,
  verifyCertificateRevocationListSignature,
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

const parsed = parseCertificateRevocationListPemOrThrow(
  crl.pem,
);

const verifyResult =
  await verifyCertificateRevocationListSignature(
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

console.log(request.pem);
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
  parseOcspResponseDerOrThrow,
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

const response = parseOcspResponseDerOrThrow(ocsp.der);

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
  unwrap,
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
const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
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

## Chain-level revocation

`checkChainRevocation()` evaluates CRL **and** OCSP evidence for every
certificate in a validated chain (the trust anchor is never checked). Each
OCSP response is fully validated — signature, responder binding and
authorization, freshness — before its verdict is trusted, and a validated
`revoked` verdict from either evidence kind always wins, regardless of
`policy.prefer`.

When both sources yield a validated `good` verdict, `policy.prefer` decides
which one is reported: the default `'best-available'` picks the source with
the fresher evidence (later `thisUpdate`, ties favoring OCSP), while `'ocsp'`
and `'crl'` pin the reported source unconditionally. The winning evidence's
timestamp is reported as `source.thisUpdate` on each certificate's status,
so callers can enforce their own maximum evidence age.

The same inputs are available on `verifyCertificateChain()` via the
`revocation` option:

<LiveCode>

```ts
import {
  createCertificate,
  createOcspResponse,
  createSelfSignedCertificate,
  generateKeyPair,
  verifyCertificateChain,
} from 'micro509';

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

const ocsp = await createOcspResponse({
  signerPrivateKey: ca.keyPair.privateKey,
  signerCertificate: ca.certificate.pem,
  responses: [
    {
      certificate: leaf.pem,
      issuerCertificate: ca.certificate.pem,
      certStatus: 'good',
      thisUpdate: new Date(Date.now() - 60_000),
      nextUpdate: new Date(Date.now() + 3_600_000),
    },
  ],
});

const result = await verifyCertificateChain({
  leaf: leaf.pem,
  roots: [ca.certificate.pem],
  revocation: {
    // hard-fail is the default: indeterminate status ⇒ verification fails
    ocspResponses: [ocsp.der],
  },
});

console.log('verified:', result.ok);
```

</LiveCode>
