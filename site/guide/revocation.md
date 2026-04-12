# Revocation

Examples below assume `ca`, `leaf`, `crlPem`, and `ocspDer` are already defined.

## CRL lifecycle

### Create a CRL

```ts
import { createCertificateRevocationList } from 'micro509/revocation';

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
      serialNumber: '01',
      revocationDate: new Date(),
      reason: 'keyCompromise',
    },
  ],
});
```

### Parse and verify a CRL

```ts
import {
  parseCertificateRevocationListPem,
  verifyCertificateRevocationList,
  isCertificateRevoked,
} from 'micro509/revocation';

const parsed = parseCertificateRevocationListPem(crlPem);

const verifyResult = await verifyCertificateRevocationList(
  crlPem,
  ca.certificate.pem,
);

if (verifyResult.ok) {
  const revoked = isCertificateRevoked('01', parsed);
}
```

## OCSP

### Build a request

```ts
import { createOcspRequest } from 'micro509/revocation';

const request = await createOcspRequest({
  requests: [
    {
      certificate: leaf.pem,
      issuerCertificate: ca.certificate.pem,
    },
  ],
});
```

### Parse and validate a response

```ts
import {
  parseOcspResponseDer,
  validateOcspResponse,
} from 'micro509/revocation';

const response = parseOcspResponseDer(ocspDer);

const result = await validateOcspResponse({
  response,
  request,
  issuerCertificate: ca.certificate.pem,
});

if (result.ok) {
  const entry = result.value.responses?.[0];
  console.log(entry?.certStatus); // 'good' | 'revoked' | 'unknown'
}
```

## Orchestrated revocation check

```ts
import { checkCertificateRevocation } from 'micro509/revocation';

const result = await checkCertificateRevocation({
  certificate: leaf.pem,
  issuerCertificate: ca.certificate.pem,
  evidence: [
    { kind: 'crl', crl: crlPem },
    { kind: 'ocsp', response: ocspDer },
  ],
});

// Always succeeds — check status discriminator
console.log('Revocation status:', result.value.status);
if (result.value.status === 'revoked') {
  console.log('Revoked at:', result.value.revokedAt);
}
```
