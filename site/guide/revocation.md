# Revocation

Examples below assume `ca`, `leaf`, `crlPem`, and `ocspDer` are already defined.

## CRL lifecycle

### Create a CRL

```ts
import { createCertificateRevocationList } from 'micro509/revocation';

const crl = await createCertificateRevocationList({
  issuerCertificate: ca.certificate,
  signerPrivateKey: ca.keyPair.privateKey,
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
  parsed,
  ca.certificate,
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
  issuerCertificate: ca.certificate,
  serialNumber: leaf.serialNumber,
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
  issuerCertificate: ca.certificate,
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
  certificate: leaf,
  issuerCertificate: ca.certificate,
  evidence: {
    crls: [crlPem],
    ocspResponses: [ocspDer],
  },
});

if (result.ok) {
  console.log('Revocation status:', result.value.status);
} else {
  console.error('Revocation check failed:', result.error);
}
```
