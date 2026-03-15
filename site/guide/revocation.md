# Revocation

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

const parsed = parseCertificateRevocationListPem(pem);

const verifyResult = await verifyCertificateRevocationList(
  parsed,
  ca.certificate,
);

const revoked = isCertificateRevoked('01', parsed);
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

const response = parseOcspResponseDer(der);

const result = await validateOcspResponse({
  response,
  request,
  issuerCertificate: ca.certificate,
});

if (result.ok) {
  // 'good' | 'revoked' | 'unknown'
  console.log(result.value.status);
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
```
