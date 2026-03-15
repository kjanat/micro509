# PKCS

## PFX / PKCS#12

### Create a PFX bundle

```ts
import { createPfx } from 'micro509/pkcs';

const pfx = await createPfx({
  certificate: cert.pem,
  privateKey: keyPair.privateKey,
  caCertificates: [ca.certificate.pem],
  password: 'secret',
});

// pfx.der — Uint8Array
// pfx.base64 — base64-encoded string
```

### Parse a PFX bundle

```ts
import { parsePfxDer } from 'micro509/pkcs';

const result = await parsePfxDer(der, 'secret');

if (result.ok) {
  result.value.certificates; // parsed certificates
  result.value.privateKey; // CryptoKey
}
```

## PKCS#7 / CMS

### Create a certificate bag

```ts
import { createPkcs7CertBagPem } from 'micro509/pkcs';

const bag = createPkcs7CertBagPem([cert1.pem, cert2.pem]);
```

### Parse a certificate bag

```ts
import { parsePkcs7CertBagPem } from 'micro509/pkcs';

const result = parsePkcs7CertBagPem(pem);

if (result.ok) {
  result.value.certificates; // parsed certificates
}
```

### Verify SignedData

```ts
import { parsePkcs7SignedDataDer, verifyPkcs7SignedData } from 'micro509/pkcs';

const result = parsePkcs7SignedDataDer(der);

if (result.ok) {
  const verifyResult = await verifyPkcs7SignedData(result.value);

  if (verifyResult.ok) {
    console.log('All signers verified');
  }
}
```

## PEM utilities

```ts
import { pemDecode, pemEncode, splitPemBlocks, categorizePemBlocks } from 'micro509/pem';

// Decode a single PEM block
const pem = '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----';
const der = pemDecode(pem);

// Encode DER as PEM
const pemEncoded = pemEncode(der, 'CERTIFICATE');

// Split a multi-block PEM file
const blocks = splitPemBlocks(multiPem);

// Categorize blocks by type
const { certificates, privateKeys, csrs } = categorizePemBlocks(multiPem);
```
