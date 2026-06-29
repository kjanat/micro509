# PKCS

## PFX / PKCS#12

### Create a PFX bundle

<LiveCode>

```ts
import { createSelfSignedCertificate } from 'micro509';
import { createPfx } from 'micro509/pkcs';

const ca = await createSelfSignedCertificate({
  subject: { commonName: 'Demo CA' },
  extensions: { basicConstraints: { ca: true } },
});
const cert = await createSelfSignedCertificate({
  subject: { commonName: 'leaf.example' },
});

const pfx = await createPfx({
  certificates: [
    { certificate: cert.certificate.pem },
    { certificate: ca.certificate.pem },
  ],
  privateKeys: [{ privateKey: cert.keyPair.privateKey }],
  encryption: { password: 'secret' },
  mac: { password: 'secret' },
});

console.log(`der bytes:  ${pfx.der.length}`);
console.log(`base64 len: ${pfx.base64.length}`);
console.log(pfx.pem.slice(0, 24));
```

</LiveCode>

### Parse a PFX bundle

<LiveCode>

```ts
import { createSelfSignedCertificate } from 'micro509';
import { createPfx, parsePfxDer } from 'micro509/pkcs';

// Build a PFX inline to parse back
const cert = await createSelfSignedCertificate({
  subject: { commonName: 'leaf.example' },
});
const pfx = await createPfx({
  certificates: [{ certificate: cert.certificate.pem }],
  privateKeys: [{ privateKey: cert.keyPair.privateKey }],
  encryption: { password: 'secret' },
  mac: { password: 'secret' },
});

const result = await parsePfxDer(pfx.der, {
  password: 'secret',
});

if (result.ok) {
  const { certificates, privateKeys, bags } = result.value;
  const leafCert = certificates[0];
  console.log(`certs:        ${certificates.length}`);
  console.log(`private keys: ${privateKeys.length}`);
  console.log(`bags:         ${bags.length}`);
  console.log(
    `subject: ${leafCert?.subject.values.commonName}`,
  );
} else {
  console.log(`parse failed: ${result.error.code}`);
}
```

</LiveCode>

## PKCS#7 / CMS

### Create a certificate bag

<LiveCode>

```ts
import { createSelfSignedCertificate } from 'micro509';
import { createPkcs7CertBagPem } from 'micro509/pkcs';

// Two real certificates to bundle
const a = await createSelfSignedCertificate({
  subject: { commonName: 'a.example' },
});
const b = await createSelfSignedCertificate({
  subject: { commonName: 'b.example' },
});

const bag = createPkcs7CertBagPem([
  a.certificate.pem,
  b.certificate.pem,
]);

console.log(`der bytes: ${bag.der.length}`);
console.log(bag.pem.slice(0, 22));
```

</LiveCode>

### Parse a certificate bag

<LiveCode>

```ts
import { createSelfSignedCertificate } from 'micro509';
import {
  createPkcs7CertBagPem,
  parsePkcs7CertBagPem,
} from 'micro509/pkcs';

// Build a real cert bag inline
const a = await createSelfSignedCertificate({
  subject: { commonName: 'a.example' },
});
const b = await createSelfSignedCertificate({
  subject: { commonName: 'b.example' },
});
const bag = createPkcs7CertBagPem([
  a.certificate.pem,
  b.certificate.pem,
]);

const result = parsePkcs7CertBagPem(bag.pem);

if (result.ok) {
  const certificates = result.value;
  console.log(`certs: ${certificates.length}`);
  for (const cert of certificates) {
    console.log(cert.subject.values.commonName);
  }
} else {
  console.log(`parse failed: ${result.error.code}`);
}
```

</LiveCode>

### Sign and verify content

<LiveCode>

```ts
import { createSelfSignedCertificate } from 'micro509';
import {
  createPkcs7SignedDataPem,
  verifyPkcs7SignedData,
} from 'micro509/pkcs';

// A signer is a certificate + its matching private key
const signer = await createSelfSignedCertificate({
  subject: { commonName: 'signer.example' },
  extensions: { keyUsage: ['digitalSignature'] },
});

// Sign content -> attached CMS SignedData (RFC 5652)
const content = new TextEncoder().encode('hello');
const signed = await createPkcs7SignedDataPem({
  content,
  signers: [
    {
      certificate: signer.certificate.pem,
      privateKey: signer.keyPair.privateKey,
    },
  ],
});

// Creation returns a typed result; verify on success
if (!signed.ok) {
  console.log(`sign failed: ${signed.error.code}`);
} else {
  const result = await verifyPkcs7SignedData(
    signed.value.pem,
  );
  if (result.ok) {
    const sd = result.value;
    const info = sd.signerInfos[0];
    console.log('verified: true');
    console.log('signers: ', sd.signerInfos.length);
    console.log('digest:  ', info?.digestAlgorithmName);
  } else {
    console.log(`verify: ${result.error.code}`);
  }
}
```

</LiveCode>

## PEM utilities

<LiveCode>

```ts
import { createSelfSignedCertificate } from 'micro509';
import {
  categorizePemBlocks,
  pemDecode,
  pemEncode,
  splitPemBlocks,
} from 'micro509/pem';

// A real certificate to feed the PEM helpers
const { certificate } = await createSelfSignedCertificate({
  subject: { commonName: 'pem.example' },
});
const pem = certificate.pem;

// Decode a single PEM block to DER
const der = pemDecode('CERTIFICATE', pem);

// Encode DER back to PEM
const pemEncoded = pemEncode('CERTIFICATE', der);

// Split a multi-block PEM file
const multiPem = `${pem}\n${pem}`;
const blocks = splitPemBlocks(multiPem);

// Categorize blocks by type
const { certificates, certificateRequests, privateKeys } =
  categorizePemBlocks(multiPem);

console.log(`der bytes:    ${der.length}`);
console.log(`round-trip:   ${pemEncoded === pem}`);
console.log(`blocks:       ${blocks.length}`);
console.log(`certs:        ${certificates.length}`);
console.log(`csrs:         ${certificateRequests.length}`);
console.log(`private keys: ${privateKeys.length}`);
```

</LiveCode>
