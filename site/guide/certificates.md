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
const sans = (parsed.subjectAltNames ?? [])
  .filter((name) => name.type !== 'directoryName')
  .map((name) => name.value);
console.log(`\
subject:   ${parsed.subject.values.commonName}
org:       ${parsed.subject.values.organization}
issuer:    ${parsed.issuer.values.commonName}
notBefore: ${parsed.notBefore.toISOString()}
notAfter:  ${parsed.notAfter.toISOString()}
sig algo:  ${parsed.signatureAlgorithmName}
ca:        ${parsed.basicConstraints?.ca ?? false}
key usage: ${parsed.keyUsage?.flags.join(', ')}
SANs:      ${sans.join(', ')}`);
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

## Fingerprint a certificate

The certificate fingerprint is a hash over the DER encoding — the identifier
`openssl x509 -fingerprint` and every TLS UI display. `certificateFingerprint`
accepts a PEM string, DER bytes, or an already-parsed certificate and returns
the digest as raw `bytes`, lowercase `hex`, and uppercase colon-separated
`colonHex` (the openssl form). It defaults to SHA-256; pass `'SHA-1'`,
`'SHA-384'`, or `'SHA-512'` for legacy interop.

<LiveCode>

```ts
import {
  certificateFingerprint,
  createSelfSignedCertificate,
} from 'micro509';

const { certificate } = await createSelfSignedCertificate({
  subject: { commonName: 'fingerprint.example' },
});

const sha256 = await certificateFingerprint(
  certificate.pem,
);
const sha1 = await certificateFingerprint(
  certificate.der,
  'SHA-1',
);

console.log(`\
SHA-256: ${sha256.colonHex}
hex:     ${sha256.hex}
SHA-1:   ${sha1.colonHex}`);
```

</LiveCode>

## Match a certificate to a private key

Before a key-intake or issuance endpoint trusts an uploaded private key, it has
to confirm the key actually belongs to the certificate it arrived with.
`certificateMatchesPrivateKey` is that check: it derives the public half of the
private key, exports it as SubjectPublicKeyInfo DER, and byte-compares it
against the certificate's own SPKI — the canonical, algorithm-agnostic way to
prove ownership. It returns a plain `boolean`, and a key of a different type (or
a different key of the same type) simply produces different SPKI and returns
`false`. The certificate argument accepts a PEM string, DER bytes, or an
already-parsed certificate.

<LiveCode>

```ts
import {
  certificateMatchesPrivateKey,
  createSelfSignedCertificate,
  generateKeyPair,
} from 'micro509';

const { certificate, keyPair } =
  await createSelfSignedCertificate({
    subject: { commonName: 'match.example' },
    algorithm: { kind: 'ecdsa', curve: 'P-256' },
  });

// The key that issued the certificate matches...
console.log(
  'own key matches:',
  await certificateMatchesPrivateKey(
    certificate.pem,
    keyPair.privateKey,
  ),
);

// ...an unrelated key of the same type does not.
const impostor = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});
console.log(
  'impostor key matches:',
  await certificateMatchesPrivateKey(
    certificate.pem,
    impostor.privateKey,
  ),
);
```

</LiveCode>

When you need the _reason_ a match failed rather than a bare `false` — or a typed
failure instead of a thrown error on untrusted input — reach for
`matchCertificatePrivateKey`, the `Result`-returning companion. It succeeds
(`ok: true`) on a match, or fails with a code of `key_mismatch` (right algorithm,
wrong key), `key_type_mismatch` (wrong algorithm), `malformed_certificate`, or
`unsupported_private_key`:

<LiveCode>

```ts
import {
  generateKeyPair,
  matchCertificatePrivateKey,
  createSelfSignedCertificate,
} from 'micro509';

const { certificate } = await createSelfSignedCertificate({
  subject: { commonName: 'reason.example' },
  algorithm: { kind: 'ecdsa', curve: 'P-256' },
});

// A key of the wrong algorithm reports why, without throwing.
const rsa = await generateKeyPair({
  kind: 'rsa',
  modulusLength: 2048,
});
const result = await matchCertificatePrivateKey(
  certificate.pem,
  rsa.privateKey,
);
console.log(result.ok ? 'match' : result.code);
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
const sans = (parsed.subjectAltNames ?? [])
  .filter((name) => name.type !== 'directoryName')
  .map((name) => name.value);
console.log(`\
subject:  ${parsed.subject.values.commonName}
sig algo: ${parsed.signatureAlgorithmName}
SANs:     ${sans.join(', ')}`);
```

</LiveCode>
