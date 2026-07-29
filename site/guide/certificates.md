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

With no key input, a fresh ECDSA P-256 pair is generated. Pass
`algorithm: { kind: 'ed25519' }` (or `'rsa'`, or another curve) to pick the
key type, or `keyPair` to reuse keys you already hold. The two are mutually
exclusive by type.

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
  distinguishedNameToString,
  parseCertificatePem,
  subjectAltNameToString,
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

// Typed metadata: RFC 4514 DN rendering, the random
// serial, the embedded subject key identifier, and the
// raw extension list with criticality
const sans = (parsed.subjectAltNames ?? []).map((name) =>
  subjectAltNameToString(name, { prefix: true }),
);
const days = Math.round(
  (parsed.notAfter.getTime() - parsed.notBefore.getTime()) /
    86_400_000,
);
console.log(`\
subject:    ${distinguishedNameToString(parsed.subject)}
serial:     ${parsed.serialNumberHex}
public key: ${parsed.publicKeyAlgorithmName}, SKI ${parsed.subjectKeyIdentifier}
signature:  ${parsed.signatureAlgorithmName}
validity:   ${days} days from ${parsed.notBefore.toISOString().slice(0, 10)}
key usage:  ${parsed.keyUsage?.flags.join(', ')}
SANs:       ${sans.join(', ')}
extensions: ${parsed.extensions
  .map(
    (ext) =>
      `${ext.oid}${ext.critical ? ' (critical)' : ''}`,
  )
  .join(', ')}`);
```

</LiveCode>

## Parse a certificate bundle

`parseCertificateChainPem` decodes a PEM bundle (a leaf plus its
intermediates, a trust store dump) into parsed certificates, skipping
non-CERTIFICATE blocks such as private keys. Combined with
`compareDistinguishedNames`, that is enough to reconstruct who issued whom
from a bundle in any order. When input arrives as "whatever the caller had",
`parseCertificateFromSource` accepts PEM text, DER bytes, or an
already-parsed certificate and returns the parsed form, throwing on
malformed input.

<LiveCode>

```ts
import {
  compareDistinguishedNames,
  createCertificate,
  createSelfSignedCertificate,
  generateKeyPair,
  parseCertificateChainPem,
  parseCertificateFromSource,
  unwrap,
} from 'micro509';

const ca = await createSelfSignedCertificate({
  subject: {
    commonName: 'Bundle Root CA',
    organization: 'Acme',
  },
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign'],
  },
});
const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
  issuer: {
    commonName: 'Bundle Root CA',
    organization: 'Acme',
  },
  subject: { commonName: 'bundle.example' },
  publicKey: leafKeys.publicKey,
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
});

// A typical fullchain dump: certificates in whatever
// order, with a stray private key between them
const bundle = [
  leaf.pem,
  await ca.keyPair.exportPkcs8Pem(),
  ca.certificate.pem,
].join('\n');

const chain = unwrap(parseCertificateChainPem(bundle));
console.log(
  `${chain.length} certificates parsed, key block skipped`,
);

// Sort out who is who: CA flags, then issuer -> subject
// links by RFC 5280 semantic DN comparison
for (const cert of chain) {
  const role =
    cert.basicConstraints?.ca === true ? 'CA  ' : 'leaf';
  const issuer = chain.find((candidate) =>
    compareDistinguishedNames(
      cert.issuer,
      candidate.subject,
    ),
  );
  const signer =
    issuer === cert
      ? 'self-signed'
      : `issued by ${issuer?.subject.values.commonName}`;
  console.log(
    `${role} ${(cert.subject.values.commonName ?? '?').padEnd(16)} ${signer}, serial ${cert.serialNumberHex}`,
  );
}

// PEM, DER, or already-parsed: one normalizer
const fromDer = parseCertificateFromSource(leaf.der);
console.log(
  `DER  ${(fromDer.subject.values.commonName ?? '?').padEnd(16)} same certificate: ${
    fromDer.serialNumberHex === chain[0]?.serialNumberHex
  }`,
);
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
  distinguishedNameToString,
  exportSpkiPem,
  getSubjectPublicKey,
  parseCertificatePem,
  unwrap,
} from 'micro509';

const { certificate } = await createSelfSignedCertificate({
  subject: {
    commonName: 'spki.example',
    organization: 'Acme',
  },
});

const parsed = unwrap(parseCertificatePem(certificate.pem));

// Algorithm and curve are inferred from the certificate's own SPKI
const publicKey = unwrap(await getSubjectPublicKey(parsed));

console.log(`\
subject:  ${distinguishedNameToString(parsed.subject)}
serial:   ${parsed.serialNumberHex}
inferred: ${parsed.publicKeyAlgorithmName} -> ${JSON.stringify(publicKey.algorithm)}
usages:   ${publicKey.usages.join(', ')}, extractable ${publicKey.extractable}`);
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
  certificateFingerprint,
  certificateMatchesPrivateKey,
  createSelfSignedCertificate,
  generateKeyPair,
} from 'micro509';

const { certificate, keyPair } =
  await createSelfSignedCertificate({
    subject: { commonName: 'match.example' },
    algorithm: { kind: 'ecdsa', curve: 'P-256' },
  });

const { colonHex } = await certificateFingerprint(
  certificate.pem,
);
console.log(`certificate:  ${colonHex.slice(0, 47)}…`);

// The key that issued the certificate matches...
console.log(
  `own key:      ${await certificateMatchesPrivateKey(
    certificate.pem,
    keyPair.privateKey,
  )}`,
);

// ...an unrelated key of the same type does not.
const impostor = await generateKeyPair({
  kind: 'ecdsa',
  curve: 'P-256',
});
console.log(
  `impostor key: ${await certificateMatchesPrivateKey(
    certificate.pem,
    impostor.privateKey,
  )}`,
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
  certificateFingerprint,
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
const { hex } = await certificateFingerprint(
  certificate.pem,
);
console.log(
  result.ok ? 'match' : result.code,
  `(certificate ${hex.slice(0, 40)}…)`,
);
```

</LiveCode>

## Parse a CSR

<LiveCode>

```ts
import {
  createCertificateSigningRequest,
  generateKeyPair,
  parseCertificateSigningRequestPem,
  subjectAltNameToString,
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
const sans = (parsed.subjectAltNames ?? []).map((name) =>
  subjectAltNameToString(name),
);
const body = csr.pem
  .trimEnd()
  .split('\n')
  .slice(1, -1)
  .join('');
console.log(`\
subject:   ${parsed.subject.values.commonName}
sig algo:  ${parsed.signatureAlgorithmName}
SANs:      ${sans.join(', ')}
signature: …${body.slice(-44)}`);
```

</LiveCode>

For extensions micro509 has no typed field for, see
[Extensions](./extensions.md).
