---
layout: home
---

# micro509

TypeScript PKI with WebCrypto, zero runtime dependencies, and typed verification
results. [Get started](./guide/getting-started.md) · [API reference](./api/index.md)

## Run it: verify a certificate

Run this example to generate a CA and leaf, inspect their PEMs and validated
chain, and see the same certificate rejected for the wrong hostname. Copy the
output to repeat the checks with OpenSSL.

```bash
npm install micro509
```

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  createCertificate,
  generateKeyPair,
  verifyCertificateChain,
} from 'micro509';

// Create a CA root
const ca = await createSelfSignedCertificate({
  subject: { commonName: 'Demo Root CA' },
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});

// Issue a leaf signed by the CA
const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
  issuer: { commonName: 'Demo Root CA' },
  subject: { commonName: 'app.example.com' },
  publicKey: leafKeys.publicKey,
  signerPrivateKey: ca.keyPair.privateKey,
  issuerCertificate: ca.certificate.pem,
  extensions: {
    extendedKeyUsage: ['serverAuth'],
    subjectAltNames: [{ type: 'dns', value: 'app.example.com' }],
  },
});

// Verify the CA → leaf chain
const verificationInput = {
  at: new Date(),
  leaf: leaf.pem,
  roots: [ca.certificate.pem],
  purpose: 'serverAuth',
  serviceIdentity: {
    type: 'dns',
    value: 'app.example.com',
  },
} as const;

console.log('Trusted root PEM (save as root.pem):\n' + ca.certificate.pem);
console.log('Leaf PEM (save as leaf.pem):\n' + leaf.pem);
console.log('Verification inputs:', {
  at: verificationInput.at.toISOString(),
  unixTime: Math.floor(verificationInput.at.getTime() / 1000),
  purpose: verificationInput.purpose,
  serviceIdentity: verificationInput.serviceIdentity,
  revocation: 'not configured',
});

const result = await verifyCertificateChain(verificationInput);
if (result.ok) {
  console.log(
    'Validated chain (leaf to root):',
    result.value.chain.map((cert) => ({
      subject: cert.subject.values,
      issuer: cert.issuer.values,
      serial: cert.serialNumberHex,
      notBefore: cert.notBefore.toISOString(),
      notAfter: cert.notAfter.toISOString(),
      subjectAltNames: cert.subjectAltNames,
      signatureAlgorithm: cert.signatureAlgorithmName,
    })),
  );
} else {
  console.log('Verification failure:', result.error);
}

// Use the same certificates and time, but ask for a different identity.
const mismatch = await verifyCertificateChain({
  ...verificationInput,
  serviceIdentity: { type: 'dns', value: 'wrong.example.com' },
});
console.log('Wrong-hostname result (expected rejection):', mismatch);
```

</LiveCode>

To check the same material independently, save the two PEM blocks as `root.pem`
and `leaf.pem`. Replace `UNIX_TIME_FROM_OUTPUT` with the printed `unixTime`:

```bash
openssl verify -CAfile root.pem -purpose sslserver -verify_hostname app.example.com -attime UNIX_TIME_FROM_OUTPUT leaf.pem
openssl verify -CAfile root.pem -purpose sslserver -verify_hostname wrong.example.com -attime UNIX_TIME_FROM_OUTPUT leaf.pem
```

The first command should accept the leaf; the second should reject its hostname.
Each run generates new certificates. Keep the printed PEMs and time to repeat
that run's checks.

The successful result covers the supplied trust roots, server purpose, and DNS
identity. Revocation requires caller-supplied evidence; micro509 does not fetch
CRLs or OCSP responses for you.

[Start with your own certificates](./guide/verification.md) ·
[Create certificates and CSRs](./guide/certificates.md) ·
[Check revocation](./guide/revocation.md)

## More PKI workflows

| Task                                    | Guide                                   |
| --------------------------------------- | --------------------------------------- |
| Issue certificates and CSRs             | [Certificates](./guide/certificates.md) |
| Validate chains and service identities  | [Verification](./guide/verification.md) |
| Create and check CRLs or OCSP responses | [Revocation](./guide/revocation.md)     |
| Import, export, and encrypt keys        | [Keys](./guide/keys.md)                 |
| Work with PFX and signed PKCS#7 content | [PKCS](./guide/pkcs.md)                 |

Library code uses WebCrypto without Node builtins. Check the
[runtime requirements](./reference/runtimes.md), [algorithm support](./reference/algorithms.md),
and [standards boundaries](./reference/standards.md) for your application.
