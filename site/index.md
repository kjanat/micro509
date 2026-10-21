---
layout: home
hero:
  name: micro509
  text: Typed PKI for modern TypeScript
  tagline: The zero-dependency TypeScript PKI toolkit for real certificate workflows.
  image:
    light: /icon.svg
    dark: /icon-light.svg
    alt: micro509
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: API Reference
      link: /api/
    - theme: alt
      text: GitHub
      link: https://github.com/kjanat/micro509
features:
  - icon: 🔏
    title: Typed Verification
    details: Typed error codes with chain index and structured failure details. Build certificate flows your code can actually reason about.
  - icon: 🌐
    title: WebCrypto Native
    details: Pure WebCrypto, zero dependencies. Node, Bun, Deno, browsers, Cloudflare Workers.
  - icon: 📦
    title: Broad PKI Workflow Coverage
    details: Certificates, CSRs, chain verification, service identity, CRLs, OCSP, PFX/PKCS#12, PKCS#7, encrypted keys — with explicitly documented standards-conformance boundaries.
    link: /reference/standards
    linkText: Conformance status
  - icon: 🛡️
    title: Explicit Trust Decisions
    details: Supply your trusted roots, expected identity, and revocation evidence. Handle failures with typed results.
---

## Verify a certificate

Check a certificate chain and its expected server identity, then handle a typed
result. This runnable example issues a leaf from a demo CA; your application
supplies its own certificates and trusted roots.

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
const result = await verifyCertificateChain({
  leaf: leaf.pem,
  roots: [ca.certificate.pem],
  purpose: 'serverAuth',
  serviceIdentity: {
    type: 'dns',
    value: 'app.example.com',
  },
});

if (result.ok) {
  console.log(`Verified ${result.value.chain.length} certificates`);
} else {
  console.log(result.error.code, result.error.index);
}
```

</LiveCode>

The successful result covers the supplied trust roots, server purpose, and DNS
identity. Revocation requires caller-supplied evidence; micro509 does not fetch
CRLs or OCSP responses for you.

[Start with your own certificates](./guide/verification.md) ·
[Create certificates and CSRs](./guide/certificates.md) ·
[Check revocation](./guide/revocation.md)
