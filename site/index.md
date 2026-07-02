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
    title: Runs Everywhere
    details: Pure WebCrypto, zero dependencies. Node, Bun, Deno, browsers, Cloudflare Workers.
  - icon: 📦
    title: Full PKI Surface
    details: Certificates, CSRs, chain verification, service identity, CRLs, OCSP, PFX/PKCS#12, PKCS#7, encrypted keys.
  - icon: 🛡️
    title: Strict by Default
    details: No any, no type assertions, no non-null assertions. Narrow defaults, explicit escape hatches.
---

## See it run

Typed, runnable PKI in a few lines. Install it and mint a self-signed cert right here:

```bash
npm install micro509
```

<LiveCode>

```ts
import { createSelfSignedCertificate } from 'micro509';

const { certificate, keyPair } =
  await createSelfSignedCertificate({
    subject: { commonName: 'example.com' },
    validity: { days: 365 },
  });

console.log(certificate.pem);
console.log(
  `key type: ${keyPair.publicKey.algorithm.name}`,
);
```

</LiveCode>
