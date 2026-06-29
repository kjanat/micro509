# Why micro509

## The problem

Existing JavaScript PKI packages tend to fall into three camps:
heavyweight standards toolkits, older crypto kitchen sinks, or narrow
parsing utilities.

micro509 aims at the practical middle: modern X.509/PKI workflows,
pure WebCrypto, zero dependencies, and typed results that let your code
act on failures instead of just logging them.

That matters most during verification. A bare `false` does not tell you
which certificate failed, whether the problem was the signature,
hostname, EKU, name constraints, or revocation freshness, or what to
show the user next.

## Typed verification results

micro509 returns a discriminated union with 21 typed error codes, the failing certificate's index, and structured failure details:

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  createCertificate,
  generateKeyPair,
  verifyCertificateChain,
} from 'micro509';

// Build a CA and leaf
const ca = await createSelfSignedCertificate({
  subject: { commonName: 'Demo CA' },
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign'],
  },
});

const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
  issuer: { commonName: 'Demo CA' },
  subject: { commonName: 'app.example.com' },
  publicKey: leafKeys.publicKey,
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
  extensions: {
    subjectAltNames: [
      { type: 'dns', value: 'app.example.com' },
    ],
  },
});

// Verify against the wrong hostname
const result = await verifyCertificateChain({
  leaf: leaf.pem,
  roots: [ca.certificate.pem],
  serviceIdentity: {
    type: 'dns',
    value: 'evil.example.com',
  },
});

if (!result.ok) {
  const e = result.error;
  const det = JSON.stringify(e.details, null, '  ');
  console.log(`\
code:    ${e.code}
message: ${e.message}
details: ${det}`);
}
// result.error.code is a union of 21 codes, e.g.:
//   'signature_invalid'
//   'certificate_expired'
//   'name_constraints_violated'
//   ... (18 more)
// result.error.index: which cert in the chain
//   failed
// result.error.details: { expected, actual }
//   for identity mismatches
```

</LiveCode>

## PKI surface

micro509 covers PKI surface that's hard to find in a single zero-dependency JS package:

| Area              | Capabilities                                                                 |
| ----------------- | ---------------------------------------------------------------------------- |
| OCSP              | Build requests, parse and validate responses, verify responder authorization |
| PFX / PKCS#12     | Create and parse password-protected key+cert bundles                         |
| PKCS#7 / CMS      | Sign content, parse and verify SignedData, extract cert bags                 |
| CRLs              | Create, parse, verify, and check revocation status                           |
| Encrypted keys    | PBES2 PKCS#8, legacy OpenSSL encrypted PEM, PKCS#1, SEC1                     |
| Key import/export | PKCS#8, SPKI, JWK, PKCS#1, SEC1 with generation for RSA, ECDSA, Ed25519      |
| Service identity  | Wildcard DNS, IPv6 normalization, URI-ID, SRV-ID, explicit CN opt-in         |

## Design principles

- **Zero dependencies** — no transitive supply chain risk
- **Pure WebCrypto** — no Node builtins in library code, runs in any modern runtime
- **Narrow defaults, explicit escape hatches** — dangerous operations like CN fallback or self-signed leaf acceptance require opt-in
- **No `any`, no type assertions, no non-null assertions** — discriminated unions and exhaustive checks throughout
- **No runtime DI** — no `reflect-metadata`, no decorators, no side effects that break edge runtimes or tree-shaking
