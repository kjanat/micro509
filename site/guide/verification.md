# Verification

## Chain verification

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  createCertificate,
  generateKeyPair,
  verifyCertificateChain,
} from 'micro509';

// Build a root CA
const root = await createSelfSignedCertificate({
  subject: { commonName: 'Demo Root CA' },
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});

// Intermediate CA signed by the root
const intKeys = await generateKeyPair();
const intermediate = await createCertificate({
  issuer: { commonName: 'Demo Root CA' },
  subject: { commonName: 'Demo Intermediate CA' },
  publicKey: intKeys.publicKey,
  signerPrivateKey: root.keyPair.privateKey,
  issuerPublicKey: root.keyPair.publicKey,
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});

// Leaf signed by the intermediate
const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
  issuer: { commonName: 'Demo Intermediate CA' },
  subject: { commonName: 'api.example.com' },
  publicKey: leafKeys.publicKey,
  signerPrivateKey: intKeys.privateKey,
  issuerPublicKey: intKeys.publicKey,
  extensions: {
    extendedKeyUsage: ['serverAuth'],
    subjectAltNames: [
      { type: 'dns', value: 'api.example.com' },
    ],
  },
});

const result = await verifyCertificateChain({
  leaf: leaf.pem,
  intermediates: [intermediate.pem],
  roots: [root.certificate.pem],
  purpose: 'serverAuth',
  serviceIdentity: {
    type: 'dns',
    value: 'api.example.com',
  },
});

if (result.ok) {
  console.log(
    `Valid chain: ${result.value.chain.length} certificates`,
  );
} else {
  console.log(`\
Failed: ${result.error.code}
At index: ${result.error.index}`);
}
```

</LiveCode>

## Verification purposes

Four built-in validation profiles. `serverAuth`,
`clientAuth`, and `ca` are passed as `purpose` to
`verifyCertificateChain`; code signing has its own
`validateForCodeSigning` profile:

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  createCertificate,
  generateKeyPair,
  verifyCertificateChain,
  validateForCodeSigning,
} from 'micro509';

// Shared root CA
const root = await createSelfSignedCertificate({
  subject: { commonName: 'Demo Root CA' },
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});

// Issue a leaf with a given EKU ('serverAuth' | 'clientAuth' | 'codeSigning')
async function issue(cn, eku) {
  const keys = await generateKeyPair();
  return createCertificate({
    issuer: { commonName: 'Demo Root CA' },
    subject: { commonName: cn },
    publicKey: keys.publicKey,
    signerPrivateKey: root.keyPair.privateKey,
    issuerPublicKey: root.keyPair.publicKey,
    extensions: {
      extendedKeyUsage: [eku],
      subjectAltNames: [{ type: 'dns', value: cn }],
    },
  });
}

// TLS server (default)
const server = await issue('srv.example', 'serverAuth');
const r1 = await verifyCertificateChain({
  leaf: server.pem,
  roots: [root.certificate.pem],
  purpose: 'serverAuth',
});

// TLS client
const client = await issue('cli.example', 'clientAuth');
const r2 = await verifyCertificateChain({
  leaf: client.pem,
  roots: [root.certificate.pem],
  purpose: 'clientAuth',
});

// Code signing
const signer = await issue('sign.example', 'codeSigning');
const r3 = await validateForCodeSigning({
  leaf: signer.pem,
  roots: [root.certificate.pem],
});

// CA certificate (verify an intermediate as a CA)
const caKeys = await generateKeyPair();
const intermediate = await createCertificate({
  issuer: { commonName: 'Demo Root CA' },
  subject: { commonName: 'Demo Intermediate CA' },
  publicKey: caKeys.publicKey,
  signerPrivateKey: root.keyPair.privateKey,
  issuerPublicKey: root.keyPair.publicKey,
  extensions: {
    basicConstraints: { ca: true },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});
const r4 = await verifyCertificateChain({
  leaf: intermediate.pem,
  roots: [root.certificate.pem],
  purpose: 'ca',
});

console.log(`\
serverAuth:  ${r1.ok ? 'ok' : `${r1.error.code}@${r1.error.index}`}
clientAuth:  ${r2.ok ? 'ok' : `${r2.error.code}@${r2.error.index}`}
codeSigning: ${r3.ok ? 'ok' : `${r3.error.code}@${r3.error.index}`}
ca:          ${r4.ok ? 'ok' : `${r4.error.code}@${r4.error.index}`}`);
```

</LiveCode>

## Service identity matching

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  parseCertificatePem,
  unwrap,
} from 'micro509';
import { matchServiceIdentity } from 'micro509/verify';

// Create and parse a certificate to match against
const { certificate } = await createSelfSignedCertificate({
  subject: { commonName: 'example.com' },
  extensions: {
    subjectAltNames: [
      { type: 'dns', value: 'example.com' },
    ],
  },
});

const parsed = unwrap(parseCertificatePem(certificate.pem));

const result = matchServiceIdentity({
  certificate: parsed,
  serviceIdentity: { type: 'dns', value: 'example.com' },
});

if (result.ok) {
  console.log('Identity matches the certificate SAN');
} else {
  console.log(result.error.code);
  // 'subject_alt_name_mismatch' | ...
}
```

</LiveCode>

Supported identity types:

- **DNS-ID** — with wildcard matching and case-insensitive comparison
- **IP-ID** — with IPv6 normalization
- **URI-ID** — scheme + host matching
- **SRV-ID** — service name matching via otherName SAN

## Error codes

The `VerifyErrorCode` type covers 21 failure modes:

| Code                                         | Meaning                                      |
| -------------------------------------------- | -------------------------------------------- |
| `no_trusted_root`                            | No trust anchor matched the chain            |
| `issuer_not_found`                           | Could not find issuer for a certificate      |
| `signature_invalid`                          | Cryptographic signature check failed         |
| `certificate_expired`                        | Certificate outside validity window          |
| `ca_required`                                | Non-CA certificate used as issuer            |
| `key_cert_sign_required`                     | Issuer missing `keyCertSign` key usage       |
| `path_length_exceeded`                       | Chain exceeds `pathLenConstraint`            |
| `authority_key_identifier_mismatch`          | AKI/SKI cross-check failed                   |
| `extended_key_usage_invalid`                 | EKU doesn't match requested purpose          |
| `subject_alt_name_mismatch`                  | SAN doesn't match service identity           |
| `common_name_fallback_suppressed`            | CN match suppressed by presented identifiers |
| `self_signed_leaf_not_allowed`               | Self-signed leaf without explicit opt-in     |
| `unrecognized_critical_extension`            | Unknown critical extension                   |
| `intermediate_eku_constraint`                | Intermediate has restrictive EKU             |
| `policy_processing_not_implemented`          | Policy processing not implemented            |
| `name_constraints_violated`                  | Name constraints check failed                |
| `initial_name_constraints_not_implemented`   | Initial name constraints not implemented     |
| `unsupported_name_constraints`               | Unsupported name constraint form             |
| `explicit_policy_required`                   | Policy required but not satisfied            |
| `initial_policy_set_not_satisfied`           | Initial policy set not met                   |
| `unsupported_signature_algorithm_parameters` | Unknown signature algorithm                  |

## CSR verification

<LiveCode>

```ts
import {
  createCertificateSigningRequest,
  generateKeyPair,
  verifyCertificateSigningRequest,
} from 'micro509';

// Build a CSR to verify
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

const result = await verifyCertificateSigningRequest(
  csr.pem,
);

if (result.ok) {
  console.log('CSR signature valid');
} else {
  console.log('CSR invalid:', result.error.code);
}
```

</LiveCode>
