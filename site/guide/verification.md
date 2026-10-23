# Verification

## What verification establishes

`parseCertificatePem` reads a certificate into typed fields.
`verifyCertificateChain` builds a path to a trust anchor and validates it using
the inputs below.

| Input             | What to supply                                                                                                                              |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `leaf`            | The certificate you want to verify.                                                                                                         |
| `intermediates`   | Available issuer certificates for path building. Missing issuers are not fetched automatically.                                             |
| `roots`           | CA certificates your application trusts. micro509 does not load a system trust store. Advanced callers can also supply bare `trustAnchors`. |
| `purpose`         | The intended use, such as `serverAuth`. Omit it to leave out this application-purpose check.                                                |
| `serviceIdentity` | The DNS, IP, URI, or SRV identity you expect. Omit it to leave out identity matching.                                                       |
| `at`              | The validation time. Defaults to the current time.                                                                                          |
| `revocation`      | CRL/OCSP evidence and policy. Omit this option to skip revocation checking. Supplying it, even as `{}`, enables the check.                  |

A successful result contains the validated chain and parsed leaf. It reflects
the purpose, identity, time, and revocation options you supplied. For certificates
that require revocation evidence, missing or unusable evidence is indeterminate
and fails under the default hard-fail policy. See [chain-level revocation](./revocation.md#chain-level-revocation)
for evidence selection and certificates exempted from checking.

## Chain verification

For existing certificates, pass the leaf, intermediates, and trusted roots to
`verifyCertificateChain`. The [server verification recipe](./recipes.md#verify-a-server-certificate)
shows a function you can use with your application's PEM inputs.

The runnable example below creates its own three-certificate chain. Its successful
result contains the certificates in leaf-to-root order. On failure, branch on
`result.error.code`. Read the optional `result.error.index` together with
`result.error.details.source` to distinguish a chain certificate from a bad
root or intermediate input. A `no_trusted_root` failure has no index.

<details>
<summary>Generate and verify a complete root, intermediate, and leaf chain</summary>

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
  issuerCertificate: root.certificate.pem,
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
  issuerCertificate: intermediate.pem,
  extensions: {
    extendedKeyUsage: ['serverAuth'],
    subjectAltNames: [{ type: 'dns', value: 'api.example.com' }],
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
  const parsedLeaf = result.value.leaf;
  console.log(`\
Valid chain: ${result.value.chain.length} certificates
leaf:        ${parsedLeaf.subject.values.commonName}
serial:      ${parsedLeaf.serialNumberHex}
expires:     ${parsedLeaf.notAfter.toISOString()}`);
} else {
  console.log(`\
Failed:   ${result.error.code}
At index: ${result.error.index}`);
}
```

</LiveCode>

</details>

## Verification purposes

Four built-in validation profiles. `serverAuth`,
`clientAuth`, and `ca` are passed as `purpose` to
`verifyCertificateChain`, or through the equivalent
`validateForTlsServer`, `validateForTlsClient`, and
`validateForCa` wrappers; code signing has its own
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

// Issue a leaf with the extended key usage under test
async function issue(cn = '', eku = '') {
  if (eku !== 'serverAuth' && eku !== 'clientAuth' && eku !== 'codeSigning') {
    throw new Error(`Unsupported EKU: ${eku}`);
  }
  const keys = await generateKeyPair();
  return createCertificate({
    issuer: { commonName: 'Demo Root CA' },
    subject: { commonName: cn },
    publicKey: keys.publicKey,
    signerPrivateKey: root.keyPair.privateKey,
    issuerCertificate: root.certificate.pem,
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
  issuerCertificate: root.certificate.pem,
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
serverAuth:  ${r1.ok ? `ok, serial ${r1.value.leaf.serialNumberHex}` : `${r1.error.code}@${r1.error.index}`}
clientAuth:  ${r2.ok ? `ok, serial ${r2.value.leaf.serialNumberHex}` : `${r2.error.code}@${r2.error.index}`}
codeSigning: ${r3.ok ? `ok, serial ${r3.value.leaf.serialNumberHex}` : `${r3.error.code}@${r3.error.index}`}
ca:          ${r4.ok ? `ok, serial ${r4.value.leaf.serialNumberHex}` : `${r4.error.code}@${r4.error.index}`}`);
```

</LiveCode>

## Service identity matching

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  parseCertificatePem,
  subjectAltNameToString,
  unwrap,
} from 'micro509';
import { matchServiceIdentity } from 'micro509/verify';

// Create and parse a certificate to match against
const { certificate } = await createSelfSignedCertificate({
  subject: { commonName: 'example.com' },
  extensions: {
    subjectAltNames: [{ type: 'dns', value: 'example.com' }],
  },
});

const parsed = unwrap(parseCertificatePem(certificate.pem));

const result = matchServiceIdentity({
  certificate: parsed,
  serviceIdentity: { type: 'dns', value: 'example.com' },
});

const sans = (parsed.subjectAltNames ?? [])
  .map((name) => subjectAltNameToString(name, { prefix: true }))
  .join(', ');

if (result.ok) {
  console.log(`\
matched: dns example.com
SANs:    ${sans}
serial:  ${parsed.serialNumberHex}`);
} else {
  console.log(result.error.code);
  // 'subject_alt_name_mismatch' | ...
}
```

</LiveCode>

Supported identity types:

- **DNS-ID** — with wildcard matching and case-insensitive comparison
- **IP-ID** — with IPv6 normalization
- **URI-ID** — scheme + host matching, with wildcard matching except for SIP
  and IP hosts compared by octets
- **SRV-ID** — service name matching via otherName SAN, with wildcard matching

## Advanced validation policy

Path building tries every issuer candidate and bare trust anchor whose subject
matches, so an input with many same-subject certificates costs more work than
its size suggests. `maxPathBuildingChecks` on `verifyCertificateChain`,
`buildCandidatePath` and the `validateFor*` profiles bounds how many candidates
and anchors one search may examine, including those it skips because they are
already on the path or their names do not match. The default is 100,000. When the bound stops the search before a trusted path
is found, the result is `path_building_limit_exceeded`.

A user notice `explicitText` or `noticeRef` organization longer than the 200
characters [RFC 5280 §4.2.1.4][rfc5280-section-4.2.1.4] allows a DisplayText is kept whole by the parser
and reported as `oversizedExplicitText` on the qualifier or
`oversizedOrganization` on the `noticeRef`, and the chain validates. [§4.2.1.4][rfc5280-section-4.2.1.4]
asks certificate users to handle an oversized `explicitText` gracefully, and
micro509 applies the same policy to the organization.
`rejectOversizedDisplayText: true` on `verifyCertificateChain` or
`validateCandidatePath` rejects such a certificate with
`display_text_oversized` instead, and `details.userNoticeField` names the
field. PKITS 4.8.19 leaves that choice for `explicitText` to the application.

## Error codes

::: info Stability
Error-code unions (`VerifyErrorCode` and every other `*ErrorCode` /
`*ReasonCode` union) may **gain new members in minor releases** as
functionality grows. Treat them as non-exhaustive: keep a `default` branch
in `switch` statements over codes. Renaming or removing a code is a
breaking change and only happens in a major release.
:::

Every failure mode in the `VerifyErrorCode` type (the runtime list is exported
as `VERIFY_ERROR_CODES`; this table is checked against it by a repo test).
Every other error-code union in the library is tabled in the
[error-code reference](../reference/errors.md), under the same enforcement:

| Code                                         | Meaning                                        |
| -------------------------------------------- | ---------------------------------------------- |
| `no_trusted_root`                            | No trust anchor matched the chain              |
| `issuer_not_found`                           | Could not find issuer for a certificate        |
| `signature_invalid`                          | Cryptographic signature check failed           |
| `certificate_expired`                        | Certificate outside validity window            |
| `ca_required`                                | Non-CA certificate used as issuer              |
| `key_cert_sign_required`                     | Issuer missing `keyCertSign` key usage         |
| `path_length_exceeded`                       | Chain exceeds `pathLenConstraint`              |
| `path_building_limit_exceeded`               | Path building exceeded bounded work limits     |
| `authority_key_identifier_mismatch`          | AKI/SKI cross-check failed                     |
| `extended_key_usage_invalid`                 | EKU doesn't match requested purpose            |
| `subject_alt_name_mismatch`                  | SAN doesn't match service identity             |
| `common_name_fallback_suppressed`            | CN match suppressed by presented identifiers   |
| `self_signed_leaf_not_allowed`               | Self-signed leaf without explicit opt-in       |
| `unrecognized_critical_extension`            | Unknown critical extension                     |
| `no_rev_avail_conflict`                      | noRevAvail with cA or a revocation pointer     |
| `display_text_oversized`                     | Notice text over 200 chars, opt-in rejection   |
| `intermediate_eku_constraint`                | Intermediate has restrictive EKU               |
| `explicit_policy_required`                   | Policy required but not satisfied              |
| `initial_policy_set_not_satisfied`           | Initial policy set not met                     |
| `unsupported_initial_name_constraints`       | Initial name constraints use unsupported forms |
| `unsupported_name_constraints`               | Unsupported name constraint form               |
| `name_constraints_violated`                  | Name constraints check failed                  |
| `unsupported_signature_algorithm_parameters` | Unknown signature algorithm                    |
| `ec_domain_parameters_missing`               | EC public key without a named curve            |
| `certificate_revoked`                        | Revocation evidence confirms revocation        |
| `revocation_indeterminate`                   | Revocation unknown under hard-fail policy      |
| `unsupported`                                | Certificate input micro509 does not decode     |
| `limit_exceeded`                             | Certificate input exceeds a decoding limit     |

## CSR verification

<LiveCode>

```ts
import {
  createCertificateSigningRequest,
  generateKeyPair,
  subjectAltNameToString,
  verifyCertificateSigningRequest,
} from 'micro509';

// Build a CSR to verify
const keyPair = await generateKeyPair({ kind: 'ed25519' });
const csr = await createCertificateSigningRequest({
  subject: { commonName: 'csr.example' },
  publicKey: keyPair.publicKey,
  signerPrivateKey: keyPair.privateKey,
  extensions: {
    subjectAltNames: [{ type: 'dns', value: 'csr.example' }],
  },
});

const result = await verifyCertificateSigningRequest(csr.pem);

if (result.ok) {
  const sans = (result.value.subjectAltNames ?? [])
    .map((name) => subjectAltNameToString(name))
    .join(', ');
  const body = csr.pem.trimEnd().split('\n').slice(1, -1).join('');
  console.log(`\
subject:   ${result.value.subject.values.commonName}
sig algo:  ${result.value.signatureAlgorithmName}
SANs:      ${sans}
signature: …${body.slice(-44)}`);
} else {
  console.log('CSR invalid:', result.error.code);
}
```

</LiveCode>

## Detached signatures

`micro509/crypto` signs and verifies raw bytes when there is no X.509 or
CMS structure around the signature: a timestamp token, a code-signing
blob, a hand-built TBS. `signData` infers the algorithm from the key and
returns the signature beside its `AlgorithmIdentifier` material;
`verifySignature` checks it against the signer's SubjectPublicKeyInfo,
retrying the alternate DER/raw ECDSA encoding when needed.

<LiveCode>

```ts
import {
  ecdsaSignatureDerToRaw,
  ecdsaSignatureRawToDer,
  signData,
  verifySignature,
} from 'micro509/crypto';
import {
  createSelfSignedCertificate,
  parseCertificatePem,
  unwrap,
} from 'micro509';

const { certificate, keyPair } = await createSelfSignedCertificate({
  subject: { commonName: 'signer.example' },
  algorithm: { kind: 'ecdsa', curve: 'P-256' },
});
const parsed = unwrap(parseCertificatePem(certificate.pem));

const data = new TextEncoder().encode('release-v1.tar.gz');
const signed = await signData(keyPair.privateKey, data);

const result = await verifySignature({
  signerSpkiDer: parsed.subjectPublicKeyInfoDer,
  signatureAlgorithm: { oid: signed.algorithmOid },
  publicKeyAlgorithm: {
    oid: parsed.publicKeyAlgorithmOid,
    parametersOid: parsed.publicKeyParametersOid,
  },
  signature: signed.signature,
  data,
});

const tampered = await verifySignature({
  signerSpkiDer: parsed.subjectPublicKeyInfoDer,
  signatureAlgorithm: { oid: signed.algorithmOid },
  publicKeyAlgorithm: {
    oid: parsed.publicKeyAlgorithmOid,
    parametersOid: parsed.publicKeyParametersOid,
  },
  signature: signed.signature,
  data: new TextEncoder().encode('release-v2.tar.gz'),
});

// ECDSA signatures convert between the DER encoding
// X.509/CMS embed and the raw r||s form WebCrypto and
// JOSE use, bridging an HSM or JWS signature into a
// PKIX structure, or the other way around.
const raw = ecdsaSignatureDerToRaw(signed.signature, 'P-256');
const der = ecdsaSignatureRawToDer(raw, 'P-256');

const rawHex = Array.from(raw, (byte) =>
  byte.toString(16).padStart(2, '0'),
).join('');
console.log(`\
algorithm: ${signed.algorithmOid}
valid:     ${result.ok && result.valid}
tampered:  ${tampered.ok && tampered.valid}
raw r||s:  ${raw.length} bytes, ${rawHex.slice(0, 48)}…
DER again: ${der.length} bytes`);
```

</LiveCode>

### Verify with an imported key

Use `verifySignatureWithKey` when you already have a WebCrypto public key,
including a non-extractable key. It verifies directly with that key. Pass
the signature's algorithm OID and parameters, and select its encoding:
`'der'` for ECDSA from `signData`, `'raw'` for ECDSA from WebCrypto or JOSE,
and `'raw'` for RSA or Ed25519.

This example imports a public JWK once, then checks a signature and an altered
message with the same non-extractable key.

<LiveCode>

```ts
import { generateKeyPair } from 'micro509/keys';
import { signData, verifySignatureWithKey } from 'micro509/crypto';

const keys = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
const publicKey = await crypto.subtle.importKey(
  'jwk',
  jwk,
  { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  false,
  ['verify'],
);
const data = new TextEncoder().encode('release-v1.tar.gz');
const signed = await signData(keys.privateKey, data);
const input = {
  publicKey,
  signatureAlgorithm: {
    oid: signed.algorithmOid,
    parametersDer: signed.parametersDer,
  },
  signatureEncoding: 'raw',
  signature: signed.signature,
  data,
} as const;

console.log('Public JWK:', jwk);
console.log('Key extractable:', publicKey.extractable);
console.log('Verification:', await verifySignatureWithKey(input));
console.log(
  'Altered message:',
  await verifySignatureWithKey({
    ...input,
    data: new TextEncoder().encode('release-v2.tar.gz'),
  }),
);
```

</LiveCode>

RSA scheme and hash must match the imported key. For RSA-PSS, pass
`parametersDer` from the signature's algorithm identifier. Supported profiles
use SHA-256, SHA-384 or SHA-512, the same MGF1 hash, and a salt as long as
the digest. A signature mismatch returns `{ ok: true, valid: false }`.
An incompatible algorithm or a key without public `verify` usage returns
an error branch with `code` and `reason`.

[rfc5280-section-4.2.1.4]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.4
