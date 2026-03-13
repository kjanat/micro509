# micro509

Tiny X.509 builders for modern TypeScript.

- create certs + CSRs
- DER + PEM + base64 outputs
- PKCS#8 + SPKI + JWK key import/export
- parse certs + CSRs back to typed metadata
- verify candidate leaf/intermediate/root chains with typed results
- custom extension build hooks + decode helpers
- browser-native chain verification via WebCrypto
- browser-native CSR signature verification too
- PKCS#7 certificate bag helpers
- CRL parse/create/verify helpers
- passwordless PFX bundle helpers
- OCSP request build + typed OCSP response parse/validation helpers
- encrypted PKCS#8 / encrypted PFX via PBES2
- encrypted traditional RSA/EC PEM helpers
- WebCrypto-first, typed, small surface

## Standards status

| Area                       | Status    | Notes                                                                                                                                                                                                                                     |
| -------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RFC 5280 path validation   | `partial` | core path validation, supported-form name constraints, initial subtree inputs, policy processing, malformed-DER coverage, and focused PKITS coverage ship; revocation stays separate and broader conformance evidence is still incomplete |
| RFC 6960 OCSP              | `partial` | request/response helpers, responder binding/authorization, freshness checks, and full request coverage ship; local responder-policy acceptance stays incomplete                                                                           |
| RFC 6125 service identity  | `partial` | `matchServiceIdentity()` ships DNS-ID, IP-ID, URI-ID, SRV-ID, wildcard, IDNA, and opt-in CN-compat checks; verification helpers still wire DNS/IP identities only                                                                         |
| RFC 9618 policy validation | `partial` | RFC 9618-style policy state, enforcement, outputs, and focused PKITS coverage ship; broader conformance evidence is still incomplete                                                                                                      |

Current conformance evidence lives in `test/pkits.test.ts`, `test/policy.test.ts`, `test/name-constraints.test.ts`, `test/ocsp-fixtures.test.ts`, `test/identity-fixtures.test.ts`, `test/revocation.test.ts`, `test/malformed-der.test.ts`, and `test/differential.test.ts`.

## Install

```bash
npm install micro509
```

- package is side-effect-free (`sideEffects: false`)
- root import stays supported; subpath imports like `micro509/verify` and `micro509/identity` give tighter tree-shaking

## Runtime matrix

| Runtime | Status      | Notes                                                                                                                                        |
| ------- | ----------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Node    | `supported` | use modern Node with WebCrypto globals (`crypto.subtle`, `TextEncoder`, `TextDecoder`, `atob`, `btoa`); package metadata targets Node `>=24` |
| Bun     | `supported` | use Bun `>=1.3`; globals needed by the library are built in                                                                                  |
| Deno    | `supported` | ESM-only package; requires WebCrypto and text/base64 web globals                                                                             |
| Browser | `supported` | modern browsers only; requires `crypto.subtle`, `TextEncoder`, `TextDecoder`, `atob`, and `btoa`                                             |
| Worker  | `supported` | works in web-worker style runtimes when the same WebCrypto/text/base64 globals exist                                                         |

The core stays ESM-only and WebCrypto-only. It does not depend on Node builtins in library code.

## Import guidance

Use the root package when you want the ergonomic all-in-one API:

```ts
import { createCertificate, verifyCertificateChain } from 'micro509';
```

Use subpath imports when you want a narrower surface or tighter tree-shaking:

```ts
import { verifyCertificateChain } from 'micro509/verify';
import { matchServiceIdentity } from 'micro509/identity';
import { getOcspResponderCandidates } from 'micro509/revocation';
import type { PolicyValidationInput } from 'micro509/policy';
```

Available public subpaths come from the build config and ship as stable package exports: `micro509/certificate`, `micro509/crl`, `micro509/csr`, `micro509/extensions`, `micro509/identity`, `micro509/keys`, `micro509/name`, `micro509/name-constraints`, `micro509/ocsp`, `micro509/parse`, `micro509/pem`, `micro509/pfx`, `micro509/pkcs12-mac`, `micro509/pkcs7`, `micro509/policy`, `micro509/result`, `micro509/revocation`, and `micro509/verify`.

## Result model

- validation and verification APIs return `Result`-style objects: `{ ok: true, value }` or `{ ok: false, error }`
- failure results still mirror `code`, `message`, and domain fields at the top level for easier migration, but `error` is the canonical payload
- business outcomes like revocation `good` / `revoked` / `unknown` now live under `value.status`
- raw certificate / CSR / CRL / OCSP parse entrypoints still throw on malformed DER or PEM; container helpers like `parsePfx*()` and `parsePkcs7*()` return typed failures instead

## Self-signed cert

```ts
import { createSelfSignedCertificate } from 'micro509';

const { certificate, keyPair } = await createSelfSignedCertificate({
  subject: {
    commonName: 'example.com',
    organization: 'Acme',
    country: 'US',
  },
  validity: { days: 30 },
  extensions: {
    keyUsage: ['digitalSignature', 'keyEncipherment'],
    subjectAltNames: [
      { type: 'dns', value: 'example.com' },
      { type: 'dns', value: 'www.example.com' },
    ],
  },
});

console.log(certificate.pem);
console.log(await keyPair.exportPkcs8Pem());
console.log(await keyPair.exportPublicJwk());
```

## CA-signed leaf cert

```ts
import { createCertificate, createSelfSignedCertificate, generateKeyPair } from 'micro509';

const ca = await createSelfSignedCertificate({
  subject: { commonName: 'Local Test CA' },
  extensions: {
    basicConstraints: { ca: true, pathLength: 0 },
    keyUsage: ['keyCertSign', 'cRLSign'],
  },
});

const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
  issuer: { commonName: 'Local Test CA' },
  subject: { commonName: 'api.local' },
  publicKey: leafKeys.publicKey,
  signerPrivateKey: ca.keyPair.privateKey,
  issuerPublicKey: ca.keyPair.publicKey,
  extensions: {
    keyUsage: ['digitalSignature'],
    extendedKeyUsage: ['serverAuth', { type: 'oid', value: '1.2.3.4.5' }],
    subjectAltNames: [{ type: 'dns', value: 'api.local' }],
  },
});

console.log(leaf.pem);
```

## CSR

```ts
import { createCertificateSigningRequest, generateKeyPair } from 'micro509';

const keyPair = await generateKeyPair({ kind: 'ed25519' });
const csr = await createCertificateSigningRequest({
  subject: { commonName: 'csr.example' },
  publicKey: keyPair.publicKey,
  signerPrivateKey: keyPair.privateKey,
  extensions: {
    subjectAltNames: [{ type: 'dns', value: 'csr.example' }],
  },
});

console.log(csr.pem);
```

## Import keys back

```ts
import {
  exportBinaryBase64,
  generateKeyPair,
  importPkcs8Pem,
  importPublicJwk,
  importSpkiBase64,
} from 'micro509';

const keyPair = await generateKeyPair({ kind: 'rsa' });

const publicKey = await importSpkiBase64(await exportBinaryBase64(keyPair.publicKey), {
  kind: 'rsa',
});

const privateKey = await importPkcs8Pem(await keyPair.exportPkcs8Pem(), {
  kind: 'rsa',
});

const jwkPublicKey = await importPublicJwk(await keyPair.exportPublicJwk(), {
  kind: 'rsa',
});
```

## Parse certs + CSRs

```ts
import {
  decodeExtension,
  decodeExtensions,
  defineExtensionDecoderMap,
  findExtension,
  parseCertificatePem,
  parseCertificateSigningRequestPem,
} from 'micro509';

const parsedCert = parseCertificatePem(certificate.pem);
console.log(parsedCert.subject.values.commonName);
console.log(parsedCert.extendedKeyUsage);
console.log(parsedCert.authorityInfoAccess);
console.log(parsedCert.crlDistributionPoints);

const parsedWithDecoders = parseCertificatePem(certificate.pem, {
  decoders: [
    {
      oid: '1.2.3.4.200',
      decode(extension) {
        return extension.valueHex;
      },
    },
  ],
});

const parsedWithMap = parseCertificatePem(certificate.pem, {
  decoderMap: defineExtensionDecoderMap({
    customText: {
      oid: '1.2.3.4.200',
      decode(extension) {
        return extension.valueHex;
      },
    },
  }),
});
console.log(parsedWithMap.decodedExtensionMap?.customText?.value);

const parsedCsr = parseCertificateSigningRequestPem(csr.pem);
console.log(parsedCsr.subjectAltNames);
```

## Encrypted PKCS#8

```ts
import { exportEncryptedPkcs8Pem, importEncryptedPkcs8Pem } from 'micro509';

const encryptedPem = await exportEncryptedPkcs8Pem(keyPair.privateKey, {
  password: 'secret123',
});

const privateKey = await importEncryptedPkcs8Pem(encryptedPem, 'secret123', { kind: 'rsa' });
```

## Encrypted traditional PEM

```ts
import { exportEncryptedPkcs1Pem, importEncryptedPkcs1Pem } from 'micro509';

const encryptedRsaPem = await exportEncryptedPkcs1Pem(keyPair.privateKey, {
  password: 'secret123',
});

const privateKey = await importEncryptedPkcs1Pem(encryptedRsaPem, 'secret123', { kind: 'rsa' });
```

## Custom extensions

```ts
import { createSelfSignedCertificate, decodeExtension, parseCertificatePem } from 'micro509';

const { certificate } = await createSelfSignedCertificate({
  subject: { commonName: 'custom.example' },
  extensions: {
    customExtensions: [
      {
        oid: '1.2.3.4.200',
        critical: true,
        value: Uint8Array.of(0x04, 0x03, 0x01, 0x02, 0x03),
      },
    ],
  },
});

const parsed = parseCertificatePem(certificate.pem);
const decoded = decodeExtension(parsed.extensions, {
  oid: '1.2.3.4.200',
  decode(extension) {
    return Array.from(extension.valueDer);
  },
});

const allDecoded = decodeExtensions(parsed.extensions, [
  {
    oid: '1.2.3.4.200',
    decode(extension) {
      return extension.valueHex;
    },
  },
]);
```

## Split PEM bundles

```ts
import { categorizePemBlocks, splitPemBlocks } from 'micro509';

const blocks = splitPemBlocks(bundle);
console.log(blocks.map((block) => block.label));

const categorized = categorizePemBlocks(bundle);
console.log(categorized.certificates.length);
```

## PKCS#7 cert bag

```ts
import { createPkcs7CertBagPem, parsePkcs7CertBagPem } from 'micro509';

const bag = createPkcs7CertBagPem([leaf.pem, root.pem]);
const certs = parsePkcs7CertBagPem(bag.pem);

if (certs.ok) {
  console.log(certs.value.map((cert) => cert.subject.values.commonName));
}
```

## PFX

```ts
import { createPfx, parsePfxPem } from 'micro509';

const pfx = await createPfx({
  certificates: [
    { certificate: leaf.pem, attributes: { friendlyName: 'leaf' } },
    { certificate: root.pem, attributes: { friendlyName: 'root' } },
  ],
  privateKeys: [{ privateKey: leafKey.privateKey, attributes: { friendlyName: 'leaf' } }],
});

const parsedPfx = await parsePfxPem(pfx.pem);

if (parsedPfx.ok) {
  console.log(parsedPfx.value.certificates.length);
  console.log(parsedPfx.value.bags[0]?.attributes.friendlyName);
}

const encryptedPfx = await createPfx({
  certificates: [{ certificate: leaf.pem }],
  privateKeys: [{ privateKey: leafKey.privateKey }],
  encryption: { password: 'secret123' },
  mac: { password: 'secret123' },
});

const parsedEncryptedPfx = await parsePfxPem(encryptedPfx.pem, {
  password: 'secret123',
  macPassword: 'secret123',
});

if (!parsedEncryptedPfx.ok) {
  console.log(parsedEncryptedPfx.error.code);
}
```

## CRL

```ts
import {
  createCertificateRevocationList,
  isCertificateRevoked,
  parseCertificateRevocationListPem,
  verifyCertificateRevocationList,
} from 'micro509';

const crl = await createCertificateRevocationList({
  issuer: { commonName: 'Example CA' },
  signerPrivateKey: caKey.privateKey,
  issuerPublicKey: caKey.publicKey,
  crlNumber: 1,
  revokedCertificates: [{ serialNumber: serialBytes }],
});

const parsedCrl = parseCertificateRevocationListPem(crl.pem);
console.log(parsedCrl.revokedCertificates.length);
console.log(isCertificateRevoked(serialBytes, parsedCrl));
console.log(await verifyCertificateRevocationList(crl.pem, caCert.pem));
```

## OCSP

```ts
import {
  createOcspRequest,
  createOcspResponse,
  parseOcspRequestPem,
  parseOcspResponseDer,
  validateOcspResponse,
  verifyOcspResponse,
} from 'micro509';

const request = await createOcspRequest({
  requests: [{ certificate: leaf.pem, issuerCertificate: issuer.pem }],
  nonce: Uint8Array.of(0xaa, 0xbb),
});

const parsedRequest = parseOcspRequestPem(request.pem);
console.log(parsedRequest.requests.length);

const response = await createOcspResponse({
  signerPrivateKey: issuerKey.privateKey,
  signerCertificate: issuer.pem,
  responses: [
    {
      certificate: leaf.pem,
      issuerCertificate: issuer.pem,
      certStatus: 'good',
    },
  ],
});

const parsedResponse = parseOcspResponseDer(response.der);
console.log(parsedResponse.responseStatus);
console.log(await verifyOcspResponse(response.der, issuer.pem));
console.log(
  await validateOcspResponse({
    response: response.der,
    issuerCertificate: issuer.pem,
    request: request.pem,
  }),
);
```

## PKCS#7 signedData parse

```ts
import { parsePkcs7SignedDataPem } from 'micro509';

const signed = parsePkcs7SignedDataPem(pkcs7Pem);

if (signed.ok) {
  console.log(signed.value.certificates.length);
  console.log(signed.value.signerInfos.length);
}
```

## Legacy private key PEM

```ts
import { exportPkcs1Pem, exportSec1Pem, importPkcs1Pem, importSec1Pem } from 'micro509';

const rsaPem = await exportPkcs1Pem(rsaKey.privateKey);
const rsaKeyAgain = await importPkcs1Pem(rsaPem, { kind: 'rsa' });

const ecPem = await exportSec1Pem(ecKey.privateKey);
const ecKeyAgain = await importSec1Pem(ecPem, {
  kind: 'ecdsa',
  namedCurve: 'P-256',
});
```

## Verify chain

```ts
import { verifyCertificateChain } from 'micro509';

const result = await verifyCertificateChain({
  leaf: leaf.pem,
  intermediates: [intermediate.pem],
  roots: [root.pem],
  purpose: 'serverAuth',
  serviceIdentity: { type: 'dns', value: 'api.local' },
  policy: { initialPolicySet: ['1.2.3.4'] },
  nameConstraints: {
    permittedSubtrees: [{ base: { type: 'dns', value: 'api.local' } }],
  },
});

if (result.ok) {
  console.log(result.value.chain.length);
  console.log(result.value.root.subject.values.commonName);
  console.log(result.value.leaf.authorityInfoAccess);
} else {
  console.log(result.error.code);
  console.log(result.error.details);
}
```

## Verify CSR

```ts
import { verifyCertificateSigningRequest } from 'micro509';

const result = await verifyCertificateSigningRequest(csr.pem);
if (result.ok) {
  console.log(result.value.subject.values.commonName);
}
```

## Notes

- keygen: `rsa`, `ecdsa`, `ed25519`
- cert sigs: RSA PKCS#1 v1.5, ECDSA P-256/P-384, Ed25519
- names: object shorthand or explicit ordered attributes
- extensions: basic constraints, key usage, extended key usage, SAN, SKI, AKI
- parsed extras: AIA, CRL distribution points, raw extension list
- custom extensions: arbitrary OID/valueDER with duplicate OID rejection
- decode helpers: single-extension, registry-style, or typed decoder-map decode over parsed extensions
- decoder maps: strongly keyed `decodedExtensionMap` on parse results
- pem helpers: split mixed cert/csr/key bundles by label
- pkcs7 helpers: create/parse degenerate signedData cert bags, parse general signedData signer metadata
- crl helpers: create/parse/verify CRLs, delta CRL indicator, issuing distribution point, freshest CRL, entry reason/invalidity extensions, revocation lookup by serial
- ocsp helpers: build requests, build signed responses, parse requests/responses, verify response signatures, derive responder candidates from AIA or local config, and run nonce/request/issuer/time checks plus responderID/delegated-responder validation and full multi-cert request coverage; focused fixtures live in `test/ocsp-fixtures.test.ts`
- pfx helpers: create/parse passwordless or encrypted cert+key bundles with bag attributes and optional MAC integrity
- legacy key helpers: PKCS#1 RSA and SEC1 EC import/export, plus encrypted traditional PEM
- extended key usage: built-ins + custom OID escape hatch
- identity helpers: `matchServiceIdentity()` covers DNS-ID, IP-ID, URI-ID, SRV-ID, wildcard, IDNA, and opt-in DNS CN compatibility; focused fixtures live in `test/identity-fixtures.test.ts`
- chain verify: async, WebCrypto-based, browser-safe, multi-candidate path building plus candidate-path validation with issuer match, signatures, time, CA/keyCertSign, pathLen, AKI/SKI, supported-form name constraints, RFC 9618 policy outputs, and optional DNS/IP identity composition in verify helpers; broader revocation orchestration stays separate
- csr verify: async, WebCrypto-based, browser-safe signature validation
- verify failures: structured `code`, `index`, `details`
