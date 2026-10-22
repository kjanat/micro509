# Recipes

These short workflows start with material your application already has. Each
function takes that material as an argument so trust roots, passwords, and
approval decisions stay under your control. See [Getting started](./getting-started.md)
for key generation and certificate setup.

## Verify a server certificate

Pass the server leaf, any available intermediate certificates, and the roots
your application trusts. micro509 does not load the operating system trust
store or fetch missing intermediates. Set both the TLS purpose and expected
service identity so the check covers how the certificate will be used.

<!-- typecheck -->

```ts
import { verifyCertificateChain } from 'micro509';

export async function verifyServer(
  leafPem: string,
  intermediatePems: readonly string[],
  trustedRootPems: readonly string[],
  hostname: string,
) {
  const result = await verifyCertificateChain({
    leaf: leafPem,
    intermediates: intermediatePems,
    roots: trustedRootPems,
    purpose: 'serverAuth',
    serviceIdentity: { type: 'dns', value: hostname },
  });

  if (!result.ok) {
    return {
      ok: false as const,
      code: result.error.code,
      index: result.error.index,
      details: result.error.details,
      message: result.error.message,
    };
  }

  return {
    ok: true as const,
    subject: result.value.leaf.subject.values.commonName,
    serialNumber: result.value.leaf.serialNumberHex,
    chainLength: result.value.chain.length,
  };
}
```

The error code identifies the failed check. The optional `index` must be read
with `details.source`: malformed roots or intermediates refer to those input
collections, not the leaf or a completed chain. Some failures, such as
`no_trusted_root`, have no index. To check revocation, add a `revocation` input with the CRL or
OCSP evidence your application has. Omitting the input skips revocation
checking.

## Issue a certificate from a CSR

Verify the CSR signature, then review its subject and requested extensions under
your enrollment policy. The signature proves possession of the request's
private key. It does not approve the requested names or usages. This example
allows one DNS name from an explicit list, then issues a server certificate
with only that approved name.

<!-- typecheck -->

```ts
import {
  createCertificate,
  getSubjectPublicKeyOrThrow,
  verifyCertificateSigningRequest,
} from 'micro509';

export async function issueApprovedServerCsr(
  csrPem: string,
  approvedDnsNames: readonly string[],
  issuerName: { readonly commonName: string },
  issuerCertificatePem: string,
  issuerPrivateKey: CryptoKey,
) {
  const checked = await verifyCertificateSigningRequest(csrPem);
  if (!checked.ok) {
    throw new Error(`CSR rejected: ${checked.error.code}`);
  }

  const requestedCommonName = checked.value.subject.values.commonName;
  const requestedSans = checked.value.subjectAltNames ?? [];
  const requestedDnsNames = requestedSans
    .filter((name) => name.type === 'dns')
    .map((name) => name.value);

  if (
    requestedCommonName === undefined ||
    requestedDnsNames.length === 0 ||
    requestedDnsNames.some(
      (name) =>
        !approvedDnsNames.includes(name) || name !== requestedCommonName,
    )
  ) {
    throw new Error('CSR names are not approved');
  }

  const publicKey = await getSubjectPublicKeyOrThrow(checked.value);
  return createCertificate({
    issuer: issuerName,
    subject: { commonName: requestedCommonName },
    publicKey,
    signerPrivateKey: issuerPrivateKey,
    issuerCertificate: issuerCertificatePem,
    extensions: {
      extendedKeyUsage: ['serverAuth'],
      subjectAltNames: requestedDnsNames.map((value) => ({
        type: 'dns',
        value,
      })),
    },
  });
}
```

This deliberately constructs the issued extensions from approved values rather
than copying the CSR's complete extension request. Add policy checks for the
subject and any other requested fields your enrollment flow accepts.

## Import a client identity from PFX

Parse a password-protected PFX, import its PKCS#8 keys, and compare each key
against the available certificates. Pair by cryptographic key match instead of
assuming bag order identifies the client certificate.

<!-- typecheck -->

```ts
import { matchCertificatePrivateKey } from 'micro509';
import { importPkcs8DerOrThrow } from 'micro509/keys';
import { parsePfxDer } from 'micro509/pkcs';

export async function importClientIdentity(
  pfxDer: Uint8Array,
  password: string,
) {
  const parsed = await parsePfxDer(pfxDer, { password });
  if (!parsed.ok) {
    throw new Error(`PFX could not be read: ${parsed.error.code}`);
  }

  for (const pkcs8Der of parsed.value.privateKeys) {
    const privateKey = await importPkcs8DerOrThrow(pkcs8Der);
    for (const certificate of parsed.value.certificates) {
      const match = await matchCertificatePrivateKey(certificate, privateKey);
      if (match.ok) {
        return { certificate, privateKey };
      }
    }
  }

  throw new Error('PFX contains no matching private key and certificate');
}
```

The parser verifies the PFX MAC when one is present and a password is supplied.
This recipe establishes that the returned private key belongs to the returned
certificate. Validate the certificate chain and client-auth purpose separately
against the roots and policy your application trusts.
