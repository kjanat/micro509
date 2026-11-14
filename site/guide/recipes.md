# Recipes

Each recipe defines a function for your application, then calls it with
generated demo material and prints the result. Replace the demo inputs with
your certificates, trust roots, passwords, and approval decisions. See [Getting started](./getting-started.md)
for key generation and certificate setup.

## Verify a server certificate

Pass the server leaf, any available intermediate certificates, and the roots
your application trusts. micro509 does not load the operating system trust
store or fetch missing intermediates. Set both the TLS purpose and expected
service identity so the check covers how the certificate will be used.

<LiveCode>

```ts
import {
  createCertificate,
  createSelfSignedCertificate,
  generateKeyPair,
  verifyCertificateChain,
} from 'micro509';

async function verifyServer(
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

const ca = await createSelfSignedCertificate({
  subject: { commonName: 'Recipe CA' },
  extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign'] },
});
const keys = await generateKeyPair();
const leaf = await createCertificate({
  issuer: { commonName: 'Recipe CA' },
  subject: { commonName: 'app.example.com' },
  publicKey: keys.publicKey,
  signerPrivateKey: ca.keyPair.privateKey,
  issuerCertificate: ca.certificate.pem,
  extensions: {
    extendedKeyUsage: ['serverAuth'],
    subjectAltNames: [{ type: 'dns', value: 'app.example.com' }],
  },
});
console.log(
  await verifyServer(leaf.pem, [], [ca.certificate.pem], 'app.example.com'),
);
console.log(
  await verifyServer(leaf.pem, [], [ca.certificate.pem], 'wrong.example.com'),
);
```

</LiveCode>

The error code identifies the failed check. The optional `index` must be read
with `details.source`: malformed roots or intermediates refer to those input
collections, not the leaf or a completed chain. Some failures, such as
`no_trusted_root`, have no index. To check revocation, add a `revocation` input with the CRL or
OCSP evidence your application has. Omitting the input skips revocation
checking.

## Authenticate a TLS client

A mutual TLS handshake proves that the client holds the private key of the
first certificate it sent. Validate that certificate for `clientAuth`, then
authorize the same certificate. The rest of the client's chain only helps build
the path. This recipe maps the SHA-256 of an authorized client's public key to
an account.

<LiveCode>

```ts
import {
  createCertificate,
  createSelfSignedCertificate,
  generateKeyPair,
  subjectPublicKeyInfoFingerprint,
  verifyCertificateChain,
} from 'micro509';

async function authenticateClient(
  handshakeChain: readonly Uint8Array[],
  trustedRootPems: readonly string[],
  accountsBySpkiSha256: ReadonlyMap<string, string>,
) {
  const [leaf, ...intermediates] = handshakeChain;
  if (leaf === undefined) {
    return { ok: false as const, reason: 'no_client_certificate' };
  }
  const result = await verifyCertificateChain({
    leaf,
    intermediates,
    roots: trustedRootPems,
    purpose: 'clientAuth',
  });
  if (!result.ok) {
    return { ok: false as const, reason: result.error.code };
  }
  const { hex } = await subjectPublicKeyInfoFingerprint(result.value.leaf);
  const account = accountsBySpkiSha256.get(hex);
  if (account === undefined) {
    return { ok: false as const, reason: 'not_authorized', spkiSha256: hex };
  }
  return { ok: true as const, account, spkiSha256: hex };
}

const ca = await createSelfSignedCertificate({
  subject: { commonName: 'Recipe Client CA' },
  extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign'] },
});
async function issueClient(commonName: string) {
  const keys = await generateKeyPair();
  return createCertificate({
    issuer: { commonName: 'Recipe Client CA' },
    subject: { commonName },
    publicKey: keys.publicKey,
    signerPrivateKey: ca.keyPair.privateKey,
    issuerCertificate: ca.certificate.pem,
    extensions: { extendedKeyUsage: ['clientAuth'] },
  });
}
const alice = await issueClient('alice');
const mallory = await issueClient('mallory');
const accounts = new Map([
  [(await subjectPublicKeyInfoFingerprint(alice.der)).hex, 'alice'],
]);
const roots = [ca.certificate.pem];

console.log('alice:', await authenticateClient([alice.der], roots, accounts));
console.log(
  'mallory:',
  await authenticateClient([mallory.der], roots, accounts),
);
console.log(
  'mallory appending alice:',
  await authenticateClient([mallory.der, alice.der], roots, accounts),
);
```

</LiveCode>

Mallory holds a valid client certificate, so validation succeeds and
authorization refuses the account. Appending Alice's public certificate leaves
Mallory's certificate in first place, and the handshake proved Mallory's key.

With `node:tls`, create the server with `requestCert: true`. After the
handshake, `socket.getPeerCertificate(true)` returns the client's first
certificate with its DER in `raw`. Further certificates follow through
`issuerCertificate` until the link is `undefined` or points back to the same
certificate. Node.js, Bun and Deno each fill that list differently, and the
recipe uses those certificates only to build the path.

## Issue a certificate from a CSR

Verify the CSR signature, then review its subject and requested extensions under
your enrollment policy. The signature proves possession of the request's
private key. It does not approve the requested names or usages. This example
allows one DNS name from an explicit list, then issues a server certificate
with only that approved name.

<LiveCode>

```ts
import {
  createCertificate,
  createCertificateSigningRequest,
  createSelfSignedCertificate,
  generateKeyPair,
  getSubjectPublicKeyOrThrow,
  verifyCertificateSigningRequest,
} from 'micro509';

async function issueApprovedServerCsr(
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

const ca = await createSelfSignedCertificate({
  subject: { commonName: 'Recipe CA' },
  extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign'] },
});
const keys = await generateKeyPair();
const csr = await createCertificateSigningRequest({
  subject: { commonName: 'app.example.com' },
  publicKey: keys.publicKey,
  signerPrivateKey: keys.privateKey,
  extensions: { subjectAltNames: [{ type: 'dns', value: 'app.example.com' }] },
});
const issued = await issueApprovedServerCsr(
  csr.pem,
  ['app.example.com'],
  { commonName: 'Recipe CA' },
  ca.certificate.pem,
  ca.keyPair.privateKey,
);
console.log('Issued certificate:');
console.log(issued.pem);
```

</LiveCode>

This deliberately constructs the issued extensions from approved values rather
than copying the CSR's complete extension request. Add policy checks for the
subject and any other requested fields your enrollment flow accepts.

## Import a client identity from PFX

Parse a password-protected PFX, import its PKCS#8 keys, and compare each key
against the available certificates. Pair by cryptographic key match instead of
assuming bag order identifies the client certificate.

<LiveCode>

```ts
import {
  createSelfSignedCertificate,
  matchCertificatePrivateKey,
  unwrap,
} from 'micro509';
import { importPkcs8DerOrThrow } from 'micro509/keys';
import { createPfx, parsePfxDer } from 'micro509/pkcs';

async function importClientIdentity(pfxDer: Uint8Array, password: string) {
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

const original = await createSelfSignedCertificate({
  subject: { commonName: 'client.example.com' },
  extensions: { extendedKeyUsage: ['clientAuth'] },
});
const pfx = unwrap(
  await createPfx({
    certificates: [{ certificate: original.certificate.pem }],
    privateKeys: [{ privateKey: original.keyPair.privateKey }],
    encryption: { password: 'demo-password' },
    mac: { password: 'demo-password' },
  }),
);
const identity = await importClientIdentity(pfx.der, 'demo-password');
console.log('Imported identity:', {
  subject: identity.certificate.subject.values,
  serialNumber: identity.certificate.serialNumberHex,
  privateKey: {
    type: identity.privateKey.type,
    algorithm: identity.privateKey.algorithm,
    usages: identity.privateKey.usages,
  },
});
```

</LiveCode>

The parser verifies the PFX MAC when one is present and a password is supplied.
This recipe establishes that the returned private key belongs to the returned
certificate. Validate the certificate chain and client-auth purpose separately
against the roots and policy your application trusts.
