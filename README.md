<picture>
  <source
    media="(prefers-color-scheme: dark)"
    srcset="https://github.com/kjanat/micro509/raw/e7e2007bfd7a18f6f247864b14ef60d54ed91dd6/site/assets/icon-light.svg"
  >
  <source
    media="(prefers-color-scheme: light)"
    srcset="https://github.com/kjanat/micro509/raw/e7e2007bfd7a18f6f247864b14ef60d54ed91dd6/site/assets/icon.svg"
  >
  <img
    alt=""
    src="https://github.com/kjanat/micro509/raw/e7e2007bfd7a18f6f247864b14ef60d54ed91dd6/site/assets/icon.svg"
    width="64"
    height="64"
    align="left"
  >
</picture>

# micro509

[![NPM](https://img.shields.io/npm/v/micro509?logo=npm&labelColor=CB3837&color=black)][npm]
[![JSR](https://img.shields.io/jsr/v/@kjanat/micro509?logoColor=083344&logo=jsr&logoSize=auto&label=&labelColor=f7df1e&color=black)][jsr]
[![Socket](https://badge.socket.dev/npm/package/micro509)][socket]

A zero-dependency TypeScript X.509 and PKI toolkit. Create certificates and
CSRs, verify certificate chains and identities, manage revocation, and work
with keys and PKCS containers using WebCrypto.

Zero dependencies. Tree-shakeable subpath entrypoints. Runs in
Node, Bun, Deno, browsers, and Cloudflare Workers.

`micro509/kdf` derives Argon2d and Argon2id keys across supported runtimes,
including versions `0x10` and `0x13`.

> **Prerelease** — API may change before 1.0.

## Install

```bash
npm install micro509
```

## Quick start

Create a self-signed certificate, verify its chain and service identity, then
see a typed failure when the requested identity does not match:

```ts
import { createSelfSignedCertificate, verifyCertificateChain } from 'micro509';

const { certificate } = await createSelfSignedCertificate({
	subject: { commonName: 'app.example.com' },
	extensions: {
		subjectAltNames: [{ type: 'dns', value: 'app.example.com' }],
	},
});

const options = {
	leaf: certificate.pem,
	roots: [certificate.pem],
	allowSelfSignedLeaf: true,
} as const;

const valid = await verifyCertificateChain({
	...options,
	serviceIdentity: { type: 'dns', value: 'app.example.com' },
});
console.log(valid.ok ? 'verified app.example.com' : valid.error.code);

const mismatch = await verifyCertificateChain({
	...options,
	serviceIdentity: { type: 'dns', value: 'admin.example.com' },
});
console.log(mismatch.ok ? 'verified' : mismatch.error.code);
```

Output:

```text
verified app.example.com
subject_alt_name_mismatch
```

A verification failure is a typed result with an error code, failing
certificate index when relevant, and structured details. Callers can handle a
specific case without parsing messages or collapsing every failure into
`false`.

The self-signed leaf option above is useful for a compact local demo. In
production, supply the appropriate trust anchors and intermediates for your
PKI.

## What it covers

- **Certificates and CSRs:** create, parse, and encode common X.509 extensions
- **Verification:** build and validate chains, enforce policy, and match DNS,
  IP, URI, and SRV service identities
- **Revocation:** create and process CRLs and OCSP requests and responses
- **Keys and signatures:** import, export, and generate RSA, ECDSA, and
  Ed25519 keys, plus signing and verification of detached data
- **PKCS workflows:** PKCS#7 SignedData and password-protected PFX/PKCS#12
- **PEM and DER:** encode, decode, and parse common formats

The root package exports the usual workflows:

```ts
import { createCertificate, parseCertificatePem, verifyCertificateChain } from 'micro509';
```

For smaller imports or more specialized types, use domain entrypoints:

```ts
import { parseCertificatePem } from 'micro509/x509';
import { verifyCertificateChain } from 'micro509/verify';
import { checkCertificateRevocation } from 'micro509/revocation';
import { createPfx } from 'micro509/pkcs';
import { generateKeyPair } from 'micro509/keys';
```

See the [API reference](https://micro509.kjanat.dev/api/) for the full entrypoint list.

## Standards and algorithms

micro509 implements core certificate path validation, service identity,
policy, PEM, safe-curve, OCSP, and PKCS container workflows. The exact claim
boundary and partial areas are documented in the [PKIX scope](./docs/PKIX-SCOPE.md).
See [algorithms](https://micro509.kjanat.dev/reference/algorithms) for supported
curves and signature schemes, [runtimes](https://micro509.kjanat.dev/reference/runtimes)
for environment support, and [standards](https://micro509.kjanat.dev/reference/standards)
for implementation coverage.

## Try it in a browser

The browser example is a single HTML file that issues a certificate and parses
it back with no build step. The Vite example adds TypeScript and a dev server.

- [Browser example][browser-example], [open in StackBlitz][browser-example:stackblitz]
- [Vite example][vite-example], [open in StackBlitz][vite-example:stackblitz]

## Documentation

- [Recipes: server verification, CSR issuance, PFX import](https://micro509.kjanat.dev/guide/recipes)
- [Migration from 0.14.0](https://micro509.kjanat.dev/guide/migration)

- [Getting started](https://micro509.kjanat.dev/guide/getting-started)
- [Certificates and extensions](https://micro509.kjanat.dev/guide/certificates)
- [Verification and trust inputs](https://micro509.kjanat.dev/guide/verification)
- [CRL and OCSP revocation](https://micro509.kjanat.dev/guide/revocation)
- [Keys and encrypted formats](https://micro509.kjanat.dev/guide/keys)
- [PKCS#7 and PKCS#12](https://micro509.kjanat.dev/guide/pkcs)
- [Error reference](https://micro509.kjanat.dev/reference/errors)
- [API reference](https://micro509.kjanat.dev/api/)
- [Contributing](./CONTRIBUTING.md)

## OpenSSL builds

This repository also publishes statically linked OpenSSL builds to GHCR for
micro509 CI and general use. See [build details](./.github/openssl/README.md).

## License

[MIT](./LICENSE)

[npm]: https://npm.im/micro509
[jsr]: https://jsr.io/@kjanat/micro509
[socket]: https://socket.dev/npm/package/micro509
[browser-example]: ./examples/browser/README.md "GitHub"
[browser-example:stackblitz]: https://stackblitz.com/github/kjanat/micro509/tree/master/examples/browser?title=micro509%20in%20the%20browser "StackBlitz"
[vite-example]: ./examples/vite/README.md "GitHub"
[vite-example:stackblitz]: https://stackblitz.com/github/kjanat/micro509/tree/master/examples/vite?title=micro509%20with%20Vite "StackBlitz"
