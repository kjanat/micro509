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

Verify certificate chains and service identities with typed failures in TypeScript.
A zero-runtime-dependency PKI toolkit built on WebCrypto, with certificate and CSR
creation, revocation, key handling, and PKCS containers.

> **Prerelease** — API may change before 1.0. ESM-only; requires a runtime with
> WebCrypto. See [runtime support](https://micro509.kjanat.dev/reference/runtimes).

## Install

```bash
npm install micro509
```

[Getting started](https://micro509.kjanat.dev/guide/getting-started) covers Bun,
Deno, other package managers, and browser imports without a build step.

## Verify a certificate

Supply a leaf, any intermediates, and roots your application already trusts.
Select the expected service identity and purpose. This complete example creates
a demo CA and leaf so you can run it immediately:

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

A failure has a machine-readable `error.code`, a certificate `index` where
applicable, and structured `details`. For example, an unexpected DNS name
produces `subject_alt_name_mismatch`; an expired certificate produces
`certificate_expired`.

Parsing a certificate does not establish trust. Verification uses the roots you
supply, not an automatically loaded system trust store. Revocation runs when
configured with caller-supplied evidence; the library does not fetch CRLs, OCSP
responses, or missing intermediates. See the
[verification guide](https://micro509.kjanat.dev/guide/verification) for the
validation contract and policy options.

## Find your workflow

| Task                                                      | Guide                                                          |
| --------------------------------------------------------- | -------------------------------------------------------------- |
| Issue certificates, create CSRs, parse PEM or DER         | [Certificates](https://micro509.kjanat.dev/guide/certificates) |
| Validate chains and match DNS, IP, URI, or SRV identities | [Verification](https://micro509.kjanat.dev/guide/verification) |
| Create and validate CRLs or OCSP responses                | [Revocation](https://micro509.kjanat.dev/guide/revocation)     |
| Generate, import, export, or decrypt keys                 | [Keys](https://micro509.kjanat.dev/guide/keys)                 |
| Work with PFX/PKCS#12 and PKCS#7/CMS SignedData           | [PKCS](https://micro509.kjanat.dev/guide/pkcs)                 |
| Encode custom extensions and inspect DER                  | [Extensions](https://micro509.kjanat.dev/guide/extensions)     |

## Imports and compatibility

Use `micro509` for the main APIs, or a domain entrypoint for a narrower surface:

```ts
import { verifyCertificateChain } from 'micro509/verify';
import { parseCertificatePem } from 'micro509/x509';
import { generateKeyPair } from 'micro509/keys';
```

The package is ESM-only and tree-shakeable. Library code uses WebCrypto and web
text/base64 globals without Node builtins. See the
[runtime requirements](https://micro509.kjanat.dev/reference/runtimes) and
[algorithm matrix](https://micro509.kjanat.dev/reference/algorithms) before
choosing a deployment target.

## Scope and evidence

The [standards reference](https://micro509.kjanat.dev/reference/standards)
summarizes shipped behavior and exclusions; [PKIX-SCOPE.md](./docs/PKIX-SCOPE.md)
records the detailed boundary and test evidence. Coverage includes NIST PKITS,
section-level conformance tests, and OpenSSL differential testing. Supported
operations are bounded by the documented algorithms and formats; parsing an
algorithm identifier does not imply support for its key operations.

## More resources

- [API reference](https://micro509.kjanat.dev/api/)
- [Error codes](https://micro509.kjanat.dev/reference/errors)
- [Changelog](./CHANGELOG.md)
- Runnable examples: [plain browser][browser-example] and [Vite][vite-example]
- [Contributing](./CONTRIBUTING.md), [PKITS harness](./test/pkits.test.ts), and
  [differential harness](./test/differential.test.ts)
- [OpenSSL CI images and binaries](./.github/openssl/README.md)

## License

[MIT](./LICENSE)

[npm]: https://npm.im/micro509
[jsr]: https://jsr.io/@kjanat/micro509
[socket]: https://socket.dev/npm/package/micro509
[browser-example]: ./examples/browser/README.md "GitHub"
[vite-example]: ./examples/vite/README.md "GitHub"
