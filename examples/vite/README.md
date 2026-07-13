# micro509 with Vite

Issue a self-signed certificate, then parse it back out of its own PEM. TypeScript, hot
reload, and `micro509` as an npm dependency.

[![Open in StackBlitz]][stackblitz]

## Locally

```bash
npm install
npm run dev
```

For the same demo with nothing to install and nothing to build, see [`examples/browser`],
one HTML file you can open.

## What it does

[`src/main.ts`] takes the form's subject, key algorithm and validity, and:

1. generates a key pair and signs a self-signed certificate — `createSelfSignedCertificate`
2. parses the certificate back from its PEM — `parseCertificatePem`
3. hashes the DER — `certificateFingerprint`

Nothing is carried over from step 1 to step 2: what the page shows is what the certificate
says about itself.

[`src/main.ts`]: ./src/main.ts
[`examples/browser`]: https://github.com/kjanat/micro509/tree/HEAD/examples/browser
[Open in StackBlitz]: https://developer.stackblitz.com/img/open_in_stackblitz_small.svg
[stackblitz]: https://stackblitz.com/github/kjanat/micro509/tree/master/examples/vite?title=micro509%20with%20Vite
