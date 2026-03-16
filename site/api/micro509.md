[micro509](modules.md) / micro509

# micro509

Stable root import for `micro509`.\
Re-exports the common certificate, parsing, verification, revocation, key, and PKCS
workflows from one package entrypoint.

Reach for this module when you want the default workflow-first package surface.
Use domain entrypoints such as `micro509/x509`, `micro509/verify`, and
`micro509/revocation` when you need exhaustive advanced types.

The root export is organized around common PKI flows:

- create certificates, CSRs, CRLs, OCSP responses, PKCS#7, and PFX artifacts
- parse DER or PEM inputs into typed certificate and request shapes
- verify certificate chains, service identities, CRLs, OCSP, and signed data
- import, export, generate, and encrypt key material with WebCrypto-safe algorithms
- work with the common extension inputs, revocation evidence, and validation results

Advanced PKCS#12 MAC plumbing, signature profile tuning, and other domain-specific helper
types stay in their owner domains instead of being headlined here.

## Examples

```ts
import {
	createSelfSignedCertificate,
	parseCertificatePem,
	verifyCertificateChain,
} from 'micro509';

const { certificate } = await createSelfSignedCertificate({
	subject: { commonName: 'example.com' },
	algorithm: { kind: 'ecdsa', namedCurve: 'P-256' },
});

const parsed = parseCertificatePem(certificate.pem);
// parsed.subject.values.commonName === 'example.com'

const result = await verifyCertificateChain({
	leaf: certificate.pem,
	roots: [certificate.pem],
	allowSelfSignedLeaf: true,
});
// result.ok === true
```

```ts
import {
	generateKeyPair,
	parseCertificateSigningRequestPem,
	createCertificateSigningRequest,
} from 'micro509';

const keyPair = await generateKeyPair({ kind: 'ecdsa', namedCurve: 'P-256' });
const csr = await createCertificateSigningRequest({
	subject: { commonName: 'example.com' },
	publicKey: keyPair.publicKey,
	signerPrivateKey: keyPair.privateKey,
});

const parsed = parseCertificateSigningRequestPem(csr.pem);
// parsed.subject.values.commonName === 'example.com'
```
