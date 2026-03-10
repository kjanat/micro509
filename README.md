# micro509

Tiny X.509 builders for modern TypeScript.

- create certs + CSRs
- DER + PEM + base64 outputs
- PKCS#8 + SPKI + JWK key import/export
- WebCrypto-first, typed, small surface

## Install

```bash
npm install micro509
```

## Self-signed cert

```ts
import { createSelfSignedCertificate } from "micro509";

const { certificate, keyPair } = await createSelfSignedCertificate({
	subject: {
		commonName: "example.com",
		organization: "Acme",
		country: "US",
	},
	validity: { days: 30 },
	extensions: {
		keyUsage: ["digitalSignature", "keyEncipherment"],
		subjectAltNames: [
			{ type: "dns", value: "example.com" },
			{ type: "dns", value: "www.example.com" },
		],
	},
});

console.log(certificate.pem);
console.log(await keyPair.exportPkcs8Pem());
console.log(await keyPair.exportPublicJwk());
```

## CA-signed leaf cert

```ts
import {
	createCertificate,
	createSelfSignedCertificate,
	generateKeyPair,
} from "micro509";

const ca = await createSelfSignedCertificate({
	subject: { commonName: "Local Test CA" },
	extensions: {
		basicConstraints: { ca: true, pathLength: 0 },
		keyUsage: ["keyCertSign", "cRLSign"],
	},
});

const leafKeys = await generateKeyPair();
const leaf = await createCertificate({
	issuer: { commonName: "Local Test CA" },
	subject: { commonName: "api.local" },
	publicKey: leafKeys.publicKey,
	signerPrivateKey: ca.keyPair.privateKey,
	issuerPublicKey: ca.keyPair.publicKey,
	extensions: {
		keyUsage: ["digitalSignature"],
		subjectAltNames: [{ type: "dns", value: "api.local" }],
	},
});

console.log(leaf.pem);
```

## CSR

```ts
import { createCertificateSigningRequest, generateKeyPair } from "micro509";

const keyPair = await generateKeyPair({ kind: "ed25519" });
const csr = await createCertificateSigningRequest({
	subject: { commonName: "csr.example" },
	publicKey: keyPair.publicKey,
	signerPrivateKey: keyPair.privateKey,
	extensions: {
		subjectAltNames: [{ type: "dns", value: "csr.example" }],
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
} from "micro509";

const keyPair = await generateKeyPair({ kind: "rsa" });

const publicKey = await importSpkiBase64(
	await exportBinaryBase64(keyPair.publicKey),
	{
		kind: "rsa",
	},
);

const privateKey = await importPkcs8Pem(await keyPair.exportPkcs8Pem(), {
	kind: "rsa",
});

const jwkPublicKey = await importPublicJwk(await keyPair.exportPublicJwk(), {
	kind: "rsa",
});
```

## Notes

- keygen: `rsa`, `ecdsa`, `ed25519`
- cert sigs: RSA PKCS#1 v1.5, ECDSA P-256/P-384, Ed25519
- names: object shorthand or explicit ordered attributes
- extensions: basic constraints, key usage, extended key usage, SAN, SKI, AKI
