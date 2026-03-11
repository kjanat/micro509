# micro509

Tiny X.509 builders for modern TypeScript.

- create certs + CSRs
- DER + PEM + base64 outputs
- PKCS#8 + SPKI + JWK key import/export
- parse certs + CSRs back to typed metadata
- verify leaf/intermediate/root chains with typed results
- custom extension build hooks + decode helpers
- browser-native chain verification via WebCrypto
- browser-native CSR signature verification too
- PKCS#7 certificate bag helpers
- CRL parse/create/verify helpers
- passwordless PFX bundle helpers
- OCSP request build + OCSP response parse helpers
- encrypted PKCS#8 / encrypted PFX via PBES2
- encrypted traditional RSA/EC PEM helpers
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
		extendedKeyUsage: ["serverAuth", { type: "oid", value: "1.2.3.4.5" }],
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

## Parse certs + CSRs

```ts
import {
	decodeExtension,
	decodeExtensions,
	defineExtensionDecoderMap,
	findExtension,
	parseCertificatePem,
	parseCertificateSigningRequestPem,
} from "micro509";

const parsedCert = parseCertificatePem(certificate.pem);
console.log(parsedCert.subject.values.commonName);
console.log(parsedCert.extendedKeyUsage);
console.log(parsedCert.authorityInfoAccess);
console.log(parsedCert.crlDistributionPoints);

const parsedWithDecoders = parseCertificatePem(certificate.pem, {
	decoders: [
		{
			oid: "1.2.3.4.200",
			decode(extension) {
				return extension.valueHex;
			},
		},
	],
});

const parsedWithMap = parseCertificatePem(certificate.pem, {
	decoderMap: defineExtensionDecoderMap({
		customText: {
			oid: "1.2.3.4.200",
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
import { exportEncryptedPkcs8Pem, importEncryptedPkcs8Pem } from "micro509";

const encryptedPem = await exportEncryptedPkcs8Pem(keyPair.privateKey, {
	password: "secret123",
});

const privateKey = await importEncryptedPkcs8Pem(
	encryptedPem,
	"secret123",
	{ kind: "rsa" },
);
```

## Encrypted traditional PEM

```ts
import { exportEncryptedPkcs1Pem, importEncryptedPkcs1Pem } from "micro509";

const encryptedRsaPem = await exportEncryptedPkcs1Pem(keyPair.privateKey, {
	password: "secret123",
});

const privateKey = await importEncryptedPkcs1Pem(
	encryptedRsaPem,
	"secret123",
	{ kind: "rsa" },
);
```

## Custom extensions

```ts
import {
	createSelfSignedCertificate,
	decodeExtension,
	parseCertificatePem,
} from "micro509";

const { certificate } = await createSelfSignedCertificate({
	subject: { commonName: "custom.example" },
	extensions: {
		customExtensions: [
			{
				oid: "1.2.3.4.200",
				critical: true,
				value: Uint8Array.of(0x04, 0x03, 0x01, 0x02, 0x03),
			},
		],
	},
});

const parsed = parseCertificatePem(certificate.pem);
const decoded = decodeExtension(parsed.extensions, {
	oid: "1.2.3.4.200",
	decode(extension) {
		return Array.from(extension.valueDer);
	},
});

const allDecoded = decodeExtensions(parsed.extensions, [
	{
		oid: "1.2.3.4.200",
		decode(extension) {
			return extension.valueHex;
		},
	},
]);
```

## Split PEM bundles

```ts
import { categorizePemBlocks, splitPemBlocks } from "micro509";

const blocks = splitPemBlocks(bundle);
console.log(blocks.map((block) => block.label));

const categorized = categorizePemBlocks(bundle);
console.log(categorized.certificates.length);
```

## PKCS#7 cert bag

```ts
import { createPkcs7CertBagPem, parsePkcs7CertBagPem } from "micro509";

const bag = createPkcs7CertBagPem([leaf.pem, root.pem]);
const certs = parsePkcs7CertBagPem(bag.pem);
console.log(certs.map((cert) => cert.subject.values.commonName));
```

## PFX

```ts
import { createPfx, parsePfxPem } from "micro509";

const pfx = await createPfx({
	certificates: [
		{ certificate: leaf.pem, attributes: { friendlyName: "leaf" } },
		{ certificate: root.pem, attributes: { friendlyName: "root" } },
	],
	privateKeys: [
		{ privateKey: leafKey.privateKey, attributes: { friendlyName: "leaf" } },
	],
});

const parsedPfx = await parsePfxPem(pfx.pem);
console.log(parsedPfx.certificates.length);
console.log(parsedPfx.bags[0]?.attributes.friendlyName);

const encryptedPfx = await createPfx({
	certificates: [{ certificate: leaf.pem }],
	privateKeys: [{ privateKey: leafKey.privateKey }],
	encryption: { password: "secret123" },
	mac: { password: "secret123" },
});

const parsedEncryptedPfx = await parsePfxPem(encryptedPfx.pem, {
	password: "secret123",
	macPassword: "secret123",
});
```

## CRL

```ts
import {
	createCertificateRevocationList,
	isCertificateRevoked,
	parseCertificateRevocationListPem,
	verifyCertificateRevocationList,
} from "micro509";

const crl = await createCertificateRevocationList({
	issuer: { commonName: "Example CA" },
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
} from "micro509";

const request = await createOcspRequest({
	requests: [{ certificate: leaf.pem, issuerCertificate: issuer.pem }],
	nonce: Uint8Array.of(0xaa, 0xbb),
});

const parsedRequest = parseOcspRequestPem(request.pem);
console.log(parsedRequest.requests.length);

const response = await createOcspResponse({
	signerPrivateKey: issuerKey.privateKey,
	signerCertificate: issuer.pem,
	responses: [{
		certificate: leaf.pem,
		issuerCertificate: issuer.pem,
		certStatus: "good",
	}],
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
import { parsePkcs7SignedDataPem } from "micro509";

const signed = parsePkcs7SignedDataPem(pkcs7Pem);
console.log(signed.certificates.length);
console.log(signed.signerInfos.length);
```

## Legacy private key PEM

```ts
import {
	exportPkcs1Pem,
	exportSec1Pem,
	importPkcs1Pem,
	importSec1Pem,
} from "micro509";

const rsaPem = await exportPkcs1Pem(rsaKey.privateKey);
const rsaKeyAgain = await importPkcs1Pem(rsaPem, { kind: "rsa" });

const ecPem = await exportSec1Pem(ecKey.privateKey);
const ecKeyAgain = await importSec1Pem(ecPem, {
	kind: "ecdsa",
	namedCurve: "P-256",
});
```

## Verify chain

```ts
import { verifyCertificateChain } from "micro509";

const result = await verifyCertificateChain({
	leaf: leaf.pem,
	intermediates: [intermediate.pem],
	roots: [root.pem],
	purpose: "serverAuth",
	dnsName: "api.local",
});

if (result.ok) {
	console.log(result.value.chain.length);
	console.log(result.value.root.subject.values.commonName);
	console.log(result.value.leaf.authorityInfoAccess);
} else {
	console.log(result.code);
	console.log(result.details);
}
```

## Verify CSR

```ts
import { verifyCertificateSigningRequest } from "micro509";

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
- ocsp helpers: build requests, build signed responses, parse requests/responses, verify response signatures, validate nonce/request/issuer/delegated responders
- pfx helpers: create/parse passwordless or encrypted cert+key bundles with bag attributes and optional MAC integrity
- legacy key helpers: PKCS#1 RSA and SEC1 EC import/export, plus encrypted traditional PEM
- extended key usage: built-ins + custom OID escape hatch
- chain verify: async, WebCrypto-based, browser-safe, multi-candidate path building, issuer match, signatures, time, CA/keyCertSign, pathLen, AKI/SKI, SAN/EKU checks
- csr verify: async, WebCrypto-based, browser-safe signature validation
- verify failures: structured `code`, `index`, `details`
