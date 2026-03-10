import { X509Certificate } from "node:crypto";
import { describe, expect, it } from "vitest";
import { readElement } from "../src/der.js";
import {
	createCertificate,
	createCertificateSigningRequest,
	createSelfSignedCertificate,
	exportBinaryBase64,
	exportPkcs8Der,
	exportSpkiDer,
	generateKeyPair,
	importPkcs8Base64,
	importPkcs8Pem,
	importPrivateJwk,
	importPublicJwk,
	importSpkiBase64,
	importSpkiPem,
	parseCertificatePem,
	parseCertificateSigningRequestPem,
} from "../src/index.js";
import { OIDS } from "../src/oids.js";

describe("micro509", () => {
	it("creates a self-signed certificate with SANs and exportable keys", async () => {
		const result = await createSelfSignedCertificate({
			subject: {
				commonName: "example.com",
				organization: "Acme",
				country: "US",
			},
			validity: { days: 14 },
			extensions: {
				keyUsage: ["digitalSignature", "keyEncipherment"],
				subjectAltNames: [
					{ type: "dns", value: "example.com" },
					{ type: "ip", value: "127.0.0.1" },
				],
			},
		});

		const certificate = new X509Certificate(result.certificate.pem);
		expect(result.certificate.pem).toContain("BEGIN CERTIFICATE");
		expect(result.certificate.der.byteLength).toBeGreaterThan(0);
		expect(certificate.subject).toContain("CN=example.com");
		expect(certificate.issuer).toContain("CN=example.com");
		expect(certificate.checkHost("example.com")).toBe("example.com");
		expect(certificate.checkIP("127.0.0.1")).toBe("127.0.0.1");
		expect(await result.keyPair.exportPkcs8Pem()).toContain("BEGIN PRIVATE KEY");
		expect(await result.keyPair.exportSpkiPem()).toContain("BEGIN PUBLIC KEY");
		expect(await result.keyPair.exportPublicJwk()).toHaveProperty("kty");
	});

	it("creates a leaf certificate signed by a CA", async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: "Micro509 Test CA" },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "Micro509 Test CA" },
			subject: { commonName: "leaf.example" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				extendedKeyUsage: ["serverAuth", { type: "oid", value: "1.2.3.4.5" }],
				subjectAltNames: [{ type: "dns", value: "leaf.example" }],
			},
		});

		const leafCertificate = new X509Certificate(leaf.pem);
		const caCertificate = new X509Certificate(ca.certificate.pem);
		expect(leafCertificate.issuer).toContain("CN=Micro509 Test CA");
		expect(leafCertificate.checkHost("leaf.example")).toBe("leaf.example");
		expect(leafCertificate.verify(caCertificate.publicKey)).toBe(true);
		expect(hasExtensionOid(leaf.der, OIDS.extendedKeyUsage)).toBe(true);
		const parsed = parseCertificatePem(leaf.pem);
		expect(parsed.subject.values.commonName).toBe("leaf.example");
		expect(parsed.issuer.values.commonName).toBe("Micro509 Test CA");
		expect(parsed.subjectAltNames).toEqual([{ type: "dns", value: "leaf.example" }]);
		expect(parsed.extendedKeyUsage).toEqual(["serverAuth", { type: "oid", value: "1.2.3.4.5" }]);
	});

	it("roundtrips keys through PEM, base64, and JWK imports", async () => {
		const original = await generateKeyPair({ kind: "rsa", modulusLength: 2048 });
		const importedPublic = await importSpkiPem(await original.exportSpkiPem(), { kind: "rsa" });
		const importedPrivate = await importPkcs8Pem(await original.exportPkcs8Pem(), { kind: "rsa" });
		const base64Public = await importSpkiBase64(await exportBinaryBase64(original.publicKey), { kind: "rsa" });
		const base64Private = await importPkcs8Base64(await exportBinaryBase64(original.privateKey), { kind: "rsa" });
		const jwkPublic = await importPublicJwk(await original.exportPublicJwk(), { kind: "rsa" });
		const jwkPrivate = await importPrivateJwk(await original.exportPrivateJwk(), { kind: "rsa" });

		const certificate = await createCertificate({
			issuer: { commonName: "imported-ca" },
			subject: { commonName: "imported-leaf" },
			publicKey: importedPublic,
			signerPrivateKey: importedPrivate,
			issuerPublicKey: importedPublic,
		});
		const certificateFromBase64 = await createCertificate({
			issuer: { commonName: "imported-ca-2" },
			subject: { commonName: "imported-leaf-2" },
			publicKey: base64Public,
			signerPrivateKey: base64Private,
			issuerPublicKey: base64Public,
		});
		const certificateFromJwk = await createCertificate({
			issuer: { commonName: "imported-ca-3" },
			subject: { commonName: "imported-leaf-3" },
			publicKey: jwkPublic,
			signerPrivateKey: jwkPrivate,
			issuerPublicKey: jwkPublic,
		});

		expect(new X509Certificate(certificate.pem).subject).toContain("CN=imported-leaf");
		expect(new X509Certificate(certificateFromBase64.pem).subject).toContain("CN=imported-leaf-2");
		expect(new X509Certificate(certificateFromJwk.pem).subject).toContain("CN=imported-leaf-3");
		expect(await exportSpkiDer(importedPublic)).toEqual(await original.exportSpkiDer());
		expect(await exportPkcs8Der(importedPrivate)).toEqual(await original.exportPkcs8Der());
		expect(await exportSpkiDer(base64Public)).toEqual(await original.exportSpkiDer());
		expect(await exportPkcs8Der(base64Private)).toEqual(await original.exportPkcs8Der());
		expect(await exportSpkiDer(jwkPublic)).toEqual(await original.exportSpkiDer());
		expect(await exportPkcs8Der(jwkPrivate)).toEqual(await original.exportPkcs8Der());
	});

	it("creates a CSR with extensionRequest attributes", async () => {
		const keyPair = await generateKeyPair({ kind: "ed25519" });
		const csr = await createCertificateSigningRequest({
			subject: { commonName: "csr.example" },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
			extensions: {
				subjectAltNames: [{ type: "dns", value: "csr.example" }],
				keyUsage: ["digitalSignature"],
				extendedKeyUsage: ["clientAuth", { type: "oid", value: "1.2.3.4.6" }],
			},
		});

		expect(csr.pem).toContain("BEGIN CERTIFICATE REQUEST");
		const top = childrenOf(csr.der, readElement(csr.der));
		const certificationRequestInfo = top[0];
		if (certificationRequestInfo === undefined) {
			throw new Error("Missing certificationRequestInfo");
		}
		const criChildren = childrenOf(csr.der, certificationRequestInfo);
		const attributes = criChildren[3];
		if (attributes === undefined) {
			throw new Error("Missing attributes");
		}
		const attribute = childrenOf(csr.der, attributes)[0];
		if (attribute === undefined) {
			throw new Error("Missing extensionRequest attribute");
		}
		const attributeChildren = childrenOf(csr.der, attribute);
		const oidElement = attributeChildren[0];
		if (oidElement === undefined) {
			throw new Error("Missing attribute OID");
		}
		expect(decodeObjectIdentifier(oidElement.value)).toBe(OIDS.extensionRequest);
		const parsed = parseCertificateSigningRequestPem(csr.pem);
		expect(parsed.subject.values.commonName).toBe("csr.example");
		expect(parsed.subjectAltNames).toEqual([{ type: "dns", value: "csr.example" }]);
		expect(parsed.keyUsage).toEqual(["digitalSignature"]);
		expect(parsed.extendedKeyUsage).toEqual(["clientAuth", { type: "oid", value: "1.2.3.4.6" }]);
	});
});

function childrenOf(
	source: Uint8Array,
	parent: { readonly start: number; readonly end: number },
): ReturnType<typeof readElement>[] {
	const children: ReturnType<typeof readElement>[] = [];
	let offset = parent.start;
	while (offset < parent.end) {
		const child = readElement(source, offset);
		children.push(child);
		offset = child.end;
	}
	return children;
}

function decodeObjectIdentifier(bytes: Uint8Array): string {
	const first = bytes[0];
	if (first === undefined) {
		throw new Error("OID is empty");
	}
	const values = [Math.floor(first / 40), first % 40];
	let current = 0;
	for (let index = 1; index < bytes.length; index += 1) {
		const next = bytes[index];
		if (next === undefined) {
			throw new Error("Malformed OID");
		}
		current = (current << 7) | (next & 0x7f);
		if ((next & 0x80) === 0) {
			values.push(current);
			current = 0;
		}
	}
	return values.join(".");
}

function hasExtensionOid(certificateDer: Uint8Array, oid: string): boolean {
	const top = childrenOf(certificateDer, readElement(certificateDer));
	const tbsCertificate = top[0];
	if (tbsCertificate === undefined) {
		throw new Error("Missing TBSCertificate");
	}
	const tbsChildren = childrenOf(certificateDer, tbsCertificate);
	const extensions = tbsChildren.find((child) => child.tag === 0xa3);
	if (extensions === undefined) {
		return false;
	}
	const extensionSequence = childrenOf(certificateDer, extensions)[0];
	if (extensionSequence === undefined) {
		return false;
	}
	for (const extension of childrenOf(certificateDer, extensionSequence)) {
		const oidElement = childrenOf(certificateDer, extension)[0];
		if (oidElement !== undefined && decodeObjectIdentifier(oidElement.value) === oid) {
			return true;
		}
	}
	return false;
}
