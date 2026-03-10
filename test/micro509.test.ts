import { X509Certificate } from "node:crypto";
import { describe, expect, it } from "vitest";
import { readElement } from "../src/der.ts";
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
	parseCertificateChainPem,
	parseCertificatePem,
	parseCertificateSigningRequestPem,
	verifyCertificateChain,
} from "../src/index.ts";
import { OIDS } from "../src/oids.ts";

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
		expect(leafCertificate.issuer).toContain("CN=Micro509 Test CA");
		expect(leafCertificate.checkHost("leaf.example")).toBe("leaf.example");
		expect(
			verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				purpose: "serverAuth",
				dnsName: "leaf.example",
			}),
		).toMatchObject({ ok: true });
		expect(hasExtensionOid(leaf.der, OIDS.extendedKeyUsage)).toBe(true);
		const parsed = parseCertificatePem(leaf.pem);
		expect(parsed.subject.values.commonName).toBe("leaf.example");
		expect(parsed.issuer.values.commonName).toBe("Micro509 Test CA");
		expect(parsed.subjectAltNames).toEqual([{ type: "dns", value: "leaf.example" }]);
		expect(parsed.extendedKeyUsage).toEqual(["serverAuth", { type: "oid", value: "1.2.3.4.5" }]);
	});

	it("parses PEM bundles and verifies a leaf to root chain", async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: "Root CA" },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const intermediateKeys = await generateKeyPair();
		const intermediate = await createCertificate({
			issuer: { commonName: "Root CA" },
			subject: { commonName: "Intermediate CA" },
			publicKey: intermediateKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "Intermediate CA" },
			subject: { commonName: "service.example" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				extendedKeyUsage: ["serverAuth"],
				subjectAltNames: [{ type: "dns", value: "service.example" }],
			},
		});

		const bundle = `${leaf.pem}\n${intermediate.pem}\n${root.certificate.pem}`;
		const parsedBundle = parseCertificateChainPem(bundle);
		expect(parsedBundle).toHaveLength(3);
		expect(parsedBundle[0]?.subject.values.commonName).toBe("service.example");

		const result = verifyCertificateChain({
			leaf: leaf.pem,
			intermediates: [intermediate.pem],
			roots: [root.certificate.pem],
			purpose: "serverAuth",
			dnsName: "service.example",
		});

		expect(result.ok).toBe(true);
		if (!result.ok) {
			throw new Error(result.message);
		}
		expect(result.value.chain).toHaveLength(3);
		expect(result.value.root.subject.values.commonName).toBe("Root CA");
	});

	it("returns structured verification errors", async () => {
		const validChain = await issueChain();

		expect(
			verifyCertificateChain({
				leaf: validChain.leaf.pem,
				intermediates: [validChain.intermediate.pem],
				roots: [],
			}),
		).toMatchObject({ ok: false, code: "issuer_not_found", index: 1 });

		expect(
			verifyCertificateChain({
				leaf: validChain.leaf.pem,
				intermediates: [validChain.intermediate.pem],
				roots: [validChain.root.certificate.pem],
				purpose: "clientAuth",
			}),
		).toMatchObject({ ok: false, code: "extended_key_usage_invalid", index: 0 });

		expect(
			verifyCertificateChain({
				leaf: validChain.leaf.pem,
				intermediates: [validChain.intermediate.pem],
				roots: [validChain.root.certificate.pem],
				purpose: "serverAuth",
				dnsName: "wrong.example",
			}),
		).toMatchObject({ ok: false, code: "subject_alt_name_mismatch", index: 0 });

		const expiredChain = await issueChain({
			leafValidity: {
				notBefore: new Date("2020-01-01T00:00:00Z"),
				notAfter: new Date("2020-01-02T00:00:00Z"),
			},
		});
		expect(
			verifyCertificateChain({
				leaf: expiredChain.leaf.pem,
				intermediates: [expiredChain.intermediate.pem],
				roots: [expiredChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: "certificate_expired", index: 0 });

		const nonCaIssuerChain = await issueChain({
			intermediateExtensions: { basicConstraints: { ca: false }, keyUsage: ["digitalSignature"] },
		});
		expect(
			verifyCertificateChain({
				leaf: nonCaIssuerChain.leaf.pem,
				intermediates: [nonCaIssuerChain.intermediate.pem],
				roots: [nonCaIssuerChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: "ca_required", index: 1 });

		const noKeyCertSignChain = await issueChain({
			intermediateExtensions: { basicConstraints: { ca: true, pathLength: 0 }, keyUsage: ["digitalSignature"] },
		});
		expect(
			verifyCertificateChain({
				leaf: noKeyCertSignChain.leaf.pem,
				intermediates: [noKeyCertSignChain.intermediate.pem],
				roots: [noKeyCertSignChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: "key_cert_sign_required", index: 1 });

		const pathLengthChain = await issueChain({
			rootExtensions: { basicConstraints: { ca: true, pathLength: 0 }, keyUsage: ["keyCertSign", "cRLSign"] },
		});
		expect(
			verifyCertificateChain({
				leaf: pathLengthChain.leaf.pem,
				intermediates: [pathLengthChain.intermediate.pem],
				roots: [pathLengthChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: "path_length_exceeded", index: 2 });

		const wrongAkiKeys = await generateKeyPair();
		const akiMismatchChain = await issueChain({ leafIssuerPublicKey: wrongAkiKeys.publicKey });
		expect(
			verifyCertificateChain({
				leaf: akiMismatchChain.leaf.pem,
				intermediates: [akiMismatchChain.intermediate.pem],
				roots: [akiMismatchChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: "authority_key_identifier_mismatch", index: 0 });

		const wrongSignerKeys = await generateKeyPair();
		const badSignatureChain = await issueChain({ leafSignerPrivateKey: wrongSignerKeys.privateKey });
		expect(
			verifyCertificateChain({
				leaf: badSignatureChain.leaf.pem,
				intermediates: [badSignatureChain.intermediate.pem],
				roots: [badSignatureChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: "signature_invalid", index: 0 });

		const selfSigned = await createSelfSignedCertificate({
			subject: { commonName: "solo.example" },
			extensions: {
				keyUsage: ["digitalSignature"],
				extendedKeyUsage: ["serverAuth"],
				subjectAltNames: [{ type: "dns", value: "solo.example" }],
			},
		});
		expect(
			verifyCertificateChain({
				leaf: selfSigned.certificate.pem,
				roots: [],
			}),
		).toMatchObject({ ok: false, code: "self_signed_leaf_not_allowed", index: 0 });
		expect(
			verifyCertificateChain({
				leaf: selfSigned.certificate.pem,
				roots: [],
				allowSelfSignedLeaf: true,
			}),
		).toMatchObject({ ok: false, code: "no_trusted_root" });
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

interface IssueChainOptions {
	readonly rootExtensions?: {
		readonly basicConstraints: { readonly ca: boolean; readonly pathLength?: number };
		readonly keyUsage: readonly ("keyCertSign" | "cRLSign" | "digitalSignature")[];
	};
	readonly intermediateExtensions?: {
		readonly basicConstraints: { readonly ca: boolean; readonly pathLength?: number };
		readonly keyUsage: readonly ("keyCertSign" | "cRLSign" | "digitalSignature")[];
	};
	readonly leafValidity?: {
		readonly notBefore: Date;
		readonly notAfter: Date;
	};
	readonly leafIssuerPublicKey?: CryptoKey;
	readonly leafSignerPrivateKey?: CryptoKey;
}

async function issueChain(options: IssueChainOptions = {}) {
	const root = await createSelfSignedCertificate({
		subject: { commonName: "Verify Root CA" },
		extensions: options.rootExtensions ?? {
			basicConstraints: { ca: true, pathLength: 1 },
			keyUsage: ["keyCertSign", "cRLSign"],
		},
	});
	const intermediateKeys = await generateKeyPair();
	const intermediate = await createCertificate({
		issuer: { commonName: "Verify Root CA" },
		subject: { commonName: "Verify Intermediate CA" },
		publicKey: intermediateKeys.publicKey,
		signerPrivateKey: root.keyPair.privateKey,
		issuerPublicKey: root.keyPair.publicKey,
		extensions: options.intermediateExtensions ?? {
			basicConstraints: { ca: true, pathLength: 0 },
			keyUsage: ["keyCertSign", "cRLSign"],
		},
	});
	const leafKeys = await generateKeyPair();
	const leafInput = {
		issuer: { commonName: "Verify Intermediate CA" },
		subject: { commonName: "verify.example" },
		publicKey: leafKeys.publicKey,
		signerPrivateKey: options.leafSignerPrivateKey ?? intermediateKeys.privateKey,
		issuerPublicKey: options.leafIssuerPublicKey ?? intermediateKeys.publicKey,
		...(options.leafValidity !== undefined ? { validity: options.leafValidity } : {}),
		extensions: {
			keyUsage: ["digitalSignature"],
			extendedKeyUsage: ["serverAuth"],
			subjectAltNames: [{ type: "dns", value: "verify.example" }],
		},
	} satisfies Parameters<typeof createCertificate>[0];
	const leaf = await createCertificate(leafInput);
	return { root, intermediate, intermediateKeys, leaf, leafKeys };
}
