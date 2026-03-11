import { X509Certificate } from "node:crypto";
import { describe, expect, it } from "vitest";
import { readElement } from "../src/der.ts";
import {
	categorizePemBlocks,
	createCertificate,
	createCertificateRevocationList,
	createCertificateSigningRequest,
	createPkcs7CertBagPem,
	createSelfSignedCertificate,
	decodeExtension,
	decodeExtensions,
	defineExtensionDecoderMap,
	exportBinaryBase64,
	exportPkcs1Der,
	exportPkcs1Pem,
	exportPkcs8Der,
	exportPkcs8Pem,
	exportPrivateJwk,
	exportPublicJwk,
	exportSec1Der,
	exportSec1Pem,
	exportSpkiDer,
	exportSpkiPem,
	findExtension,
	generateKeyPair,
	importPkcs1Der,
	importPkcs1Pem,
	importPkcs8Base64,
	importPkcs8Pem,
	importPrivateJwk,
	importPublicJwk,
	importSec1Der,
	importSec1Pem,
	importSpkiBase64,
	importSpkiPem,
	isCertificateRevoked,
	parseCertificateChainPem,
	parseCertificatePem,
	parseCertificateRevocationListPem,
	parseCertificateSigningRequestPem,
	parsePkcs7CertBagPem,
	pemDecode,
	splitPemBlocks,
	verifyCertificateChain,
	verifyCertificateRevocationList,
	verifyCertificateSigningRequest,
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
				authorityInfoAccess: [
					{ method: "ocsp", uri: "http://ocsp.example.test" },
					{ method: "caIssuers", uri: "http://issuer.example.test/ca.der" },
				],
				crlDistributionPoints: ["http://issuer.example.test/ca.crl"],
				subjectAltNames: [{ type: "dns", value: "leaf.example" }],
			},
		});

		const leafCertificate = new X509Certificate(leaf.pem);
		expect(leafCertificate.issuer).toContain("CN=Micro509 Test CA");
		expect(leafCertificate.checkHost("leaf.example")).toBe("leaf.example");
		expect(
			await verifyCertificateChain({
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
		expect(parsed.authorityInfoAccess).toEqual([
			{ method: "ocsp", uri: "http://ocsp.example.test" },
			{ method: "caIssuers", uri: "http://issuer.example.test/ca.der" },
		]);
		expect(parsed.crlDistributionPoints).toEqual(["http://issuer.example.test/ca.crl"]);
	});

	it("supports custom extension encode and decode hooks", async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: "custom-ext.example" },
			extensions: {
				customExtensions: [
					{ oid: "1.2.3.4.200", critical: true, value: Uint8Array.of(0x04, 0x03, 0x01, 0x02, 0x03) },
					{ oid: "1.2.3.4.201", value: Uint8Array.of(0x04, 0x01, 0xff) },
				],
			},
		});

		const parsed = parseCertificatePem(certificate.certificate.pem);
		const extension = findExtension(parsed.extensions, "1.2.3.4.200");
		if (extension === undefined) {
			throw new Error("Missing custom extension");
		}
		expect(extension.critical).toBe(true);
		expect(Array.from(extension.valueDer)).toEqual([0x04, 0x03, 0x01, 0x02, 0x03]);
		expect(
			decodeExtension(parsed.extensions, {
				oid: "1.2.3.4.200",
				decode(input) {
					return Array.from(input.valueDer).join(":");
				},
			}),
		).toBe("4:3:1:2:3");
		expect(
			decodeExtensions(parsed.extensions, [
				{
					oid: "1.2.3.4.200",
					decode(input) {
						return input.valueHex;
					},
				},
				{
					oid: "1.2.3.4.201",
					decode(input) {
						return input.critical ? "critical" : "non-critical";
					},
				},
			]),
		).toEqual([
			{ oid: "1.2.3.4.200", critical: true, value: "0403010203" },
			{ oid: "1.2.3.4.201", critical: false, value: "non-critical" },
		]);

		await expect(
			createSelfSignedCertificate({
				subject: { commonName: "dup-ext.example" },
				extensions: {
					keyUsage: ["digitalSignature"],
					customExtensions: [{ oid: OIDS.keyUsage, value: Uint8Array.of(0x05, 0x00) }],
				},
			}),
		).rejects.toThrow("Duplicate extension OID");
	});

	it("runs decoder registries directly during parse", async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: "parse-registry.example" },
			extensions: {
				customExtensions: [
					{ oid: "1.2.3.4.210", value: Uint8Array.of(0x04, 0x02, 0xaa, 0xbb) },
				],
			},
		});

		const parsed = parseCertificatePem(certificate.certificate.pem, {
			decoders: [
				{
					oid: "1.2.3.4.210",
					decode(extension) {
						return extension.valueHex;
					},
				},
			],
		});

		expect(parsed.decodedExtensions).toEqual([
			{ oid: "1.2.3.4.210", critical: false, value: "0402aabb" },
		]);
		const typedParsed = parseCertificatePem(certificate.certificate.pem, {
			decoderMap: defineExtensionDecoderMap({
				customText: {
					oid: "1.2.3.4.210",
					decode: (extension: { readonly valueHex: string }) => extension.valueHex,
				},
			}),
		});
		expect(typedParsed.decodedExtensionMap?.customText).toEqual({
			oid: "1.2.3.4.210",
			critical: false,
			value: "0402aabb",
		});
	});

	it("splits mixed PEM bundles by label", async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: "bundle.example" },
		});
		const csr = await createCertificateSigningRequest({
			subject: { commonName: "bundle.example" },
			publicKey: certificate.keyPair.publicKey,
			signerPrivateKey: certificate.keyPair.privateKey,
		});
		const privateKeyPem = await certificate.keyPair.exportPkcs8Pem();
		const bundle = `${certificate.certificate.pem}\n${csr.pem}\n${privateKeyPem}`;

		expect(splitPemBlocks(bundle).map((block) => block.label)).toEqual([
			"CERTIFICATE",
			"CERTIFICATE REQUEST",
			"PRIVATE KEY",
		]);
		expect(categorizePemBlocks(bundle)).toMatchObject({
			certificates: [{ label: "CERTIFICATE" }],
			certificateRequests: [{ label: "CERTIFICATE REQUEST" }],
			privateKeys: [{ label: "PRIVATE KEY" }],
			publicKeys: [],
			others: [],
		});
	});

	it("roundtrips RSA PKCS#1 and EC SEC1 private keys", async () => {
		const rsa = await generateKeyPair({ kind: "rsa", modulusLength: 2048 });
		const pkcs1Pem = await exportPkcs1Pem(rsa.privateKey);
		const pkcs1Der = await exportPkcs1Der(rsa.privateKey);
		const rsaFromPem = await importPkcs1Pem(pkcs1Pem, { kind: "rsa" });
		const rsaFromDer = await importPkcs1Der(pkcs1Der, { kind: "rsa" });
		expect(await exportPkcs8Der(rsaFromPem)).toEqual(await exportPkcs8Der(rsa.privateKey));
		expect(await exportPkcs8Der(rsaFromDer)).toEqual(await exportPkcs8Der(rsa.privateKey));

		const ec = await generateKeyPair({ kind: "ecdsa", namedCurve: "P-256" });
		const sec1Pem = await exportSec1Pem(ec.privateKey);
		const sec1Der = await exportSec1Der(ec.privateKey);
		const ecFromPem = await importSec1Pem(sec1Pem, { kind: "ecdsa", namedCurve: "P-256" });
		const ecFromDer = await importSec1Der(sec1Der, { kind: "ecdsa", namedCurve: "P-256" });
		expect(await exportPkcs8Der(ecFromPem)).toEqual(await exportPkcs8Der(ec.privateKey));
		expect(await exportPkcs8Der(ecFromDer)).toEqual(await exportPkcs8Der(ec.privateKey));
	});

	it("creates and parses PKCS#7 certificate bags", async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: "PKCS7 Root" },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "PKCS7 Root" },
			subject: { commonName: "pkcs7-leaf.example" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
		});
		const bag = createPkcs7CertBagPem([leaf.pem, root.certificate.pem]);
		const parsed = parsePkcs7CertBagPem(bag.pem);
		expect(parsed.map((certificate) => certificate.subject.values.commonName)).toEqual([
			"pkcs7-leaf.example",
			"PKCS7 Root",
		]);
	});

	it("creates, parses, and verifies CRLs", async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: "CRL Issuer" },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "CRL Issuer" },
			subject: { commonName: "revoked.example" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const parsedLeaf = parseCertificatePem(leaf.pem);
		const crl = await createCertificateRevocationList({
			issuer: { commonName: "CRL Issuer" },
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			crlNumber: 7,
			revokedCertificates: [{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) }],
		});
		const parsedCrl = parseCertificateRevocationListPem(crl.pem);
		expect(parsedCrl.issuer.commonName).toBe("CRL Issuer");
		expect(parsedCrl.crlNumber).toBe(7);
		expect(parsedCrl.revokedCertificates).toHaveLength(1);
		expect(isCertificateRevoked(parsedLeaf.serialNumberHex, parsedCrl)).toBe(true);
		expect(await verifyCertificateRevocationList(crl.pem, issuer.certificate.pem)).toMatchObject({ ok: true });

		const wrongSigner = await generateKeyPair();
		const badCrl = await createCertificateRevocationList({
			issuer: { commonName: "CRL Issuer" },
			signerPrivateKey: wrongSigner.privateKey,
			revokedCertificates: [{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) }],
		});
		expect(await verifyCertificateRevocationList(badCrl.der, issuer.certificate.der)).toMatchObject({
			ok: false,
			code: "signature_invalid",
		});
	});

	it("builds across multiple candidate intermediates", async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: "Path Root" },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const badIntermediateKeys = await generateKeyPair();
		const goodIntermediateKeys = await generateKeyPair();
		const badIntermediate = await createCertificate({
			issuer: { commonName: "Path Root" },
			subject: { commonName: "Shared Intermediate" },
			publicKey: badIntermediateKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ["digitalSignature"],
			},
		});
		const goodIntermediate = await createCertificate({
			issuer: { commonName: "Path Root" },
			subject: { commonName: "Shared Intermediate" },
			publicKey: goodIntermediateKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "Shared Intermediate" },
			subject: { commonName: "multi-path.example" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: goodIntermediateKeys.privateKey,
			issuerPublicKey: goodIntermediateKeys.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				extendedKeyUsage: ["serverAuth"],
				subjectAltNames: [{ type: "dns", value: "multi-path.example" }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			intermediates: [badIntermediate.pem, goodIntermediate.pem],
			roots: [root.certificate.pem],
			purpose: "serverAuth",
			dnsName: "multi-path.example",
		});
		expect(result).toMatchObject({ ok: true });
		if (result.ok) {
			expect(result.value.chain.map((certificate) => certificate.subject.values.commonName)).toEqual([
				"multi-path.example",
				"Shared Intermediate",
				"Path Root",
			]);
		}
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

		const result = await verifyCertificateChain({
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
			await verifyCertificateChain({
				leaf: validChain.leaf.pem,
				intermediates: [validChain.intermediate.pem],
				roots: [],
			}),
		).toMatchObject({
			ok: false,
			code: "issuer_not_found",
			index: 1,
			details: { subjectCommonName: "Verify Intermediate CA" },
		});

		expect(
			await verifyCertificateChain({
				leaf: validChain.leaf.pem,
				intermediates: [validChain.intermediate.pem],
				roots: [validChain.root.certificate.pem],
				purpose: "clientAuth",
			}),
		).toMatchObject({
			ok: false,
			code: "extended_key_usage_invalid",
			index: 0,
			details: { expected: "clientAuth", subjectCommonName: "verify.example" },
		});

		expect(
			await verifyCertificateChain({
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
			await verifyCertificateChain({
				leaf: expiredChain.leaf.pem,
				intermediates: [expiredChain.intermediate.pem],
				roots: [expiredChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: "certificate_expired", index: 0 });

		const nonCaIssuerChain = await issueChain({
			intermediateExtensions: { basicConstraints: { ca: false }, keyUsage: ["digitalSignature"] },
		});
		expect(
			await verifyCertificateChain({
				leaf: nonCaIssuerChain.leaf.pem,
				intermediates: [nonCaIssuerChain.intermediate.pem],
				roots: [nonCaIssuerChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: "ca_required", index: 1 });

		const noKeyCertSignChain = await issueChain({
			intermediateExtensions: { basicConstraints: { ca: true, pathLength: 0 }, keyUsage: ["digitalSignature"] },
		});
		expect(
			await verifyCertificateChain({
				leaf: noKeyCertSignChain.leaf.pem,
				intermediates: [noKeyCertSignChain.intermediate.pem],
				roots: [noKeyCertSignChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: "key_cert_sign_required", index: 1 });

		const pathLengthChain = await issueChain({
			rootExtensions: { basicConstraints: { ca: true, pathLength: 0 }, keyUsage: ["keyCertSign", "cRLSign"] },
		});
		expect(
			await verifyCertificateChain({
				leaf: pathLengthChain.leaf.pem,
				intermediates: [pathLengthChain.intermediate.pem],
				roots: [pathLengthChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: "path_length_exceeded", index: 2 });

		const wrongAkiKeys = await generateKeyPair();
		const akiMismatchChain = await issueChain({ leafIssuerPublicKey: wrongAkiKeys.publicKey });
		expect(
			await verifyCertificateChain({
				leaf: akiMismatchChain.leaf.pem,
				intermediates: [akiMismatchChain.intermediate.pem],
				roots: [akiMismatchChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: "authority_key_identifier_mismatch", index: 0 });

		const wrongSignerKeys = await generateKeyPair();
		const badSignatureChain = await issueChain({ leafSignerPrivateKey: wrongSignerKeys.privateKey });
		expect(
			await verifyCertificateChain({
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
			await verifyCertificateChain({
				leaf: selfSigned.certificate.pem,
				roots: [],
			}),
		).toMatchObject({ ok: false, code: "self_signed_leaf_not_allowed", index: 0 });
		expect(
			await verifyCertificateChain({
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

	it("rejects purpose=ca when leaf is not a CA", async () => {
		const chain = await issueChain();
		expect(
			await verifyCertificateChain({
				leaf: chain.leaf.pem,
				intermediates: [chain.intermediate.pem],
				roots: [chain.root.certificate.pem],
				purpose: "ca",
			}),
		).toMatchObject({ ok: false, code: "ca_required", index: 0 });
	});

	it("verifies IP SAN match and rejects mismatch", async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: "IP CA" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "IP CA" },
			subject: { commonName: "ip-leaf" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [
					{ type: "ip", value: "10.0.0.1" },
					{ type: "ip", value: "::1" },
				],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				ipAddress: "10.0.0.1",
			}),
		).toMatchObject({ ok: true });
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				ipAddress: "10.0.0.2",
			}),
		).toMatchObject({ ok: false, code: "subject_alt_name_mismatch" });
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				ipAddress: "::1",
			}),
		).toMatchObject({ ok: true });
	});

	it("matches wildcard DNS names correctly", async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: "Wildcard CA" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "Wildcard CA" },
			subject: { commonName: "wildcard-leaf" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				extendedKeyUsage: ["serverAuth"],
				subjectAltNames: [{ type: "dns", value: "*.example.com" }],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				purpose: "serverAuth",
				dnsName: "sub.example.com",
			}),
		).toMatchObject({ ok: true });
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				dnsName: "deep.sub.example.com",
			}),
		).toMatchObject({ ok: false, code: "subject_alt_name_mismatch" });
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				dnsName: "example.com",
			}),
		).toMatchObject({ ok: false, code: "subject_alt_name_mismatch" });
	});

	it("allows self-signed leaf when root is trusted", async () => {
		const selfSigned = await createSelfSignedCertificate({
			subject: { commonName: "self.example" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "digitalSignature"],
				subjectAltNames: [{ type: "dns", value: "self.example" }],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: selfSigned.certificate.pem,
				roots: [selfSigned.certificate.pem],
				allowSelfSignedLeaf: true,
				dnsName: "self.example",
			}),
		).toMatchObject({ ok: true });
	});

	it("verifies chain with DER certificate sources", async () => {
		const chain = await issueChain();
		const leafDer = new Uint8Array(
			pemDecode("CERTIFICATE", chain.leaf.pem),
		);
		const intermediateDer = new Uint8Array(
			pemDecode("CERTIFICATE", chain.intermediate.pem),
		);
		const rootDer = new Uint8Array(
			pemDecode("CERTIFICATE", chain.root.certificate.pem),
		);
		expect(
			await verifyCertificateChain({
				leaf: leafDer,
				intermediates: [intermediateDer],
				roots: [rootDer],
			}),
		).toMatchObject({ ok: true });
	});

	it("roundtrips email, URI, and IPv6 SANs through build and parse", async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: "san-variety" },
			extensions: {
				subjectAltNames: [
					{ type: "email", value: "user@example.com" },
					{ type: "uri", value: "https://example.com/path" },
					{ type: "ip", value: "fe80::1" },
				],
			},
		});
		const parsed = parseCertificatePem(certificate.pem);
		expect(parsed.subjectAltNames).toEqual([
			{ type: "email", value: "user@example.com" },
			{ type: "uri", value: "https://example.com/path" },
			{ type: "ip", value: "fe80:0:0:0:0:0:0:1" },
		]);
	});

	it("parses all known EKU types", async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: "EKU CA" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign"],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "EKU CA" },
			subject: { commonName: "eku-leaf" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				extendedKeyUsage: [
					"serverAuth",
					"clientAuth",
					"codeSigning",
					"emailProtection",
					"timeStamping",
					"ocspSigning",
				],
			},
		});
		const parsed = parseCertificatePem(leaf.pem);
		expect(parsed.extendedKeyUsage).toEqual([
			"serverAuth",
			"clientAuth",
			"codeSigning",
			"emailProtection",
			"timeStamping",
			"ocspSigning",
		]);
	});

	it("passes through custom AIA method OIDs", async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: "aia-custom" },
			extensions: {
				authorityInfoAccess: [
					{ method: { type: "oid", value: "1.3.6.1.5.5.7.48.99" }, uri: "http://custom.example/aia" },
				],
			},
		});
		const parsed = parseCertificatePem(certificate.pem);
		expect(parsed.authorityInfoAccess).toEqual([
			{ method: { type: "oid", value: "1.3.6.1.5.5.7.48.99" }, uri: "http://custom.example/aia" },
		]);
	});

	it("includes basicConstraints and customExtensions in CSR requested extensions", async () => {
		const keyPair = await generateKeyPair({ kind: "ed25519" });
		const csr = await createCertificateSigningRequest({
			subject: { commonName: "csr-bc.example" },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 2 },
				customExtensions: [
					{ oid: "1.2.3.4.999", value: Uint8Array.of(0x05, 0x00), critical: true },
				],
			},
		});
		const parsed = parseCertificateSigningRequestPem(csr.pem);
		expect(parsed.basicConstraints).toEqual({ ca: true, pathLength: 2 });
		const custom = findExtension(parsed.requestedExtensions, "1.2.3.4.999");
		expect(custom).toBeDefined();
		expect(custom?.critical).toBe(true);
	});

	it("decodeExtension returns undefined for missing OID", async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: "decode-miss" },
		});
		const parsed = parseCertificatePem(certificate.pem);
		expect(
			decodeExtension(parsed.extensions, {
				oid: "1.2.3.4.999.888",
				decode: () => "should not run",
			}),
		).toBeUndefined();
	});

	it("decodeExtensions skips missing decoders", async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: "decode-skip" },
		});
		const parsed = parseCertificatePem(certificate.pem);
		const result = decodeExtensions(parsed.extensions, [
			{ oid: "1.2.3.4.999.777", decode: () => "never" },
			{ oid: "1.2.3.4.999.888", decode: () => "never" },
		]);
		expect(result).toEqual([]);
	});

	it("rejects notAfter <= notBefore", async () => {
		await expect(
			createSelfSignedCertificate({
				subject: { commonName: "bad-validity" },
				validity: {
					notBefore: new Date("2025-01-02T00:00:00Z"),
					notAfter: new Date("2025-01-01T00:00:00Z"),
				},
			}),
		).rejects.toThrow("notAfter must be after notBefore");
	});

	it("rejects empty subject name", async () => {
		await expect(
			createSelfSignedCertificate({ subject: {} }),
		).rejects.toThrow("Name must contain at least one attribute");
	});

	it("rejects invalid country code length", async () => {
		await expect(
			createSelfSignedCertificate({ subject: { country: "USA" } }),
		).rejects.toThrow("Country must be a 2-character code");
	});

	it("imports and exports keys via ecdsa and ed25519", async () => {
		const ecP384 = await generateKeyPair({ kind: "ecdsa", namedCurve: "P-384" });
		const ecPub = await importSpkiBase64(
			await exportBinaryBase64(ecP384.publicKey),
			{ kind: "ecdsa", namedCurve: "P-384" },
		);
		const ecPriv = await importPkcs8Base64(
			await exportBinaryBase64(ecP384.privateKey),
			{ kind: "ecdsa", namedCurve: "P-384" },
		);
		expect(await exportSpkiDer(ecPub)).toEqual(await ecP384.exportSpkiDer());
		expect(await exportPkcs8Der(ecPriv)).toEqual(await ecP384.exportPkcs8Der());

		const ed = await generateKeyPair({ kind: "ed25519" });
		const edPub = await importSpkiPem(await ed.exportSpkiPem(), { kind: "ed25519" });
		const edPriv = await importPkcs8Pem(await ed.exportPkcs8Pem(), { kind: "ed25519" });
		expect(await exportSpkiDer(edPub)).toEqual(await ed.exportSpkiDer());
		expect(await exportPkcs8Der(edPriv)).toEqual(await ed.exportPkcs8Der());
	});

	it("exports keys with standalone PEM and JWK helpers", async () => {
		const keyPair = await generateKeyPair({ kind: "ed25519" });
		expect(await exportSpkiPem(keyPair.publicKey)).toContain("BEGIN PUBLIC KEY");
		expect(await exportPkcs8Pem(keyPair.privateKey)).toContain("BEGIN PRIVATE KEY");
		expect(await exportPublicJwk(keyPair.publicKey)).toHaveProperty("kty");
		expect(await exportPrivateJwk(keyPair.privateKey)).toHaveProperty("kty");
	});

	it("creates certificates with RSA SHA-384, SHA-512 and ECDSA P-384", async () => {
		const rsaSha384 = await createSelfSignedCertificate({
			subject: { commonName: "rsa384.example" },
			algorithm: { kind: "rsa", modulusLength: 2048, hash: "SHA-384" },
		});
		expect(rsaSha384.certificate.pem).toContain("BEGIN CERTIFICATE");
		const parsed384 = parseCertificatePem(rsaSha384.certificate.pem);
		expect(parsed384.signatureAlgorithmOid).toBe("1.2.840.113549.1.1.12");

		const rsaSha512 = await createSelfSignedCertificate({
			subject: { commonName: "rsa512.example" },
			algorithm: { kind: "rsa", modulusLength: 2048, hash: "SHA-512" },
		});
		const parsed512 = parseCertificatePem(rsaSha512.certificate.pem);
		expect(parsed512.signatureAlgorithmOid).toBe("1.2.840.113549.1.1.13");

		const ecP384 = await createSelfSignedCertificate({
			subject: { commonName: "ecp384.example" },
			algorithm: { kind: "ecdsa", namedCurve: "P-384" },
		});
		const parsedEc384 = parseCertificatePem(ecP384.certificate.pem);
		expect(parsedEc384.signatureAlgorithmOid).toBe("1.2.840.10045.4.3.3");
	});

	it("rejects empty and multi-certificate leaf sources", async () => {
		const chain = await issueChain();
		await expect(
			verifyCertificateChain({
				leaf: "",
				roots: [chain.root.certificate.pem],
			}),
		).rejects.toThrow("No certificate found");

		const mixedLeaf = `${chain.leaf.pem}\n${chain.intermediate.pem}`;
		await expect(
			verifyCertificateChain({
				leaf: mixedLeaf,
				roots: [chain.root.certificate.pem],
			}),
		).rejects.toThrow("Expected a single certificate source");
	});

	it("rejects invalid wildcard and invalid IPv6 verification inputs", async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: "pattern-ca" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "pattern-ca" },
			subject: { commonName: "pattern-leaf" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				subjectAltNames: [{ type: "dns", value: "a*b.example.com" }],
			},
		});

		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				dnsName: "axb.example.com",
			}),
		).toMatchObject({ ok: false, code: "subject_alt_name_mismatch" });

		await expect(
			verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				ipAddress: "2001::db8::1",
			}),
		).rejects.toThrow("Invalid IPv6 address");
	});

	it("verifies chains signed with RSA SHA-384 and ECDSA P-384", async () => {
		const rsaCaKeys = await generateKeyPair({ kind: "rsa", modulusLength: 2048, hash: "SHA-384" });
		const rsaCa = await createSelfSignedCertificate({
			subject: { commonName: "rsa-ca-384" },
			keyPair: rsaCaKeys,
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const rsaLeafKeys = await generateKeyPair({ kind: "rsa", modulusLength: 2048, hash: "SHA-384" });
		const rsaLeaf = await createCertificate({
			issuer: { commonName: "rsa-ca-384" },
			subject: { commonName: "rsa-leaf-384" },
			publicKey: rsaLeafKeys.publicKey,
			signerPrivateKey: rsaCaKeys.privateKey,
			issuerPublicKey: rsaCaKeys.publicKey,
		});

		expect(
			await verifyCertificateChain({
				leaf: rsaLeaf.pem,
				roots: [rsaCa.certificate.pem],
			}),
		).toMatchObject({ ok: true });

		const p384CaKeys = await generateKeyPair({ kind: "ecdsa", namedCurve: "P-384" });
		const p384Ca = await createSelfSignedCertificate({
			subject: { commonName: "p384-ca" },
			keyPair: p384CaKeys,
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const p384LeafKeys = await generateKeyPair({ kind: "ecdsa", namedCurve: "P-384" });
		const p384Leaf = await createCertificate({
			issuer: { commonName: "p384-ca" },
			subject: { commonName: "p384-leaf" },
			publicKey: p384LeafKeys.publicKey,
			signerPrivateKey: p384CaKeys.privateKey,
			issuerPublicKey: p384CaKeys.publicKey,
		});

		expect(
			await verifyCertificateChain({
				leaf: p384Leaf.pem,
				roots: [p384Ca.certificate.pem],
			}),
		).toMatchObject({ ok: true });
	});

	it("verifies certificate request signatures for RSA and Ed25519", async () => {
		const rsaKeys = await generateKeyPair({ kind: "rsa", modulusLength: 2048, hash: "SHA-512" });
		const rsaCsr = await createCertificateSigningRequest({
			subject: { commonName: "rsa-csr" },
			publicKey: rsaKeys.publicKey,
			signerPrivateKey: rsaKeys.privateKey,
		});
		expect(await verifyCertificateSigningRequest(rsaCsr.pem)).toMatchObject({ ok: true });

		const edKeys = await generateKeyPair({ kind: "ed25519" });
		const edCsr = await createCertificateSigningRequest({
			subject: { commonName: "ed-csr" },
			publicKey: edKeys.publicKey,
			signerPrivateKey: edKeys.privateKey,
		});
		expect(await verifyCertificateSigningRequest(edCsr.der)).toMatchObject({ ok: true });
	});

	it("parses all supported name fields", async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: {
				country: "US",
				state: "CA",
				locality: "San Francisco",
				street: "Market St",
				organization: "Acme",
				organizationalUnit: "PKI",
				commonName: "full-name.example",
				givenName: "Jane",
				surname: "Doe",
				title: "Engineer",
				serialNumber: "12345",
				emailAddress: "jane@example.com",
			},
		});
		const parsed = parseCertificatePem(certificate.pem);
		expect(parsed.subject.values).toMatchObject({
			country: "US",
			state: "CA",
			locality: "San Francisco",
			street: "Market St",
			organization: "Acme",
			organizationalUnit: "PKI",
			commonName: "full-name.example",
			givenName: "Jane",
			surname: "Doe",
			title: "Engineer",
			serialNumber: "12345",
			emailAddress: "jane@example.com",
		});
	});

	it("categorizes public and unknown PEM blocks from text and from blocks", async () => {
		const keyPair = await generateKeyPair({ kind: "ed25519" });
		const publicPem = await keyPair.exportSpkiPem();
		const unknownPem = "-----BEGIN SOMETHING-----\nAQID\n-----END SOMETHING-----";
		const bundle = `${publicPem}\n${unknownPem}`;

		expect(categorizePemBlocks(bundle)).toMatchObject({
			publicKeys: [{ label: "PUBLIC KEY" }],
			others: [{ label: "SOMETHING" }],
		});
		expect(categorizePemBlocks(splitPemBlocks(bundle))).toMatchObject({
			publicKeys: [{ label: "PUBLIC KEY" }],
			others: [{ label: "SOMETHING" }],
		});
		expect(() => pemDecode("CERTIFICATE", publicPem)).toThrow("Invalid PEM for CERTIFICATE");
	});

	it("parses CSR without extensionRequest attributes", async () => {
		const keyPair = await generateKeyPair({ kind: "ed25519" });
		const csr = await createCertificateSigningRequest({
			subject: { commonName: "csr-noext.example" },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
		});
		const parsed = parseCertificateSigningRequestPem(csr.pem);
		expect(parsed.requestedExtensions).toEqual([]);
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
				authorityInfoAccess: [{ method: "ocsp", uri: "http://csr.example/ocsp" }],
				crlDistributionPoints: ["http://csr.example/crl"],
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
		expect(parsed.authorityInfoAccess).toEqual([{ method: "ocsp", uri: "http://csr.example/ocsp" }]);
		expect(parsed.crlDistributionPoints).toEqual(["http://csr.example/crl"]);
	});

	it("verifies certificate request signatures with WebCrypto", async () => {
		const goodKeyPair = await generateKeyPair({ kind: "ecdsa", namedCurve: "P-256" });
		const goodCsr = await createCertificateSigningRequest({
			subject: { commonName: "verify-csr.example" },
			publicKey: goodKeyPair.publicKey,
			signerPrivateKey: goodKeyPair.privateKey,
		});
		expect(await verifyCertificateSigningRequest(goodCsr.pem)).toMatchObject({ ok: true });

		const wrongSigner = await generateKeyPair({ kind: "ecdsa", namedCurve: "P-256" });
		const badCsr = await createCertificateSigningRequest({
			subject: { commonName: "bad-csr.example" },
			publicKey: goodKeyPair.publicKey,
			signerPrivateKey: wrongSigner.privateKey,
		});
		expect(await verifyCertificateSigningRequest(badCsr.der)).toMatchObject({
			ok: false,
			code: "signature_invalid",
			details: { subjectCommonName: "bad-csr.example" },
		});
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

function hexToBytes(value: string): Uint8Array {
	const normalized = value.length % 2 === 0 ? value : `0${value}`;
	const bytes: number[] = [];
	for (let index = 0; index < normalized.length; index += 2) {
		bytes.push(Number.parseInt(normalized.slice(index, index + 2), 16));
	}
	return Uint8Array.from(bytes);
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
