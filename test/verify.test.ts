import { sequence, tlv } from "@/der.ts";
import {
	checkExtendedKeyUsage,
	createCertificate,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificateChainPem,
	parseCertificatePem,
	pemDecode,
	trustAnchorFromCertificate,
	verifyCertificateChain,
} from "@/index.ts";
import { parseNameConstraints } from "@/parse.ts";
import { describe, expect, it } from "bun:test";
import { issueChain } from "./helpers.ts";

describe("chain verification", () => {
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
			expect(
				result.value.chain.map(
					(certificate) => certificate.subject.values.commonName,
				),
			).toEqual(["multi-path.example", "Shared Intermediate", "Path Root"]);
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
			intermediateExtensions: {
				basicConstraints: { ca: false },
				keyUsage: ["digitalSignature"],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: nonCaIssuerChain.leaf.pem,
				intermediates: [nonCaIssuerChain.intermediate.pem],
				roots: [nonCaIssuerChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: "ca_required", index: 1 });

		const noKeyCertSignChain = await issueChain({
			intermediateExtensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ["digitalSignature"],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: noKeyCertSignChain.leaf.pem,
				intermediates: [noKeyCertSignChain.intermediate.pem],
				roots: [noKeyCertSignChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: "key_cert_sign_required", index: 1 });

		const pathLengthChain = await issueChain({
			rootExtensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		expect(
			await verifyCertificateChain({
				leaf: pathLengthChain.leaf.pem,
				intermediates: [pathLengthChain.intermediate.pem],
				roots: [pathLengthChain.root.certificate.pem],
			}),
		).toMatchObject({ ok: false, code: "path_length_exceeded", index: 2 });

		const wrongAkiKeys = await generateKeyPair();
		const akiMismatchChain = await issueChain({
			leafIssuerPublicKey: wrongAkiKeys.publicKey,
		});
		expect(
			await verifyCertificateChain({
				leaf: akiMismatchChain.leaf.pem,
				intermediates: [akiMismatchChain.intermediate.pem],
				roots: [akiMismatchChain.root.certificate.pem],
			}),
		).toMatchObject({
			ok: false,
			code: "authority_key_identifier_mismatch",
			index: 0,
		});

		const wrongSignerKeys = await generateKeyPair();
		const badSignatureChain = await issueChain({
			leafSignerPrivateKey: wrongSignerKeys.privateKey,
		});
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
		).toMatchObject({ ok: false, code: "no_trusted_root" });
		expect(
			await verifyCertificateChain({
				leaf: selfSigned.certificate.pem,
				roots: [selfSigned.certificate.pem],
			}),
		).toMatchObject({
			ok: false,
			code: "self_signed_leaf_not_allowed",
			index: 0,
		});
		expect(
			await verifyCertificateChain({
				leaf: selfSigned.certificate.pem,
				roots: [selfSigned.certificate.pem],
				allowSelfSignedLeaf: true,
			}),
		).toMatchObject({ ok: true });
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
		const leafDer = new Uint8Array(pemDecode("CERTIFICATE", chain.leaf.pem));
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
		const rsaCaKeys = await generateKeyPair({
			kind: "rsa",
			modulusLength: 2048,
			hash: "SHA-384",
		});
		const rsaCa = await createSelfSignedCertificate({
			subject: { commonName: "rsa-ca-384" },
			keyPair: rsaCaKeys,
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const rsaLeafKeys = await generateKeyPair({
			kind: "rsa",
			modulusLength: 2048,
			hash: "SHA-384",
		});
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

		const p384CaKeys = await generateKeyPair({
			kind: "ecdsa",
			namedCurve: "P-384",
		});
		const p384Ca = await createSelfSignedCertificate({
			subject: { commonName: "p384-ca" },
			keyPair: p384CaKeys,
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const p384LeafKeys = await generateKeyPair({
			kind: "ecdsa",
			namedCurve: "P-384",
		});
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

	it("verifies an Ed25519 certificate chain", async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: "Ed25519 Root CA" },
			algorithm: { kind: "ed25519" },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const leafKeys = await generateKeyPair({ kind: "ed25519" });
		const leaf = await createCertificate({
			issuer: { commonName: "Ed25519 Root CA" },
			subject: { commonName: "ed25519-leaf.example" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [{ type: "dns", value: "ed25519-leaf.example" }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result).toMatchObject({ ok: true });
	});

	it("rejects chain with unrecognized critical extension", async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: "Critical Ext CA" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign"],
				customExtensions: [
					{
						oid: "1.2.3.4.5.6.7.8.9",
						critical: true,
						value: new Uint8Array([0x05, 0x00]),
					},
				],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "Critical Ext CA" },
			subject: { commonName: "critical.example" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [{ type: "dns", value: "critical.example" }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [ca.certificate.pem],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe("unrecognized_critical_extension");
			expect(result.details?.actual).toBe("1.2.3.4.5.6.7.8.9");
		}
	});

	it("allows chain with non-critical unknown extension", async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: "NonCritical Ext CA" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign"],
				customExtensions: [
					{
						oid: "1.2.3.4.5.6.7.8.9",
						critical: false,
						value: new Uint8Array([0x05, 0x00]),
					},
				],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "NonCritical Ext CA" },
			subject: { commonName: "noncritical.example" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [{ type: "dns", value: "noncritical.example" }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [ca.certificate.pem],
		});
		expect(result.ok).toBe(true);
	});

	it("checks EKU separately from chain validation", async () => {
		const chain = await issueChain();
		const verifyResult = await verifyCertificateChain({
			leaf: chain.leaf.pem,
			intermediates: [chain.intermediate.pem],
			roots: [chain.root.certificate.pem],
		});
		expect(verifyResult.ok).toBe(true);
		if (!verifyResult.ok) return;
		// Leaf has serverAuth EKU
		const serverAuth = checkExtendedKeyUsage(
			verifyResult.value.chain,
			"serverAuth",
		);
		expect(serverAuth.ok).toBe(true);
		// Leaf does not have codeSigning EKU
		const codeSigning = checkExtendedKeyUsage(
			verifyResult.value.chain,
			"codeSigning",
		);
		expect(codeSigning.ok).toBe(false);
		if (!codeSigning.ok) {
			expect(codeSigning.code).toBe("leaf_eku_missing");
		}
	});

	it("validates chain using trust anchors instead of root certificates", async () => {
		const chain = await issueChain();
		const rootParsed = parseCertificatePem(chain.root.certificate.pem);
		const anchor = trustAnchorFromCertificate(rootParsed);
		// Verify with trust anchor (no root cert needed in pool)
		const result = await verifyCertificateChain({
			leaf: chain.leaf.pem,
			intermediates: [chain.intermediate.pem],
			roots: [],
			trustAnchors: [anchor],
		});
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		// Chain terminates at the intermediate (anchor verifies intermediate's signature)
		expect(result.value.root.subject.values.commonName).toBe(
			"Verify Intermediate CA",
		);
		expect(result.value.chain).toHaveLength(2); // leaf + intermediate
	});

	it("rejects chain when trust anchor has wrong key", async () => {
		const chain = await issueChain();
		const otherCa = await createSelfSignedCertificate({
			subject: { commonName: "Verify Root CA" }, // same name, different key
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign"],
			},
		});
		const wrongAnchor = trustAnchorFromCertificate(
			parseCertificatePem(otherCa.certificate.pem),
		);
		const result = await verifyCertificateChain({
			leaf: chain.leaf.pem,
			intermediates: [chain.intermediate.pem],
			roots: [],
			trustAnchors: [wrongAnchor],
		});
		expect(result.ok).toBe(false);
	});

	// -----------------------------------------------------------------------
	// Name constraints
	// -----------------------------------------------------------------------

	it("permits a leaf DNS SAN within CA permitted DNS subtree", async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: "NC Root CA" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: "dns", value: "example.com" } }],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "NC Root CA" },
			subject: { commonName: "allowed.example.com" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [{ type: "dns", value: "allowed.example.com" }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(true);
	});

	it("rejects a leaf DNS SAN outside CA permitted DNS subtree", async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: "NC Root CA" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: "dns", value: "example.com" } }],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "NC Root CA" },
			subject: { commonName: "evil.notexample.com" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [{ type: "dns", value: "evil.notexample.com" }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe("name_constraints_violated");
		}
	});

	it("rejects a leaf DNS SAN matching excluded DNS subtree", async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: "NC Root CA" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
				nameConstraints: {
					excludedSubtrees: [
						{ base: { type: "dns", value: "forbidden.example.com" } },
					],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "NC Root CA" },
			subject: { commonName: "host.forbidden.example.com" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [{ type: "dns", value: "host.forbidden.example.com" }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe("name_constraints_violated");
		}
	});

	it("enforces name constraints from intermediate CA, not just root", async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: "NC Root CA" },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const intermediateKeys = await generateKeyPair();
		const intermediate = await createCertificate({
			issuer: { commonName: "NC Root CA" },
			subject: { commonName: "NC Intermediate CA" },
			publicKey: intermediateKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ["keyCertSign", "cRLSign"],
				nameConstraints: {
					permittedSubtrees: [
						{ base: { type: "dns", value: "narrow.example.com" } },
					],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "NC Intermediate CA" },
			subject: { commonName: "host.narrow.example.com" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [{ type: "dns", value: "host.narrow.example.com" }],
			},
		});
		const okResult = await verifyCertificateChain({
			leaf: leaf.pem,
			intermediates: [intermediate.pem],
			roots: [root.certificate.pem],
		});
		expect(okResult.ok).toBe(true);

		// Same intermediate, but leaf outside the permitted subtree
		const badLeafKeys = await generateKeyPair();
		const badLeaf = await createCertificate({
			issuer: { commonName: "NC Intermediate CA" },
			subject: { commonName: "other.example.com" },
			publicKey: badLeafKeys.publicKey,
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [{ type: "dns", value: "other.example.com" }],
			},
		});
		const failResult = await verifyCertificateChain({
			leaf: badLeaf.pem,
			intermediates: [intermediate.pem],
			roots: [root.certificate.pem],
		});
		expect(failResult.ok).toBe(false);
		if (!failResult.ok) {
			expect(failResult.code).toBe("name_constraints_violated");
		}
	});

	it("permits leaf IP SAN within CA permitted IP subnet", async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: "NC IP Root CA" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
				nameConstraints: {
					permittedSubtrees: [
						{
							base: {
								type: "ip",
								addressBytes: Uint8Array.of(10, 0, 0, 0),
								maskBytes: Uint8Array.of(255, 0, 0, 0),
							},
						},
					],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "NC IP Root CA" },
			subject: { commonName: "ip-leaf" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [{ type: "ip", value: "10.1.2.3" }],
			},
		});
		const okResult = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(okResult.ok).toBe(true);

		// IP outside subnet
		const badKeys = await generateKeyPair();
		const badLeaf = await createCertificate({
			issuer: { commonName: "NC IP Root CA" },
			subject: { commonName: "ip-leaf-bad" },
			publicKey: badKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [{ type: "ip", value: "192.168.1.1" }],
			},
		});
		const failResult = await verifyCertificateChain({
			leaf: badLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(failResult.ok).toBe(false);
		if (!failResult.ok) {
			expect(failResult.code).toBe("name_constraints_violated");
		}
	});

	it("permits email SAN within CA permitted email domain", async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: "NC Email Root CA" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
				nameConstraints: {
					permittedSubtrees: [
						{ base: { type: "email", value: "example.com" } },
					],
				},
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "NC Email Root CA" },
			subject: { commonName: "email-leaf" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [{ type: "email", value: "user@example.com" }],
			},
		});
		const okResult = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [root.certificate.pem],
		});
		expect(okResult.ok).toBe(true);

		// Email outside domain
		const badKeys = await generateKeyPair();
		const badLeaf = await createCertificate({
			issuer: { commonName: "NC Email Root CA" },
			subject: { commonName: "email-leaf-bad" },
			publicKey: badKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [{ type: "email", value: "user@otherdomain.com" }],
			},
		});
		const failResult = await verifyCertificateChain({
			leaf: badLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(failResult.ok).toBe(false);
		if (!failResult.ok) {
			expect(failResult.code).toBe("name_constraints_violated");
		}
	});

	it("parses and round-trips nameConstraints extension", async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: "NC Parse Test CA" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
				nameConstraints: {
					permittedSubtrees: [
						{ base: { type: "dns", value: "example.com" } },
						{ base: { type: "email", value: ".example.org" } },
					],
					excludedSubtrees: [
						{ base: { type: "dns", value: "bad.example.com" } },
					],
				},
			},
		});
		const parsed = parseCertificatePem(root.certificate.pem);
		expect(parsed.nameConstraints).toBeDefined();
		expect(parsed.nameConstraints?.permittedSubtrees).toHaveLength(2);
		expect(parsed.nameConstraints?.excludedSubtrees).toHaveLength(1);
		const permitted = parsed.nameConstraints?.permittedSubtrees;
		expect(permitted?.[0]?.base).toEqual({
			type: "dns",
			value: "example.com",
		});
		expect(permitted?.[1]?.base).toEqual({
			type: "email",
			value: ".example.org",
		});
		const excluded = parsed.nameConstraints?.excludedSubtrees;
		expect(excluded?.[0]?.base).toEqual({
			type: "dns",
			value: "bad.example.com",
		});
	});

	it("does not apply name constraints to self-issued intermediates", async () => {
		// A self-issued certificate should NOT be checked against name
		// constraints, per RFC 5280 §6.1.3(b).
		const root = await createSelfSignedCertificate({
			subject: { commonName: "NC Self-Issued Root" },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ["keyCertSign", "cRLSign"],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: "dns", value: "example.com" } }],
				},
			},
		});
		// Self-issued intermediate: issuer == subject, yet CN is not
		// in the permitted DNS subtree. Should still pass because
		// self-issued certs are exempt from name constraint checking.
		const intermediateKeys = await generateKeyPair();
		const intermediate = await createCertificate({
			issuer: { commonName: "NC Self-Issued Root" },
			subject: { commonName: "NC Self-Issued Root" },
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
			issuer: { commonName: "NC Self-Issued Root" },
			subject: { commonName: "ok.example.com" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [{ type: "dns", value: "ok.example.com" }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			intermediates: [intermediate.pem],
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(true);
	});

	it("applies name constraints to self-issued leaf certificate", async () => {
		// RFC 5280 §4.2.1.10: self-issued certs are exempt UNLESS they
		// are the final (leaf) certificate in the path.
		const root = await createSelfSignedCertificate({
			subject: { commonName: "NC Self-Issued Leaf Root" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: "dns", value: "example.com" } }],
				},
			},
		});
		// Self-issued leaf: issuer == subject, with a DNS SAN outside
		// the permitted subtree. Must be rejected because it's the leaf.
		const leafKeys = await generateKeyPair();
		const selfIssuedLeaf = await createCertificate({
			issuer: { commonName: "NC Self-Issued Leaf Root" },
			subject: { commonName: "NC Self-Issued Leaf Root" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [{ type: "dns", value: "evil.org" }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: selfIssuedLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe("name_constraints_violated");
		}
	});

	it("rejects URI SAN subdomain when constraint has no leading period", async () => {
		// RFC 5280 §4.2.1.10: for URIs, a constraint without a leading
		// period specifies a host (exact match only), not a domain.
		const root = await createSelfSignedCertificate({
			subject: { commonName: "NC URI Exact Root" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: "uri", value: "example.com" } }],
				},
			},
		});
		// Exact match — should pass.
		const okKeys = await generateKeyPair();
		const okLeaf = await createCertificate({
			issuer: { commonName: "NC URI Exact Root" },
			subject: { commonName: "uri-exact-ok" },
			publicKey: okKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [{ type: "uri", value: "https://example.com/path" }],
			},
		});
		const okResult = await verifyCertificateChain({
			leaf: okLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(okResult.ok).toBe(true);

		// Subdomain — should fail (no subdomain expansion for URI).
		const badKeys = await generateKeyPair();
		const badLeaf = await createCertificate({
			issuer: { commonName: "NC URI Exact Root" },
			subject: { commonName: "uri-sub-bad" },
			publicKey: badKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [
					{ type: "uri", value: "https://sub.example.com/path" },
				],
			},
		});
		const badResult = await verifyCertificateChain({
			leaf: badLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(badResult.ok).toBe(false);
		if (!badResult.ok) {
			expect(badResult.code).toBe("name_constraints_violated");
		}
	});

	it("rejects GeneralSubtree with maximum field during parsing", () => {
		// RFC 5280 §4.2.1.10: maximum MUST be absent in this profile.
		// Build nameConstraints extension value DER with maximum present:
		//   SEQUENCE { [0] { SEQUENCE { [2]"example.com", [1]INTEGER 5 } } }
		const dnsName = tlv(0x82, new TextEncoder().encode("example.com"));
		const maximum = tlv(0x81, Uint8Array.of(5));
		const subtree = sequence([dnsName, maximum]);
		const permitted = tlv(0xa0, subtree);
		const ncValue = sequence([permitted]);
		expect(() => parseNameConstraints(ncValue)).toThrow(/maximum/i);
	});

	it("rejects GeneralSubtree with non-zero minimum during parsing", () => {
		// RFC 5280 §4.2.1.10: minimum MUST be zero.
		const dnsName = tlv(0x82, new TextEncoder().encode("example.com"));
		const minimum = tlv(0x80, Uint8Array.of(3)); // minimum = 3 (non-zero)
		const subtree = sequence([dnsName, minimum]);
		const permitted = tlv(0xa0, subtree);
		const ncValue = sequence([permitted]);
		expect(() => parseNameConstraints(ncValue)).toThrow(/minimum/i);
	});

	it("checks subject emailAddress against rfc822Name constraints when no SAN email", async () => {
		// RFC 5280 §4.2.1.10: when constraints are imposed on rfc822Name
		// but the cert has no SAN email, apply to subject emailAddress.
		const root = await createSelfSignedCertificate({
			subject: { commonName: "NC Email DN Root" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
				nameConstraints: {
					permittedSubtrees: [
						{ base: { type: "email", value: "example.com" } },
					],
				},
			},
		});
		// Leaf with emailAddress in subject DN, no SAN email — should pass.
		const okKeys = await generateKeyPair();
		const okLeaf = await createCertificate({
			issuer: { commonName: "NC Email DN Root" },
			subject: { commonName: "email-ok", emailAddress: "user@example.com" },
			publicKey: okKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [{ type: "dns", value: "example.com" }],
			},
		});
		const okResult = await verifyCertificateChain({
			leaf: okLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(okResult.ok).toBe(true);

		// Leaf with emailAddress in subject DN outside permitted domain.
		const badKeys = await generateKeyPair();
		const badLeaf = await createCertificate({
			issuer: { commonName: "NC Email DN Root" },
			subject: { commonName: "email-bad", emailAddress: "user@evil.org" },
			publicKey: badKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [{ type: "dns", value: "example.com" }],
			},
		});
		const badResult = await verifyCertificateChain({
			leaf: badLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(badResult.ok).toBe(false);
		if (!badResult.ok) {
			expect(badResult.code).toBe("name_constraints_violated");
		}
	});

	it("permits URI SAN within CA permitted URI subtree and rejects outside", async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: "NC URI Root CA" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: "uri", value: ".example.com" } }],
				},
			},
		});
		const okKeys = await generateKeyPair();
		const okLeaf = await createCertificate({
			issuer: { commonName: "NC URI Root CA" },
			subject: { commonName: "uri-ok" },
			publicKey: okKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [
					{ type: "uri", value: "https://app.example.com/path" },
				],
			},
		});
		const okResult = await verifyCertificateChain({
			leaf: okLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(okResult.ok).toBe(true);

		const badKeys = await generateKeyPair();
		const badLeaf = await createCertificate({
			issuer: { commonName: "NC URI Root CA" },
			subject: { commonName: "uri-bad" },
			publicKey: badKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				subjectAltNames: [{ type: "uri", value: "https://evil.org/sneaky" }],
			},
		});
		const failResult = await verifyCertificateChain({
			leaf: badLeaf.pem,
			roots: [root.certificate.pem],
		});
		expect(failResult.ok).toBe(false);
		if (!failResult.ok) {
			expect(failResult.code).toBe("name_constraints_violated");
		}
	});
});
