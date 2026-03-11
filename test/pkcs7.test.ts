import { describe, expect, it } from "vitest";
import {
	createCertificate,
	createPkcs7CertBagPem,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificatePem,
	parsePkcs7CertBagPem,
	parsePkcs7SignedDataDer,
	verifyPkcs7SignedData,
} from "../src/index.ts";
import { OIDS } from "../src/oids.ts";
import { createCmsSignedDataWithSignedAttrs, createSyntheticPkcs7SignedData } from "./helpers.ts";

describe("pkcs7", () => {
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
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error("unreachable");
		expect(
			parsed.value.map((certificate) => certificate.subject.values.commonName),
		).toEqual(["pkcs7-leaf.example", "PKCS7 Root"]);
	});

	it("verifies PKCS#7 signedData with signed attributes (CMS digest-then-sign)", async () => {
		const signer = await createSelfSignedCertificate({
			subject: { commonName: "CMS SignedAttrs Signer" },
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const content = new TextEncoder().encode("Hello CMS signed attributes");
		const signedDataDer = await createCmsSignedDataWithSignedAttrs(
			parsedSigner,
			signer.keyPair.privateKey,
			content,
		);
		const result = await verifyPkcs7SignedData(signedDataDer);
		expect(result.ok).toBe(true);
		if (!result.ok) {
			throw new Error(`Verify failed: ${result.code} — ${result.message}`);
		}
		expect(result.value.signerInfos[0]?.hasSignedAttrs).toBe(true);
		expect(result.value.encapsulatedContent).toEqual(content);
	});

	it("rejects PKCS#7 signedData with tampered content (message digest mismatch)", async () => {
		const signer = await createSelfSignedCertificate({
			subject: { commonName: "CMS Tamper Test" },
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const content = new TextEncoder().encode("Original content");
		const signedDataDer = await createCmsSignedDataWithSignedAttrs(
			parsedSigner,
			signer.keyPair.privateKey,
			content,
		);
		// Tamper: replace encapsulated content bytes in the DER
		const tampered = new Uint8Array(signedDataDer);
		// Find "Original content" and change first byte
		const target = new TextEncoder().encode("Original content");
		for (let i = 0; i < tampered.length - target.length; i++) {
			if (
				tampered[i] === target[0]
				&& tampered.slice(i, i + target.length).every((b, j) => b === target[j])
			) {
				tampered[i] = 0xff;
				break;
			}
		}
		const result = await verifyPkcs7SignedData(tampered);
		expect(result.ok).toBe(false);
		if (result.ok) throw new Error("unreachable");
		expect(result.code).toBe("message_digest_mismatch");
	});

	it("parses generic PKCS#7 signedData signer metadata", async () => {
		const signer = await createSelfSignedCertificate({
			subject: { commonName: "CMS Signer" },
		});
		const parsedSigner = parseCertificatePem(signer.certificate.pem);
		const signedDataDer = createSyntheticPkcs7SignedData(parsedSigner);
		const parsed = parsePkcs7SignedDataDer(signedDataDer);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error("unreachable");
		expect(parsed.value.contentTypeOid).toBe(OIDS.pkcs7SignedData);
		expect(parsed.value.certificates).toHaveLength(1);
		expect(parsed.value.signerInfos[0]).toMatchObject({
			version: 1,
			digestAlgorithmOid: OIDS.sha256,
			signatureAlgorithmOid: OIDS.sha256WithRSAEncryption,
			serialNumberHex: parsedSigner.serialNumberHex,
		});
	});
});
