import {
	createCertificate,
	createCertificateRevocationList,
	createSelfSignedCertificate,
	generateKeyPair,
	isCertificateRevoked,
	parseCertificatePem,
	parseCertificateRevocationListPem,
	validateCertificateRevocationList,
	verifyCertificateRevocationList,
} from "@/index.ts";
import { describe, expect, it } from "bun:test";
import { hexToBytes } from "./helpers.ts";

describe("crl", () => {
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
			revokedCertificates: [
				{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) },
			],
		});
		const parsedCrl = parseCertificateRevocationListPem(crl.pem);
		expect(parsedCrl.issuer.commonName).toBe("CRL Issuer");
		expect(parsedCrl.crlNumber).toBe(7);
		expect(parsedCrl.revokedCertificates).toHaveLength(1);
		expect(isCertificateRevoked(parsedLeaf.serialNumberHex, parsedCrl)).toBe(
			true,
		);
		expect(
			await verifyCertificateRevocationList(crl.pem, issuer.certificate.pem),
		).toMatchObject({ ok: true });

		const wrongSigner = await generateKeyPair();
		const badCrl = await createCertificateRevocationList({
			issuer: { commonName: "CRL Issuer" },
			signerPrivateKey: wrongSigner.privateKey,
			revokedCertificates: [
				{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) },
			],
		});
		expect(
			await verifyCertificateRevocationList(badCrl.der, issuer.certificate.der),
		).toMatchObject({
			ok: false,
			code: "signature_invalid",
		});
	});

	it("parses CRL entry extensions and delta CRL indicator", async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: "Delta CRL Issuer" },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: "Delta CRL Issuer" },
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			crlNumber: 9,
			baseCrlNumber: 8,
			issuingDistributionPointUri: "http://example.test/idp.crl",
			freshestCrlUris: ["http://example.test/freshest.crl"],
			revokedCertificates: [
				{
					serialNumber: Uint8Array.of(0x01),
					reasonCode: "keyCompromise",
					invalidityDate: new Date("2024-01-01T00:00:00Z"),
				},
			],
		});
		const parsed = parseCertificateRevocationListPem(crl.pem);
		expect(parsed.baseCrlNumber).toBe(8);
		expect(parsed.issuingDistributionPointUri).toBe(
			"http://example.test/idp.crl",
		);
		expect(parsed.freshestCrlUris).toEqual([
			"http://example.test/freshest.crl",
		]);
		expect(parsed.revokedCertificates[0]).toMatchObject({
			serialNumberHex: "01",
			reasonCode: "keyCompromise",
		});
		expect(parsed.revokedCertificates[0]?.invalidityDate?.toISOString()).toBe(
			"2024-01-01T00:00:00.000Z",
		);
	});

	it("validates CRL with issuer linkage and freshness", async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: "CRL Validate CA" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const otherCa = await createSelfSignedCertificate({
			subject: { commonName: "Other CA" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const now = new Date();
		const crl = await createCertificateRevocationList({
			issuer: { commonName: "CRL Validate CA" },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			thisUpdate: now,
			nextUpdate: new Date(now.getTime() + 3_600_000),
		});
		// Valid case
		const valid = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: ca.certificate.pem,
			at: now,
		});
		expect(valid.ok).toBe(true);
		// Wrong issuer
		const wrongIssuer = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: otherCa.certificate.pem,
			at: now,
		});
		expect(wrongIssuer.ok).toBe(false);
		if (!wrongIssuer.ok) {
			expect(wrongIssuer.code).toBe("issuer_mismatch");
		}
		// Stale CRL (well past nextUpdate)
		const stale = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: ca.certificate.pem,
			at: new Date(now.getTime() + 7_200_000),
		});
		expect(stale.ok).toBe(false);
		if (!stale.ok) {
			expect(stale.code).toBe("stale_crl");
		}
		// Barely stale CRL rescued by clock skew tolerance
		// Use 5s margin to avoid ASN.1 second-truncation races
		const staleWithSkew = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: ca.certificate.pem,
			at: new Date(now.getTime() + 3_605_000),
			clockSkewMs: 10_000,
		});
		expect(staleWithSkew.ok).toBe(true);
	});
});
