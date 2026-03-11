import {
	createCertificate,
	createOcspRequest,
	createOcspResponse,
	createSelfSignedCertificate,
	generateKeyPair,
	parseOcspRequestPem,
	parseOcspResponsePem,
	validateOcspResponse,
	verifyOcspResponse,
} from "@/index.ts";
import { describe, expect, it } from "bun:test";

describe("ocsp", () => {
	it("builds, parses, and verifies OCSP responses", async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: "OCSP CA" },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "OCSP CA" },
			subject: { commonName: "ocsp-leaf.example" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const request = await createOcspRequest({
			requests: [
				{ certificate: leaf.pem, issuerCertificate: issuer.certificate.pem },
			],
			nonce: Uint8Array.of(0xaa, 0xbb),
		});
		const parsedRequest = parseOcspRequestPem(request.pem);
		expect(parsedRequest.requests).toHaveLength(1);
		expect(parsedRequest.nonce).toBe("aabb");
		const ocspResponse = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: "good",
					thisUpdate: new Date("2024-01-01T00:00:00Z"),
				},
			],
			nonce: Uint8Array.of(0xaa, 0xbb),
		});
		const parsedResponse = parseOcspResponsePem(ocspResponse.pem);
		expect(parsedResponse.responseStatus).toBe("successful");
		expect(parsedResponse.responses?.[0]).toMatchObject({ certStatus: "good" });
		expect(parsedResponse.nonce).toBe("aabb");
		expect(
			await verifyOcspResponse(ocspResponse.der, issuer.certificate.pem),
		).toMatchObject({ ok: true });
		expect(
			await validateOcspResponse({
				response: ocspResponse.der,
				issuerCertificate: issuer.certificate.pem,
				request: request.pem,
			}),
		).toMatchObject({ ok: true });
		const wrongNonceRequest = await createOcspRequest({
			requests: [
				{ certificate: leaf.pem, issuerCertificate: issuer.certificate.pem },
			],
			nonce: Uint8Array.of(0x00),
		});
		expect(
			await validateOcspResponse({
				response: ocspResponse.der,
				issuerCertificate: issuer.certificate.pem,
				request: wrongNonceRequest.pem,
			}),
		).toMatchObject({ ok: false, code: "nonce_mismatch" });
	});

	it("validates delegated OCSP responder with included certificate", async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: "Delegating CA" },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const responderKeys = await generateKeyPair();
		const responder = await createCertificate({
			issuer: { commonName: "Delegating CA" },
			subject: { commonName: "OCSP Responder" },
			publicKey: responderKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			extensions: {
				keyUsage: ["digitalSignature"],
				extendedKeyUsage: ["ocspSigning"],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "Delegating CA" },
			subject: { commonName: "delegated-ocsp.example" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const request = await createOcspRequest({
			requests: [
				{ certificate: leaf.pem, issuerCertificate: issuer.certificate.pem },
			],
			nonce: Uint8Array.of(0xca, 0xfe),
		});
		const response = await createOcspResponse({
			signerPrivateKey: responderKeys.privateKey,
			signerCertificate: responder.pem,
			includedCertificates: [responder.pem],
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: "good",
				},
			],
			nonce: Uint8Array.of(0xca, 0xfe),
		});
		expect(
			await validateOcspResponse({
				response: response.der,
				issuerCertificate: issuer.certificate.pem,
				request: request.pem,
			}),
		).toMatchObject({ ok: true });
	});

	it("parses OCSP responses with revoked and unknown cert status", async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: "OCSP Status CA" },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "OCSP Status CA" },
			subject: { commonName: "status-leaf.example" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const revokedResponse = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: "revoked",
					revokedAt: new Date("2024-06-15T00:00:00Z"),
					thisUpdate: new Date("2024-07-01T00:00:00Z"),
				},
			],
		});
		const parsedRevoked = parseOcspResponsePem(revokedResponse.pem);
		expect(parsedRevoked.responses?.[0]?.certStatus).toBe("revoked");
		expect(parsedRevoked.responses?.[0]?.revokedAt?.toISOString()).toBe(
			"2024-06-15T00:00:00.000Z",
		);

		const unknownResponse = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: "unknown",
					thisUpdate: new Date("2024-07-01T00:00:00Z"),
				},
			],
		});
		const parsedUnknown = parseOcspResponsePem(unknownResponse.pem);
		expect(parsedUnknown.responses?.[0]?.certStatus).toBe("unknown");
	});

	it("validates OCSP response with clock skew tolerance", async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: "Clock Skew CA" },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ["keyCertSign", "cRLSign"],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: "Clock Skew CA" },
			subject: { commonName: "clock-skew.example" },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: { keyUsage: ["digitalSignature"] },
		});
		const now = new Date();
		const thisUpdate = new Date(now.getTime() + 10_000); // 10s in the future
		const nextUpdate = new Date(now.getTime() + 60_000);
		const response = await createOcspResponse({
			signerPrivateKey: ca.keyPair.privateKey,
			signerCertificate: ca.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: "good",
					thisUpdate,
					nextUpdate,
				},
			],
		});
		// Without skew tolerance, validation fails
		const noSkew = await validateOcspResponse({
			response: response.der,
			issuerCertificate: ca.certificate.pem,
			at: now,
		});
		expect(noSkew.ok).toBe(false);
		if (!noSkew.ok) {
			expect(noSkew.code).toBe("stale_response");
		}
		// With 15s skew tolerance, validation succeeds
		const withSkew = await validateOcspResponse({
			response: response.der,
			issuerCertificate: ca.certificate.pem,
			at: now,
			clockSkewMs: 15_000,
		});
		expect(withSkew.ok).toBe(true);
	});
});
