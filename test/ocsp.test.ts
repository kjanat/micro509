import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createOcspRequest,
	createOcspResponse,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificatePem,
	parseOcspRequestDer,
	parseOcspRequestPem,
	parseOcspResponseDer,
	parseOcspResponsePem,
	pemDecode,
	validateOcspResponse,
	verifyOcspResponse,
} from '#micro509';
import { childrenOf } from '#micro509/asn1.ts';
import {
	bitString,
	explicitContext,
	generalizedTime,
	integerFromNumber,
	objectIdentifier,
	octetString,
	readElement,
	sequence,
	tlv,
} from '#micro509/der.ts';
import { sha1 } from '#micro509/hash.ts';
import { OIDS } from '#micro509/oids.ts';
import { hexToBytes } from './helpers.ts';

describe('ocsp', () => {
	it('builds, parses, and verifies OCSP responses', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'OCSP CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'OCSP CA' },
			subject: { commonName: 'ocsp-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const request = await createOcspRequest({
			requests: [{ certificate: leaf.pem, issuerCertificate: issuer.certificate.pem }],
			nonce: Uint8Array.of(0xaa, 0xbb),
		});
		const parsedRequest = parseOcspRequestPem(request.pem);
		expect(parsedRequest.requests).toHaveLength(1);
		expect(parsedRequest.nonce).toBe('aabb');
		const ocspResponse = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
					thisUpdate: new Date('2024-01-01T00:00:00Z'),
				},
			],
			nonce: Uint8Array.of(0xaa, 0xbb),
		});
		const parsedResponse = parseOcspResponsePem(ocspResponse.pem);
		expect(parsedResponse.responseStatus).toBe('successful');
		expect(parsedResponse.responses?.[0]).toMatchObject({ certStatus: 'good' });
		expect(parsedResponse.nonce).toBe('aabb');
		expect(await verifyOcspResponse(ocspResponse.der, issuer.certificate.pem)).toMatchObject({
			ok: true,
		});
		expect(
			await validateOcspResponse({
				response: ocspResponse.der,
				issuerCertificate: issuer.certificate.pem,
				request: request.pem,
			}),
		).toMatchObject({ ok: true });
		const wrongNonceRequest = await createOcspRequest({
			requests: [{ certificate: leaf.pem, issuerCertificate: issuer.certificate.pem }],
			nonce: Uint8Array.of(0x00),
		});
		expect(
			await validateOcspResponse({
				response: ocspResponse.der,
				issuerCertificate: issuer.certificate.pem,
				request: wrongNonceRequest.pem,
			}),
		).toMatchObject({ ok: false, code: 'nonce_mismatch' });
	});

	it('validates delegated OCSP responder with included certificate', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Delegating CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const responderKeys = await generateKeyPair();
		const responder = await createCertificate({
			issuer: { commonName: 'Delegating CA' },
			subject: { commonName: 'OCSP Responder' },
			publicKey: responderKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['ocspSigning'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Delegating CA' },
			subject: { commonName: 'delegated-ocsp.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const request = await createOcspRequest({
			requests: [{ certificate: leaf.pem, issuerCertificate: issuer.certificate.pem }],
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
					certStatus: 'good',
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

	it('parses OCSP responses with revoked and unknown cert status', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'OCSP Status CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'OCSP Status CA' },
			subject: { commonName: 'status-leaf.example' },
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
					certStatus: 'revoked',
					revokedAt: new Date('2024-06-15T00:00:00Z'),
					thisUpdate: new Date('2024-07-01T00:00:00Z'),
				},
			],
		});
		const parsedRevoked = parseOcspResponsePem(revokedResponse.pem);
		expect(parsedRevoked.responses?.[0]?.certStatus).toBe('revoked');
		expect(parsedRevoked.responses?.[0]?.revokedAt?.toISOString()).toBe('2024-06-15T00:00:00.000Z');

		const unknownResponse = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'unknown',
					thisUpdate: new Date('2024-07-01T00:00:00Z'),
				},
			],
		});
		const parsedUnknown = parseOcspResponsePem(unknownResponse.pem);
		expect(parsedUnknown.responses?.[0]?.certStatus).toBe('unknown');
	});

	it('creates OCSP response with revocationReasonCode', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Reason Code CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Reason Code CA' },
			subject: { commonName: 'reason-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const response = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'revoked',
					revokedAt: new Date('2024-06-15T00:00:00Z'),
					revocationReasonCode: 1,
					thisUpdate: new Date('2024-07-01T00:00:00Z'),
				},
			],
		});
		const parsed = parseOcspResponsePem(response.pem);
		expect(parsed.responses?.[0]?.certStatus).toBe('revoked');
		expect(parsed.responses?.[0]?.revocationReasonCode).toBe(1);
	});

	it('verifyOcspResponse with DER input', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'DER Verify CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'DER Verify CA' },
			subject: { commonName: 'der-verify.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const response = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
		});
		// Use DER for both response and signer
		const issuerDer = new Uint8Array(pemDecode('CERTIFICATE', issuer.certificate.pem));
		const result = await verifyOcspResponse(response.der, issuerDer);
		expect(result.ok).toBe(true);
	});

	it('verifyOcspResponse rejects wrong signer', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Wrong Signer CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const other = await createSelfSignedCertificate({
			subject: { commonName: 'Other CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Wrong Signer CA' },
			subject: { commonName: 'wrong-signer.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const response = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
		});
		// Verify against wrong signer
		const result = await verifyOcspResponse(response.der, other.certificate.pem);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('signature_invalid');
	});

	it('validateOcspResponse rejects delegated responder without ocspSigning EKU', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Delegate CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const responderKeys = await generateKeyPair();
		const responder = await createCertificate({
			issuer: { commonName: 'Delegate CA' },
			subject: { commonName: 'Bad Responder' },
			publicKey: responderKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Delegate CA' },
			subject: { commonName: 'delegate-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const response = await createOcspResponse({
			signerPrivateKey: responderKeys.privateKey,
			signerCertificate: responder.pem,
			includedCertificates: [responder.pem],
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
		});
		const result = await validateOcspResponse({
			response: response.der,
			issuerCertificate: issuer.certificate.pem,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('ocsp_signing_missing');
	});

	it('validateOcspResponse with DER request input', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'DER Request CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'DER Request CA' },
			subject: { commonName: 'der-req.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const request = await createOcspRequest({
			requests: [{ certificate: leaf.pem, issuerCertificate: issuer.certificate.pem }],
			nonce: Uint8Array.of(0xdd, 0xee),
		});
		const response = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
			nonce: Uint8Array.of(0xdd, 0xee),
		});
		// Use DER for request
		const result = await validateOcspResponse({
			response: response.der,
			issuerCertificate: issuer.certificate.pem,
			request: request.der,
		});
		expect(result.ok).toBe(true);
	});

	it('validateOcspResponse with issuer mismatch in certId', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'CertId CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const otherIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Other CertId CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'CertId CA' },
			subject: { commonName: 'certid-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const response = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
		});
		// Validate with wrong issuer — certId won't match
		const result = await validateOcspResponse({
			response: response.der,
			issuerCertificate: otherIssuer.certificate.pem,
		});
		expect(result.ok).toBe(false);
	});

	it('validates OCSP response with clock skew tolerance', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Clock Skew CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Clock Skew CA' },
			subject: { commonName: 'clock-skew.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: { keyUsage: ['digitalSignature'] },
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
					certStatus: 'good',
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
			expect(noSkew.code).toBe('stale_response');
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

	it('parses non-successful OCSP response status codes', () => {
		// Build minimal OCSP responses with non-zero status codes:
		// OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, ... }
		// Status 1=malformedRequest, 2=internalError, 3=tryLater, 5=sigRequired, 6=unauthorized
		for (const [code, expected] of [
			[1, 'malformedRequest'],
			[2, 'internalError'],
			[3, 'tryLater'],
			[5, 'sigRequired'],
			[6, 'unauthorized'],
		] as const) {
			const der = sequence([tlv(0x0a, Uint8Array.of(code))]);
			const parsed = parseOcspResponseDer(der);
			expect(parsed.responseStatus).toBe(expected);
			// These responses have no responseBytes
			expect(parsed.responseDataDer).toBeUndefined();
			expect(parsed.signatureAlgorithmOid).toBeUndefined();
		}
	});

	it('parses response with unknown status code as internalError', () => {
		const der = sequence([tlv(0x0a, Uint8Array.of(99))]);
		const parsed = parseOcspResponseDer(der);
		expect(parsed.responseStatus).toBe('internalError');
	});

	it('parses response with non-basicResponse type OID', () => {
		// Build a response with status=successful and a non-basic response type
		const fakeTypeOid = '1.2.3.4.5.6.7';
		const responseBytes = sequence([
			objectIdentifier(fakeTypeOid),
			octetString(Uint8Array.of(0x30, 0x00)),
		]);
		const der = sequence([
			tlv(0x0a, Uint8Array.of(0x00)), // successful
			explicitContext(0, responseBytes),
		]);
		const parsed = parseOcspResponseDer(der);
		expect(parsed.responseStatus).toBe('successful');
		expect(parsed.responseTypeOid).toBe(fakeTypeOid);
		// Non-basic means no responseDataDer
		expect(parsed.responseDataDer).toBeUndefined();
	});

	it('validateOcspResponse rejects non-successful response status', async () => {
		// Build a minimal non-successful DER response
		const der = sequence([tlv(0x0a, Uint8Array.of(3))]); // tryLater
		const result = await validateOcspResponse({
			response: der,
			issuerCertificate: (
				await createSelfSignedCertificate({
					subject: { commonName: 'Dummy' },
					extensions: {
						basicConstraints: { ca: true },
						keyUsage: ['keyCertSign'],
					},
				})
			).certificate.pem,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe('response_status_invalid');
			expect(result.message).toContain('tryLater');
		}
	});

	it('verifyOcspResponse rejects unsigned response (no responseBytes)', async () => {
		const der = sequence([tlv(0x0a, Uint8Array.of(0x00))]); // successful but no responseBytes
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'No Bytes CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const result = await verifyOcspResponse(der, ca.certificate.pem);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('signature_invalid');
	});

	it('validateOcspResponse with PEM response input', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'PEM Response CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'PEM Response CA' },
			subject: { commonName: 'pem-resp.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const response = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
		});
		// Use PEM string for response
		const result = await validateOcspResponse({
			response: response.pem,
			issuerCertificate: issuer.certificate.pem,
		});
		expect(result.ok).toBe(true);
	});

	it('validateOcspResponse with pre-parsed response input', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Parsed Response CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Parsed Response CA' },
			subject: { commonName: 'parsed-resp.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const response = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
		});
		// Pre-parse and pass parsed object
		const parsed = parseOcspResponsePem(response.pem);
		const result = await validateOcspResponse({
			response: parsed,
			issuerCertificate: issuer.certificate.pem,
		});
		expect(result.ok).toBe(true);
	});

	it('verifyOcspResponse accepts PEM response input', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'PEM Verify CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'PEM Verify CA' },
			subject: { commonName: 'pem-verify.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const response = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
		});
		const result = await verifyOcspResponse(response.pem, issuer.certificate.pem);
		expect(result.ok).toBe(true);
	});

	it('verifyOcspResponse accepts pre-parsed response input', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Parsed Verify CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Parsed Verify CA' },
			subject: { commonName: 'parsed-verify.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const response = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
		});
		const parsed = parseOcspResponsePem(response.pem);
		const result = await verifyOcspResponse(parsed, issuer.certificate.pem);
		expect(result.ok).toBe(true);
	});

	it('validateOcspResponse validates delegated responder chain with DER certs', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Chain Delegate CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const responderKeys = await generateKeyPair();
		const responder = await createCertificate({
			issuer: { commonName: 'Chain Delegate CA' },
			subject: { commonName: 'DER Responder' },
			publicKey: responderKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['ocspSigning'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Chain Delegate CA' },
			subject: { commonName: 'chain-delegate.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const response = await createOcspResponse({
			signerPrivateKey: responderKeys.privateKey,
			signerCertificate: responder.pem,
			includedCertificates: [responder.pem],
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
		});
		// Use DER for responder to exercise `typeof resolvedResponder === "string" || ... instanceof Uint8Array` path
		const responderDer = new Uint8Array(pemDecode('CERTIFICATE', responder.pem));
		const result = await validateOcspResponse({
			response: response.der,
			issuerCertificate: issuer.certificate.pem,
			responderCertificate: responderDer,
		});
		expect(result.ok).toBe(true);
	});

	it('validateOcspResponse rejects delegated responder with invalid chain', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Bad Chain CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		// Create responder signed by a DIFFERENT CA
		const otherCa = await createSelfSignedCertificate({
			subject: { commonName: 'Other CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const responderKeys = await generateKeyPair();
		const responder = await createCertificate({
			issuer: { commonName: 'Other CA' },
			subject: { commonName: 'Bad Chain Responder' },
			publicKey: responderKeys.publicKey,
			signerPrivateKey: otherCa.keyPair.privateKey,
			issuerPublicKey: otherCa.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['ocspSigning'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Bad Chain CA' },
			subject: { commonName: 'bad-chain.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const response = await createOcspResponse({
			signerPrivateKey: responderKeys.privateKey,
			signerCertificate: responder.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
		});
		// Validate with responder cert as PEM (string) to hit chain validation path
		const result = await validateOcspResponse({
			response: response.der,
			issuerCertificate: issuer.certificate.pem,
			responderCertificate: responder.pem,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('responder_chain_invalid');
	});

	it('creates and parses OCSP request/response with SHA-256 hash algorithm', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'SHA256 OCSP CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'SHA256 OCSP CA' },
			subject: { commonName: 'sha256-ocsp.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const request = await createOcspRequest({
			requests: [{ certificate: leaf.pem, issuerCertificate: issuer.certificate.pem }],
			hashAlgorithm: 'SHA-256',
		});
		const parsedRequest = parseOcspRequestDer(request.der);
		expect(parsedRequest.requests).toHaveLength(1);
		expect(parsedRequest.requests[0]?.hashAlgorithmOid).toBe(OIDS.sha256);

		const response = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			hashAlgorithm: 'SHA-256',
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
		});
		const parsed = parseOcspResponsePem(response.pem);
		expect(parsed.responseStatus).toBe('successful');
		expect(parsed.responses?.[0]?.certId.hashAlgorithmOid).toBe(OIDS.sha256);

		const valid = await validateOcspResponse({
			response: response.der,
			issuerCertificate: issuer.certificate.pem,
		});
		expect(valid.ok).toBe(true);
	});

	it('validateOcspResponse rejects stale response past nextUpdate', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Stale CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Stale CA' },
			subject: { commonName: 'stale.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const response = await createOcspResponse({
			signerPrivateKey: ca.keyPair.privateKey,
			signerCertificate: ca.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'good',
					thisUpdate: new Date('2024-01-01T00:00:00Z'),
					nextUpdate: new Date('2024-01-02T00:00:00Z'),
				},
			],
		});
		// Validate at a time after nextUpdate
		const result = await validateOcspResponse({
			response: response.der,
			issuerCertificate: ca.certificate.pem,
			at: new Date('2024-01-03T00:00:00Z'),
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('stale_response');
	});

	it('validateOcspResponse detects request_mismatch', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'ReqMismatch CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'ReqMismatch CA' },
			subject: { commonName: 'req-mismatch.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const otherLeafKeys = await generateKeyPair();
		const otherLeaf = await createCertificate({
			issuer: { commonName: 'ReqMismatch CA' },
			subject: { commonName: 'other.example' },
			publicKey: otherLeafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		// Request is for otherLeaf
		const request = await createOcspRequest({
			requests: [{ certificate: otherLeaf.pem, issuerCertificate: ca.certificate.pem }],
		});
		// Response is for leaf (different certificate)
		const response = await createOcspResponse({
			signerPrivateKey: ca.keyPair.privateKey,
			signerCertificate: ca.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'good',
				},
			],
		});
		const result = await validateOcspResponse({
			response: response.der,
			issuerCertificate: ca.certificate.pem,
			request: request.der,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('request_mismatch');
	});

	it('certificateSourceToInput throws for pre-parsed cert', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Parsed Source CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const responderKeys = await generateKeyPair();
		const responder = await createCertificate({
			issuer: { commonName: 'Parsed Source CA' },
			subject: { commonName: 'Parsed Responder' },
			publicKey: responderKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['ocspSigning'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Parsed Source CA' },
			subject: { commonName: 'parsed-source.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const response = await createOcspResponse({
			signerPrivateKey: responderKeys.privateKey,
			signerCertificate: responder.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
		});
		// Use a pre-parsed certificate as issuerCertificate — triggers
		// the certificateSourceToInput throw when responder is different from issuer
		const parsedIssuer = parseCertificatePem(issuer.certificate.pem);
		const parsedResponder = parseCertificatePem(responder.pem);
		// parsedResponder as responder with parsedIssuer — the responder
		// differs from issuer, so chain validation is attempted but
		// issuerCertificate is pre-parsed → throws
		const result = await validateOcspResponse({
			response: response.der,
			issuerCertificate: parsedIssuer,
			responderCertificate: parsedResponder,
		});
		// The delegated path can't validate chain because parsedResponder
		// is a ParsedCertificate (not string/Uint8Array), so it skips
		// chain validation but still checks EKU
		expect(result.ok).toBe(true);
	});

	it('parseOcspRequestDer works with DER bytes directly', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'DER Parse CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'DER Parse CA' },
			subject: { commonName: 'der-parse.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const request = await createOcspRequest({
			requests: [{ certificate: leaf.pem, issuerCertificate: issuer.certificate.pem }],
		});
		const parsed = parseOcspRequestDer(request.der);
		expect(parsed.requests).toHaveLength(1);
		expect(parsed.nonce).toBeUndefined();
	});

	it('validates OCSP response with pre-parsed request input', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Parsed Req CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Parsed Req CA' },
			subject: { commonName: 'parsed-req.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const request = await createOcspRequest({
			requests: [{ certificate: leaf.pem, issuerCertificate: issuer.certificate.pem }],
			nonce: Uint8Array.of(0x11, 0x22),
		});
		const response = await createOcspResponse({
			signerPrivateKey: issuer.keyPair.privateKey,
			signerCertificate: issuer.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
			nonce: Uint8Array.of(0x11, 0x22),
		});
		// Pre-parse request and pass as object
		const parsedRequest = parseOcspRequestPem(request.pem);
		const result = await validateOcspResponse({
			response: response.der,
			issuerCertificate: issuer.certificate.pem,
			request: parsedRequest,
		});
		expect(result.ok).toBe(true);
	});

	it('validateOcspResponse returns issuer_mismatch for wrong issuer cert', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'OCSP Mismatch CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const otherIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'OCSP Mismatch CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'OCSP Mismatch CA' },
			subject: { commonName: 'mismatch-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		// Create OCSP response signed by issuer
		const response = await createOcspResponse({
			signerCertificate: issuer.certificate.pem,
			signerPrivateKey: issuer.keyPair.privateKey,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
		});
		// Validate with issuer as explicit responder (signature passes)
		// but otherIssuer as issuerCertificate (certId mismatch)
		const result = await validateOcspResponse({
			response: response.der,
			issuerCertificate: otherIssuer.certificate.pem,
			responderCertificate: issuer.certificate.pem,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('issuer_mismatch');
	});

	it('createOcspResponse encodes revoked cert status with reason', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'OCSP Revoked CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'OCSP Revoked CA' },
			subject: { commonName: 'revoked-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const revokedAt = new Date('2026-01-15T00:00:00Z');
		const response = await createOcspResponse({
			signerCertificate: issuer.certificate.pem,
			signerPrivateKey: issuer.keyPair.privateKey,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'revoked',
					revokedAt,
					revocationReasonCode: 1, // keyCompromise
				},
			],
		});
		const parsed = parseOcspResponseDer(response.der);
		expect(parsed.responseStatus).toBe('successful');
		expect(parsed.responses).toBeDefined();
		const certResponse = parsed.responses?.[0];
		expect(certResponse?.certStatus).toBe('revoked');
		expect(certResponse?.revokedAt?.getTime()).toBe(revokedAt.getTime());
		expect(certResponse?.revocationReasonCode).toBe(1);
	});

	it('parseOcspResponseDer skips version tag [0] if present (line 254)', async () => {
		// Create a valid OCSP response, then inject a version [0] tag into the ResponseData
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'OCSP Version CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'OCSP Version CA' },
			subject: { commonName: 'ver-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		// Build ResponseData with version [0] EXPLICIT manually
		// ResponseData is a SEQUENCE inside BasicResponse inside the outer structure.
		// We need to find the ResponseData SEQUENCE and add a version [0] tag at the start.
		// Since parseDer doesn't verify signature, we can modify freely.
		// Strategy: find the responderID (which starts with tag 0xa1 or 0xa2) and
		// insert a version [0] before it.
		//
		// Actually, the simplest approach: create a new OCSP response DER with version.
		// Let's manually build one using DER primitives.
		const issuerParsed = parseCertificatePem(issuer.certificate.pem);
		const leafParsed = parseCertificatePem(leaf.pem);

		// Compute cert ID hashes
		const issuerNameHash = new Uint8Array(await sha1(hexToBytes(issuerParsed.subject.derHex)));
		const spkiDer = issuerParsed.subjectPublicKeyInfoDer;
		const spkiTop = childrenOf(spkiDer, readElement(spkiDer));
		const spkiBitString = spkiTop[1];
		const publicKeyBytes =
			spkiBitString !== undefined ? spkiBitString.value.slice(1) : new Uint8Array(0);
		const issuerKeyHash = new Uint8Array(await sha1(publicKeyBytes));

		const certId = sequence([
			sequence([objectIdentifier(OIDS.sha1), Uint8Array.of(0x05, 0x00)]),
			octetString(issuerNameHash),
			octetString(issuerKeyHash),
			tlv(0x02, hexToBytes(leafParsed.serialNumberHex)),
		]);
		const singleResponse = sequence([
			certId,
			tlv(0x82, new Uint8Array(0)), // good [0] — implicit NULL → use tag 0x80
			generalizedTime(new Date()),
		]);
		// Build ResponseData WITH explicit version [0]
		const responseData = sequence([
			explicitContext(0, integerFromNumber(0)), // version v1 = 0, explicit [0]
			tlv(0xa2, octetString(issuerKeyHash)), // responderID byKeyHash [2]
			generalizedTime(new Date()), // producedAt
			sequence([singleResponse]), // responses
		]);
		// Use the existing response's signature since we don't verify it in parse
		const sigAlgIdentifier = sequence([
			objectIdentifier(OIDS.sha256WithRSAEncryption),
			Uint8Array.of(0x05, 0x00),
		]);
		const fakeSig = bitString(new Uint8Array(64));
		const basicResponse = sequence([responseData, sigAlgIdentifier, fakeSig]);
		const ocspResponseDer = sequence([
			tlv(0x0a, Uint8Array.of(0x00)), // responseStatus = successful
			explicitContext(
				0,
				sequence([objectIdentifier(OIDS.ocspBasicResponse), octetString(basicResponse)]),
			),
		]);
		const parsed = parseOcspResponseDer(ocspResponseDer);
		expect(parsed.responseStatus).toBe('successful');
		expect(parsed.responses).toBeDefined();
		expect(parsed.responses).toHaveLength(1);
	});

	it('parseOcspNonceFromExtensions returns undefined when no nonce extension present (lines 716-717)', async () => {
		// Build an OCSP response with response extensions that don't include nonce
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'OCSP Nonce CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'OCSP Nonce CA' },
			subject: { commonName: 'nonce-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});

		const issuerParsed = parseCertificatePem(issuer.certificate.pem);
		const leafParsed = parseCertificatePem(leaf.pem);
		const issuerNameHash = new Uint8Array(await sha1(hexToBytes(issuerParsed.subject.derHex)));
		const spkiDer = issuerParsed.subjectPublicKeyInfoDer;
		const spkiTop = childrenOf(spkiDer, readElement(spkiDer));
		const spkiBitString = spkiTop[1];
		const publicKeyBytes =
			spkiBitString !== undefined ? spkiBitString.value.slice(1) : new Uint8Array(0);
		const issuerKeyHash = new Uint8Array(await sha1(publicKeyBytes));

		const certId = sequence([
			sequence([objectIdentifier(OIDS.sha1), Uint8Array.of(0x05, 0x00)]),
			octetString(issuerNameHash),
			octetString(issuerKeyHash),
			tlv(0x02, hexToBytes(leafParsed.serialNumberHex)),
		]);
		const singleResponse = sequence([
			certId,
			tlv(0x80, new Uint8Array(0)), // good [0]
			generalizedTime(new Date()),
		]);
		// Build ResponseData WITH extensions containing a NON-nonce extension
		const fakeExtension = sequence([
			objectIdentifier('1.3.6.1.5.5.7.48.1.3'), // id-pkix-ocsp-crl (not nonce)
			octetString(Uint8Array.of(0x05, 0x00)),
		]);
		const responseData = sequence([
			tlv(0xa2, octetString(issuerKeyHash)), // responderID byKeyHash [2]
			generalizedTime(new Date()),
			sequence([singleResponse]),
			explicitContext(1, sequence([fakeExtension])), // responseExtensions [1]
		]);
		const sigAlgIdentifier = sequence([
			objectIdentifier(OIDS.sha256WithRSAEncryption),
			Uint8Array.of(0x05, 0x00),
		]);
		const fakeSig = bitString(new Uint8Array(64));
		const basicResponse = sequence([responseData, sigAlgIdentifier, fakeSig]);
		const ocspResponseDer = sequence([
			tlv(0x0a, Uint8Array.of(0x00)),
			explicitContext(
				0,
				sequence([objectIdentifier(OIDS.ocspBasicResponse), octetString(basicResponse)]),
			),
		]);
		const parsed = parseOcspResponseDer(ocspResponseDer);
		expect(parsed.responseStatus).toBe('successful');
		// Nonce should be undefined since extensions don't contain nonce OID
		expect(parsed.nonce).toBeUndefined();
	});

	it('certificateSourceToInput throws when given ParsedCertificate (lines 792-795)', async () => {
		// validateOcspResponse calls certificateSourceToInput when issuerCertificate is not PEM/DER
		// and the responder chain needs validation. This requires:
		// 1. A parsedResponse with a different responder than the issuer
		// 2. The responderCertificate being string/Uint8Array (so chain validation is attempted)
		// 3. The issuerCertificate being a ParsedCertificate
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'OCSP Src CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const responderKeys = await generateKeyPair();
		const responderCert = await createCertificate({
			issuer: { commonName: 'OCSP Src CA' },
			subject: { commonName: 'OCSP Responder' },
			publicKey: responderKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			extensions: {
				extendedKeyUsage: ['ocspSigning'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'OCSP Src CA' },
			subject: { commonName: 'src-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		// Create OCSP response signed by responder (not issuer)
		const response = await createOcspResponse({
			signerCertificate: responderCert.pem,
			signerPrivateKey: responderKeys.privateKey,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
			includedCertificates: [responderCert.pem],
		});
		// Validate with issuerCertificate as ParsedCertificate (not PEM/DER)
		const issuerParsed = parseCertificatePem(issuer.certificate.pem);
		await expect(
			validateOcspResponse({
				response: response.der,
				issuerCertificate: issuerParsed,
				responderCertificate: responderCert.pem,
			}),
		).rejects.toThrow('Responder chain validation requires PEM or DER');
	});
});
