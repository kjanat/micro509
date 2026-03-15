import { describe, expect, it } from 'bun:test';
import { createCertificate, createSelfSignedCertificate, generateKeyPair } from 'micro509';
import * as revocation from 'micro509/revocation';

describe('revocation domain', () => {
	it('creates a CRL with an empty revoked list', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Revocation Domain CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});

		const crl = await revocation.createCertificateRevocationList({
			issuer: { commonName: 'Revocation Domain CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 1,
			revokedCertificates: [],
		});

		expect(crl.pem).toContain('BEGIN X509 CRL');
		expect(crl.der).toBeInstanceOf(Uint8Array);
		expect(crl.der.length).toBeGreaterThan(0);
	});

	it('parses and validates a CRL against the issuing CA', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Revocation Validate CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});

		const crl = await revocation.createCertificateRevocationList({
			issuer: { commonName: 'Revocation Validate CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 2,
		});

		const parsed = revocation.parseCertificateRevocationListPem(crl.pem);
		expect(parsed.issuer.values.commonName).toBe('Revocation Validate CA');
		expect(parsed.revokedCertificates).toHaveLength(0);
		expect(parsed.crlNumber).toBe(2);

		const result = await revocation.validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: ca.certificate.pem,
		});
		expect(result.ok).toBe(true);
	});

	it('creates an OCSP request for a leaf certificate', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'OCSP Domain CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});

		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'OCSP Domain CA' },
			subject: { commonName: 'ocsp-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});

		const ocspReq = await revocation.createOcspRequest({
			requests: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
				},
			],
		});

		expect(ocspReq.der).toBeInstanceOf(Uint8Array);
		expect(ocspReq.der.length).toBeGreaterThan(0);
	});

	it('returns unknown status when no evidence is provided', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'No Evidence CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});

		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'No Evidence CA' },
			subject: { commonName: 'no-evidence.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});

		const result = await revocation.checkCertificateRevocation({
			certificate: leaf.der,
			issuerCertificate: ca.certificate.der,
		});

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.status).toBe('unknown');
		if (result.value.status !== 'unknown') return;
		expect(result.value.code).toBe('revocation_evidence_missing');
		expect(result.value.details.indeterminateEvidence).toHaveLength(0);
	});
});
