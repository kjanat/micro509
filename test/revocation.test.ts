import { describe, expect, it } from 'bun:test';
import {
	checkCertificateRevocation,
	createCertificateRevocationList,
	createOcspResponse,
	parseCertificatePem,
} from '#micro509';
import { hexToBytes, issueChain } from './helpers.ts';

describe('revocation boundary', () => {
	it('returns unknown when no revocation evidence is provided', async () => {
		const { leaf, intermediate } = await issueChain();
		const certificate = parseCertificatePem(leaf.pem);
		const issuerCertificate = parseCertificatePem(intermediate.pem);

		expect(
			await checkCertificateRevocation({
				certificate,
				issuerCertificate,
			}),
		).toEqual({
			ok: false,
			status: 'unknown',
			code: 'revocation_evidence_missing',
			message: 'No CRL or OCSP evidence provided',
			details: {
				checkedSources: [],
				indeterminateEvidence: [],
			},
		});
	});

	it('returns revoked when CRL evidence revokes the certificate', async () => {
		const { leaf, intermediate, intermediateKeys } = await issueChain();
		const certificate = parseCertificatePem(leaf.pem);
		const issuerCertificate = parseCertificatePem(intermediate.pem);
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Verify Intermediate CA' },
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			revokedCertificates: [
				{
					serialNumber: hexToBytes(certificate.serialNumberHex),
					reasonCode: 'keyCompromise',
				},
			],
		});

		expect(
			await checkCertificateRevocation({
				certificate,
				issuerCertificate,
				evidence: [
					{
						kind: 'crl',
						crl: crl.pem,
					},
				],
			}),
		).toMatchObject({
			ok: true,
			status: 'revoked',
			source: 'crl',
			revocationReason: 'keyCompromise',
		});
	});

	it('returns good when OCSP evidence is conclusive and CRL evidence is non-applicable', async () => {
		const { leaf, intermediate, intermediateKeys } = await issueChain();
		const certificate = parseCertificatePem(leaf.pem);
		const issuerCertificate = parseCertificatePem(intermediate.pem);
		const nonApplicableCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Verify Intermediate CA' },
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			issuingDistributionPoint: {
				onlyContainsCACerts: true,
			},
		});
		const ocspResponse = await createOcspResponse({
			signerPrivateKey: intermediateKeys.privateKey,
			signerCertificate: intermediate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: intermediate.pem,
					certStatus: 'good',
				},
			],
		});

		expect(
			await checkCertificateRevocation({
				certificate,
				issuerCertificate,
				evidence: [
					{
						kind: 'crl',
						crl: nonApplicableCrl.pem,
					},
					{
						kind: 'ocsp',
						response: ocspResponse.pem,
					},
				],
			}),
		).toEqual({
			ok: true,
			status: 'good',
			source: 'ocsp',
			message: 'Certificate is not revoked according to OCSP evidence',
		});
	});

	it('returns unknown with indeterminate evidence details when no source is conclusive', async () => {
		const { leaf, intermediate, intermediateKeys } = await issueChain();
		const certificate = parseCertificatePem(leaf.pem);
		const issuerCertificate = parseCertificatePem(intermediate.pem);
		const nonApplicableCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Verify Intermediate CA' },
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			issuingDistributionPoint: {
				onlyContainsCACerts: true,
			},
		});
		const unknownOcspResponse = await createOcspResponse({
			signerPrivateKey: intermediateKeys.privateKey,
			signerCertificate: intermediate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: intermediate.pem,
					certStatus: 'unknown',
				},
			],
		});

		expect(
			await checkCertificateRevocation({
				certificate,
				issuerCertificate,
				evidence: [
					{
						kind: 'crl',
						crl: nonApplicableCrl.pem,
					},
					{
						kind: 'ocsp',
						response: unknownOcspResponse.pem,
					},
				],
			}),
		).toEqual({
			ok: false,
			status: 'unknown',
			code: 'revocation_status_unknown',
			message: 'No revocation evidence established certificate status',
			details: {
				checkedSources: ['crl', 'ocsp'],
				indeterminateEvidence: [
					{
						source: 'crl',
						code: 'non_applicable',
						message: 'CRL only applies to CA certificates',
						reason: 'certificate_scope_mismatch',
					},
					{
						source: 'ocsp',
						code: 'certificate_status_unknown',
						message: 'OCSP responder returned certificate status unknown',
					},
				],
			},
		});
	});
});
