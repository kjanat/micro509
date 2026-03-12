import { describe, expect, it } from 'bun:test';
import { checkCertificateRevocation, parseCertificatePem } from '#micro509';
import { issueChain } from './helpers.ts';

describe('revocation boundary', () => {
	it('returns unknown when no revocation evidence is provided', async () => {
		const { leaf, intermediate } = await issueChain();
		const certificate = parseCertificatePem(leaf.pem);
		const issuerCertificate = parseCertificatePem(intermediate.pem);

		expect(
			checkCertificateRevocation({
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
			},
		});
	});
});
