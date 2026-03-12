import { describe, expect, it } from 'bun:test';
import { matchServiceIdentity, parseCertificatePem } from '#micro509';
import { issueChain } from './helpers.ts';

describe('identity boundary', () => {
	it('matches DNS SANs through the dedicated identity API', async () => {
		const { leaf } = await issueChain();
		const certificate = parseCertificatePem(leaf.pem);

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'dns', value: 'verify.example' },
			}),
		).toEqual({ ok: true });
	});

	it('fails closed for identity types not wired yet', async () => {
		const { leaf } = await issueChain();
		const certificate = parseCertificatePem(leaf.pem);

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'uri', value: 'https://verify.example' },
			}),
		).toMatchObject({ ok: false, code: 'service_identity_type_unsupported' });
	});
});
