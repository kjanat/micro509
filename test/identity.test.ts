import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createSelfSignedCertificate,
	generateKeyPair,
	matchServiceIdentity,
	parseCertificatePem,
} from '#micro509';
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

	it('matches IP SANs through the dedicated identity API', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Identity CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Identity CA' },
			subject: { commonName: 'identity-ip.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
				subjectAltNames: [{ type: 'ip', value: '2001:db8::1' }],
			},
		});
		const certificate = parseCertificatePem(leaf.pem);

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'ip', value: '2001:0db8:0:0:0:0:0:1' },
			}),
		).toEqual({ ok: true });
	});

	it('allows DNS CN fallback through the dedicated identity API', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Identity CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Identity CA' },
			subject: { commonName: 'fallback.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
			},
		});
		const certificate = parseCertificatePem(leaf.pem);

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: {
					type: 'dns',
					value: 'fallback.example',
					allowCommonNameFallback: true,
				},
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
