import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createSelfSignedCertificate,
	generateKeyPair,
	matchServiceIdentity,
	parseCertificatePem,
} from 'micro509';

type CreateCertificateInput = Parameters<typeof createCertificate>[0];
type FixtureSubjectAltNames = NonNullable<
	NonNullable<CreateCertificateInput['extensions']>['subjectAltNames']
>;
type FixtureServiceIdentity = Parameters<typeof matchServiceIdentity>[0]['serviceIdentity'];

async function matchIdentityFixture(input: {
	readonly commonName: string;
	readonly subjectAltNames?: FixtureSubjectAltNames;
	readonly serviceIdentity: FixtureServiceIdentity;
}) {
	const issuerCommonName = 'Identity Fixture Root';
	const root = await createSelfSignedCertificate({
		subject: { commonName: issuerCommonName },
		extensions: {
			basicConstraints: { ca: true },
			keyUsage: ['keyCertSign', 'cRLSign'],
		},
	});
	const leafKeys = await generateKeyPair();
	const leaf = await createCertificate({
		issuer: { commonName: issuerCommonName },
		subject: { commonName: input.commonName },
		publicKey: leafKeys.publicKey,
		signerPrivateKey: root.keyPair.privateKey,
		issuerPublicKey: root.keyPair.publicKey,
		extensions:
			input.subjectAltNames === undefined
				? ({ keyUsage: ['digitalSignature'] } satisfies NonNullable<
						CreateCertificateInput['extensions']
					>)
				: ({
						keyUsage: ['digitalSignature'],
						subjectAltNames: input.subjectAltNames,
					} satisfies NonNullable<CreateCertificateInput['extensions']>),
	});
	return matchServiceIdentity({
		certificate: parseCertificatePem(leaf.pem),
		serviceIdentity: input.serviceIdentity,
	});
}

describe('identity fixtures', () => {
	it('covers DNS-ID exact match fixtures', async () => {
		expect(
			await matchIdentityFixture({
				commonName: 'fixture.example',
				subjectAltNames: [{ type: 'dns', value: 'api.example.com' }],
				serviceIdentity: { type: 'dns', value: 'api.example.com' },
			}),
		).toEqual({ ok: true, value: undefined });

		expect(
			await matchIdentityFixture({
				commonName: 'fixture.example',
				subjectAltNames: [{ type: 'dns', value: 'api.example.com' }],
				serviceIdentity: { type: 'dns', value: 'www.example.com' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
	});

	it('covers wildcard DNS-ID fixtures', async () => {
		expect(
			await matchIdentityFixture({
				commonName: 'wildcard.example.com',
				subjectAltNames: [{ type: 'dns', value: '*.example.com' }],
				serviceIdentity: { type: 'dns', value: 'chat.example.com' },
			}),
		).toEqual({ ok: true, value: undefined });

		expect(
			await matchIdentityFixture({
				commonName: 'wildcard.example.com',
				subjectAltNames: [{ type: 'dns', value: '*.example.com' }],
				serviceIdentity: { type: 'dns', value: 'deep.chat.example.com' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
	});

	it('covers IP-ID fixtures', async () => {
		expect(
			await matchIdentityFixture({
				commonName: 'ip-fixture.example',
				subjectAltNames: [{ type: 'ip', value: '2001:db8::1' }],
				serviceIdentity: { type: 'ip', value: '2001:0db8:0:0:0:0:0:1' },
			}),
		).toEqual({ ok: true, value: undefined });

		expect(
			await matchIdentityFixture({
				commonName: 'ip-fixture.example',
				subjectAltNames: [{ type: 'ip', value: '2001:db8::1' }],
				serviceIdentity: { type: 'ip', value: '2001:db8::2' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
	});

	it('covers URI-ID fixtures', async () => {
		expect(
			await matchIdentityFixture({
				commonName: 'uri-fixture.example',
				subjectAltNames: [{ type: 'uri', value: 'https://api.example.com/login' }],
				serviceIdentity: { type: 'uri', value: 'https://api.example.com/admin' },
			}),
		).toEqual({ ok: true, value: undefined });

		expect(
			await matchIdentityFixture({
				commonName: 'uri-fixture.example',
				subjectAltNames: [{ type: 'uri', value: 'https://api.example.com/login' }],
				serviceIdentity: { type: 'uri', value: 'wss://api.example.com/socket' },
			}),
		).toMatchObject({ ok: false, code: 'service_identity_service_mismatch' });
	});

	it('covers SRV-ID fixtures', async () => {
		expect(
			await matchIdentityFixture({
				commonName: 'srv-fixture.example',
				subjectAltNames: [{ type: 'srv', value: '_xmpp-client.im.example.org' }],
				serviceIdentity: { type: 'srv', value: '_XMPP-CLIENT.im.example.org' },
			}),
		).toEqual({ ok: true, value: undefined });

		expect(
			await matchIdentityFixture({
				commonName: 'srv-fixture.example',
				subjectAltNames: [{ type: 'srv', value: '_xmpp-client.im.example.org' }],
				serviceIdentity: { type: 'srv', value: '_xmpp-server.im.example.org' },
			}),
		).toMatchObject({ ok: false, code: 'service_identity_service_mismatch' });
	});

	it('covers IDNA fixtures across DNS-ID, URI-ID, and SRV-ID', async () => {
		expect(
			await matchIdentityFixture({
				commonName: 'idna-dns.example',
				subjectAltNames: [{ type: 'dns', value: '*.xn--bcher-kva.example' }],
				serviceIdentity: { type: 'dns', value: 'shop.bücher.example' },
			}),
		).toEqual({ ok: true, value: undefined });

		expect(
			await matchIdentityFixture({
				commonName: 'idna-uri.example',
				subjectAltNames: [{ type: 'uri', value: 'https://xn--bcher-kva.example/login' }],
				serviceIdentity: { type: 'uri', value: 'https://bücher.example/admin' },
			}),
		).toEqual({ ok: true, value: undefined });

		expect(
			await matchIdentityFixture({
				commonName: 'idna-srv.example',
				subjectAltNames: [{ type: 'srv', value: '_xmpp-client.xn--bcher-kva.example' }],
				serviceIdentity: { type: 'srv', value: '_xmpp-client.bücher.example' },
			}),
		).toEqual({ ok: true, value: undefined });

		expect(
			await matchIdentityFixture({
				commonName: 'idna-dns.example',
				subjectAltNames: [{ type: 'dns', value: '*.xn--bcher-kva.example' }],
				serviceIdentity: { type: 'dns', value: 'shop.example.com' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
	});

	it('covers opt-in CN compatibility fixtures', async () => {
		expect(
			await matchIdentityFixture({
				commonName: 'fallback.example',
				serviceIdentity: {
					type: 'dns',
					value: 'fallback.example',
					allowCommonNameFallback: true,
				},
			}),
		).toEqual({ ok: true, value: undefined });

		expect(
			await matchIdentityFixture({
				commonName: 'fallback.example',
				subjectAltNames: [{ type: 'srv', value: '_xmpp-client.im.example.org' }],
				serviceIdentity: {
					type: 'dns',
					value: 'fallback.example',
					allowCommonNameFallback: true,
				},
			}),
		).toMatchObject({ ok: false, code: 'common_name_fallback_suppressed' });
	});
});
