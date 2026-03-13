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
		).toEqual({ ok: true, value: undefined });
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
		).toEqual({ ok: true, value: undefined });
		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'ip', value: '2001:db8::2' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
	});

	it('matches wildcard DNS SANs through the dedicated identity API', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Wildcard Identity CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Wildcard Identity CA' },
			subject: { commonName: 'wildcard.example.com' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
				subjectAltNames: [{ type: 'dns', value: '*.example.com' }],
			},
		});
		const certificate = parseCertificatePem(leaf.pem);

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'dns', value: 'api.example.com' },
			}),
		).toEqual({ ok: true, value: undefined });
		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'dns', value: 'deep.api.example.com' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'dns', value: 'example.com' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
	});

	it('matches IDNA DNS SANs across A-label and U-label forms', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'IDNA Identity CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'IDNA Identity CA' },
			subject: { commonName: 'idna.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
				subjectAltNames: [{ type: 'dns', value: '*.xn--bcher-kva.example' }],
			},
		});
		const certificate = parseCertificatePem(leaf.pem);

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'dns', value: 'SHOP.XN--BCHER-KVA.EXAMPLE' },
			}),
		).toEqual({ ok: true, value: undefined });
		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'dns', value: 'shop.bücher.example' },
			}),
		).toEqual({ ok: true, value: undefined });
	});

	it('rejects invalid wildcard SAN patterns through the dedicated identity API', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Pattern Identity CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Pattern Identity CA' },
			subject: { commonName: 'pattern.example.com' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				subjectAltNames: [{ type: 'dns', value: 'a*b.example.com' }],
			},
		});
		const certificate = parseCertificatePem(leaf.pem);

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'dns', value: 'axb.example.com' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
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
		).toEqual({ ok: true, value: undefined });
	});

	it('suppresses DNS CN fallback when a DNS SAN is present', async () => {
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
				subjectAltNames: [{ type: 'dns', value: 'other.example' }],
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
		).toMatchObject({
			ok: false,
			code: 'common_name_fallback_suppressed',
			details: {
				commonNameFallbackReason: 'suppressed_by_presented_identifier',
				presentedIdentifierTypes: ['dns'],
			},
		});
	});

	it('suppresses DNS CN fallback when a URI SAN is present', async () => {
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
				subjectAltNames: [{ type: 'uri', value: 'https://api.example.com/login' }],
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
		).toMatchObject({
			ok: false,
			code: 'common_name_fallback_suppressed',
			details: {
				commonNameFallbackReason: 'suppressed_by_presented_identifier',
				presentedIdentifierTypes: ['uri'],
			},
		});
	});

	it('suppresses DNS CN fallback when an SRV SAN is present', async () => {
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
				subjectAltNames: [{ type: 'srv', value: '_xmpp-client.im.example.org' }],
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
		).toMatchObject({
			ok: false,
			code: 'common_name_fallback_suppressed',
			details: {
				commonNameFallbackReason: 'suppressed_by_presented_identifier',
				presentedIdentifierTypes: ['srv'],
			},
		});
	});

	it('still allows DNS CN fallback when only IP SANs are present', async () => {
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
				subjectAltNames: [{ type: 'ip', value: '10.0.0.1' }],
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
		).toEqual({ ok: true, value: undefined });
	});

	it('rejects DNS CN fallback when disabled or mismatched', async () => {
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
			subject: { commonName: 'other.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
			},
		});
		const certificate = parseCertificatePem(leaf.pem);

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'dns', value: 'other.example' },
			}),
		).toMatchObject({
			ok: false,
			code: 'subject_alt_name_mismatch',
			details: { commonNameFallbackReason: 'disabled' },
		});
		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: {
					type: 'dns',
					value: 'fallback.example',
					allowCommonNameFallback: true,
				},
			}),
		).toMatchObject({
			ok: false,
			code: 'subject_alt_name_mismatch',
			details: { commonNameFallbackReason: 'common_name_mismatch' },
		});
	});

	it('throws for invalid IPv6 identity inputs through the dedicated identity API', async () => {
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
			subject: { commonName: 'ipv6.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				subjectAltNames: [{ type: 'ip', value: '::1' }],
			},
		});
		const certificate = parseCertificatePem(leaf.pem);

		expect(() =>
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'ip', value: '1:2:3:4:5:6:7:8:9' },
			}),
		).toThrow('Invalid IPv6');
	});

	it('matches URI SANs by scheme and host through the dedicated identity API', async () => {
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
			subject: { commonName: 'uri.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
				subjectAltNames: [{ type: 'uri', value: 'https://api.example.com/admin' }],
			},
		});
		const certificate = parseCertificatePem(leaf.pem);

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'uri', value: 'https://api.example.com/login' },
			}),
		).toEqual({ ok: true, value: undefined });
		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'uri', value: 'wss://api.example.com/socket' },
			}),
		).toMatchObject({ ok: false, code: 'service_identity_service_mismatch' });
	});

	it('rejects URI SANs with matching scheme but different host', async () => {
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
			subject: { commonName: 'uri-host.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
				subjectAltNames: [{ type: 'uri', value: 'https://api.example.com/admin' }],
			},
		});
		const certificate = parseCertificatePem(leaf.pem);

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'uri', value: 'https://admin.example.com/login' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
	});

	it('rejects URI identities when no URI SAN is present and throws on malformed inputs', async () => {
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
			subject: { commonName: 'uri-missing.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
				subjectAltNames: [{ type: 'dns', value: 'uri-missing.example' }],
			},
		});
		const certificate = parseCertificatePem(leaf.pem);

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'uri', value: 'https://uri-missing.example/login' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
		expect(() =>
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'uri', value: 'not a uri' },
			}),
		).toThrow('Invalid URI service identity');
	});

	it('matches URI SANs across IDNA host forms', async () => {
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
			subject: { commonName: 'uri-idna.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
				subjectAltNames: [{ type: 'uri', value: 'HTTPS://xn--bcher-kva.example/admin' }],
			},
		});
		const certificate = parseCertificatePem(leaf.pem);

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'uri', value: 'https://bücher.example/login' },
			}),
		).toEqual({ ok: true, value: undefined });
	});

	it('matches SRV SANs by service and domain through the dedicated identity API', async () => {
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
			subject: { commonName: 'srv.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
				subjectAltNames: [{ type: 'srv', value: '_xmpp-client.im.example.org' }],
			},
		});
		const certificate = parseCertificatePem(leaf.pem);

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'srv', value: '_XMPP-CLIENT.im.example.org' },
			}),
		).toEqual({ ok: true, value: undefined });
		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'srv', value: '_xmpp-server.im.example.org' },
			}),
		).toMatchObject({ ok: false, code: 'service_identity_service_mismatch' });
	});

	it('rejects SRV SANs with matching service but different domain', async () => {
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
			subject: { commonName: 'srv-domain.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
				subjectAltNames: [{ type: 'srv', value: '_xmpp-client.im.example.org' }],
			},
		});
		const certificate = parseCertificatePem(leaf.pem);

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'srv', value: '_xmpp-client.chat.example.org' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
	});

	it('rejects SRV identities when no SRV SAN is present and throws on malformed inputs', async () => {
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
			subject: { commonName: 'srv-missing.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
				subjectAltNames: [{ type: 'dns', value: 'srv-missing.example' }],
			},
		});
		const certificate = parseCertificatePem(leaf.pem);

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'srv', value: '_xmpp-client.srv-missing.example' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
		expect(() =>
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'srv', value: 'xmpp-client.example.org' },
			}),
		).toThrow('Invalid SRV service identity');
	});

	it('matches SRV SANs across IDNA host forms', async () => {
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
			subject: { commonName: 'srv-idna.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
				subjectAltNames: [{ type: 'srv', value: '_xmpp-client.xn--bcher-kva.example' }],
			},
		});
		const certificate = parseCertificatePem(leaf.pem);

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'srv', value: '_XMPP-CLIENT.bücher.example' },
			}),
		).toEqual({ ok: true, value: undefined });
	});
});
