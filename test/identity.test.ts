import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createSelfSignedCertificate,
	generateKeyPair,
	matchServiceIdentity,
	parseCertificatePem,
	unwrap,
	verifyCertificateChain,
} from '#micro509';
import { concatBytes, ia5String, objectIdentifier, tlv } from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import { issueChain } from '#test/helpers';

describe('identity boundary', () => {
	it('matches DNS SANs through the dedicated identity API', async () => {
		const { leaf } = await issueChain();
		const certificate = unwrap(parseCertificatePem(leaf.pem));

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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

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

	it('ignores tampered malformed IP SANs during identity matching', async () => {
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
		const certificate = unwrap(parseCertificatePem(leaf.pem));
		const tamperedCertificate = {
			...certificate,
			subjectAltNames: [
				{ type: 'ip' as const, value: '1.2.3.999' },
				{ type: 'ip' as const, value: '2001:db8::1' },
			],
		};

		expect(
			matchServiceIdentity({
				certificate: tamperedCertificate,
				serviceIdentity: { type: 'ip', value: '2001:db8::1' },
			}),
		).toEqual({ ok: true, value: undefined });
	});

	it('ignores tampered SAN additions in ParsedCertificate identity matching', async () => {
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
			subject: { commonName: 'different.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
			},
		});
		const certificate = unwrap(parseCertificatePem(leaf.pem));
		const tamperedCertificate = {
			...certificate,
			subjectAltNames: [{ type: 'dns' as const, value: 'forged.example' }],
		};

		expect(
			matchServiceIdentity({
				certificate: tamperedCertificate,
				serviceIdentity: { type: 'dns', value: 'forged.example' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
	});

	it('fails closed for malformed ParsedCertificate DER during identity matching', async () => {
		const { leaf } = await issueChain();
		const certificate = unwrap(parseCertificatePem(leaf.pem));
		expect(
			matchServiceIdentity({
				certificate: { ...certificate, der: Uint8Array.of(0xff, 0xff) },
				serviceIdentity: { type: 'dns', value: 'verify.example' },
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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

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

	it('fails closed for invalid IPv6 identity inputs through the dedicated identity API', async () => {
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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'ip', value: '1:2:3:4:5:6:7:8:9' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

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
		).toMatchObject({ ok: false, code: 'service_identity_mismatch' });
	});

	it('matches SIP URI SANs whose scheme-defined host has no authority delimiter', async () => {
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
			subject: { commonName: 'sip.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth'],
				subjectAltNames: [{ type: 'uri', value: 'sip:user@voice.college.example:5060' }],
			},
		});
		const certificate = unwrap(parseCertificatePem(leaf.pem));

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'uri', value: 'sip:voice.college.example' },
			}),
		).toEqual({ ok: true, value: undefined });
		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'uri', value: 'https:voice.college.example' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'uri', value: 'https://admin.example.com/login' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
	});

	it('rejects URI identities when no URI SAN is present and fails closed on malformed inputs', async () => {
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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'uri', value: 'https://uri-missing.example/login' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'uri', value: 'not a uri' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

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
		).toMatchObject({ ok: false, code: 'service_identity_mismatch' });
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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'srv', value: '_xmpp-client.chat.example.org' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
	});

	it('rejects SRV identities when no SRV SAN is present and fails closed on malformed inputs', async () => {
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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'srv', value: '_xmpp-client.srv-missing.example' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'srv', value: 'xmpp-client.example.org' },
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
	});

	it.each([
		['_imaps.verify.example', '_imaps.verify.example.'],
		['_imaps.verify.example.', '_imaps.verify.example'],
		['_imaps.verify.example.', '_IMAPS.Verify.Example.'],
	])(
		'matches the SRV SAN %s against the reference %s across the root dot',
		async (san, reference) => {
			const { leaf } = await issueChain({ leafSubjectAltNames: [{ type: 'srv', value: san }] });
			const certificate = unwrap(parseCertificatePem(leaf.pem));
			expect(certificate.subjectAltNames).toEqual([{ type: 'srv', value: san }]);
			expect(
				matchServiceIdentity({ certificate, serviceIdentity: { type: 'srv', value: reference } }),
			).toEqual({ ok: true, value: undefined });
		},
	);

	it.each([
		['_imaps.other.example.', 'SRV domain not present in SAN'],
		['_imaps.sub.verify.example.', 'SRV domain not present in SAN'],
		['_pop3.verify.example.', 'SRV service not present in SAN'],
		['_imaps.verify.example..', 'service identity input is malformed'],
		['_imaps..', 'service identity input is malformed'],
		['_imaps.verify..example.', 'service identity input is malformed'],
	])(
		'does not match the dotted SRV SAN against the reference %s: %s',
		async (reference, message) => {
			const { leaf } = await issueChain({
				leafSubjectAltNames: [{ type: 'srv', value: '_imaps.verify.example.' }],
			});
			const certificate = unwrap(parseCertificatePem(leaf.pem));
			const result = matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'srv', value: reference },
			});
			expect(result).toMatchObject({ ok: false, message });
		},
	);

	it.each(['_123.example.com', '_mail.example_com', '_-mail.example.com'])(
		'holds the SRV-ID %s to the SRVName grammar on both sides',
		async (value) => {
			const { certificate } = await createSelfSignedCertificate({
				subject: { commonName: 'srv-grammar.example' },
				extensions: {
					subjectAltNames: [
						{
							type: 'unknown',
							tag: 0xa0,
							value: concatBytes([objectIdentifier(OIDS.idOnDnsSrv), tlv(0xa0, ia5String(value))]),
						},
					],
				},
			});
			const parsed = unwrap(parseCertificatePem(certificate.pem));
			expect(parsed.subjectAltNames).toEqual([{ type: 'srv', value }]);
			expect(
				matchServiceIdentity({ certificate: parsed, serviceIdentity: { type: 'srv', value } }),
			).toMatchObject({ ok: false, message: 'service identity input is malformed' });
		},
	);

	it('fails closed for unsupported direct identity types at runtime', async () => {
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
			subject: { commonName: 'unsupported-type.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'unsupported-type.example' }],
			},
		});
		const certificate = unwrap(parseCertificatePem(leaf.pem));
		const serviceIdentity = { type: 'dns' as const, value: 'unsupported-type.example' };
		Object.defineProperty(serviceIdentity, 'type', { value: 'gopher' });

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity,
			}),
		).toMatchObject({ ok: false, code: 'unsupported_service_identity_type' });
	});

	it('fails closed for malformed identity values with hostile coercion', async () => {
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
			subject: { commonName: 'hostile-value.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'hostile-value.example' }],
			},
		});
		const certificate = unwrap(parseCertificatePem(leaf.pem));
		const hostileValue = {
			[Symbol.toPrimitive](): string {
				throw new Error('should not coerce');
			},
		};
		const serviceIdentity = { type: 'dns' as const, value: 'hostile-value.example' };
		Object.defineProperty(serviceIdentity, 'value', { value: hostileValue });

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity,
			}),
		).toMatchObject({ ok: false, code: 'subject_alt_name_mismatch' });
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
		const certificate = unwrap(parseCertificatePem(leaf.pem));

		expect(
			matchServiceIdentity({
				certificate,
				serviceIdentity: { type: 'srv', value: '_XMPP-CLIENT.bücher.example' },
			}),
		).toEqual({ ok: true, value: undefined });
	});
});

type LeafSubjectAltNames = NonNullable<
	NonNullable<Parameters<typeof createCertificate>[0]['extensions']>['subjectAltNames']
>;
type ServiceIdentity = NonNullable<Parameters<typeof verifyCertificateChain>[0]['serviceIdentity']>;

async function verifyServiceIdentity(
	subjectAltNames: LeafSubjectAltNames,
	serviceIdentity: ServiceIdentity,
): Promise<boolean> {
	const root = await createSelfSignedCertificate({
		subject: { commonName: 'Service Host Root' },
		extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
	});
	const leafKeys = await generateKeyPair();
	const leaf = await createCertificate({
		issuer: { commonName: 'Service Host Root' },
		subject: { commonName: 'service-host-leaf' },
		publicKey: leafKeys.publicKey,
		signerPrivateKey: root.keyPair.privateKey,
		issuerPublicKey: root.keyPair.publicKey,
		extensions: { keyUsage: ['digitalSignature'], subjectAltNames },
	});
	const result = await verifyCertificateChain({
		leaf: leaf.pem,
		roots: [root.certificate.pem],
		serviceIdentity,
	});
	return result.ok;
}

function rawSrvName(value: string): LeafSubjectAltNames[number] {
	return {
		type: 'unknown',
		tag: 0xa0,
		value: concatBytes([objectIdentifier(OIDS.idOnDnsSrv), tlv(0xa0, ia5String(value))]),
	};
}

describe('URI-ID and SRV-ID hosts in a verified chain', () => {
	it.each([
		['ldap://%62locked.example/', 'ldap://blocked.example/', true],
		['https://blocked.example./', 'https://blocked.example/', true],
		['https://blocked.example/', 'https://blocked.example./', true],
		['https://user@Blocked.Example:8443/x', 'https://blocked.example/', true],
		['sip:voice.college.example;transport=tcp', 'sip:voice.college.example', true],
		['https://blocked.example;extra/', 'https://blocked.example/', false],
		['https://blocked.example%3Bextra/', 'https://blocked.example/', false],
		['https://blocked.example;extra/', 'https://blocked.example;extra/', false],
	] as const)(
		'reads presented %s against %s by RFC 3986 §3.2.2',
		async (presented, reference, ok) => {
			expect(
				await verifyServiceIdentity([{ type: 'uri', value: presented }], {
					type: 'uri',
					value: reference,
				}),
			).toBe(ok);
		},
	);

	it.each([
		['https://us%65r:pw@example.com/', 'https://example.com/', true],
		['https://@example.com/', 'https://example.com/', true],
		['https://example.com/', 'https://j\u{f6}rg@example.com/', true],
		['https://bad%zz@example.com/', 'https://example.com/', false],
		['https://bad%@example.com/', 'https://example.com/', false],
		['https://a b@example.com/', 'https://example.com/', false],
		['https://a[b@example.com/', 'https://example.com/', false],
		['https://example.com/', 'https://bad%zz@example.com/', false],
		['https://example.com/', 'https://a\u{200e}b@example.com/', false],
	] as const)(
		'reads the host of %s against %s only after an RFC 3986 §3.2.1 userinfo',
		async (presented, reference, ok) => {
			expect(
				await verifyServiceIdentity([{ type: 'uri', value: presented }], {
					type: 'uri',
					value: reference,
				}),
			).toBe(ok);
		},
	);

	it.each([
		['sip:alice/phone@attacker.example', 'sip:alice/phone@victim.example', false],
		['sip:alice?x@victim.example', 'sip:victim.example', true],
		['sip:alice;day=tuesday@victim.example;transport=tcp?subject=a', 'sip:victim.example', true],
		['sip:%61lice:s%65cret@victim.example', 'sip:victim.example', true],
		['sip:alice:@victim.example', 'sip:victim.example', true],
		['sip:a@b@victim.example', 'sip:victim.example', false],
		['sip:@victim.example', 'sip:victim.example', false],
		['sip::pw@victim.example', 'sip:victim.example', false],
		['sip:bad%zz@victim.example', 'sip:victim.example', false],
		['sip:alice:%zz@victim.example', 'sip:victim.example', false],
		['sip:alice:pw;x@victim.example', 'sip:victim.example', false],
		['sip:al[ice@victim.example', 'sip:victim.example', false],
		['sip:victim.example/path', 'sip:victim.example', false],
	] as const)(
		'reads the host of the SIP URI %s against %s by RFC 3261 §25.1',
		async (presented, reference, ok) => {
			expect(
				await verifyServiceIdentity([{ type: 'uri', value: presented }], {
					type: 'uri',
					value: reference,
				}),
			).toBe(ok);
		},
	);

	it.each([
		['https://[2001:db8::1]/', 'https://[2001:DB8:0::1]:443/', true],
		['https://192.0.2.1/', 'https://192.0.2.1:443/', true],
		['https://192.0.2.1/', 'https://192.0.2.2/', false],
		['https://[2001:db8::1]/', 'https://[2001:db8::2]/', false],
	] as const)(
		'compares the IP host of %s and %s by its octets (RFC 9525 §6.4)',
		async (presented, reference, ok) => {
			expect(
				await verifyServiceIdentity([{ type: 'uri', value: presented }], {
					type: 'uri',
					value: reference,
				}),
			).toBe(ok);
		},
	);

	it.each([
		['https://*.example.com/', 'https://api.example.com/', true],
		['https://*.example.com/', 'https://example.com/', false],
		['https://*.example.com/', 'https://a.b.example.com/', false],
		['https://*.*.example.com/', 'https://a.b.example.com/', false],
		['https://f*o.example.com/', 'https://foo.example.com/', false],
		['https://*.example.com/', 'https://*.example.com/', false],
		['sip:*.example.com', 'sip:voice.example.com', false],
		['sips:*.example.com', 'sips:voice.example.com', false],
	] as const)(
		'matches the URI-ID wildcard %s against %s (RFC 9525 §6.3, RFC 5922 §7.2)',
		async (presented, reference, ok) => {
			expect(
				await verifyServiceIdentity([{ type: 'uri', value: presented }], {
					type: 'uri',
					value: reference,
				}),
			).toBe(ok);
		},
	);

	it.each([
		['_imap.*.example.com', '_imap.mail.example.com', true],
		['_imap.*.example.com', '_imap.example.com', false],
		['_imap.*.example.com', '_imap.a.b.example.com', false],
		['_imap.*.example.com', '_pop3.mail.example.com', false],
		['_imap.m*.example.com', '_imap.mail.example.com', false],
		['_imap.*.example.com', '_imap.*.example.com', false],
	] as const)(
		'matches the SRV-ID wildcard %s against %s (RFC 9525 §6.3)',
		async (presented, reference, ok) => {
			expect(
				await verifyServiceIdentity([rawSrvName(presented)], { type: 'srv', value: reference }),
			).toBe(ok);
		},
	);
});
