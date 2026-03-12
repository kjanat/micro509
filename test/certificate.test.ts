import { describe, expect, it } from 'bun:test';
import { X509Certificate } from 'node:crypto';
import {
	createCertificate,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificatePem,
	verifyCertificateChain,
} from '#micro509';
import { OIDS } from '#micro509/oids.ts';
import { hasExtensionOid } from './helpers.ts';

describe('certificate', () => {
	it('creates a self-signed certificate with SANs and exportable keys', async () => {
		const result = await createSelfSignedCertificate({
			subject: {
				commonName: 'example.com',
				organization: 'Acme',
				country: 'US',
			},
			validity: { days: 14 },
			extensions: {
				keyUsage: ['digitalSignature', 'keyEncipherment'],
				subjectAltNames: [
					{ type: 'dns', value: 'example.com' },
					{ type: 'ip', value: '127.0.0.1' },
				],
			},
		});

		const certificate = new X509Certificate(result.certificate.pem);
		expect(result.certificate.pem).toContain('BEGIN CERTIFICATE');
		expect(result.certificate.der.byteLength).toBeGreaterThan(0);
		expect(certificate.subject).toContain('CN=example.com');
		expect(certificate.issuer).toContain('CN=example.com');
		expect(certificate.checkHost('example.com')).toBe('example.com');
		expect(certificate.checkIP('127.0.0.1')).toBe('127.0.0.1');
		expect(await result.keyPair.exportPkcs8Pem()).toContain('BEGIN PRIVATE KEY');
		expect(await result.keyPair.exportSpkiPem()).toContain('BEGIN PUBLIC KEY');
		expect(await result.keyPair.exportPublicJwk()).toHaveProperty('kty');
	});

	it('creates a leaf certificate signed by a CA', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Micro509 Test CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Micro509 Test CA' },
			subject: { commonName: 'leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth', { type: 'oid', value: '1.2.3.4.5' }],
				authorityInfoAccess: [
					{ method: 'ocsp', uri: 'http://ocsp.example.test' },
					{ method: 'caIssuers', uri: 'http://issuer.example.test/ca.der' },
				],
				crlDistributionPoints: ['http://issuer.example.test/ca.crl'],
				subjectAltNames: [{ type: 'dns', value: 'leaf.example' }],
			},
		});

		const leafCertificate = new X509Certificate(leaf.pem);
		expect(leafCertificate.issuer).toContain('CN=Micro509 Test CA');
		expect(leafCertificate.checkHost('leaf.example')).toBe('leaf.example');
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				purpose: 'serverAuth',
				serviceIdentity: { type: 'dns', value: 'leaf.example' },
			}),
		).toMatchObject({ ok: true });
		expect(hasExtensionOid(leaf.der, OIDS.extendedKeyUsage)).toBe(true);
		const parsed = parseCertificatePem(leaf.pem);
		expect(parsed.subject.values.commonName).toBe('leaf.example');
		expect(parsed.issuer.values.commonName).toBe('Micro509 Test CA');
		expect(parsed.subjectAltNames).toEqual([{ type: 'dns', value: 'leaf.example' }]);
		expect(parsed.extendedKeyUsage).toEqual(['serverAuth', { type: 'oid', value: '1.2.3.4.5' }]);
		expect(parsed.authorityInfoAccess).toEqual([
			{ method: 'ocsp', uri: 'http://ocsp.example.test' },
			{ method: 'caIssuers', uri: 'http://issuer.example.test/ca.der' },
		]);
		expect(parsed.crlDistributionPoints).toEqual(['http://issuer.example.test/ca.crl']);
	});

	it('roundtrips email, URI, and IPv6 SANs through build and parse', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: 'san-variety' },
			extensions: {
				subjectAltNames: [
					{ type: 'email', value: 'user@example.com' },
					{ type: 'uri', value: 'https://example.com/path' },
					{ type: 'ip', value: 'fe80::1' },
				],
			},
		});
		const parsed = parseCertificatePem(certificate.pem);
		expect(parsed.subjectAltNames).toEqual([
			{ type: 'email', value: 'user@example.com' },
			{ type: 'uri', value: 'https://example.com/path' },
			{ type: 'ip', value: 'fe80:0:0:0:0:0:0:1' },
		]);
	});

	it('passes through custom AIA method OIDs', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: 'aia-custom' },
			extensions: {
				authorityInfoAccess: [
					{
						method: { type: 'oid', value: '1.3.6.1.5.5.7.48.99' },
						uri: 'http://custom.example/aia',
					},
				],
			},
		});
		const parsed = parseCertificatePem(certificate.pem);
		expect(parsed.authorityInfoAccess).toEqual([
			{
				method: { type: 'oid', value: '1.3.6.1.5.5.7.48.99' },
				uri: 'http://custom.example/aia',
			},
		]);
	});

	it('rejects notAfter <= notBefore', async () => {
		expect(
			createSelfSignedCertificate({
				subject: { commonName: 'bad-validity' },
				validity: {
					notBefore: new Date('2025-01-02T00:00:00Z'),
					notAfter: new Date('2025-01-01T00:00:00Z'),
				},
			}),
		).rejects.toThrow('notAfter must be after notBefore');
	});

	it('rejects empty subject name', async () => {
		expect(createSelfSignedCertificate({ subject: {} })).rejects.toThrow(
			'Name must contain at least one attribute',
		);
	});

	it('rejects invalid country code length', async () => {
		expect(createSelfSignedCertificate({ subject: { country: 'USA' } })).rejects.toThrow(
			'Country must be a 2-character code',
		);
	});

	it('creates certificates with RSA SHA-384, SHA-512 and ECDSA P-384', async () => {
		const rsaSha384 = await createSelfSignedCertificate({
			subject: { commonName: 'rsa384.example' },
			algorithm: { kind: 'rsa', modulusLength: 2048, hash: 'SHA-384' },
		});
		expect(rsaSha384.certificate.pem).toContain('BEGIN CERTIFICATE');
		const parsed384 = parseCertificatePem(rsaSha384.certificate.pem);
		expect(parsed384.signatureAlgorithmOid).toBe('1.2.840.113549.1.1.12');

		const rsaSha512 = await createSelfSignedCertificate({
			subject: { commonName: 'rsa512.example' },
			algorithm: { kind: 'rsa', modulusLength: 2048, hash: 'SHA-512' },
		});
		const parsed512 = parseCertificatePem(rsaSha512.certificate.pem);
		expect(parsed512.signatureAlgorithmOid).toBe('1.2.840.113549.1.1.13');

		const ecP384 = await createSelfSignedCertificate({
			subject: { commonName: 'ecp384.example' },
			algorithm: { kind: 'ecdsa', namedCurve: 'P-384' },
		});
		const parsedEc384 = parseCertificatePem(ecP384.certificate.pem);
		expect(parsedEc384.signatureAlgorithmOid).toBe('1.2.840.10045.4.3.3');
	});

	it('rejects pathLength without ca:true', async () => {
		expect(
			createSelfSignedCertificate({
				subject: { commonName: 'bad-bc.example' },
				extensions: {
					basicConstraints: { ca: false, pathLength: 1 },
				},
			}),
		).rejects.toThrow('pathLength requires ca=true');
	});
});
