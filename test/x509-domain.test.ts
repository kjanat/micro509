import { describe, expect, it } from 'bun:test';
import { exportSpkiDer, generateKeyPair, type KeyAlgorithmInput, unwrap } from '#micro509';
import type { NameInput } from '#micro509/x509';
import * as x509 from '#micro509/x509';

describe('x509 domain', () => {
	it('does not expose internal helpers', () => {
		expect('nameFieldKeyFromOid' in x509).toBe(false);
	});

	it('creates a self-signed cert with extensions and parses back decoded values', async () => {
		const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const subject: NameInput = {
			commonName: 'test-ca.example',
			organization: 'X509 Domain Test',
			country: 'US',
		};

		const { certificate } = await x509.createSelfSignedCertificate({
			subject,
			keyPair,
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
				subjectAltNames: [
					{ type: 'dns', value: 'test-ca.example' },
					{ type: 'ip', value: '127.0.0.1' },
				],
			},
		});

		expect(certificate.pem).toStartWith('-----BEGIN CERTIFICATE-----');
		expect(certificate.der.byteLength).toBeGreaterThan(0);

		const parsed = unwrap(x509.parseCertificatePem(certificate.pem));

		expect(parsed.version).toBe(3);
		expect(parsed.subject.values.commonName).toBe('test-ca.example');
		expect(parsed.subject.values.organization).toBe('X509 Domain Test');
		expect(parsed.subject.values.country).toBe('US');
		expect(parsed.issuer.values.commonName).toBe('test-ca.example');

		expect(parsed.basicConstraints).toEqual({ ca: true, pathLength: 1 });
		expect(parsed.keyUsage).toEqual({ flags: ['keyCertSign', 'cRLSign'], nonZeroPadding: false });

		const dns = parsed.subjectAltNames?.find((s) => s.type === 'dns');
		expect(dns).toBeDefined();
		expect(dns?.type === 'dns' && dns.value).toBe('test-ca.example');

		const ip = parsed.subjectAltNames?.find((s) => s.type === 'ip');
		expect(ip).toBeDefined();
		expect(ip?.type === 'ip' && ip.value).toBe('127.0.0.1');
	});

	it('exposes OrThrow parse variants alongside the Result variants', async () => {
		const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const { certificate } = await x509.createSelfSignedCertificate({
			subject: { commonName: 'orthrow.example' },
			keyPair,
		});

		expect(x509.parseCertificatePemOrThrow(certificate.pem).subject.values.commonName).toBe(
			'orthrow.example',
		);
		expect(x509.parseCertificateDerOrThrow(certificate.der).subject.values.commonName).toBe(
			'orthrow.example',
		);
		expect(() => x509.parseCertificatePemOrThrow('not a pem')).toThrow();
		expect(() => x509.parseCertificateDerOrThrow(new Uint8Array([0x30, 0x00]))).toThrow();

		const csr = await x509.createCertificateSigningRequest({
			subject: { commonName: 'orthrow-csr.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
		});

		expect(x509.parseCertificateSigningRequestPemOrThrow(csr.pem).subject.values.commonName).toBe(
			'orthrow-csr.example',
		);
		expect(x509.parseCertificateSigningRequestDerOrThrow(csr.der).subject.values.commonName).toBe(
			'orthrow-csr.example',
		);
		expect(() => x509.parseCertificateSigningRequestPemOrThrow('not a pem')).toThrow();
		expect(() =>
			x509.parseCertificateSigningRequestDerOrThrow(new Uint8Array([0x30, 0x00])),
		).toThrow();
	});

	it('creates a CSR and parses back subject fields', async () => {
		const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-384' });

		const csr = await x509.createCertificateSigningRequest({
			subject: {
				commonName: 'leaf.example.com',
				organization: 'CSR Test Org',
				country: 'NL',
			},
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
			extensions: {
				subjectAltNames: [{ type: 'dns', value: 'leaf.example.com' }],
			},
		});

		expect(csr.pem).toContain('CERTIFICATE REQUEST');

		const parsed = unwrap(x509.parseCertificateSigningRequestPem(csr.pem));

		expect(parsed.version).toBe(1);
		expect(parsed.subject.values.commonName).toBe('leaf.example.com');
		expect(parsed.subject.values.organization).toBe('CSR Test Org');
		expect(parsed.subject.values.country).toBe('NL');

		const dns = parsed.subjectAltNames?.find((s) => s.type === 'dns');
		expect(dns).toBeDefined();
		expect(dns?.type === 'dns' && dns.value).toBe('leaf.example.com');
	});

	it.each<[string, KeyAlgorithmInput]>([
		['rsa', { kind: 'rsa', modulusLength: 2048 }],
		['ecdsa P-256', { kind: 'ecdsa', curve: 'P-256' }],
		['ed25519', { kind: 'ed25519' }],
	])('getSubjectPublicKey imports a %s subject key from a parsed certificate', async (_label, algorithm) => {
		const keyPair = await generateKeyPair(algorithm);
		const { certificate } = await x509.createSelfSignedCertificate({
			subject: { commonName: 'spki.example' },
			keyPair,
		});
		const parsed = x509.parseCertificateDerOrThrow(certificate.der);

		const publicKey = unwrap(await x509.getSubjectPublicKey(parsed));

		expect(publicKey.type).toBe('public');
		expect(await exportSpkiDer(publicKey)).toEqual(parsed.subjectPublicKeyInfoDer);
	});

	it('getSubjectPublicKeyOrThrow imports the subject key of a parsed CSR', async () => {
		const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const csr = await x509.createCertificateSigningRequest({
			subject: { commonName: 'spki-csr.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
		});
		const parsed = x509.parseCertificateSigningRequestDerOrThrow(csr.der);

		const publicKey = await x509.getSubjectPublicKeyOrThrow(parsed);

		expect(publicKey.type).toBe('public');
		expect(await exportSpkiDer(publicKey)).toEqual(parsed.subjectPublicKeyInfoDer);
	});

	it('getSubjectPublicKey rejects an unsupported public key algorithm OID', async () => {
		const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const { certificate } = await x509.createSelfSignedCertificate({
			subject: { commonName: 'bogus-spki.example' },
			keyPair,
		});
		// SPKI whose AlgorithmIdentifier carries the unassigned OID 1.2.3.4
		const bogusSpki = new Uint8Array([
			0x30, 0x0b, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x03, 0x02, 0x00, 0x00,
		]);
		const parsed = {
			...x509.parseCertificateDerOrThrow(certificate.der),
			subjectPublicKeyInfoDer: bogusSpki,
		};

		const result = await x509.getSubjectPublicKey(parsed);

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.code).toBe('malformed');
		}
		await expect(x509.getSubjectPublicKeyOrThrow(parsed)).rejects.toThrow(
			'Unsupported SubjectPublicKeyInfo algorithm',
		);
	});

	it('encodeName produces DER bytes from a NameInput', () => {
		const der = x509.encodeName({
			commonName: 'example.com',
			organization: 'Test Org',
			country: 'DE',
		});

		expect(der).toBeInstanceOf(Uint8Array);
		// DER SEQUENCE tag 0x30, plus country(2-char) + org + CN = non-trivial
		expect(der.byteLength).toBeGreaterThan(20);
		expect(der[0]).toBe(0x30); // SEQUENCE tag
	});

	it('encodeSubjectAltName produces DER bytes for a DNS name', () => {
		const der = x509.encodeSubjectAltName({ type: 'dns', value: 'example.org' });

		expect(der).toBeInstanceOf(Uint8Array);
		expect(der.byteLength).toBeGreaterThan(0);
		// implicit context tag [2] for dNSName = 0x82
		expect(der[0]).toBe(0x82);
	});

	it('encodeCertificatePolicies produces DER bytes for a policy OID', () => {
		const der = x509.encodeCertificatePolicies([{ policyIdentifier: '2.23.140.1.2.1' }]);

		expect(der).toBeInstanceOf(Uint8Array);
		expect(der.byteLength).toBeGreaterThan(0);
		expect(der[0]).toBe(0x30); // SEQUENCE tag
	});
});
