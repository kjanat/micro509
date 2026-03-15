import { describe, expect, it } from 'bun:test';
import { generateKeyPair } from '#micro509';
import type { NameInput } from '#micro509/x509/index.ts';
import * as x509 from '#micro509/x509/index.ts';

describe('x509 domain', () => {
	it('does not expose internal helpers', () => {
		expect('nameFieldKeyFromOid' in x509).toBe(false);
	});

	it('creates a self-signed cert with extensions and parses back decoded values', async () => {
		const keyPair = await generateKeyPair({ kind: 'ecdsa', namedCurve: 'P-256' });
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

		const parsed = x509.parseCertificatePem(certificate.pem);

		expect(parsed.version).toBe(3);
		expect(parsed.subject.values.commonName).toBe('test-ca.example');
		expect(parsed.subject.values.organization).toBe('X509 Domain Test');
		expect(parsed.subject.values.country).toBe('US');
		expect(parsed.issuer.values.commonName).toBe('test-ca.example');

		expect(parsed.basicConstraints).toEqual({ ca: true, pathLength: 1 });
		expect(parsed.keyUsage).toEqual(['keyCertSign', 'cRLSign']);

		const dns = parsed.subjectAltNames?.find((s) => s.type === 'dns');
		expect(dns).toBeDefined();
		expect(dns?.type === 'dns' && dns.value).toBe('test-ca.example');

		const ip = parsed.subjectAltNames?.find((s) => s.type === 'ip');
		expect(ip).toBeDefined();
		expect(ip?.type === 'ip' && ip.value).toBe('127.0.0.1');
	});

	it('creates a CSR and parses back subject fields', async () => {
		const keyPair = await generateKeyPair({ kind: 'ecdsa', namedCurve: 'P-384' });

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

		const parsed = x509.parseCertificateSigningRequestPem(csr.pem);

		expect(parsed.version).toBe(1);
		expect(parsed.subject.values.commonName).toBe('leaf.example.com');
		expect(parsed.subject.values.organization).toBe('CSR Test Org');
		expect(parsed.subject.values.country).toBe('NL');

		const dns = parsed.subjectAltNames?.find((s) => s.type === 'dns');
		expect(dns).toBeDefined();
		expect(dns?.type === 'dns' && dns.value).toBe('leaf.example.com');
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
