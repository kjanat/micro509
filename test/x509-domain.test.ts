import { describe, expect, it } from 'bun:test';
import type { NameInput } from '#micro509/x509/index.ts';
import * as x509 from '#micro509/x509/index.ts';

describe('x509 domain', () => {
	it('exposes the consolidated advanced X.509 surface', () => {
		const nameInput: NameInput = { commonName: 'example.com' };

		expect(nameInput.commonName).toBe('example.com');
		expect(typeof x509.createCertificate).toBe('function');
		expect(typeof x509.createCertificateSigningRequest).toBe('function');
		expect(typeof x509.encodeName).toBe('function');
		expect(typeof x509.parseCertificatePem).toBe('function');
		expect(typeof x509.defineExtensionDecoder).toBe('function');
		expect(typeof x509.encodeCertificatePolicies).toBe('function');
		expect('nameFieldKeyFromOid' in x509).toBe(false);
	});
});
