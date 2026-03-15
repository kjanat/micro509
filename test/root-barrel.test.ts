import { describe, expect, it } from 'bun:test';
import * as micro509 from '#micro509';

describe('root barrel', () => {
	it('keeps the common workflow surface at root', () => {
		expect(typeof micro509.createCertificate).toBe('function');
		expect(typeof micro509.createCertificateSigningRequest).toBe('function');
		expect(typeof micro509.parseCertificatePem).toBe('function');
		expect(typeof micro509.verifyCertificateChain).toBe('function');
		expect(typeof micro509.checkCertificateRevocation).toBe('function');
		expect(typeof micro509.createPfx).toBe('function');
		expect(typeof micro509.verifyPkcs7SignedData).toBe('function');
		expect(typeof micro509.generateKeyPair).toBe('function');
		expect(typeof micro509.pemEncode).toBe('function');
	});

	it('leaves advanced PKCS plumbing in its owner domain', () => {
		expect('createPkcs12MacData' in micro509).toBe(false);
		expect('parsePkcs12MacData' in micro509).toBe(false);
	});
});
