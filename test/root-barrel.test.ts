import { describe, expect, it } from 'bun:test';
import * as micro509 from 'micro509';
import {
	createCertificateSigningRequest,
	createPfx,
	createSelfSignedCertificate,
	exportPkcs8Pem,
	generateKeyPair,
	importPkcs8Pem,
	parseCertificatePem,
	parseCertificateSigningRequestPem,
	parsePfxPem,
	pemDecode,
	pemEncode,
	verifyCertificateChain,
	unwrap,
} from 'micro509';

describe('root barrel', () => {
	it('self-signed cert round-trips through parse and chain verify', async () => {
		const { certificate, keyPair } = await createSelfSignedCertificate({
			subject: { commonName: 'barrel.example' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'digitalSignature'],
				subjectAltNames: [{ type: 'dns', value: 'barrel.example' }],
			},
		});
		expect(certificate.pem).toContain('-----BEGIN CERTIFICATE-----');

		const parsed = unwrap(parseCertificatePem(certificate.pem));
		expect(parsed.subject.values.commonName).toBe('barrel.example');
		expect(parsed.issuer.values.commonName).toBe('barrel.example');

		const result = await verifyCertificateChain({
			leaf: certificate.pem,
			roots: [certificate.pem],
			allowSelfSignedLeaf: true,
		});
		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error('unreachable');
		expect(result.value.leaf.subject.values.commonName).toBe('barrel.example');
		expect(result.value.chain).toHaveLength(1);
		expect(result.value.root.subject.values.commonName).toBe('barrel.example');

		// verify failure path: without allowSelfSignedLeaf
		const denied = await verifyCertificateChain({
			leaf: certificate.pem,
			roots: [certificate.pem],
		});
		expect(denied.ok).toBe(false);
		if (!denied.ok) {
			expect(denied.code).toBe('self_signed_leaf_not_allowed');
		}

		// exported private key should be importable
		const pkcs8Pem = await keyPair.exportPkcs8Pem();
		expect(pkcs8Pem).toContain('-----BEGIN PRIVATE KEY-----');
	});

	it('CSR round-trips through create and parse', async () => {
		const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'csr-barrel.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
			extensions: {
				subjectAltNames: [{ type: 'dns', value: 'csr-barrel.example' }],
			},
		});
		expect(csr.pem).toContain('-----BEGIN CERTIFICATE REQUEST-----');

		const parsed = unwrap(parseCertificateSigningRequestPem(csr.pem));
		expect(parsed.subject.values.commonName).toBe('csr-barrel.example');
		expect(parsed.subjectPublicKeyInfoDer.byteLength).toBeGreaterThan(0);
	});

	it('key pair export/import round-trips through PKCS#8 PEM', async () => {
		const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-384' });
		const pem = await exportPkcs8Pem(keyPair.privateKey);
		expect(pem).toContain('-----BEGIN PRIVATE KEY-----');

		const imported = unwrap(await importPkcs8Pem(pem, { kind: 'ecdsa', curve: 'P-384' }));
		expect(imported.type).toBe('private');

		// sign with imported key to prove it works
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'reimported.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: imported,
		});
		const parsed = unwrap(parseCertificateSigningRequestPem(csr.pem));
		expect(parsed.subject.values.commonName).toBe('reimported.example');
	});

	it('PEM encode/decode round-trips binary data', () => {
		const original = crypto.getRandomValues(new Uint8Array(128));
		const pem = pemEncode('TEST DATA', original);
		expect(pem).toContain('-----BEGIN TEST DATA-----');
		expect(pem).toContain('-----END TEST DATA-----');

		const decoded = pemDecode('TEST DATA', pem);
		expect(new Uint8Array(decoded)).toEqual(original);
	});

	it('PEM decode rejects label mismatch', () => {
		const pem = pemEncode('CERTIFICATE', new Uint8Array(16));
		expect(() => pemDecode('PRIVATE KEY', pem)).toThrow();
	});

	it('PFX round-trips through create and parse', async () => {
		const { certificate, keyPair } = await createSelfSignedCertificate({
			subject: { commonName: 'pfx-barrel.example' },
		});
		const pfx = unwrap(
			await createPfx({
				certificates: [
					{
						certificate: certificate.pem,
						attributes: { friendlyName: 'barrel-cert' },
					},
				],
				privateKeys: [
					{
						privateKey: keyPair.privateKey,
						attributes: { friendlyName: 'barrel-key' },
					},
				],
			}),
		);
		expect(pfx.pem).toContain('-----BEGIN PKCS12-----');

		const parsed = await parsePfxPem(pfx.pem);
		expect(parsed.ok).toBe(true);
		if (!parsed.ok) throw new Error('unreachable');
		expect(parsed.value.certificates).toHaveLength(1);
		expect(parsed.value.certificates[0]?.subject.values.commonName).toBe('pfx-barrel.example');
		expect(parsed.value.privateKeys).toHaveLength(1);
		expect(parsed.value.bags[0]).toMatchObject({
			kind: 'certificate',
			attributes: { friendlyName: 'barrel-cert' },
		});
	});

	it('leaves advanced PKCS plumbing in its owner domain', () => {
		expect('createPkcs12MacData' in micro509).toBe(false);
		expect('parsePkcs12MacData' in micro509).toBe(false);
	});
});
