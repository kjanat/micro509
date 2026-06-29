import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificatePem,
	unwrap,
} from '#micro509';
import * as verify from '#micro509/verify/index.ts';

describe('verify domain', () => {
	describe('verifyCertificateChain', () => {
		it('verifies a self-signed leaf with allowSelfSignedLeaf', async () => {
			const { certificate } = await createSelfSignedCertificate({
				subject: { commonName: 'self-signed.example' },
			});
			const result = await verify.verifyCertificateChain({
				leaf: certificate.pem,
				roots: [certificate.pem],
				allowSelfSignedLeaf: true,
			});
			expect(result.ok).toBe(true);
			if (!result.ok) return;
			expect(result.value.chain.length).toBeGreaterThanOrEqual(1);
			expect(result.value.leaf.subject.values.commonName).toBe('self-signed.example');
			expect(result.value.root.subject.values.commonName).toBe('self-signed.example');
		});

		it('fails with no_trusted_root when roots is empty and allowSelfSignedLeaf is false', async () => {
			const { certificate } = await createSelfSignedCertificate({
				subject: { commonName: 'untrusted.example' },
			});
			const result = await verify.verifyCertificateChain({
				leaf: certificate.pem,
				roots: [],
			});
			expect(result.ok).toBe(false);
			if (result.ok) return;
			expect(result.error.code).toBe('no_trusted_root');
		});
	});

	describe('matchServiceIdentity', () => {
		it('matches a dns SAN against the same hostname', async () => {
			const { certificate } = await createSelfSignedCertificate({
				subject: { commonName: 'example.com' },
				extensions: {
					subjectAltNames: [{ type: 'dns', value: 'example.com' }],
				},
			});
			const parsed = unwrap(parseCertificatePem(certificate.pem));
			const result = verify.matchServiceIdentity({
				certificate: parsed,
				serviceIdentity: { type: 'dns', value: 'example.com' },
			});
			expect(result.ok).toBe(true);
		});

		it('fails when dns SAN does not match the requested hostname', async () => {
			const { certificate } = await createSelfSignedCertificate({
				subject: { commonName: 'example.com' },
				extensions: {
					subjectAltNames: [{ type: 'dns', value: 'example.com' }],
				},
			});
			const parsed = unwrap(parseCertificatePem(certificate.pem));
			const result = verify.matchServiceIdentity({
				certificate: parsed,
				serviceIdentity: { type: 'dns', value: 'other.com' },
			});
			expect(result.ok).toBe(false);
			if (result.ok) return;
			expect(result.error.code).toBe('subject_alt_name_mismatch');
		});
	});

	describe('checkExtendedKeyUsage', () => {
		it('succeeds when the leaf has the requested EKU', async () => {
			const root = await createSelfSignedCertificate({
				subject: { commonName: 'EKU Root CA' },
				extensions: {
					basicConstraints: { ca: true },
					keyUsage: ['keyCertSign'],
				},
			});
			const leafKeys = await generateKeyPair();
			const leaf = await createCertificate({
				issuer: { commonName: 'EKU Root CA' },
				subject: { commonName: 'eku-leaf.example' },
				publicKey: leafKeys.publicKey,
				signerPrivateKey: root.keyPair.privateKey,
				issuerPublicKey: root.keyPair.publicKey,
				extensions: {
					extendedKeyUsage: ['serverAuth'],
				},
			});
			const chain = [
				unwrap(parseCertificatePem(leaf.pem)),
				unwrap(parseCertificatePem(root.certificate.pem)),
			];
			const result = verify.checkExtendedKeyUsage(chain, 'serverAuth');
			expect(result.ok).toBe(true);
		});

		it('fails when the leaf lacks the requested EKU', async () => {
			const root = await createSelfSignedCertificate({
				subject: { commonName: 'EKU Root CA' },
				extensions: {
					basicConstraints: { ca: true },
					keyUsage: ['keyCertSign'],
				},
			});
			const leafKeys = await generateKeyPair();
			const leaf = await createCertificate({
				issuer: { commonName: 'EKU Root CA' },
				subject: { commonName: 'eku-leaf.example' },
				publicKey: leafKeys.publicKey,
				signerPrivateKey: root.keyPair.privateKey,
				issuerPublicKey: root.keyPair.publicKey,
				extensions: {
					extendedKeyUsage: ['serverAuth'],
				},
			});
			const chain = [
				unwrap(parseCertificatePem(leaf.pem)),
				unwrap(parseCertificatePem(root.certificate.pem)),
			];
			const result = verify.checkExtendedKeyUsage(chain, 'clientAuth');
			expect(result.ok).toBe(false);
			if (result.ok) return;
			expect(result.error.code).toBe('leaf_eku_missing');
			expect(result.index).toBe(0);
		});
	});

	describe('validateForTlsServer', () => {
		it('validates a leaf with serverAuth EKU and matching SAN', async () => {
			const root = await createSelfSignedCertificate({
				subject: { commonName: 'TLS Root CA' },
				extensions: {
					basicConstraints: { ca: true },
					keyUsage: ['keyCertSign', 'cRLSign'],
				},
			});
			const leafKeys = await generateKeyPair();
			const leaf = await createCertificate({
				issuer: { commonName: 'TLS Root CA' },
				subject: { commonName: 'tls.example' },
				publicKey: leafKeys.publicKey,
				signerPrivateKey: root.keyPair.privateKey,
				issuerPublicKey: root.keyPair.publicKey,
				extensions: {
					keyUsage: ['digitalSignature'],
					extendedKeyUsage: ['serverAuth'],
					subjectAltNames: [{ type: 'dns', value: 'tls.example' }],
				},
			});
			const result = await verify.validateForTlsServer({
				leaf: leaf.pem,
				roots: [root.certificate.pem],
				serviceIdentity: { type: 'dns', value: 'tls.example' },
			});
			expect(result.ok).toBe(true);
			if (!result.ok) return;
			expect(result.value.leaf.subject.values.commonName).toBe('tls.example');
		});

		it('fails when service identity does not match', async () => {
			const root = await createSelfSignedCertificate({
				subject: { commonName: 'TLS Root CA' },
				extensions: {
					basicConstraints: { ca: true },
					keyUsage: ['keyCertSign', 'cRLSign'],
				},
			});
			const leafKeys = await generateKeyPair();
			const leaf = await createCertificate({
				issuer: { commonName: 'TLS Root CA' },
				subject: { commonName: 'tls.example' },
				publicKey: leafKeys.publicKey,
				signerPrivateKey: root.keyPair.privateKey,
				issuerPublicKey: root.keyPair.publicKey,
				extensions: {
					keyUsage: ['digitalSignature'],
					extendedKeyUsage: ['serverAuth'],
					subjectAltNames: [{ type: 'dns', value: 'tls.example' }],
				},
			});
			const result = await verify.validateForTlsServer({
				leaf: leaf.pem,
				roots: [root.certificate.pem],
				serviceIdentity: { type: 'dns', value: 'wrong.example' },
			});
			expect(result.ok).toBe(false);
			if (result.ok) return;
			expect(result.error.code).toBe('subject_alt_name_mismatch');
		});
	});
});
