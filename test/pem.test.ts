import { describe, expect, it } from 'bun:test';
import {
	categorizePemBlocks,
	createCertificateSigningRequest,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificateChainPem,
	pemDecode,
	splitPemBlocks,
} from 'micro509';

describe('pem', () => {
	it('splits mixed PEM bundles by label', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bundle.example' },
		});
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'bundle.example' },
			publicKey: certificate.keyPair.publicKey,
			signerPrivateKey: certificate.keyPair.privateKey,
		});
		const privateKeyPem = await certificate.keyPair.exportPkcs8Pem();
		const bundle = `${certificate.certificate.pem}\n${csr.pem}\n${privateKeyPem}`;

		expect(splitPemBlocks(bundle).map((block) => block.label)).toEqual([
			'CERTIFICATE',
			'CERTIFICATE REQUEST',
			'PRIVATE KEY',
		]);
		expect(categorizePemBlocks(bundle)).toMatchObject({
			certificates: [{ label: 'CERTIFICATE' }],
			certificateRequests: [{ label: 'CERTIFICATE REQUEST' }],
			privateKeys: [{ label: 'PRIVATE KEY' }],
			publicKeys: [],
			others: [],
		});
	});

	it('categorizes public and unknown PEM blocks from text and from blocks', async () => {
		const keyPair = await generateKeyPair({ kind: 'ed25519' });
		const publicPem = await keyPair.exportSpkiPem();
		const unknownPem = '-----BEGIN SOMETHING-----\nAQID\n-----END SOMETHING-----';
		const bundle = `${publicPem}\n${unknownPem}`;

		expect(categorizePemBlocks(bundle)).toMatchObject({
			publicKeys: [{ label: 'PUBLIC KEY' }],
			others: [{ label: 'SOMETHING' }],
		});
		expect(categorizePemBlocks(splitPemBlocks(bundle))).toMatchObject({
			publicKeys: [{ label: 'PUBLIC KEY' }],
			others: [{ label: 'SOMETHING' }],
		});
		expect(() => pemDecode('CERTIFICATE', publicPem)).toThrow('Invalid PEM for CERTIFICATE');
	});

	it('rejects single-line PEM envelopes', () => {
		const pem = '-----BEGIN CERTIFICATE-----AQID-----END CERTIFICATE-----';
		expect(() => pemDecode('CERTIFICATE', pem)).toThrow('Invalid PEM for CERTIFICATE');
	});

	it('rejects malformed base64 inside PEM envelopes with stable errors', () => {
		const pem = '-----BEGIN CERTIFICATE-----\n@@@@\n-----END CERTIFICATE-----';
		expect(() => pemDecode('CERTIFICATE', pem)).toThrow('Invalid PEM for CERTIFICATE');
	});

	it('pemDecode tolerates harmless whitespace around base64 body lines', () => {
		const pem = '-----BEGIN CERTIFICATE-----\n AQID \n-----END CERTIFICATE-----';
		expect(Array.from(pemDecode('CERTIFICATE', pem))).toEqual([1, 2, 3]);
	});

	it('pemDecode tolerates embedded horizontal whitespace inside base64 body lines', () => {
		const pem = '-----BEGIN CERTIFICATE-----\nAQ I\tD\n-----END CERTIFICATE-----';
		expect(Array.from(pemDecode('CERTIFICATE', pem))).toEqual([1, 2, 3]);
	});

	it('pemDecode tolerates whitespace-only separator lines inside the body', () => {
		const pem = '-----BEGIN CERTIFICATE-----\nAQID\n \t\n-----END CERTIFICATE-----';
		expect(Array.from(pemDecode('CERTIFICATE', pem))).toEqual([1, 2, 3]);
	});

	it('splitPemBlocks rejects truncated trailing PEM blocks instead of dropping them', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'truncated-pem.example' },
		});
		const malformedBundle = `${certificate.certificate.pem}\n-----BEGIN CERTIFICATE-----\nAQID`;
		expect(() => splitPemBlocks(malformedBundle)).toThrow('Malformed PEM block');
	});

	it('splitPemBlocks keeps adjacent concatenated PEM blocks working', async () => {
		const first = await createSelfSignedCertificate({
			subject: { commonName: 'adjacent-first.example' },
		});
		const second = await createSelfSignedCertificate({
			subject: { commonName: 'adjacent-second.example' },
		});
		const adjacentBundle = `${first.certificate.pem}${second.certificate.pem}`;
		expect(splitPemBlocks(adjacentBundle).map((block) => block.label)).toEqual([
			'CERTIFICATE',
			'CERTIFICATE',
		]);
	});

	it('splitPemBlocks still ignores non-PEM text between blocks', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'noise-between.example' },
		});
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'noise-between.example' },
			publicKey: certificate.keyPair.publicKey,
			signerPrivateKey: certificate.keyPair.privateKey,
		});
		const bundle = `${certificate.certificate.pem}\nnot pem text\n${csr.pem}`;
		expect(splitPemBlocks(bundle).map((block) => block.label)).toEqual([
			'CERTIFICATE',
			'CERTIFICATE REQUEST',
		]);
	});

	it('parseCertificateChainPem rejects malformed trailing PEM blocks instead of silently shrinking bundles', async () => {
		const first = await createSelfSignedCertificate({
			subject: { commonName: 'first-chain.example' },
		});
		const second = await createSelfSignedCertificate({
			subject: { commonName: 'second-chain.example' },
		});
		const malformedBundle = `${first.certificate.pem}\n${second.certificate.pem}\n-----BEGIN CERTIFICATE-----\nAQID`;
		expect(() => parseCertificateChainPem(malformedBundle)).toThrow('Malformed PEM block');
	});

	it('splitPemBlocks resists polynomial ReDoS on many unclosed BEGIN markers', () => {
		// Pathological input: thousands of BEGIN openers with no matching END.
		// The previous lazy-body regex was O(n^2) here and would hang; the linear
		// indexOf scan completes in milliseconds.
		const malicious = '-----BEGIN A-----\n'.repeat(100_000);
		const start = performance.now();
		expect(() => splitPemBlocks(malicious)).toThrow('Malformed PEM block');
		expect(performance.now() - start).toBeLessThan(1000);
	});
});
