import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createSelfSignedCertificate,
	generateKeyPair,
	verifyCertificateChain,
} from '#micro509';

const SHARED_NAME = { commonName: 'Shared Subject CA' } as const;
const VALIDITY = {
	notBefore: new Date('2020-01-01T00:00:00Z'),
	notAfter: new Date('2099-01-01T00:00:00Z'),
};

async function issueSameSubjectCandidates(count: number) {
	const shared = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
	const intermediates: string[] = [];
	for (let index = 1; index <= count; index += 1) {
		const certificate = await createCertificate({
			issuer: SHARED_NAME,
			subject: SHARED_NAME,
			publicKey: shared.publicKey,
			signerPrivateKey: shared.privateKey,
			issuerPublicKey: shared.publicKey,
			serialNumber: Uint8Array.of(1, index),
			validity: VALIDITY,
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		intermediates.push(certificate.pem);
	}
	const leafKeys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
	const leaf = await createCertificate({
		issuer: SHARED_NAME,
		subject: { commonName: 'same-subject-leaf.example' },
		publicKey: leafKeys.publicKey,
		signerPrivateKey: shared.privateKey,
		issuerPublicKey: shared.publicKey,
		serialNumber: Uint8Array.of(2, 1),
		validity: VALIDITY,
	});
	const unrelatedRoot = await createSelfSignedCertificate({
		subject: { commonName: 'Unrelated Root' },
		algorithm: { kind: 'ecdsa', curve: 'P-256' },
		validity: VALIDITY,
		extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign'] },
	});
	return { leaf: leaf.pem, intermediates, root: unrelatedRoot.certificate.pem };
}

async function countSignatureVerifications<T>(run: () => Promise<T>) {
	const subtle = globalThis.crypto.subtle;
	const original = subtle.verify;
	let verifications = 0;
	Object.defineProperty(subtle, 'verify', {
		configurable: true,
		value: (...args: Parameters<SubtleCrypto['verify']>) => {
			verifications += 1;
			return original.apply(subtle, args);
		},
	});
	try {
		const value = await run();
		return { value, verifications };
	} finally {
		Object.defineProperty(subtle, 'verify', { configurable: true, value: original });
	}
}

describe('path search cost', () => {
	it('bounds signature checks when many same-subject CAs share one key', async () => {
		const count = 12;
		const { leaf, intermediates, root } = await issueSameSubjectCandidates(count);

		const { value, verifications } = await countSignatureVerifications(() =>
			verifyCertificateChain({ leaf, intermediates, roots: [root], at: VALIDITY.notBefore }),
		);

		expect(value.ok).toBe(false);
		if (!value.ok) {
			expect(value.code).toBe('no_trusted_root');
		}
		expect(verifications).toBeLessThanOrEqual(4 * (count + 1));
	});
});
