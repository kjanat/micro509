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

/**
 * Distinct CA certificates that share one subject and one key, so every
 * candidate-to-candidate edge is a valid signature and the search must explore
 * the whole graph before reporting that nothing anchors.
 */
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

describe('path search cost', () => {
	// The timeout is the assertion: before dead ends were memoized per
	// certificate and CA count, and each certificate-to-key signature check
	// cached, this bundle ran for more than ten minutes. It now settles in
	// well under a second.
	it('terminates on many same-subject CAs sharing one key', async () => {
		const { leaf, intermediates, root } = await issueSameSubjectCandidates(30);

		const result = await verifyCertificateChain({
			leaf,
			intermediates,
			roots: [root],
			at: VALIDITY.notBefore,
		});

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.code).toBe('no_trusted_root');
	}, 5_000);
});
