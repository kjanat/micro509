import { describe, expect, it } from 'bun:test';
import {
	buildCandidatePath,
	createCertificate,
	createCertificateRevocationList,
	createOcspResponse,
	createSelfSignedCertificate,
	parseCertificatePem,
	trustAnchorFromCertificate,
	unwrap,
	validateCandidatePath,
	validateForCa,
	validateForCodeSigning,
	validateForTlsClient,
	validateForTlsServer,
	verifyCertificateChain,
} from '#micro509';
import { subjectPublicKeyInfoFingerprint } from '#micro509/x509';
import { expectRejectedWith, issueChain } from '#test/helpers';

const validity = {
	notBefore: new Date('2020-01-01T00:00:00.000Z'),
	notAfter: new Date('2035-01-01T00:00:00.000Z'),
};
const at = new Date('2025-01-01T00:00:00.000Z');

async function fixture() {
	const chain = await issueChain({ validity });
	const leaf = unwrap(parseCertificatePem(chain.leaf.pem));
	const intermediate = unwrap(parseCertificatePem(chain.intermediate.pem));
	const root = unwrap(parseCertificatePem(chain.root.certificate.pem));
	return {
		chain,
		leaf,
		intermediate,
		root,
		leafHash: (await subjectPublicKeyInfoFingerprint(leaf)).hex,
		intermediateHash: (await subjectPublicKeyInfoFingerprint(intermediate)).hex,
		rootHash: (await subjectPublicKeyInfoFingerprint(root)).hex,
	};
}

describe('SPKI distrust', () => {
	it('validates denylist syntax and treats an empty list as a no-op', async () => {
		const f = await fixture();
		const baseline = await verifyCertificateChain({
			leaf: f.leaf.der,
			intermediates: [f.intermediate.der],
			roots: [f.root.der],
			at,
			distrustedSpkiSha256: [],
		});
		expect(baseline.ok).toBe(true);
		for (const invalid of ['abc', 'g'.repeat(64), '0'.repeat(63), `${'0'.repeat(64)}:`]) {
			await expectRejectedWith(
				verifyCertificateChain({
					leaf: f.leaf.der,
					roots: [f.root.der],
					distrustedSpkiSha256: [invalid],
				}),
				RangeError,
			);
			await expectRejectedWith(
				buildCandidatePath({
					leaf: f.leaf.der,
					roots: [f.root.der],
					distrustedSpkiSha256: [invalid],
				}),
				RangeError,
			);
			await expectRejectedWith(
				validateCandidatePath({ chain: [f.leaf, f.root], distrustedSpkiSha256: [invalid] }),
				RangeError,
			);
		}
	});

	it.each([
		['leaf', 0],
		['intermediate', 1],
		['root', 2],
	] as const)('rejects a distrusted %s and reports its chain index', async (position, index) => {
		const f = await fixture();
		const hash =
			position === 'leaf'
				? f.leafHash
				: position === 'intermediate'
					? f.intermediateHash
					: f.rootHash;
		const result = await verifyCertificateChain({
			leaf: f.leaf.der,
			intermediates: [f.intermediate.der],
			roots: [f.root.der],
			at,
			distrustedSpkiSha256: [hash.toUpperCase()],
		});
		expect(result).toMatchObject({
			ok: false,
			code: 'public_key_distrusted',
			index,
			details: { actual: hash },
		});
	});

	it('ignores an unrelated blocked key and rejects alternate cross-signed routes by key', async () => {
		const f = await fixture();
		const unrelated = await issueChain({ validity });
		const unrelatedHash = (await subjectPublicKeyInfoFingerprint(unrelated.intermediate.der)).hex;
		const allowed = await verifyCertificateChain({
			leaf: f.leaf.der,
			intermediates: [f.intermediate.der],
			roots: [f.root.der],
			at,
			distrustedSpkiSha256: [unrelatedHash],
		});
		expect(allowed.ok).toBe(true);

		const alternateRoot = await createSelfSignedCertificate({
			subject: { commonName: 'Alternate Root' },
			validity,
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const crossSigned = await createCertificate({
			issuer: { commonName: 'Alternate Root' },
			subject: { commonName: 'Verify Intermediate CA' },
			publicKey: f.chain.intermediateKeys.publicKey,
			signerPrivateKey: alternateRoot.keyPair.privateKey,
			issuerCertificate: alternateRoot.certificate.der,
			validity,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		// Both cross-signed intermediate certificates carry the same key.
		const blockedHash = f.intermediateHash;
		for (const intermediates of [
			[f.intermediate, crossSigned],
			[crossSigned, f.intermediate],
		]) {
			const result = await verifyCertificateChain({
				leaf: f.leaf.der,
				intermediates: intermediates.map((certificate) => certificate.der),
				roots: [f.root.der, alternateRoot.certificate.der],
				at,
				distrustedSpkiSha256: [blockedHash],
			});
			expect(result).toMatchObject({ ok: false, code: 'public_key_distrusted' });
		}
		const allowedAlternateRoot = await verifyCertificateChain({
			leaf: f.leaf.der,
			intermediates: [f.intermediate.der, crossSigned.der],
			roots: [f.root.der, alternateRoot.certificate.der],
			at,
			distrustedSpkiSha256: [f.rootHash],
		});
		expect(allowedAlternateRoot.ok).toBe(true);
		if (allowedAlternateRoot.ok) {
			expect(allowedAlternateRoot.value.root.subject.values.commonName).toBe('Alternate Root');
		}
	});

	it('checks a bare anchor returned by path building and requires it in direct validation', async () => {
		const f = await fixture();
		const anchor = trustAnchorFromCertificate(f.root);
		const wrongRoot = await createSelfSignedCertificate({
			subject: { commonName: f.root.subject.values.commonName },
			validity,
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const built = await buildCandidatePath({
			leaf: f.leaf.der,
			intermediates: [f.intermediate.der],
			roots: [],
			trustAnchors: [anchor],
			at,
		});
		expect(built).toMatchObject({ ok: true });
		if (!built.ok) return;
		const blockedDuringBuild = await buildCandidatePath({
			leaf: f.leaf.der,
			intermediates: [f.intermediate.der],
			roots: [],
			trustAnchors: [
				trustAnchorFromCertificate(unwrap(parseCertificatePem(wrongRoot.certificate.pem))),
				anchor,
			],
			at,
			distrustedSpkiSha256: [f.rootHash],
		});
		expect(blockedDuringBuild).toMatchObject({ ok: false, code: 'public_key_distrusted' });
		if (!blockedDuringBuild.ok) expect(blockedDuringBuild.index).toBeUndefined();
		const blockedInVerify = await verifyCertificateChain({
			leaf: f.leaf.der,
			intermediates: [f.intermediate.der],
			roots: [],
			trustAnchors: [
				trustAnchorFromCertificate(unwrap(parseCertificatePem(wrongRoot.certificate.pem))),
				anchor,
			],
			at,
			distrustedSpkiSha256: [f.rootHash],
		});
		expect(blockedInVerify).toMatchObject({ ok: false, code: 'public_key_distrusted' });
		if (!blockedInVerify.ok) expect(blockedInVerify.index).toBeUndefined();
		const baseline = await validateCandidatePath({
			chain: built.value.chain,
			anchorCertificateInChain: false,
			trustAnchor: built.value.trustAnchor,
			at,
			distrustedSpkiSha256: ['0'.repeat(64)],
		});
		expect(baseline.ok).toBe(true);
		const denied = await validateCandidatePath({
			chain: built.value.chain,
			anchorCertificateInChain: false,
			trustAnchor: built.value.trustAnchor,
			at,
			distrustedSpkiSha256: [f.rootHash],
		});
		expect(denied).toMatchObject({
			ok: false,
			code: 'public_key_distrusted',
			details: { actual: f.rootHash },
		});
		await expectRejectedWith(
			validateCandidatePath({
				chain: built.value.chain.slice(0, -1),
				anchorCertificateInChain: false,
				at,
				distrustedSpkiSha256: [f.rootHash],
			}),
			RangeError,
		);
	});

	it('rejects distrusted keys at every validation profile and cannot be bypassed for self-signed leaves', async () => {
		const f = await fixture();
		const input = {
			leaf: f.leaf.der,
			intermediates: [f.intermediate.der],
			roots: [f.root.der],
			at,
			distrustedSpkiSha256: [f.leafHash],
		};
		for (const result of await Promise.all([
			validateForTlsServer({ ...input, serviceIdentity: { type: 'dns', value: 'verify.example' } }),
			validateForTlsClient(input),
			validateForCodeSigning(input),
			validateForCa(input),
		])) {
			expect(result).toMatchObject({ ok: false, code: 'public_key_distrusted', index: 0 });
		}
		const selfSigned = await issueChain();
		const result = await verifyCertificateChain({
			leaf: selfSigned.root.certificate.der,
			roots: [selfSigned.root.certificate.der],
			allowSelfSignedLeaf: true,
			distrustedSpkiSha256: [
				(await subjectPublicKeyInfoFingerprint(selfSigned.root.certificate.der)).hex,
			],
		});
		expect(result).toMatchObject({ ok: false, code: 'public_key_distrusted', index: 0 });
	});

	it('reparses direct validation certificate DER instead of trusting caller-mutated SPKI fields', async () => {
		const f = await fixture();
		const spoofed = { ...f.leaf, subjectPublicKeyInfoDer: f.root.subjectPublicKeyInfoDer };
		const result = await validateCandidatePath({
			chain: [spoofed, f.intermediate, f.root],
			at,
			distrustedSpkiSha256: [f.leafHash],
		});
		expect(result).toMatchObject({ ok: false, code: 'public_key_distrusted', index: 0 });
		const blockedRoot = await validateCandidatePath({
			chain: [f.leaf, f.intermediate, f.root],
			at,
			distrustedSpkiSha256: [f.rootHash],
		});
		expect(blockedRoot).toMatchObject({ ok: false, code: 'public_key_distrusted', index: 2 });
	});

	it('keeps SPKI distrust ahead of good OCSP evidence and soft-fail revocation policy', async () => {
		const f = await fixture();
		const thisUpdate = new Date(Date.now() - 60_000);
		const response = await createOcspResponse({
			signerPrivateKey: f.chain.intermediateKeys.privateKey,
			signerCertificate: f.chain.intermediate.pem,
			responses: [
				{
					certificate: f.chain.leaf.pem,
					issuerCertificate: f.chain.intermediate.pem,
					certStatus: 'good',
					thisUpdate,
					nextUpdate: new Date(Date.now() + 3_600_000),
				},
			],
		});
		const crlTimes = {
			thisUpdate: new Date(Date.now() - 60_000),
			nextUpdate: new Date(Date.now() + 3_600_000),
		};
		const [intermediateCrl, rootCrl] = await Promise.all([
			createCertificateRevocationList({
				crlNumber: 11,
				issuer: { commonName: 'Verify Intermediate CA' },
				signerPrivateKey: f.chain.intermediateKeys.privateKey,
				issuerCertificate: f.chain.intermediate.der,
				...crlTimes,
			}),
			createCertificateRevocationList({
				crlNumber: 12,
				issuer: { commonName: 'Verify Root CA' },
				signerPrivateKey: f.chain.root.keyPair.privateKey,
				issuerCertificate: f.chain.root.certificate.der,
				...crlTimes,
			}),
		]);
		const result = await verifyCertificateChain({
			leaf: f.chain.leaf.pem,
			intermediates: [f.chain.intermediate.pem],
			roots: [f.chain.root.certificate.pem],
			at: new Date(Date.now() + 5_000),
			distrustedSpkiSha256: [f.leafHash],
			revocation: {
				crls: [intermediateCrl.der, rootCrl.der],
				ocspResponses: [response.der],
				policy: { mode: 'hard-fail' },
			},
		});
		expect(result).toMatchObject({ ok: false, code: 'public_key_distrusted', index: 0 });
		const noRevAvailLeaf = await createCertificate({
			issuer: { commonName: 'Verify Intermediate CA' },
			subject: { commonName: 'no-rev-avail.example' },
			publicKey: f.chain.leafKeys.publicKey,
			signerPrivateKey: f.chain.intermediateKeys.privateKey,
			issuerCertificate: f.chain.intermediate.der,
			validity,
			extensions: { keyUsage: ['digitalSignature'], noRevAvail: true },
		});
		const noRevAvailResult = await verifyCertificateChain({
			leaf: noRevAvailLeaf.pem,
			intermediates: [f.chain.intermediate.pem],
			roots: [f.chain.root.certificate.pem],
			at: new Date(Date.now() + 5_000),
			distrustedSpkiSha256: [f.leafHash],
			revocation: { policy: { mode: 'soft-fail' } },
		});
		expect(noRevAvailResult).toMatchObject({
			ok: false,
			code: 'public_key_distrusted',
			index: 0,
		});
	});
});
