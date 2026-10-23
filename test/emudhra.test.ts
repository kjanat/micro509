import { describe, expect, it } from 'bun:test';
import { readFile } from 'node:fs/promises';
import {
	checkChainRevocation,
	parseCertificateChainPem,
	parseCertificateDer,
	subjectPublicKeyInfoFingerprint,
	unwrap,
	verifyCertificateChain,
} from '#micro509';

const fixtureDir = new URL('./fixtures/emudhra/', import.meta.url);
const verificationTime = new Date('2026-10-23T20:00:00Z');

const chainPairs = [
	{
		label: 'DV G3B',
		originalFile: 'dv-g3b-emudhra.we-have-a-problem.com.pem',
		sectigoFile: 'dv-g3b-aaa-emudhra.we-have-a-problem.com.pem',
		spkiSha256: 'ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105',
	},
	{
		label: 'DV G3B no-CT',
		originalFile: 'dv-g3b-noct-emudhra.we-have-a-problem.com.pem',
		sectigoFile: 'dv-g3b-aaa-noct-emudhra.we-have-a-problem.com.pem',
		spkiSha256: 'ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105',
	},
	{
		label: 'DV G3C',
		originalFile: 'dv-g3c-emudhra.we-have-a-problem.com.pem',
		sectigoFile: 'dv-g3c-aaa-emudhra.we-have-a-problem.com.pem',
		spkiSha256: '49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f',
	},
	{
		label: 'OV G3B',
		originalFile: 'ov-g3b-emudhra.we-have-a-problem.com.pem',
		sectigoFile: 'ov-g3b-aaa-emudhra.we-have-a-problem.com.pem',
		spkiSha256: '43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b',
	},
	{
		label: 'OV G3C',
		originalFile: 'ov-g3c-emudhra.we-have-a-problem.com.pem',
		sectigoFile: 'ov-g3c-aaa-emudhra.we-have-a-problem.com.pem',
		spkiSha256: '63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8',
	},
	{
		label: 'EV G3B',
		originalFile: 'ev-g3b-emudhra.we-have-a-problem.com.pem',
		sectigoFile: 'ev-g3b-aaa-emudhra.we-have-a-problem.com.pem',
		spkiSha256: 'e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41',
	},
	{
		label: 'EV G3C',
		originalFile: 'ev-g3c-emudhra.we-have-a-problem.com.pem',
		sectigoFile: 'ev-g3c-aaa-emudhra.we-have-a-problem.com.pem',
		spkiSha256: '5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0',
	},
] as const;

async function readBytes(name: string): Promise<Uint8Array> {
	return new Uint8Array(await readFile(new URL(name, fixtureDir)));
}

async function readChain(name: string) {
	return unwrap(parseCertificateChainPem(await readFile(new URL(name, fixtureDir), 'utf8')));
}

function required<T>(value: T | undefined): T {
	if (value === undefined) throw new Error('Published eMudhra fixture is missing a certificate');
	return value;
}

describe('published eMudhra intermediate compromise incident', () => {
	it('matches the published SPKI SHA-256 for all 14 original and cross-signed chains', async () => {
		for (const pair of chainPairs) {
			const original = await readChain(pair.originalFile);
			const sectigo = await readChain(pair.sectigoFile);
			expect((await subjectPublicKeyInfoFingerprint(required(original[1]))).hex).toBe(
				pair.spkiSha256,
			);
			expect((await subjectPublicKeyInfoFingerprint(required(sectigo[1]))).hex).toBe(
				pair.spkiSha256,
			);
		}
	});

	it('verifies each intended chain, then rejects alternate candidate ordering by SPKI', async () => {
		const aaaRoot = unwrap(
			parseCertificateDer(await readBytes('aaa-certificate-services-root.crt')),
		);

		for (const pair of chainPairs) {
			const original = await readChain(pair.originalFile);
			const sectigo = await readChain(pair.sectigoFile);
			const originalLeaf = required(original[0]);
			const originalIntermediate = required(original[1]);
			const originalRoot = required(original[2]);
			const sectigoLeaf = required(sectigo[0]);
			const sectigoIntermediate = required(sectigo[1]);
			const expectedSha256 = pair.spkiSha256;

			const originalBaseline = await verifyCertificateChain({
				leaf: originalLeaf.der,
				intermediates: [originalIntermediate.der],
				roots: [originalRoot.der],
				at: verificationTime,
			});
			expect(originalBaseline.ok).toBe(true);
			if (originalBaseline.ok) {
				expect(originalBaseline.value.chain[1]?.der).toEqual(originalIntermediate.der);
				expect(originalBaseline.value.root.der).toEqual(originalRoot.der);
			}

			const sectigoBaseline = await verifyCertificateChain({
				leaf: sectigoLeaf.der,
				intermediates: [sectigoIntermediate.der],
				roots: [aaaRoot.der],
				at: verificationTime,
			});
			expect(sectigoBaseline.ok).toBe(true);
			if (sectigoBaseline.ok) {
				expect(sectigoBaseline.value.chain[1]?.der).toEqual(sectigoIntermediate.der);
				expect(sectigoBaseline.value.root.der).toEqual(aaaRoot.der);
			}

			const intermediates = [originalIntermediate.der, sectigoIntermediate.der];
			const roots = [originalRoot.der, aaaRoot.der];
			for (const leaf of [originalLeaf, sectigoLeaf]) {
				for (const candidates of [intermediates, [...intermediates].reverse()]) {
					for (const candidateRoots of [roots, [...roots].reverse()]) {
						const baseline = await verifyCertificateChain({
							leaf: leaf.der,
							intermediates: candidates,
							roots: candidateRoots,
							at: verificationTime,
						});
						expect(baseline.ok).toBe(true);

						const denied = await verifyCertificateChain({
							leaf: leaf.der,
							intermediates: candidates,
							roots: candidateRoots,
							at: verificationTime,
							distrustedSpkiSha256: [expectedSha256],
						});
						expect(denied).toMatchObject({
							ok: false,
							code: 'public_key_distrusted',
						});
					}
				}
			}
		}
	});

	it('reports revoked intermediates from both CRLs at a fixed time, including full-chain verification', async () => {
		const emsignCrl = await readBytes('emsign-root-tls-g3.crl');
		const sectigoCrl = await readBytes('aaa-certificate-services.crl');
		const aaaRoot = unwrap(
			parseCertificateDer(await readBytes('aaa-certificate-services-root.crt')),
		);

		for (const pair of chainPairs) {
			const original = await readChain(pair.originalFile);
			const sectigo = await readChain(pair.sectigoFile);
			const originalLeaf = required(original[0]);
			const originalIntermediate = required(original[1]);
			const originalRoot = required(original[2]);
			const sectigoLeaf = required(sectigo[0]);
			const sectigoIntermediate = required(sectigo[1]);

			const originalRevocation = await checkChainRevocation({
				chain: [originalIntermediate, originalRoot],
				crls: [emsignCrl],
				at: verificationTime,
			});
			expect(originalRevocation.value.certificates[0]?.status).toBe('revoked');
			const originalFullChain = await verifyCertificateChain({
				leaf: originalLeaf.der,
				intermediates: [originalIntermediate.der],
				roots: [originalRoot.der],
				at: verificationTime,
				revocation: { crls: [emsignCrl] },
			});
			expect(originalFullChain).toMatchObject({
				ok: false,
				code: 'certificate_revoked',
				index: 1,
			});

			const sectigoRevocation = await checkChainRevocation({
				chain: [sectigoIntermediate, aaaRoot],
				crls: [sectigoCrl],
				at: verificationTime,
			});
			expect(sectigoRevocation.value.certificates[0]?.status).toBe('revoked');
			const sectigoFullChain = await verifyCertificateChain({
				leaf: sectigoLeaf.der,
				intermediates: [sectigoIntermediate.der],
				roots: [aaaRoot.der],
				at: verificationTime,
				revocation: { crls: [sectigoCrl] },
			});
			expect(sectigoFullChain).toMatchObject({
				ok: false,
				code: 'certificate_revoked',
				index: 1,
			});
		}
	});
});
