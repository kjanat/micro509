import { describe, expect, it } from 'bun:test';
import {
	checkChainRevocation,
	createCertificate,
	createCertificateRevocationList,
	createOcspResponse,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificatePem,
	unwrap,
	validateCertificateRevocationList,
} from '#micro509';
import { hexToBytes } from '#test/helpers';

const CA_NAME = 'Delta Shadow CA';
const HOUR_MS = 60 * 60 * 1000;

async function scenario() {
	const ca = await createSelfSignedCertificate({
		subject: { commonName: CA_NAME },
		extensions: {
			basicConstraints: { ca: true, pathLength: 0 },
			keyUsage: ['keyCertSign', 'cRLSign'],
		},
	});
	const leafKeys = await generateKeyPair();
	const leaf = await createCertificate({
		issuer: { commonName: CA_NAME },
		subject: { commonName: 'revoked.example' },
		publicKey: leafKeys.publicKey,
		signerPrivateKey: ca.keyPair.privateKey,
		issuerPublicKey: ca.keyPair.publicKey,
	});
	const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
	const chain = [parsedLeaf, unwrap(parseCertificatePem(ca.certificate.pem))];
	const at = new Date(Date.now() + 5_000);
	const nextUpdate = new Date(at.getTime() + 24 * HOUR_MS);
	const baseThisUpdate = new Date(at.getTime() - 3 * HOUR_MS);
	const revocation = [
		{
			serialNumber: hexToBytes(parsedLeaf.serialNumberHex),
			revocationDate: baseThisUpdate,
			reasonCode: 'keyCompromise' as const,
		},
	];

	const crl = (
		fields: Omit<
			Parameters<typeof createCertificateRevocationList>[0],
			'issuer' | 'issuerPublicKey' | 'nextUpdate'
		>,
	): ReturnType<typeof createCertificateRevocationList> =>
		createCertificateRevocationList({
			issuer: { commonName: CA_NAME },
			issuerPublicKey: ca.keyPair.publicKey,
			nextUpdate,
			...fields,
		});
	const attackerKeys = await generateKeyPair();
	const forgedNewerDelta = await crl({
		signerPrivateKey: attackerKeys.privateKey,
		crlNumber: 7,
		baseCrlNumber: 5,
		thisUpdate: new Date(at.getTime() - HOUR_MS),
	});
	const ocspGood = await createOcspResponse({
		signerPrivateKey: ca.keyPair.privateKey,
		signerCertificate: ca.certificate.pem,
		responses: [
			{
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				certStatus: 'good',
				thisUpdate: baseThisUpdate,
				nextUpdate,
			},
		],
	});

	return {
		chain,
		at,
		forgedNewerDelta: forgedNewerDelta.der,
		ocspGood: ocspGood.der,
		caDer: ca.certificate.der,
		base: (revokes: boolean) =>
			crl({
				signerPrivateKey: ca.keyPair.privateKey,
				crlNumber: 5,
				thisUpdate: baseThisUpdate,
				...(revokes ? { revokedCertificates: revocation } : {}),
			}),
		revokingDelta: () =>
			crl({
				signerPrivateKey: ca.keyPair.privateKey,
				crlNumber: 6,
				baseCrlNumber: 5,
				thisUpdate: new Date(at.getTime() - 2 * HOUR_MS),
				revokedCertificates: revocation,
			}),
	};
}

type Scenario = Awaited<ReturnType<typeof scenario>>;

async function verdict(
	s: Scenario,
	crls: readonly Uint8Array[],
	ocspResponses: readonly Uint8Array[],
) {
	const result = await checkChainRevocation({ chain: s.chain, crls, ocspResponses, at: s.at });
	const status = result.value.certificates[0];
	return { decision: result.value.decision, status: status?.status, source: status?.source?.kind };
}

describe('checkChainRevocation with a delta CRL whose signature does not verify', () => {
	it('fixes the premise: the forged delta is newer and fails authentication', async () => {
		const s = await scenario();
		expect(
			await validateCertificateRevocationList({
				crl: s.forgedNewerDelta,
				issuerCertificate: s.caDer,
				at: s.at,
			}),
		).toMatchObject({ ok: false, code: 'signature_invalid' });
	});

	it('keeps an authentic revoking delta in force, in either evidence order', async () => {
		const s = await scenario();
		const base = (await s.base(false)).der;
		const delta = (await s.revokingDelta()).der;
		for (const crls of [
			[base, delta, s.forgedNewerDelta],
			[base, s.forgedNewerDelta, delta],
		]) {
			expect(await verdict(s, crls, [s.ocspGood])).toEqual({
				decision: 'deny',
				status: 'revoked',
				source: 'crl',
			});
			expect(await verdict(s, crls, [])).toEqual({
				decision: 'deny',
				status: 'revoked',
				source: 'crl',
			});
		}
	});

	it("keeps the base CRL's own revocation in force when only a forged delta is offered", async () => {
		const s = await scenario();
		const base = (await s.base(true)).der;
		expect(await verdict(s, [base, s.forgedNewerDelta], [s.ocspGood])).toEqual({
			decision: 'deny',
			status: 'revoked',
			source: 'crl',
		});
	});

	it('falls back to the base CRL alone when no delta authenticates', async () => {
		const s = await scenario();
		const base = (await s.base(false)).der;
		expect(await verdict(s, [base, s.forgedNewerDelta], [])).toEqual({
			decision: 'allow',
			status: 'good',
			source: 'crl',
		});
	});
});
