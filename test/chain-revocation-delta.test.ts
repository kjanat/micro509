import { describe, expect, it } from 'bun:test';
import {
	checkCertificateRevocationAgainstCrl,
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
import { addRevokedEntryCertificateIssuers, hexToBytes } from '#test/helpers';

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

	const forgedDeltas = (count: number, baseCrlNumber = 5) =>
		Promise.all(
			Array.from(
				{ length: count },
				async (_, index) =>
					(
						await crl({
							signerPrivateKey: attackerKeys.privateKey,
							crlNumber: 100 + index,
							baseCrlNumber,
							thisUpdate: new Date(at.getTime() - HOUR_MS),
						})
					).der,
			),
		);
	const ocspRevoked = await createOcspResponse({
		signerPrivateKey: ca.keyPair.privateKey,
		signerCertificate: ca.certificate.pem,
		responses: [
			{
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				certStatus: 'revoked',
				revokedAt: baseThisUpdate,
				revocationReasonCode: 1,
				thisUpdate: baseThisUpdate,
				nextUpdate,
			},
		],
	});

	return {
		chain,
		at,
		leafPem: leaf.pem,
		caPem: ca.certificate.pem,
		crl,
		forgedDeltas,
		forgedNewerDelta: forgedNewerDelta.der,
		ocspRevoked: ocspRevoked.der,
		ocspGood: ocspGood.der,
		caDer: ca.certificate.der,
		base: (revokes: boolean) =>
			crl({
				signerPrivateKey: ca.keyPair.privateKey,
				crlNumber: 5,
				thisUpdate: baseThisUpdate,
				...(revokes ? { revokedCertificates: revocation } : {}),
			}),
		baseNumbered: (crlNumber: number) =>
			crl({ signerPrivateKey: ca.keyPair.privateKey, crlNumber, thisUpdate: baseThisUpdate }),
		unresolvableDelta: () =>
			crl({
				signerPrivateKey: ca.keyPair.privateKey,
				crlNumber: 8,
				baseCrlNumber: 5,
				thisUpdate: new Date(at.getTime() - HOUR_MS),
				revokedCertificates: [...revocation, ...revocation],
			}),
		unsupportedIssuerDelta: async () =>
			addRevokedEntryCertificateIssuers(
				(
					await crl({
						signerPrivateKey: ca.keyPair.privateKey,
						crlNumber: 8,
						baseCrlNumber: 5,
						thisUpdate: new Date(at.getTime() - HOUR_MS),
						revokedCertificates: revocation,
					})
				).der,
				ca.keyPair.privateKey,
				[{ entryIndex: 0, names: [{ type: 'email', value: 'unsupported@example.test' }] }],
			),
		olderGoodDelta: () =>
			crl({
				signerPrivateKey: ca.keyPair.privateKey,
				crlNumber: 6,
				baseCrlNumber: 5,
				thisUpdate: new Date(at.getTime() - 2 * HOUR_MS),
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

async function leafStatus(
	s: Scenario,
	crls: readonly Uint8Array[],
	ocspResponses: readonly Uint8Array[],
	mode: 'hard-fail' | 'soft-fail' = 'hard-fail',
) {
	const result = await checkChainRevocation({
		chain: s.chain,
		crls,
		ocspResponses,
		at: s.at,
		policy: { mode },
	});
	const status = result.value.certificates[0];
	return {
		decision: result.value.decision,
		status: status?.status,
		indeterminateReasons: status?.indeterminateReasons,
	};
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

describe('checkChainRevocation with an authenticated delta CRL that cannot settle the status', () => {
	it('fixes the premise: the delta lists the certificate twice, which fails as signature_invalid', async () => {
		const s = await scenario();
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: s.leafPem,
				issuerCertificate: s.caPem,
				crl: (await s.base(false)).der,
				deltaCrl: (await s.unresolvableDelta()).der,
				at: s.at,
			}),
		).toMatchObject({ ok: false, code: 'signature_invalid' });
	});

	it('fixes the premise: an entry naming only an email certificateIssuer is non_applicable', async () => {
		const s = await scenario();
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: s.leafPem,
				issuerCertificate: s.caPem,
				crl: (await s.base(false)).der,
				deltaCrl: await s.unsupportedIssuerDelta(),
				at: s.at,
			}),
		).toMatchObject({
			ok: false,
			code: 'non_applicable',
			details: { reason: 'unsupported_indirect_crl' },
		});
	});

	it('stays indeterminate over the base CRL, an older delta CRL and OCSP good', async () => {
		const s = await scenario();
		for (const unusable of [(await s.unresolvableDelta()).der, await s.unsupportedIssuerDelta()]) {
			const crls = [(await s.base(false)).der, (await s.olderGoodDelta()).der, unusable];
			expect(await leafStatus(s, crls, [s.ocspGood])).toEqual({
				decision: 'deny',
				status: 'indeterminate',
				indeterminateReasons: ['delta_crl_unusable'],
			});
			expect(await leafStatus(s, crls, [s.ocspGood], 'soft-fail')).toEqual({
				decision: 'allow',
				status: 'indeterminate',
				indeterminateReasons: ['delta_crl_unusable'],
			});
		}
	});

	it('yields to an OCSP revocation', async () => {
		const s = await scenario();
		const crls = [(await s.base(false)).der, (await s.unresolvableDelta()).der];
		expect(await verdict(s, crls, [s.ocspRevoked])).toEqual({
			decision: 'deny',
			status: 'revoked',
			source: 'ocsp',
		});
	});
});

describe('checkChainRevocation delta CRL attempt limits', () => {
	it('evaluates the base CRL alone after rejecting four delta CRLs', async () => {
		const s = await scenario();
		const crls = [(await s.base(false)).der, ...(await s.forgedDeltas(4))];
		expect(await leafStatus(s, crls, [])).toEqual({
			decision: 'allow',
			status: 'good',
			indeterminateReasons: undefined,
		});
	});

	it('stays indeterminate over OCSP good when a fifth delta CRL is left unexamined', async () => {
		const s = await scenario();
		const crls = [(await s.base(false)).der, ...(await s.forgedDeltas(5))];
		expect(await leafStatus(s, crls, [s.ocspGood])).toEqual({
			decision: 'deny',
			status: 'indeterminate',
			indeterminateReasons: ['delta_crl_retry_limit_exceeded'],
		});
	});

	it('spends at most 32 delta CRL checks per call', async () => {
		const s = await scenario();
		const deltas = await s.forgedDeltas(4, 1);
		const bases = async (count: number) =>
			Promise.all(
				Array.from({ length: count }, async (_, index) => (await s.baseNumbered(index + 1)).der),
			);
		expect(await leafStatus(s, [...(await bases(8)), ...deltas], [])).toEqual({
			decision: 'allow',
			status: 'good',
			indeterminateReasons: undefined,
		});
		expect(await leafStatus(s, [...(await bases(9)), ...deltas], [])).toEqual({
			decision: 'deny',
			status: 'indeterminate',
			indeterminateReasons: ['no_applicable_ocsp', 'delta_crl_retry_limit_exceeded'],
		});
	});

	it('shares the per-base limit between CRL signer candidates', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Delta Budget Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const untrusted = await createSelfSignedCertificate({
			subject: { commonName: 'Delta Budget Untrusted Root' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crlIssuerKeys = await generateKeyPair();
		const crlIssuerName = { commonName: 'Delta Budget CRL Issuer' };
		const signerFrom = (issuer: typeof root, issuerName: string) =>
			createCertificate({
				issuer: { commonName: issuerName },
				subject: crlIssuerName,
				publicKey: crlIssuerKeys.publicKey,
				signerPrivateKey: issuer.keyPair.privateKey,
				issuerPublicKey: issuer.keyPair.publicKey,
				extensions: { keyUsage: ['cRLSign'] },
			});
		const genuineSigner = await signerFrom(root, 'Delta Budget Root');
		const rogueSigner = await signerFrom(untrusted, 'Delta Budget Untrusted Root');
		const uri = 'http://example.test/delta-budget.crl';
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Delta Budget Root' },
			subject: { commonName: 'delta-budget.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: { type: 'fullName', fullName: [{ type: 'uri', value: uri }] },
						crlIssuer: [
							{
								type: 'directoryName',
								derHex: unwrap(parseCertificatePem(genuineSigner.pem)).subject.derHex,
							},
						],
					},
				],
			},
		});
		const at = new Date(Date.now() + 5_000);
		const thisUpdate = new Date(at.getTime() - HOUR_MS);
		const indirectCrl = (
			fields: Pick<
				Parameters<typeof createCertificateRevocationList>[0],
				'signerPrivateKey' | 'crlNumber' | 'baseCrlNumber'
			>,
		) =>
			createCertificateRevocationList({
				issuer: crlIssuerName,
				issuerPublicKey: crlIssuerKeys.publicKey,
				thisUpdate,
				nextUpdate: new Date(at.getTime() + 24 * HOUR_MS),
				issuingDistributionPoint: {
					distributionPoint: { type: 'fullName', fullName: [{ type: 'uri', value: uri }] },
					indirectCrl: true,
				},
				...fields,
			});
		const attackerKeys = await generateKeyPair();
		const crls = [
			(await indirectCrl({ signerPrivateKey: crlIssuerKeys.privateKey, crlNumber: 5 })).der,
			...(await Promise.all(
				[6, 7, 8].map(
					async (crlNumber) =>
						(
							await indirectCrl({
								signerPrivateKey: attackerKeys.privateKey,
								crlNumber,
								baseCrlNumber: 5,
							})
						).der,
				),
			)),
		];
		const chain = [
			unwrap(parseCertificatePem(leaf.pem)),
			unwrap(parseCertificatePem(root.certificate.pem)),
		];
		const evaluate = async (extraCertificates: readonly string[]) => {
			const result = await checkChainRevocation({ chain, crls, extraCertificates, at });
			return (
				result.value.certificates[0]?.indeterminateReasons ?? result.value.certificates[0]?.status
			);
		};
		expect(await evaluate([genuineSigner.pem])).toBe('good');
		expect(await evaluate([rogueSigner.pem, genuineSigner.pem])).toEqual([
			'no_applicable_ocsp',
			'delta_crl_retry_limit_exceeded',
		]);
	});
});
