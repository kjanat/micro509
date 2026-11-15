import { describe, expect, it } from 'bun:test';
import type { CrlSource } from '#micro509';
import {
	checkCertificateRevocation,
	checkCertificateRevocationAgainstCrl,
	checkChainRevocation,
	createCertificate,
	createCertificateRevocationList,
	createOcspResponse,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificatePem,
	parseCertificateRevocationListDer,
	unwrap,
	validateCertificateRevocationList,
} from '#micro509';
import { callerVerification } from '#micro509/internal/crypto/sig-verify';
import { checkCertificateRevocationAgainstCrlsBy } from '#micro509/revocation/crl';
import { addRevokedEntryCertificateIssuers, hexToBytes, withCrlIssuer } from '#test/helpers';

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
		issuerCertificate: ca.certificate.der,
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
			'issuer' | 'issuerCertificate' | 'nextUpdate'
		>,
	): ReturnType<typeof createCertificateRevocationList> =>
		createCertificateRevocationList({
			issuer: { commonName: CA_NAME },
			issuerCertificate: ca.certificate.der,
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

	const forgedDeltas = (count: number, baseCrlNumber = 5, firstCrlNumber = 100) =>
		Promise.all(
			Array.from(
				{ length: count },
				async (_, index) =>
					(
						await crl({
							signerPrivateKey: attackerKeys.privateKey,
							crlNumber: firstCrlNumber + index,
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
		baseNumbered: (crlNumber: number, reasonCode?: 'keyCompromise' | 'certificateHold') =>
			crl({
				signerPrivateKey: ca.keyPair.privateKey,
				crlNumber,
				thisUpdate: baseThisUpdate,
				...(reasonCode === undefined
					? {}
					: { revokedCertificates: revocation.map((entry) => ({ ...entry, reasonCode })) }),
			}),
		caOnlyBase: (crlNumber: number) =>
			crl({
				signerPrivateKey: ca.keyPair.privateKey,
				crlNumber,
				thisUpdate: baseThisUpdate,
				issuingDistributionPoint: { onlyContainsCACerts: true },
			}),
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
		forgedBase: () =>
			crl({
				signerPrivateKey: attackerKeys.privateKey,
				crlNumber: 5,
				thisUpdate: baseThisUpdate,
			}),
		printableIssuerRevokingDelta: async () => {
			const delta = await crl({
				signerPrivateKey: ca.keyPair.privateKey,
				crlNumber: 6,
				baseCrlNumber: 5,
				thisUpdate: new Date(at.getTime() - 2 * HOUR_MS),
				revokedCertificates: revocation,
			});
			const utf8Name = unwrap(parseCertificatePem(ca.certificate.pem)).subject.derHex;
			const printableName = utf8Name.replace(
				`0c0f${Buffer.from(CA_NAME).toString('hex')}`,
				`130f${Buffer.from(CA_NAME).toString('hex')}`,
			);
			if (printableName === utf8Name) throw new Error('expected a UTF8String common name');
			return withCrlIssuer(delta.der, ca.keyPair.privateKey, hexToBytes(printableName));
		},
		otherScopeDeltas: (count: number) =>
			Promise.all(
				Array.from(
					{ length: count },
					async (_, index) =>
						(
							await crl({
								signerPrivateKey: ca.keyPair.privateKey,
								crlNumber: 100 + index,
								baseCrlNumber: 5,
								thisUpdate: new Date(at.getTime() - HOUR_MS),
								issuingDistributionPoint: { onlyContainsCACerts: true },
							})
						).der,
				),
			),
		olderGoodDelta: () =>
			crl({
				signerPrivateKey: ca.keyPair.privateKey,
				crlNumber: 6,
				baseCrlNumber: 5,
				thisUpdate: new Date(at.getTime() - 2 * HOUR_MS),
			}),
		expiredDelta: (reasonCode: 'keyCompromise' | 'certificateHold') =>
			createCertificateRevocationList({
				issuer: { commonName: CA_NAME },
				issuerCertificate: ca.certificate.der,
				signerPrivateKey: ca.keyPair.privateKey,
				crlNumber: 6,
				baseCrlNumber: 5,
				thisUpdate: new Date(at.getTime() - 2 * HOUR_MS),
				nextUpdate: new Date(at.getTime() - HOUR_MS),
				revokedCertificates: revocation.map((entry) => ({ ...entry, reasonCode })),
			}),
		expiredCleanDeltas: (count: number) =>
			Promise.all(
				Array.from(
					{ length: count },
					async (_, index) =>
						(
							await createCertificateRevocationList({
								issuer: { commonName: CA_NAME },
								issuerCertificate: ca.certificate.der,
								signerPrivateKey: ca.keyPair.privateKey,
								crlNumber: 10 + index,
								baseCrlNumber: 5,
								thisUpdate: new Date(at.getTime() - 2 * HOUR_MS + index * 60_000),
								nextUpdate: new Date(at.getTime() - HOUR_MS + index * 60_000),
							})
						).der,
				),
			),
		newerCleanDelta: () =>
			crl({
				signerPrivateKey: ca.keyPair.privateKey,
				crlNumber: 7,
				baseCrlNumber: 5,
				thisUpdate: new Date(at.getTime() - HOUR_MS),
			}),
		revokingDelta: (baseCrlNumber = 5, crlNumber = 6) =>
			crl({
				signerPrivateKey: ca.keyPair.privateKey,
				crlNumber,
				baseCrlNumber,
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
	crls: readonly CrlSource[],
	ocspResponses: readonly Uint8Array[],
	mode: 'hard-fail' | 'soft-fail' = 'hard-fail',
	limits: { readonly clockSkewMs?: number; readonly crlMaxAgeMs?: number } = {},
) {
	const result = await checkChainRevocation({
		chain: s.chain,
		crls,
		ocspResponses,
		at: s.at,
		policy: { mode, ...limits },
	});
	const status = result.value.certificates[0];
	return {
		decision: result.value.decision,
		status: status?.status,
		indeterminateReasons: status?.indeterminateReasons,
	};
}

const HELPER_BASES = {
	clean: (s: Scenario) => s.baseNumbered(5),
	keyCompromise: (s: Scenario) => s.baseNumbered(5, 'keyCompromise'),
	certificateHold: (s: Scenario) => s.baseNumbered(5, 'certificateHold'),
	forged: (s: Scenario) => s.forgedBase(),
};

const HELPER_DELTAS = {
	none: async () => [],
	revoking: async (s: Scenario) => [(await s.revokingDelta()).der],
	'forged and revoking': async (s: Scenario) => [s.forgedNewerDelta, (await s.revokingDelta()).der],
	'four forged': (s: Scenario) => s.forgedDeltas(4),
	'five forged': (s: Scenario) => s.forgedDeltas(5),
	unresolvable: async (s: Scenario) => [(await s.unresolvableDelta()).der],
	'PrintableString-issuer revoking': async (s: Scenario) => [
		await s.printableIssuerRevokingDelta(),
	],
	'five other-scope': (s: Scenario) => s.otherScopeDeltas(5),
	'expired revoking': async (s: Scenario) => [(await s.expiredDelta('keyCompromise')).der],
	'expired holding': async (s: Scenario) => [(await s.expiredDelta('certificateHold')).der],
	'six expired clean': (s: Scenario) => s.expiredCleanDeltas(6),
	'newer current clean and older expired revoking': async (s: Scenario) => [
		(await s.expiredDelta('keyCompromise')).der,
		(await s.newerCleanDelta()).der,
	],
	'forged and expired revoking': async (s: Scenario) => [
		...(await s.forgedDeltas(1)),
		(await s.expiredDelta('keyCompromise')).der,
	],
} satisfies Record<string, (s: Scenario) => Promise<readonly Uint8Array[]>>;

describe('checkCertificateRevocationAgainstCrlsBy', () => {
	it.each([
		{ base: 'clean', deltas: 'none', expected: 'good' },
		{ base: 'clean', deltas: 'revoking', expected: 'revoked' },
		{ base: 'clean', deltas: 'forged and revoking', expected: 'revoked' },
		{ base: 'clean', deltas: 'four forged', expected: 'good' },
		{ base: 'clean', deltas: 'five forged', expected: 'unsettled' },
		{ base: 'keyCompromise', deltas: 'five forged', expected: 'revoked' },
		{ base: 'certificateHold', deltas: 'five forged', expected: 'unsettled' },
		{ base: 'clean', deltas: 'unresolvable', expected: 'unsettled' },
		{ base: 'keyCompromise', deltas: 'unresolvable', expected: 'revoked' },
		{ base: 'forged', deltas: 'revoking', expected: 'signature_invalid' },
		{ base: 'clean', deltas: 'PrintableString-issuer revoking', expected: 'revoked' },
		{ base: 'clean', deltas: 'five other-scope', expected: 'good' },
		{ base: 'clean', deltas: 'expired revoking', expected: 'revoked' },
		{ base: 'clean', deltas: 'forged and expired revoking', expected: 'revoked' },
		{ base: 'clean', deltas: 'expired holding', expected: 'good' },
		{ base: 'clean', deltas: 'six expired clean', expected: 'good' },
		{
			base: 'clean',
			deltas: 'newer current clean and older expired revoking',
			expected: 'revoked',
		},
	] as const)(
		'checks a $base base CRL with $deltas delta CRLs as $expected',
		async ({ base, deltas, expected }) => {
			const s = await scenario();
			const parse = (der: Uint8Array) => unwrap(parseCertificateRevocationListDer(der));
			const result = await checkCertificateRevocationAgainstCrlsBy(
				unwrap(parseCertificatePem(s.leafPem)),
				parse((await HELPER_BASES[base](s)).der),
				(await HELPER_DELTAS[deltas](s)).map(parse),
				{ kind: 'certificate', certificate: s.caPem },
				{ at: s.at },
				callerVerification(undefined),
			);
			expect(
				result.kind === 'unsettled'
					? 'unsettled'
					: result.result.ok
						? result.result.value.status
						: result.result.code,
			).toBe(expected);
		},
	);
});

describe('checkCertificateRevocationAgainstCrlsBy with a shared delta CRL budget', () => {
	it.each([
		{ remaining: 4, expected: 'good' },
		{ remaining: 3, expected: 'unsettled' },
		{ remaining: 0, expected: 'unsettled' },
	] as const)(
		'checks four forged delta CRLs with $remaining attempts left as $expected',
		async ({ remaining, expected }) => {
			const s = await scenario();
			const parse = (der: Uint8Array) => unwrap(parseCertificateRevocationListDer(der));
			const budget = { remaining };
			const result = await checkCertificateRevocationAgainstCrlsBy(
				unwrap(parseCertificatePem(s.leafPem)),
				parse((await s.baseNumbered(5)).der),
				(await s.forgedDeltas(4)).map(parse),
				{ kind: 'certificate', certificate: s.caPem },
				{ at: s.at },
				callerVerification(undefined),
				[budget],
			);
			expect(
				result.kind === 'unsettled'
					? 'unsettled'
					: result.result.ok
						? result.result.value.status
						: result.result.code,
			).toBe(expected);
			expect(budget.remaining).toBe(0);
		},
	);
});

describe('checkCertificateRevocationAgainstCrlsBy with a complete CRL that does not cover the certificate', () => {
	it('spends no delta CRL attempt on it', async () => {
		const s = await scenario();
		const parse = (der: Uint8Array) => unwrap(parseCertificateRevocationListDer(der));
		const attacker = await generateKeyPair();
		const forged = await Promise.all(
			Array.from({ length: 5 }, async (_, index) =>
				parse(
					(
						await s.crl({
							signerPrivateKey: attacker.privateKey,
							crlNumber: 100 + index,
							baseCrlNumber: 5,
							thisUpdate: new Date(s.at.getTime() - HOUR_MS),
							issuingDistributionPoint: { onlyContainsCACerts: true },
						})
					).der,
				),
			),
		);
		const budget = { remaining: 32 };
		const result = await checkCertificateRevocationAgainstCrlsBy(
			unwrap(parseCertificatePem(s.leafPem)),
			parse((await s.caOnlyBase(5)).der),
			forged,
			{ kind: 'certificate', certificate: s.caPem },
			{ at: s.at },
			callerVerification(undefined),
			[budget],
		);
		expect(result).toMatchObject({
			kind: 'checked',
			result: { ok: false, code: 'non_applicable' },
		});
		expect(budget.remaining).toBe(32);
	});
});

describe('checkCertificateRevocationAgainstCrl and checkCertificateRevocation with a delta CRL that fails', () => {
	it.each([
		{ base: 'keyCompromise', delta: 'forged', crl: 'revoked', evidence: 'revoked' },
		{ base: 'keyCompromise', delta: 'unresolvable', crl: 'revoked', evidence: 'revoked' },
		{ base: 'certificateHold', delta: 'forged', crl: 'signature_invalid', evidence: 'good' },
		{ base: 'clean', delta: 'forged', crl: 'signature_invalid', evidence: 'good' },
		{ base: 'clean', delta: 'unresolvable', crl: 'signature_invalid', evidence: 'good' },
		{ base: 'clean', delta: 'expired revoking', crl: 'revoked', evidence: 'revoked' },
		{ base: 'clean', delta: 'expired holding', crl: 'stale_crl', evidence: 'good' },
	] as const)(
		'keeps a $base base CRL entry beside a $delta delta CRL as $crl',
		async ({ base, delta, crl, evidence }) => {
			const s = await scenario();
			const baseDer = (await HELPER_BASES[base](s)).der;
			const deltaDer =
				delta === 'forged'
					? ((await s.forgedDeltas(1))[0] ?? s.forgedNewerDelta)
					: delta === 'unresolvable'
						? (await s.unresolvableDelta()).der
						: (
								await s.expiredDelta(
									delta === 'expired revoking' ? 'keyCompromise' : 'certificateHold',
								)
							).der;
			const direct = await checkCertificateRevocationAgainstCrl({
				certificate: s.leafPem,
				issuerCertificate: s.caPem,
				crl: baseDer,
				deltaCrl: deltaDer,
				at: s.at,
			});
			expect(direct.ok ? direct.value.status : direct.code).toBe(crl);
			const combined = await checkCertificateRevocation({
				certificate: s.leafPem,
				issuerCertificate: s.caPem,
				evidence: [
					{ kind: 'crl', crl: baseDer, deltaCrl: deltaDer },
					{ kind: 'ocsp', response: s.ocspGood },
				],
				at: s.at,
			});
			expect(combined).toMatchObject({ ok: true, value: { status: evidence } });
		},
	);
});

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

	it("keeps the base CRL's keyCompromise revocation in force", async () => {
		const s = await scenario();
		const crls = [(await s.base(true)).der, (await s.unresolvableDelta()).der];
		expect(await leafStatus(s, crls, [s.ocspGood], 'soft-fail')).toEqual({
			decision: 'deny',
			status: 'revoked',
			indeterminateReasons: undefined,
		});
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

describe('checkChainRevocation with a delta CRL past its nextUpdate', () => {
	it('reads a current clean base CRL beside six authentic delta CRLs past their nextUpdate as good', async () => {
		const s = await scenario();
		const crls = [(await s.base(false)).der, ...(await s.expiredCleanDeltas(6))];
		expect(await leafStatus(s, crls, [])).toEqual({
			decision: 'allow',
			status: 'good',
			indeterminateReasons: undefined,
		});
	});

	it('reads a permanent revocation an older expired delta CRL records beside a newer clean one', async () => {
		const s = await scenario();
		const crls = [
			(await s.base(false)).der,
			(await s.newerCleanDelta()).der,
			(await s.expiredDelta('keyCompromise')).der,
		];
		expect(await leafStatus(s, crls, [s.ocspGood], 'soft-fail')).toEqual({
			decision: 'deny',
			status: 'revoked',
			indeterminateReasons: undefined,
		});
	});

	it.each([
		{ reason: 'keyCompromise', mode: 'hard-fail', decision: 'deny', status: 'revoked' },
		{ reason: 'keyCompromise', mode: 'soft-fail', decision: 'deny', status: 'revoked' },
		{ reason: 'certificateHold', mode: 'hard-fail', decision: 'allow', status: 'good' },
	] as const)(
		'reads a $reason entry beside a current clean base CRL under $mode as $status',
		async ({ reason, mode, decision, status }) => {
			const s = await scenario();
			const crls = [(await s.base(false)).der, (await s.expiredDelta(reason)).der];
			expect(await leafStatus(s, crls, [s.ocspGood], mode)).toEqual({
				decision,
				status,
				indeterminateReasons: undefined,
			});
		},
	);
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

	it('spends no delta CRL attempts on a CRL signer candidate that is not authorized', async () => {
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
				issuerCertificate: issuer.certificate.der,
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
			issuerCertificate: root.certificate.der,
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
				issuerCertificate: genuineSigner.der,
				thisUpdate,
				nextUpdate: new Date(at.getTime() + 24 * HOUR_MS),
				issuingDistributionPoint: {
					distributionPoint: { type: 'fullName', fullName: [{ type: 'uri', value: uri }] },
					indirectCrl: true,
				},
				...fields,
			});
		const attackerKeys = await generateKeyPair();
		const rootCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Budget Root' },
			signerPrivateKey: root.keyPair.privateKey,
			issuerCertificate: root.certificate.der,
			crlNumber: 1,
			thisUpdate,
			nextUpdate: new Date(at.getTime() + 24 * HOUR_MS),
		});
		const crls = [
			rootCrl.der,
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
		expect(await evaluate([rogueSigner.pem, genuineSigner.pem])).toBe('good');
		expect(await evaluate([genuineSigner.pem, rogueSigner.pem])).toBe('good');
	});
});

describe('checkChainRevocation delta CRL attempt limits for a CRL signer', () => {
	it.each([
		{ signerBases: 8, copies: 1, expected: 'good' },
		{ signerBases: 8, copies: 2, expected: 'good' },
		{ signerBases: 9, copies: 1, expected: ['no_applicable_ocsp', 'crl_signer_indeterminate'] },
	] as const)(
		'counts the delta CRL checks for a CRL signer against the 32 per call ($signerBases signer base CRLs, $copies copies each)',
		async ({ signerBases, copies, expected }) => {
			const root = await createSelfSignedCertificate({
				subject: { commonName: 'Signer Budget Root' },
				extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
			});
			const signerKeys = await generateKeyPair();
			const signer = await createCertificate({
				issuer: { commonName: 'Signer Budget Root' },
				subject: { commonName: 'Signer Budget CRL Issuer' },
				publicKey: signerKeys.publicKey,
				signerPrivateKey: root.keyPair.privateKey,
				issuerCertificate: root.certificate.der,
				extensions: { keyUsage: ['cRLSign'] },
			});
			const uri = 'http://example.test/signer-budget.crl';
			const leaf = await createCertificate({
				issuer: { commonName: 'Signer Budget Root' },
				subject: { commonName: 'signer-budget.example' },
				publicKey: (await generateKeyPair()).publicKey,
				signerPrivateKey: root.keyPair.privateKey,
				issuerCertificate: root.certificate.der,
				extensions: {
					crlDistributionPoints: [
						{
							distributionPoint: { type: 'fullName', fullName: [{ type: 'uri', value: uri }] },
							crlIssuer: [
								{
									type: 'directoryName',
									derHex: unwrap(parseCertificatePem(signer.pem)).subject.derHex,
								},
							],
						},
					],
				},
			});
			const at = new Date(Date.now() + 5_000);
			const thisUpdate = new Date(at.getTime() - HOUR_MS);
			const nextUpdate = new Date(at.getTime() + 24 * HOUR_MS);
			const leafCrl = await createCertificateRevocationList({
				issuer: { commonName: 'Signer Budget CRL Issuer' },
				issuerCertificate: signer.der,
				signerPrivateKey: signerKeys.privateKey,
				crlNumber: 1,
				thisUpdate,
				nextUpdate,
				issuingDistributionPoint: {
					distributionPoint: { type: 'fullName', fullName: [{ type: 'uri', value: uri }] },
					indirectCrl: true,
				},
			});
			const attackerKeys = await generateKeyPair();
			const rootCrl = (crlNumber: number, baseCrlNumber?: number) =>
				createCertificateRevocationList({
					issuer: { commonName: 'Signer Budget Root' },
					issuerCertificate: root.certificate.der,
					signerPrivateKey:
						baseCrlNumber === undefined ? root.keyPair.privateKey : attackerKeys.privateKey,
					crlNumber,
					...(baseCrlNumber === undefined ? {} : { baseCrlNumber }),
					thisUpdate,
					nextUpdate,
				});
			const signerCrls = [
				...(await Promise.all(
					Array.from({ length: signerBases }, async (_, index) => (await rootCrl(index + 1)).der),
				)),
				...(await Promise.all(
					[100, 101, 102, 103].map(async (crlNumber) => (await rootCrl(crlNumber, 1)).der),
				)),
			];
			const crls = [leafCrl.der, ...Array.from({ length: copies }, () => signerCrls).flat()];
			const result = await checkChainRevocation({
				chain: [
					unwrap(parseCertificatePem(leaf.pem)),
					unwrap(parseCertificatePem(root.certificate.pem)),
				],
				crls,
				extraCertificates: [signer.pem],
				at,
			});
			const status = result.value.certificates[0];
			expect(status?.indeterminateReasons ?? status?.status).toEqual(expected);
		},
	);
});

describe('checkChainRevocation delta CRL attempt limits for a delegated OCSP responder', () => {
	it.each([
		{ bases: 4, expected: 'good' },
		{ bases: 5, expected: ['delta_crl_retry_limit_exceeded'] },
	] as const)(
		'counts the delta CRL checks for the responder against the 32 per call ($bases base CRLs)',
		async ({ bases, expected }) => {
			const ca = await createSelfSignedCertificate({
				subject: { commonName: 'Responder Budget CA' },
				extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
			});
			const issue = async (commonName: string, extendedKeyUsage?: readonly ['ocspSigning']) => {
				const keys = await generateKeyPair();
				const certificate = await createCertificate({
					issuer: { commonName: 'Responder Budget CA' },
					subject: { commonName },
					publicKey: keys.publicKey,
					signerPrivateKey: ca.keyPair.privateKey,
					issuerCertificate: ca.certificate.der,
					...(extendedKeyUsage === undefined ? {} : { extensions: { extendedKeyUsage } }),
				});
				return { keys, certificate };
			};
			const leaf = await issue('responder-budget.example');
			const responder = await issue('Responder Budget Responder', ['ocspSigning']);
			const at = new Date(Date.now() + 5_000);
			const thisUpdate = new Date(at.getTime() - HOUR_MS);
			const nextUpdate = new Date(at.getTime() + 24 * HOUR_MS);
			const attackerKeys = await generateKeyPair();
			const caCrl = (crlNumber: number, baseCrlNumber?: number) =>
				createCertificateRevocationList({
					issuer: { commonName: 'Responder Budget CA' },
					issuerCertificate: ca.certificate.der,
					signerPrivateKey:
						baseCrlNumber === undefined ? ca.keyPair.privateKey : attackerKeys.privateKey,
					crlNumber,
					...(baseCrlNumber === undefined ? {} : { baseCrlNumber }),
					thisUpdate,
					nextUpdate,
				});
			const crls = [
				...(await Promise.all(
					Array.from({ length: bases }, async (_, index) => (await caCrl(index + 1)).der),
				)),
				...(await Promise.all(
					[100, 101, 102, 103].map(async (crlNumber) => (await caCrl(crlNumber, 1)).der),
				)),
			];
			const response = await createOcspResponse({
				signerPrivateKey: responder.keys.privateKey,
				signerCertificate: responder.certificate.pem,
				includedCertificates: [responder.certificate.pem],
				responses: [
					{
						certificate: leaf.certificate.pem,
						issuerCertificate: ca.certificate.pem,
						certStatus: 'good',
						thisUpdate,
						nextUpdate,
					},
				],
			});
			const result = await checkChainRevocation({
				chain: [
					unwrap(parseCertificatePem(leaf.certificate.pem)),
					unwrap(parseCertificatePem(ca.certificate.pem)),
				],
				crls,
				ocspResponses: [response.der],
				at,
			});
			const status = result.value.certificates[0];
			expect(status?.indeterminateReasons ?? status?.status).toEqual(expected);
		},
	);
});

describe('checkChainRevocation delta CRL attempt limits with a base CRL that lists the certificate', () => {
	it('keeps a keyCompromise revocation in force, which no delta CRL can remove', async () => {
		const s = await scenario();
		const crls = [(await s.baseNumbered(5, 'keyCompromise')).der, ...(await s.forgedDeltas(5))];
		expect(await leafStatus(s, crls, [s.ocspGood], 'soft-fail')).toEqual({
			decision: 'deny',
			status: 'revoked',
			indeterminateReasons: undefined,
		});
	});

	it('keeps a keyCompromise revocation in force after the per-call limit runs out', async () => {
		const s = await scenario();
		const bases = await Promise.all(
			Array.from({ length: 8 }, async (_, index) => (await s.baseNumbered(index + 1)).der),
		);
		const revoking = (await s.baseNumbered(9, 'keyCompromise')).der;
		expect(
			await leafStatus(s, [...bases, revoking, ...(await s.forgedDeltas(4, 1))], [], 'soft-fail'),
		).toEqual({ decision: 'deny', status: 'revoked', indeterminateReasons: undefined });
	});

	it('stays indeterminate for a certificateHold, which a delta CRL can remove', async () => {
		const s = await scenario();
		const crls = [(await s.baseNumbered(5, 'certificateHold')).der, ...(await s.forgedDeltas(5))];
		expect(await leafStatus(s, crls, [s.ocspGood])).toEqual({
			decision: 'deny',
			status: 'indeterminate',
			indeterminateReasons: ['delta_crl_retry_limit_exceeded'],
		});
	});
});

describe('checkChainRevocation keeping a base CRL revocation beside delta CRLs it cannot use', () => {
	it('judges certificate expiry at the evaluation time, whatever the clock skew', async () => {
		const s = await scenario();
		const leaf = s.chain[0];
		if (leaf === undefined) throw new Error('chain has no leaf');
		const clockSkewMs = leaf.notAfter.getTime() - s.at.getTime() + HOUR_MS;
		for (const deltas of [await s.forgedDeltas(5), [(await s.unresolvableDelta()).der]]) {
			const crls = [(await s.baseNumbered(5, 'keyCompromise')).der, ...deltas];
			expect(await leafStatus(s, crls, [s.ocspGood], 'soft-fail', { clockSkewMs })).toEqual({
				decision: 'deny',
				status: 'revoked',
				indeterminateReasons: undefined,
			});
		}
	});

	it('lets an unusable but current delta CRL stand in for an over-age base CRL', async () => {
		const s = await scenario();
		const crls = [(await s.base(true)).der, (await s.unresolvableDelta()).der];
		expect(
			await leafStatus(s, crls, [s.ocspGood], 'soft-fail', { crlMaxAgeMs: 2 * HOUR_MS }),
		).toEqual({ decision: 'deny', status: 'revoked', indeterminateReasons: undefined });
	});

	it.each([
		{
			revokes: false,
			expected: {
				decision: 'allow',
				status: 'indeterminate',
				indeterminateReasons: ['delta_crl_retry_limit_exceeded'],
			},
		},
		{
			revokes: true,
			expected: { decision: 'deny', status: 'revoked', indeterminateReasons: undefined },
		},
	] as const)(
		'does not let unexamined delta CRLs stand in for an over-age base CRL (base revokes $revokes)',
		async ({ revokes, expected }) => {
			const s = await scenario();
			const crls = [(await s.base(revokes)).der, ...(await s.forgedDeltas(5))];
			expect(
				await leafStatus(s, crls, [s.ocspGood], 'soft-fail', { crlMaxAgeMs: 2 * HOUR_MS }),
			).toEqual(expected);
		},
	);
});

describe('checkChainRevocation delta CRL attempt limits and evidence that cannot matter', () => {
	it('spends no attempts on delta CRLs for base CRLs that do not cover the certificate', async () => {
		const s = await scenario();
		const outOfScope = await Promise.all(
			Array.from({ length: 8 }, async (_, index) => (await s.caOnlyBase(10 + index)).der),
		);
		const crls = [
			...outOfScope,
			...(await s.forgedDeltas(4, 10)),
			(await s.base(false)).der,
			(await s.revokingDelta()).der,
		];
		expect(await leafStatus(s, crls, [s.ocspGood], 'soft-fail')).toEqual({
			decision: 'deny',
			status: 'revoked',
			indeterminateReasons: undefined,
		});
	});

	it('spends one attempt on repeated copies of the same delta CRL', async () => {
		const s = await scenario();
		const crls = [
			(await s.base(false)).der,
			...Array.from({ length: 4 }, () => s.forgedNewerDelta),
			(await s.revokingDelta()).der,
		];
		expect(await leafStatus(s, crls, [s.ocspGood], 'soft-fail')).toEqual({
			decision: 'deny',
			status: 'revoked',
			indeterminateReasons: undefined,
		});
	});
});

describe('checkChainRevocation with pre-parsed or repeated CRL evidence', () => {
	it("judges a parsed base CRL's applicability from its DER", async () => {
		const s = await scenario();
		const base = unwrap(parseCertificateRevocationListDer((await s.base(true)).der));
		const leafSubject = unwrap(parseCertificatePem(s.leafPem)).subject;
		expect(await leafStatus(s, [{ ...base, issuer: leafSubject }], [s.ocspGood])).toEqual({
			decision: 'deny',
			status: 'revoked',
			indeterminateReasons: undefined,
		});
	});

	it('keeps a parsed delta CRL whose decoded fields copy another delta', async () => {
		const s = await scenario();
		const forged = unwrap(parseCertificateRevocationListDer(s.forgedNewerDelta));
		const authentic = unwrap(parseCertificateRevocationListDer((await s.revokingDelta()).der));
		const disguised = {
			...authentic,
			signatureAlgorithmOid: forged.signatureAlgorithmOid,
			signatureValue: forged.signatureValue,
			tbsCertListDer: forged.tbsCertListDer,
		};
		expect(
			await leafStatus(
				s,
				[(await s.base(false)).der, s.forgedNewerDelta, disguised],
				[],
				'soft-fail',
			),
		).toEqual({ decision: 'deny', status: 'revoked', indeterminateReasons: undefined });
	});

	it('counts parsed copies of one delta CRL once, whatever their decoded fields', async () => {
		const s = await scenario();
		const forged = unwrap(parseCertificateRevocationListDer(s.forgedNewerDelta));
		const copies = Array.from({ length: 4 }, (_, index) => ({
			...forged,
			signatureValue: Uint8Array.of(index),
		}));
		const crls = [(await s.base(false)).der, ...copies, (await s.revokingDelta()).der];
		expect(await leafStatus(s, crls, [s.ocspGood], 'soft-fail')).toEqual({
			decision: 'deny',
			status: 'revoked',
			indeterminateReasons: undefined,
		});
	});

	it('gives repeated copies of one base CRL a single per-base budget', async () => {
		const s = await scenario();
		const base = (await s.base(false)).der;
		const crls = [
			...Array.from({ length: 8 }, () => base),
			...(await s.forgedDeltas(4, 5, 6)),
			(await s.baseNumbered(10)).der,
			(await s.revokingDelta(10, 11)).der,
		];
		expect(await leafStatus(s, crls, [s.ocspGood], 'soft-fail')).toEqual({
			decision: 'deny',
			status: 'revoked',
			indeterminateReasons: undefined,
		});
	});
});
