import { describe, expect, it } from 'bun:test';
import type { CrlSource, SupersededDeltaCrlPolicy } from '#micro509';
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
	validateOcspResponse,
} from '#micro509';
import { callerVerification } from '#micro509/internal/crypto/sig-verify';
import { checkCertificateRevocationAgainstCrlsBy } from '#micro509/revocation/crl';
import {
	addRevokedEntryCertificateIssuers,
	hexToBytes,
	withCrlIssuer,
	withoutCrlNextUpdate,
	withRevokedEntryReasonCode,
} from '#test/helpers';
import {
	PARAMETER_SIGNATURE_OID,
	parameterKey,
	resignedCrl,
} from '#test/oracles/parameter-signature';

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
		newestCleanDelta: () =>
			crl({
				signerPrivateKey: ca.keyPair.privateKey,
				crlNumber: 20,
				baseCrlNumber: 5,
				thisUpdate: new Date(at.getTime() - HOUR_MS / 2),
			}),
		unrecognizedReasonDelta: async () =>
			withRevokedEntryReasonCode(
				(
					await crl({
						signerPrivateKey: ca.keyPair.privateKey,
						crlNumber: 6,
						baseCrlNumber: 5,
						thisUpdate: new Date(at.getTime() - 2 * HOUR_MS),
						revokedCertificates: revocation,
					})
				).der,
				ca.keyPair.privateKey,
				11,
			),
		heldDelta: () =>
			crl({
				signerPrivateKey: ca.keyPair.privateKey,
				crlNumber: 6,
				baseCrlNumber: 5,
				thisUpdate: new Date(at.getTime() - 2 * HOUR_MS),
				revokedCertificates: revocation.map((entry) => ({
					...entry,
					reasonCode: 'certificateHold' as const,
				})),
			}),
		newerCleanDelta: () =>
			crl({
				signerPrivateKey: ca.keyPair.privateKey,
				crlNumber: 7,
				baseCrlNumber: 5,
				thisUpdate: new Date(at.getTime() - HOUR_MS),
			}),
		deltaAt: (
			crlNumber: number,
			thisUpdateHours: number,
			options: {
				readonly nextUpdateHours?: number;
				readonly reasonCode?: 'keyCompromise' | 'certificateHold';
				readonly onlyContainsCACerts?: true;
			} = {},
		) =>
			createCertificateRevocationList({
				issuer: { commonName: CA_NAME },
				issuerCertificate: ca.certificate.der,
				signerPrivateKey: ca.keyPair.privateKey,
				crlNumber,
				baseCrlNumber: 5,
				thisUpdate: new Date(at.getTime() + thisUpdateHours * HOUR_MS),
				nextUpdate:
					options.nextUpdateHours === undefined
						? nextUpdate
						: new Date(at.getTime() + options.nextUpdateHours * HOUR_MS),
				...(options.onlyContainsCACerts === undefined
					? {}
					: { issuingDistributionPoint: { onlyContainsCACerts: true } }),
				...(options.reasonCode === undefined
					? {}
					: {
							revokedCertificates: revocation.map((entry) => ({
								...entry,
								reasonCode: options.reasonCode,
							})),
						}),
			}),
		withoutNextUpdate: (der: Uint8Array) => withoutCrlNextUpdate(der, ca.keyPair.privateKey),
		delegatedOcspGood: async () => {
			const responderKeys = await generateKeyPair();
			const responder = await createCertificate({
				issuer: { commonName: CA_NAME },
				subject: { commonName: 'Delta Shadow Responder' },
				publicKey: responderKeys.publicKey,
				signerPrivateKey: ca.keyPair.privateKey,
				issuerCertificate: ca.certificate.der,
				extensions: { extendedKeyUsage: ['ocspSigning'] },
			});
			return (
				await createOcspResponse({
					signerPrivateKey: responderKeys.privateKey,
					signerCertificate: responder.der,
					includedCertificates: [responder.der],
					responses: [
						{
							certificate: leaf.pem,
							issuerCertificate: ca.certificate.pem,
							certStatus: 'good',
							thisUpdate: baseThisUpdate,
							nextUpdate,
						},
					],
				})
			).der;
		},
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
	limits: {
		readonly clockSkewMs?: number;
		readonly crlMaxAgeMs?: number;
		readonly unreadSupersededDeltaCrls?: SupersededDeltaCrlPolicy;
	} = {},
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

async function ders(
	crls: readonly ReturnType<typeof createCertificateRevocationList>[],
): Promise<readonly Uint8Array[]> {
	return (await Promise.all(crls)).map((crl) => crl.der);
}

function olderCleanAndNewerExpiredRevoking(
	s: Scenario,
	clean: number,
): Promise<readonly Uint8Array[]> {
	return ders([
		...Array.from({ length: clean }, (_, index) => s.deltaAt(6 + index, -2.5 + index / 4)),
		s.deltaAt(10, -1, { nextUpdateHours: -0.5, reasonCode: 'keyCompromise' }),
	]);
}

function newerExpiredCleanAndOlderCurrentRevoking(
	s: Scenario,
	expired: number,
): Promise<readonly Uint8Array[]> {
	return ders([
		s.deltaAt(7, -2, { reasonCode: 'keyCompromise' }),
		...Array.from({ length: expired }, (_, index) =>
			s.deltaAt(40 - index, -1 - index / 20, { nextUpdateHours: -0.5 }),
		),
	]);
}

function fullNameDistributionPoint(uri: string) {
	return { type: 'fullName' as const, fullName: [{ type: 'uri' as const, value: uri }] };
}

async function responderScopedScenario() {
	const ca = await createSelfSignedCertificate({
		subject: { commonName: 'Responder Scope CA' },
		extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
	});
	const responderUri = 'http://example.test/responders.crl';
	const issue = async (
		commonName: string,
		uri: string,
		extendedKeyUsage?: readonly ['ocspSigning'],
	) => {
		const keys = await generateKeyPair();
		const certificate = await createCertificate({
			issuer: { commonName: 'Responder Scope CA' },
			subject: { commonName },
			publicKey: keys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerCertificate: ca.certificate.der,
			extensions: {
				crlDistributionPoints: [{ distributionPoint: fullNameDistributionPoint(uri) }],
				...(extendedKeyUsage === undefined ? {} : { extendedKeyUsage }),
			},
		});
		return { keys, certificate };
	};
	const leaf = await issue('responder-scope.example', 'http://example.test/leaves.crl');
	const responder = await issue('Responder Scope Responder', responderUri, ['ocspSigning']);
	const at = new Date(Date.now() + 5_000);
	const scopedCrl = (crlNumber: number, thisUpdateHours: number, baseCrlNumber?: number) =>
		createCertificateRevocationList({
			issuer: { commonName: 'Responder Scope CA' },
			issuerCertificate: ca.certificate.der,
			signerPrivateKey: ca.keyPair.privateKey,
			crlNumber,
			...(baseCrlNumber === undefined ? {} : { baseCrlNumber }),
			thisUpdate: new Date(at.getTime() + thisUpdateHours * HOUR_MS),
			nextUpdate: new Date(
				at.getTime() + (baseCrlNumber === undefined ? 24 : thisUpdateHours + 0.5) * HOUR_MS,
			),
			issuingDistributionPoint: { distributionPoint: fullNameDistributionPoint(responderUri) },
		});
	const ocsp = await createOcspResponse({
		signerPrivateKey: responder.keys.privateKey,
		signerCertificate: responder.certificate.pem,
		includedCertificates: [responder.certificate.pem],
		responses: [
			{
				certificate: leaf.certificate.pem,
				issuerCertificate: ca.certificate.pem,
				certStatus: 'good',
				thisUpdate: new Date(at.getTime() - HOUR_MS),
				nextUpdate: new Date(at.getTime() + 24 * HOUR_MS),
			},
		],
	});
	return {
		ca,
		leaf: leaf.certificate,
		at,
		ocsp: ocsp.der,
		base: (await scopedCrl(5, -3)).der,
		deltas: await ders(
			Array.from({ length: 6 }, (_, index) => scopedCrl(10 + index, -2.5 + index / 4, 5)),
		),
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
	'newest clean and older unresolvable': async (s: Scenario) => [
		(await s.unresolvableDelta()).der,
		(await s.newestCleanDelta()).der,
	],
	'newest clean and older unrecognized reason': async (s: Scenario) => [
		await s.unrecognizedReasonDelta(),
		(await s.newestCleanDelta()).der,
	],
	'newer current clean and older expired revoking': async (s: Scenario) => [
		(await s.expiredDelta('keyCompromise')).der,
		(await s.newerCleanDelta()).der,
	],
	'forged and expired revoking': async (s: Scenario) => [
		...(await s.forgedDeltas(1)),
		(await s.expiredDelta('keyCompromise')).der,
	],
	'four older current clean and newer expired revoking': (s: Scenario) =>
		olderCleanAndNewerExpiredRevoking(s, 4),
	'three older current clean and newer expired revoking': (s: Scenario) =>
		olderCleanAndNewerExpiredRevoking(s, 3),
	'newer expired clean and older current revoking': async (s: Scenario) =>
		ders([
			s.deltaAt(6, -2, { reasonCode: 'keyCompromise' }),
			s.deltaAt(7, -1, { nextUpdateHours: -0.5 }),
		]),
	'newer expired clean and older current holding': async (s: Scenario) =>
		ders([
			s.deltaAt(6, -2, { reasonCode: 'certificateHold' }),
			s.deltaAt(7, -1, { nextUpdateHours: -0.5 }),
		]),
	'newest current clean, expired clean and older expired revoking': async (s: Scenario) =>
		ders([
			s.deltaAt(7, -2, { nextUpdateHours: -1.25, reasonCode: 'keyCompromise' }),
			s.deltaAt(8, -1.5, { nextUpdateHours: -1 }),
			s.deltaAt(9, -0.5),
		]),
	'newer current clean with a lower CRL number and older current holding': async (s: Scenario) =>
		ders([s.deltaAt(9, -2, { reasonCode: 'certificateHold' }), s.deltaAt(7, -1)]),
	'four newer expired clean and older current revoking': (s: Scenario) =>
		newerExpiredCleanAndOlderCurrentRevoking(s, 4),
	'three newer expired clean and older current revoking': (s: Scenario) =>
		newerExpiredCleanAndOlderCurrentRevoking(s, 3),
	'newest expired clean, current clean and alike-ranked current revoking': async (s: Scenario) =>
		ders([
			s.deltaAt(20, -2, { reasonCode: 'keyCompromise' }),
			s.deltaAt(8, -1.5),
			s.deltaAt(40, -0.5, { nextUpdateHours: -0.25 }),
		]),
	'two current clean and an older holding one with a higher CRL number': async (s: Scenario) =>
		ders([
			s.deltaAt(10, -2.75, { reasonCode: 'certificateHold' }),
			s.deltaAt(8, -2),
			s.deltaAt(9, -1),
		]),
	'expired clean, current clean and an older holding one with a higher CRL number': async (
		s: Scenario,
	) =>
		ders([
			s.deltaAt(10, -2.75, { reasonCode: 'certificateHold' }),
			s.deltaAt(8, -2),
			s.deltaAt(20, -1, { nextUpdateHours: -0.5 }),
		]),
	'six without nextUpdate': async (s: Scenario) =>
		Promise.all(
			(
				await ders(Array.from({ length: 6 }, (_, index) => s.deltaAt(10 + index, -2 + index / 60)))
			).map(s.withoutNextUpdate),
		),
	'newest current clean and four older expired clean': (s: Scenario) =>
		ders([
			...Array.from({ length: 4 }, (_, index) =>
				s.deltaAt(6 + index, -2.5 + index / 4, { nextUpdateHours: -0.5 }),
			),
			s.deltaAt(20, -0.5),
		]),
	'newest current clean and four older without nextUpdate': async (s: Scenario) => [
		...(await Promise.all(
			(
				await ders(Array.from({ length: 4 }, (_, index) => s.deltaAt(6 + index, -2.5 + index / 4)))
			).map(s.withoutNextUpdate),
		)),
		...(await ders([s.deltaAt(20, -0.5)])),
	],
	'newest current clean and four older over two hours old': (s: Scenario) =>
		ders([
			...Array.from({ length: 4 }, (_, index) => s.deltaAt(6 + index, -2.9 + index / 10)),
			s.deltaAt(20, -0.5),
		]),
	'five current clean': (s: Scenario) =>
		ders(Array.from({ length: 5 }, (_, index) => s.deltaAt(6 + index, -2.5 + index / 4))),
	'four forged and older current clean': async (s: Scenario) => [
		...(await s.forgedDeltas(4)),
		...(await ders([s.deltaAt(6, -2)])),
	],
} satisfies Record<string, (s: Scenario) => Promise<readonly Uint8Array[]>>;

const NEWEST_FIRST_CASES = [
	{ deltas: 'four older current clean and newer expired revoking', expected: 'revoked' },
	{ deltas: 'three older current clean and newer expired revoking', expected: 'revoked' },
	{ deltas: 'newer expired clean and older current revoking', expected: 'revoked' },
	{ deltas: 'newer expired clean and older current holding', expected: 'revoked' },
	{
		deltas: 'newest current clean, expired clean and older expired revoking',
		expected: 'revoked',
	},
	{
		deltas: 'newer current clean with a lower CRL number and older current holding',
		expected: 'revoked',
	},
	{ deltas: 'four forged and older current clean', expected: 'unsettled' },
	{ deltas: 'four newer expired clean and older current revoking', expected: 'unsettled' },
	{ deltas: 'three newer expired clean and older current revoking', expected: 'revoked' },
	{
		deltas: 'newest expired clean, current clean and alike-ranked current revoking',
		expected: 'revoked',
	},
] as const;

function underEachPolicy<Row extends { readonly expected: string; readonly ignore?: string }>(
	rows: readonly Row[],
) {
	return rows.flatMap((row) => [
		{ ...row, policy: 'indeterminate' as const },
		{ ...row, policy: 'ignore' as const, expected: row.ignore ?? row.expected },
	]);
}

describe('checkCertificateRevocationAgainstCrlsBy', () => {
	it.each(
		underEachPolicy([
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
			{ base: 'clean', deltas: 'six expired clean', expected: 'unsettled', ignore: 'good' },
			{ base: 'clean', deltas: 'five current clean', expected: 'unsettled', ignore: 'good' },
			{ base: 'keyCompromise', deltas: 'six expired clean', expected: 'revoked' },
			{ base: 'keyCompromise', deltas: 'five current clean', expected: 'revoked' },
			{
				base: 'clean',
				deltas: 'newer current clean and older expired revoking',
				expected: 'revoked',
			},
			...NEWEST_FIRST_CASES.map(({ deltas, expected }) => ({
				base: 'clean' as const,
				deltas,
				expected,
			})),
		] as const),
	)(
		'checks a $base base CRL with $deltas delta CRLs under $policy as $expected',
		async ({ base, deltas, policy, expected }) => {
			const s = await scenario();
			const parse = (der: Uint8Array) => unwrap(parseCertificateRevocationListDer(der));
			const result = await checkCertificateRevocationAgainstCrlsBy(
				unwrap(parseCertificatePem(s.leafPem)),
				parse((await HELPER_BASES[base](s)).der),
				(await HELPER_DELTAS[deltas](s)).map(parse),
				{ kind: 'certificate', certificate: s.caPem },
				{ at: s.at, unreadSupersededDeltaCrls: policy },
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

describe('checkCertificateRevocationAgainstCrlsBy with an older delta CRL that a newer clean one contradicts', () => {
	it.each([
		{ deltas: 'newest clean and older unresolvable', policy: 'revoked', expected: 'unsettled' },
		{
			deltas: 'newest clean and older unrecognized reason',
			policy: 'revoked',
			expected: 'revoked',
		},
		{
			deltas: 'newest clean and older unrecognized reason',
			policy: 'reject',
			expected: 'reason_code_unrecognized',
		},
	] as const)(
		'reads $deltas under unrecognizedReasonCode $policy as $expected',
		async ({ deltas, policy, expected }) => {
			const s = await scenario();
			const parse = (der: Uint8Array) => unwrap(parseCertificateRevocationListDer(der));
			const result = await checkCertificateRevocationAgainstCrlsBy(
				unwrap(parseCertificatePem(s.leafPem)),
				parse((await s.baseNumbered(5)).der),
				(await HELPER_DELTAS[deltas](s)).map(parse),
				{ kind: 'certificate', certificate: s.caPem },
				{ at: s.at, unrecognizedReasonCode: policy },
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

	it.each([
		{
			deltas: 'newest clean and older unresolvable',
			policy: 'revoked',
			reasons: ['no_applicable_ocsp', 'delta_crl_unusable'],
		},
		{
			deltas: 'newest clean and older unrecognized reason',
			policy: 'reject',
			reasons: ['no_applicable_ocsp', 'crl_reason_code_unrecognized'],
		},
	] as const)(
		'keeps chain revocation from good over $deltas under unrecognizedReasonCode $policy',
		async ({ deltas, policy, reasons }) => {
			const s = await scenario();
			const result = await checkChainRevocation({
				chain: s.chain,
				crls: [(await s.baseNumbered(5)).der, ...(await HELPER_DELTAS[deltas](s))],
				at: s.at,
				policy: { unrecognizedReasonCode: policy },
			});
			expect(result.value.decision).toBe('deny');
			expect(result.value.certificates[0]?.indeterminateReasons).toEqual(reasons);
		},
	);
});

describe('checkCertificateRevocation and checkChainRevocation with several delta CRLs for one base CRL', () => {
	it.each([
		{ older: 'certificateHold', expected: 'good', decision: 'allow' },
		{ older: 'keyCompromise', expected: 'revoked', decision: 'deny' },
	] as const)(
		'give one verdict for a newer clean delta CRL beside an older $older one',
		async ({ older, expected, decision }) => {
			const s = await scenario();
			const base = (await s.baseNumbered(5)).der;
			const olderDelta = (
				older === 'certificateHold' ? await s.heldDelta() : await s.revokingDelta()
			).der;
			const newerDelta = (await s.newerCleanDelta()).der;
			const single = await checkCertificateRevocation({
				certificate: s.leafPem,
				issuerCertificate: s.caPem,
				evidence: [
					{ kind: 'crl', crl: base, deltaCrl: olderDelta },
					{ kind: 'crl', crl: base, deltaCrl: newerDelta },
				],
				at: s.at,
			});
			expect(single).toMatchObject({ ok: true, value: { status: expected } });
			const chain = await checkChainRevocation({
				chain: s.chain,
				crls: [base, olderDelta, newerDelta],
				at: s.at,
			});
			expect(chain.value.decision).toBe(decision);
			expect(chain.value.certificates[0]?.status).toBe(expected);
		},
	);
});

describe('checkCertificateRevocation with CRL evidence that does not decode', () => {
	const garbage = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]);

	it('still checks a complete CRL whose deltaCrl does not decode', async () => {
		const s = await scenario();
		const result = await checkCertificateRevocation({
			certificate: s.leafPem,
			issuerCertificate: s.caPem,
			evidence: [
				{ kind: 'crl', crl: (await s.base(true)).der, deltaCrl: garbage },
				{ kind: 'ocsp', response: s.ocspGood },
			],
			at: s.at,
		});
		expect(result).toMatchObject({ ok: true, value: { status: 'revoked' } });
	});

	it('still pools the deltaCrl of an entry whose complete CRL does not decode', async () => {
		const s = await scenario();
		const single = await checkCertificateRevocation({
			certificate: s.leafPem,
			issuerCertificate: s.caPem,
			evidence: [
				{ kind: 'crl', crl: (await s.base(false)).der },
				{ kind: 'crl', crl: garbage, deltaCrl: (await s.revokingDelta()).der },
			],
			at: s.at,
		});
		expect(single).toMatchObject({ ok: true, value: { status: 'revoked' } });
	});

	it('reports a CRL that does not decode as malformed', async () => {
		const s = await scenario();
		const result = await checkCertificateRevocation({
			certificate: s.leafPem,
			issuerCertificate: s.caPem,
			evidence: [{ kind: 'crl', crl: garbage }],
			at: s.at,
		});
		expect(result).toMatchObject({
			ok: true,
			value: {
				status: 'indeterminate',
				details: { indeterminateEvidence: [{ kind: 'crl', code: 'malformed' }] },
			},
		});
	});
});

describe('checkCertificateRevocation delta CRL attempt limits', () => {
	it.each([
		{ bases: 8, expected: { status: 'good' } },
		{ bases: 9, expected: { status: 'indeterminate' } },
	] as const)(
		'spends at most 32 delta CRL checks per call, as chain revocation does ($bases base CRLs)',
		async ({ bases, expected }) => {
			const s = await scenario();
			const deltas = await s.forgedDeltas(4, 1);
			const completeCrls = await Promise.all(
				Array.from({ length: bases }, async (_, index) => (await s.baseNumbered(index + 1)).der),
			);
			const result = await checkCertificateRevocation({
				certificate: s.leafPem,
				issuerCertificate: s.caPem,
				evidence: completeCrls.map((crl, index) => {
					const deltaCrl = deltas[index];
					return deltaCrl === undefined
						? { kind: 'crl' as const, crl }
						: { kind: 'crl' as const, crl, deltaCrl };
				}),
				at: s.at,
			});
			expect(result).toMatchObject({
				ok: true,
				value:
					expected.status === 'indeterminate'
						? {
								status: 'indeterminate',
								details: { indeterminateEvidence: [{ code: 'delta_crl_retry_limit_exceeded' }] },
							}
						: expected,
			});
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

describe('checkCertificateRevocationAgainstCrlsBy with a shared delta CRL budget and genuine delta CRLs', () => {
	it.each(
		underEachPolicy([
			{
				deltas: 'four older current clean and newer expired revoking',
				remaining: 1,
				expected: 'revoked',
			},
			{ deltas: 'forged and expired revoking', remaining: 1, expected: 'unsettled' },
			{
				deltas: 'newest current clean, expired clean and older expired revoking',
				remaining: 1,
				expected: 'unsettled',
				ignore: 'good',
			},
			{
				deltas: 'newest current clean, expired clean and older expired revoking',
				remaining: 3,
				expected: 'revoked',
			},
			{
				deltas: 'newer current clean with a lower CRL number and older current holding',
				remaining: 1,
				expected: 'unsettled',
			},
			{
				deltas: 'newest expired clean, current clean and alike-ranked current revoking',
				remaining: 2,
				expected: 'unsettled',
			},
			{
				deltas: 'four newer expired clean and older current revoking',
				remaining: 1,
				expected: 'unsettled',
			},
			{ deltas: 'six expired clean', remaining: 1, expected: 'unsettled', ignore: 'good' },
			{ deltas: 'five current clean', remaining: 4, expected: 'unsettled', ignore: 'good' },
			{
				deltas: 'two current clean and an older holding one with a higher CRL number',
				remaining: 1,
				expected: 'unsettled',
			},
			{
				deltas: 'two current clean and an older holding one with a higher CRL number',
				remaining: 3,
				expected: 'revoked',
			},
			{
				deltas: 'expired clean, current clean and an older holding one with a higher CRL number',
				remaining: 2,
				expected: 'unsettled',
			},
			{
				deltas: 'expired clean, current clean and an older holding one with a higher CRL number',
				remaining: 3,
				expected: 'revoked',
			},
		] as const),
	)(
		'checks $deltas delta CRLs with $remaining attempts left under $policy as $expected',
		async ({ deltas, remaining, policy, expected }) => {
			const s = await scenario();
			const parse = (der: Uint8Array) => unwrap(parseCertificateRevocationListDer(der));
			const result = await checkCertificateRevocationAgainstCrlsBy(
				unwrap(parseCertificatePem(s.leafPem)),
				parse((await s.baseNumbered(5)).der),
				(await HELPER_DELTAS[deltas](s)).map(parse),
				{ kind: 'certificate', certificate: s.caPem },
				{ at: s.at, unreadSupersededDeltaCrls: policy },
				callerVerification(undefined),
				[{ remaining }],
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

describe('checkCertificateRevocationAgainstCrlsBy with unread superseded delta CRLs of each kind', () => {
	it.each(
		underEachPolicy(
			(
				[
					{ deltas: 'six expired clean', maxAgeMs: undefined },
					{ deltas: 'six without nextUpdate', maxAgeMs: undefined },
					{ deltas: 'newest current clean and four older expired clean', maxAgeMs: undefined },
					{ deltas: 'newest current clean and four older without nextUpdate', maxAgeMs: undefined },
					{
						deltas: 'newest current clean and four older over two hours old',
						maxAgeMs: 2 * HOUR_MS,
					},
					{ deltas: 'five current clean', maxAgeMs: undefined },
				] as const
			).flatMap((row) => [
				{ ...row, budget: 'per-base', expected: 'unsettled', ignore: 'good' } as const,
				{ ...row, budget: 'shared', expected: 'unsettled', ignore: 'good' } as const,
			]),
		),
	)(
		'checks $deltas at the $budget limit under $policy as $expected',
		async ({ deltas, maxAgeMs, budget, policy, expected }) => {
			const s = await scenario();
			const parse = (der: Uint8Array) => unwrap(parseCertificateRevocationListDer(der));
			const result = await checkCertificateRevocationAgainstCrlsBy(
				unwrap(parseCertificatePem(s.leafPem)),
				parse((await s.baseNumbered(5)).der),
				(await HELPER_DELTAS[deltas](s)).map(parse),
				{ kind: 'certificate', certificate: s.caPem },
				{
					at: s.at,
					unreadSupersededDeltaCrls: policy,
					...(maxAgeMs === undefined ? {} : { maxAgeMs }),
				},
				callerVerification(undefined),
				budget === 'shared' ? [{ remaining: 1 }] : [],
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

describe('checkCertificateRevocation under each unreadSupersededDeltaCrls policy', () => {
	it.each(
		underEachPolicy([
			{ deltas: 'six expired clean', remaining: 1, expected: 'revoked' },
			{ deltas: 'five current clean', remaining: 0, expected: 'revoked' },
		] as const),
	)(
		'keeps a keyCompromise base CRL revocation beside $deltas delta CRLs with $remaining attempts left under $policy',
		async ({ deltas, remaining, policy, expected }) => {
			const s = await scenario();
			const parse = (der: Uint8Array) => unwrap(parseCertificateRevocationListDer(der));
			const result = await checkCertificateRevocationAgainstCrlsBy(
				unwrap(parseCertificatePem(s.leafPem)),
				parse((await s.baseNumbered(5, 'keyCompromise')).der),
				(await HELPER_DELTAS[deltas](s)).map(parse),
				{ kind: 'certificate', certificate: s.caPem },
				{ at: s.at, unreadSupersededDeltaCrls: policy },
				callerVerification(undefined),
				[{ remaining }],
			);
			expect(result.kind === 'checked' && result.result.ok && result.result.value.status).toBe(
				expected,
			);
		},
	);

	it.each([
		{ policy: 'default', expected: { status: 'indeterminate' } },
		{ policy: 'indeterminate', expected: { status: 'indeterminate' } },
		{ policy: 'ignore', expected: { status: 'good' } },
	] as const)(
		'checkCertificateRevocation reads six expired clean delta CRLs under $policy as $expected.status',
		async ({ policy, expected }) => {
			const s = await scenario();
			const base = (await s.baseNumbered(5)).der;
			const result = await checkCertificateRevocation({
				certificate: s.leafPem,
				issuerCertificate: s.caPem,
				evidence: (await s.expiredCleanDeltas(6)).map((deltaCrl) => ({
					kind: 'crl' as const,
					crl: base,
					deltaCrl,
				})),
				at: s.at,
				...(policy === 'default' ? {} : { unreadSupersededDeltaCrls: policy }),
			});
			expect(result).toMatchObject({
				ok: true,
				value:
					expected.status === 'indeterminate'
						? {
								status: 'indeterminate',
								details: { indeterminateEvidence: [{ code: 'delta_crl_retry_limit_exceeded' }] },
							}
						: expected,
			});
		},
	);
});

describe('checkChainRevocation and checkCertificateRevocation read delta CRLs newest first', () => {
	it.each(NEWEST_FIRST_CASES)(
		'give $expected for $deltas delta CRLs',
		async ({ deltas, expected }) => {
			const s = await scenario();
			const base = (await s.baseNumbered(5)).der;
			const deltaDers = await HELPER_DELTAS[deltas](s);
			const chain = await leafStatus(s, [base, ...deltaDers], []);
			expect(chain.decision).toBe('deny');
			expect(chain.status).toBe(expected === 'unsettled' ? 'indeterminate' : expected);
			if (expected === 'unsettled') {
				expect(chain.indeterminateReasons).toContain('delta_crl_retry_limit_exceeded');
			}
			const single = await checkCertificateRevocation({
				certificate: s.leafPem,
				issuerCertificate: s.caPem,
				evidence: deltaDers.map((deltaCrl) => ({ kind: 'crl' as const, crl: base, deltaCrl })),
				at: s.at,
			});
			expect(single).toMatchObject({
				ok: true,
				value:
					expected === 'unsettled'
						? {
								status: 'indeterminate',
								details: { indeterminateEvidence: [{ code: 'delta_crl_retry_limit_exceeded' }] },
							}
						: { status: expected },
			});
		},
	);
});

describe('validateOcspResponse and checkCertificateRevocation delta CRL limits for a delegated responder', () => {
	const completeCrls = (s: Scenario, count: number) =>
		Promise.all(
			Array.from({ length: count }, async (_, index) => (await s.baseNumbered(index + 1)).der),
		);

	it.each([
		{ bases: 8, expected: 'accepted' },
		{ bases: 9, expected: 'responder_revocation_unknown' },
	] as const)(
		'validateOcspResponse spends at most 32 delta CRL checks on the responder ($bases base CRLs)',
		async ({ bases, expected }) => {
			const s = await scenario();
			const result = await validateOcspResponse({
				response: await s.delegatedOcspGood(),
				issuerCertificate: s.caPem,
				at: s.at,
				responderRevocationCrls: [
					...(await completeCrls(s, bases)),
					...(await s.forgedDeltas(4, 1)),
				],
			});
			expect(result.ok ? 'accepted' : result.code).toBe(expected);
		},
	);

	it.each([
		{ policy: 'default', expected: 'responder_revocation_unknown' },
		{ policy: 'ignore', expected: 'accepted' },
	] as const)(
		'validateOcspResponse reads six expired clean responder delta CRLs under $policy as $expected',
		async ({ policy, expected }) => {
			const s = await scenario();
			const result = await validateOcspResponse({
				response: await s.delegatedOcspGood(),
				issuerCertificate: s.caPem,
				at: s.at,
				responderRevocationCrls: [
					(await s.baseNumbered(5)).der,
					...(await s.expiredCleanDeltas(6)),
				],
				...(policy === 'default' ? {} : { responderRevocationUnreadSupersededDeltaCrls: policy }),
			});
			expect(result.ok ? 'accepted' : result.code).toBe(expected);
		},
	);

	it.each([
		{ policy: 'indeterminate', status: 'indeterminate' },
		{ policy: 'ignore', status: 'good' },
	] as const)(
		'checkCertificateRevocation and checkChainRevocation pass $policy to the responder',
		async ({ policy, status }) => {
			const s = await responderScopedScenario();
			const single = await checkCertificateRevocation({
				certificate: s.leaf.pem,
				issuerCertificate: s.ca.certificate.pem,
				evidence: [
					{ kind: 'ocsp', response: s.ocsp },
					...s.deltas.map((deltaCrl) => ({ kind: 'crl' as const, crl: s.base, deltaCrl })),
				],
				at: s.at,
				unreadSupersededDeltaCrls: policy,
			});
			expect(single).toMatchObject({ ok: true, value: { status } });
			const chain = await checkChainRevocation({
				chain: [
					unwrap(parseCertificatePem(s.leaf.pem)),
					unwrap(parseCertificatePem(s.ca.certificate.pem)),
				],
				crls: [s.base, ...s.deltas],
				ocspResponses: [s.ocsp],
				at: s.at,
				policy: { unreadSupersededDeltaCrls: policy },
			});
			expect(chain.value.certificates[0]?.status).toBe(status);
		},
	);

	it('validateOcspResponse skips a responder CRL that does not decode', async () => {
		const s = await scenario();
		const result = await validateOcspResponse({
			response: await s.delegatedOcspGood(),
			issuerCertificate: s.caPem,
			at: s.at,
			responderRevocationCrls: [
				Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x01),
				(await s.baseNumbered(1)).der,
			],
		});
		expect(result).toMatchObject({ ok: true });
	});

	it('checkCertificateRevocation shares its 32 delta CRL checks with the responder', async () => {
		const s = await scenario();
		const deltas = await s.forgedDeltas(4, 1);
		const result = await checkCertificateRevocation({
			certificate: s.leafPem,
			issuerCertificate: s.caPem,
			evidence: [
				{ kind: 'ocsp', response: await s.delegatedOcspGood() },
				...(await completeCrls(s, 8)).map((crl, index) => {
					const deltaCrl = deltas[index];
					return deltaCrl === undefined
						? { kind: 'crl' as const, crl }
						: { kind: 'crl' as const, crl, deltaCrl };
				}),
			],
			at: s.at,
		});
		expect(result).toMatchObject({
			ok: true,
			value: {
				status: 'indeterminate',
				details: {
					indeterminateEvidence: Array.from({ length: 8 }, () => ({
						kind: 'crl',
						code: 'delta_crl_retry_limit_exceeded',
					})),
				},
			},
		});
	});
});

describe('checkCertificateRevocation stops at the first evidence that revokes', () => {
	it.each([
		{ order: 'revoking CRL first', calls: 0 },
		{ order: 'revoking CRL last', calls: 1 },
	] as const)(
		'verifies later evidence only before a revocation ($order)',
		async ({ order, calls }) => {
			const s = await scenario();
			const revoking = { kind: 'crl' as const, crl: (await s.base(true)).der };
			const other = {
				kind: 'crl' as const,
				crl: await resignedCrl((await s.baseNumbered(6)).der, parameterKey('stop', true)),
			};
			let verified = 0;
			const result = await checkCertificateRevocation({
				certificate: s.leafPem,
				issuerCertificate: s.caPem,
				evidence: order === 'revoking CRL first' ? [revoking, other] : [other, revoking],
				at: s.at,
				signatureVerifiers: {
					[PARAMETER_SIGNATURE_OID]: async () => {
						verified += 1;
						return false;
					},
				},
			});
			expect(result).toMatchObject({ ok: true, value: { status: 'revoked' } });
			expect(verified).toBe(calls);
		},
	);
});

describe('checkCertificateRevocation classifies each CRL by its delta CRL indicator', () => {
	it('pools a delta CRL in crl and checks a complete CRL in deltaCrl', async () => {
		const s = await scenario();
		const result = await checkCertificateRevocation({
			certificate: s.leafPem,
			issuerCertificate: s.caPem,
			evidence: [
				{ kind: 'crl', crl: (await s.revokingDelta()).der, deltaCrl: (await s.base(false)).der },
			],
			at: s.at,
		});
		expect(result).toMatchObject({ ok: true, value: { status: 'revoked' } });
	});
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

describe('checkCertificateRevocationAgainstCrl with a delta CRL it cannot apply', () => {
	it('fails a delta CRL issued after the evaluation time as stale', async () => {
		const s = await scenario();
		const result = await checkCertificateRevocationAgainstCrl({
			certificate: s.leafPem,
			issuerCertificate: s.caPem,
			crl: (await s.baseNumbered(5)).der,
			deltaCrl: (await s.deltaAt(9, 1, { reasonCode: 'keyCompromise' })).der,
			at: s.at,
		});
		expect(result).toMatchObject({ ok: false, code: 'stale_crl' });
	});

	it('fails an expired delta CRL whose scope excludes the certificate instead of taking its revocation', async () => {
		const s = await scenario();
		const result = await checkCertificateRevocationAgainstCrl({
			certificate: s.leafPem,
			issuerCertificate: s.caPem,
			crl: (await s.caOnlyBase(5)).der,
			deltaCrl: (
				await s.deltaAt(9, -2, {
					nextUpdateHours: -1,
					reasonCode: 'keyCompromise',
					onlyContainsCACerts: true,
				})
			).der,
			at: s.at,
		});
		expect(result).toMatchObject({ ok: false, code: 'stale_crl' });
	});
});

describe('checkCertificateRevocationAgainstCrl and checkCertificateRevocation with a delta CRL that fails', () => {
	it.each([
		{ base: 'keyCompromise', delta: 'forged', crl: 'revoked', evidence: 'revoked' },
		{ base: 'keyCompromise', delta: 'unresolvable', crl: 'revoked', evidence: 'revoked' },
		{ base: 'certificateHold', delta: 'forged', crl: 'signature_invalid', evidence: 'revoked' },
		{ base: 'clean', delta: 'forged', crl: 'signature_invalid', evidence: 'good' },
		{
			base: 'clean',
			delta: 'unresolvable',
			crl: 'signature_invalid',
			evidence: 'indeterminate',
		},
		{ base: 'clean', delta: 'expired revoking', crl: 'revoked', evidence: 'revoked' },
		{ base: 'clean', delta: 'expired holding', crl: 'good', evidence: 'good' },
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
	it.each([
		{
			base: false,
			policy: 'default',
			mode: 'hard-fail',
			expected: {
				decision: 'deny',
				status: 'indeterminate',
				indeterminateReasons: ['no_applicable_ocsp', 'delta_crl_retry_limit_exceeded'],
			},
		},
		{
			base: false,
			policy: 'indeterminate',
			mode: 'soft-fail',
			expected: {
				decision: 'allow',
				status: 'indeterminate',
				indeterminateReasons: ['no_applicable_ocsp', 'delta_crl_retry_limit_exceeded'],
			},
		},
		{
			base: false,
			policy: 'ignore',
			mode: 'hard-fail',
			expected: { decision: 'allow', status: 'good', indeterminateReasons: undefined },
		},
		{
			base: true,
			policy: 'indeterminate',
			mode: 'soft-fail',
			expected: { decision: 'deny', status: 'revoked', indeterminateReasons: undefined },
		},
	] as const)(
		'reads a base CRL revoking: $base beside six authentic delta CRLs past their nextUpdate under $policy and $mode',
		async ({ base, policy, mode, expected }) => {
			const s = await scenario();
			const crls = [(await s.base(base)).der, ...(await s.expiredCleanDeltas(6))];
			expect(
				await leafStatus(
					s,
					crls,
					[],
					mode,
					policy === 'default' ? {} : { unreadSupersededDeltaCrls: policy },
				),
			).toEqual(expected);
		},
	);

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

describe('checkChainRevocation delta CRL attempts for each CRL signer certificate', () => {
	it('gives a second certificate for the same signing key its own attempts', async () => {
		const at = new Date(Date.now() + 5_000);
		const window = {
			thisUpdate: new Date(at.getTime() - HOUR_MS),
			nextUpdate: new Date(at.getTime() + 24 * HOUR_MS),
		};
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Twin Signer Root' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const caKeys = await generateKeyPair();
		const ca = await createCertificate({
			issuer: { commonName: 'Twin Signer Root' },
			subject: { commonName: 'Twin Signer CA' },
			publicKey: caKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerCertificate: root.certificate.der,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const point = (name: string) =>
			({
				type: 'fullName',
				fullName: [{ type: 'uri', value: `http://example.test/${name}.crl` }],
			}) as const;
		const signerKeys = await generateKeyPair();
		const twin = () =>
			createCertificate({
				issuer: { commonName: 'Twin Signer CA' },
				subject: { commonName: 'Twin Signer CA' },
				publicKey: signerKeys.publicKey,
				signerPrivateKey: caKeys.privateKey,
				issuerCertificate: ca.der,
				extensions: {
					keyUsage: ['cRLSign'],
					crlDistributionPoints: [{ distributionPoint: point('signers') }],
				},
			});
		const revokedTwin = await twin();
		const goodTwin = await twin();
		const leaf = await createCertificate({
			issuer: { commonName: 'Twin Signer CA' },
			subject: { commonName: 'twin-signer.example' },
			publicKey: (await generateKeyPair()).publicKey,
			signerPrivateKey: caKeys.privateKey,
			issuerCertificate: ca.der,
			extensions: { crlDistributionPoints: [{ distributionPoint: point('leaf') }] },
		});
		const leafScope = { issuingDistributionPoint: { distributionPoint: point('leaf') } };
		const leafCrl = await createCertificateRevocationList({
			crlNumber: 5,
			issuer: { commonName: 'Twin Signer CA' },
			signerPrivateKey: signerKeys.privateKey,
			issuerCertificate: goodTwin.der,
			...leafScope,
			...window,
		});
		const attacker = await generateKeyPair();
		const forged = await Promise.all(
			[100, 101, 102, 103].map(
				async (crlNumber) =>
					(
						await createCertificateRevocationList({
							crlNumber,
							baseCrlNumber: 5,
							issuer: { commonName: 'Twin Signer CA' },
							signerPrivateKey: attacker.privateKey,
							issuerCertificate: goodTwin.der,
							...leafScope,
							...window,
						})
					).der,
			),
		);
		const signersCrl = await createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: 'Twin Signer CA' },
			signerPrivateKey: caKeys.privateKey,
			issuerCertificate: ca.der,
			issuingDistributionPoint: { distributionPoint: point('signers') },
			revokedCertificates: [
				{
					serialNumber: hexToBytes(unwrap(parseCertificatePem(revokedTwin.pem)).serialNumberHex),
					reasonCode: 'superseded',
				},
			],
			...window,
		});
		const rootCrl = await createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: 'Twin Signer Root' },
			signerPrivateKey: root.keyPair.privateKey,
			issuerCertificate: root.certificate.der,
			...window,
		});
		const result = await checkChainRevocation({
			chain: [
				unwrap(parseCertificatePem(leaf.pem)),
				unwrap(parseCertificatePem(ca.pem)),
				unwrap(parseCertificatePem(root.certificate.pem)),
			],
			crls: [leafCrl.der, ...forged, signersCrl.der, rootCrl.der],
			extraCertificates: [revokedTwin.pem, goodTwin.pem],
			at,
		});
		expect(result.value.certificates[0]?.status).toBe('good');
		expect(result.value.certificates[0]?.source?.signerCertificate?.serialNumberHex).toBe(
			unwrap(parseCertificatePem(goodTwin.pem)).serialNumberHex,
		);
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

describe('checkChainRevocation unreadSupersededDeltaCrls for a CRL signer', () => {
	it.each([
		{ policy: 'default', expected: ['no_applicable_ocsp', 'crl_signer_indeterminate'] },
		{ policy: 'ignore', expected: 'good' },
	] as const)(
		'reads six expired clean delta CRLs for the CRL signer under $policy as $expected',
		async ({ policy, expected }) => {
			const root = await createSelfSignedCertificate({
				subject: { commonName: 'Signer Policy Root' },
				extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
			});
			const signerKeys = await generateKeyPair();
			const signer = await createCertificate({
				issuer: { commonName: 'Signer Policy Root' },
				subject: { commonName: 'Signer Policy CRL Issuer' },
				publicKey: signerKeys.publicKey,
				signerPrivateKey: root.keyPair.privateKey,
				issuerCertificate: root.certificate.der,
				extensions: { keyUsage: ['cRLSign'] },
			});
			const uri = 'http://example.test/signer-policy.crl';
			const leaf = await createCertificate({
				issuer: { commonName: 'Signer Policy Root' },
				subject: { commonName: 'signer-policy.example' },
				publicKey: (await generateKeyPair()).publicKey,
				signerPrivateKey: root.keyPair.privateKey,
				issuerCertificate: root.certificate.der,
				extensions: {
					crlDistributionPoints: [
						{
							distributionPoint: fullNameDistributionPoint(uri),
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
			const leafCrl = await createCertificateRevocationList({
				issuer: { commonName: 'Signer Policy CRL Issuer' },
				issuerCertificate: signer.der,
				signerPrivateKey: signerKeys.privateKey,
				crlNumber: 1,
				thisUpdate: new Date(at.getTime() - HOUR_MS),
				nextUpdate: new Date(at.getTime() + 24 * HOUR_MS),
				issuingDistributionPoint: {
					distributionPoint: fullNameDistributionPoint(uri),
					indirectCrl: true,
				},
			});
			const rootCrl = (crlNumber: number, thisUpdateHours: number, baseCrlNumber?: number) =>
				createCertificateRevocationList({
					issuer: { commonName: 'Signer Policy Root' },
					issuerCertificate: root.certificate.der,
					signerPrivateKey: root.keyPair.privateKey,
					crlNumber,
					...(baseCrlNumber === undefined ? {} : { baseCrlNumber }),
					thisUpdate: new Date(at.getTime() + thisUpdateHours * HOUR_MS),
					nextUpdate: new Date(
						at.getTime() + (baseCrlNumber === undefined ? 24 : thisUpdateHours + 0.5) * HOUR_MS,
					),
				});
			const crls = [
				leafCrl.der,
				...(await ders([
					rootCrl(5, -3),
					...Array.from({ length: 6 }, (_, index) => rootCrl(10 + index, -2.5 + index / 4, 5)),
				])),
			];
			const result = await checkChainRevocation({
				chain: [
					unwrap(parseCertificatePem(leaf.pem)),
					unwrap(parseCertificatePem(root.certificate.pem)),
				],
				crls,
				extraCertificates: [signer.pem],
				at,
				...(policy === 'default' ? {} : { policy: { unreadSupersededDeltaCrls: policy } }),
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
