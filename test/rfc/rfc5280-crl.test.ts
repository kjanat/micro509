import { describe, expect, it } from 'bun:test';
import {
	checkCertificateRevocation,
	checkCertificateRevocationAgainstCrl,
	checkChainRevocation,
	createCertificate,
	createCertificateRevocationList,
	createOcspResponse,
	createSelfSignedCertificate,
	generateKeyPair,
	type ParsedCertificate,
	parseCertificatePem,
	parseCertificateRevocationListDerOrThrow,
	type RevocationPolicy,
	unwrap,
	validateCertificateRevocationList,
	validateOcspResponse,
	verifyCertificateChain,
} from '#micro509';
import { integer, sequence, tlv } from '#micro509/internal/asn1/der';
import {
	expectRejectedErrorCode,
	expectRejectedWith,
	hexToBytes,
	rfcDir,
	withCrlExtension,
	withoutCrlNextUpdate,
} from '#test/helpers';

const rfc5280Lines = (await Bun.file(`${rfcDir}/rfc5280.txt`).text()).split('\n');

const printed = (from: number, to: number): string =>
	rfc5280Lines
		.slice(from - 1, to)
		.join(' ')
		.replace(/\s+/g, ' ')
		.trim();

const THIS_UPDATE = new Date('2025-01-01T00:00:00Z');

async function crlIssuer() {
	return createSelfSignedCertificate({
		subject: { commonName: 'RFC 5280 CRL CA' },
		extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
	});
}

describe('RFC 5280', () => {
	describe('§5.1.2.5 "Conforming CRL issuers MUST include the nextUpdate field in all CRLs" (L3272)', () => {
		it('prints the sentences this suite enforces', () => {
			const section = printed(3272, 3276);
			expect(section).toContain(
				'Conforming CRL issuers MUST include the nextUpdate field in all CRLs',
			);
			expect(section).toContain(
				'The behavior of clients processing CRLs that omit nextUpdate is not specified by this profile.',
			);
		});

		it('encodes nextUpdate in every CRL the builder signs', async () => {
			const ca = await crlIssuer();
			const nextUpdate = new Date('2025-01-08T00:00:00Z');
			const crl = await createCertificateRevocationList({
				issuer: { commonName: 'RFC 5280 CRL CA' },
				signerPrivateKey: ca.keyPair.privateKey,
				issuerPublicKey: ca.keyPair.publicKey,
				thisUpdate: THIS_UPDATE,
				nextUpdate,
			});
			expect(parseCertificateRevocationListDerOrThrow(crl.der).nextUpdate).toEqual(nextUpdate);
		});

		it('still parses a received CRL that omits nextUpdate ("not specified by this profile", L3275)', async () => {
			const ca = await crlIssuer();
			const crl = await createCertificateRevocationList({
				issuer: { commonName: 'RFC 5280 CRL CA' },
				signerPrivateKey: ca.keyPair.privateKey,
				issuerPublicKey: ca.keyPair.publicKey,
				thisUpdate: THIS_UPDATE,
				nextUpdate: new Date('2025-01-08T00:00:00Z'),
			});
			const parsed = parseCertificateRevocationListDerOrThrow(
				await withoutCrlNextUpdate(crl.der, ca.keyPair.privateKey),
			);
			expect(parsed.nextUpdate).toBeUndefined();
			expect(parsed.thisUpdate).toEqual(THIS_UPDATE);
		});
	});

	describe('micro509 builder invariant (UNSPECIFIED in RFC 5280 and X.509): nextUpdate must encode a later second than thisUpdate', () => {
		it('rejects nextUpdate earlier than, equal to, or in the same second as thisUpdate', async () => {
			const ca = await crlIssuer();
			for (const nextUpdate of [
				new Date(THIS_UPDATE.getTime() - 1),
				THIS_UPDATE,
				new Date(THIS_UPDATE.getTime() + 999),
			]) {
				await expectRejectedErrorCode(
					createCertificateRevocationList({
						issuer: { commonName: 'RFC 5280 CRL CA' },
						signerPrivateKey: ca.keyPair.privateKey,
						issuerPublicKey: ca.keyPair.publicKey,
						thisUpdate: THIS_UPDATE,
						nextUpdate,
					}),
					'next_update_not_after_this_update',
				);
			}
		});

		it('rejects a past nextUpdate against the default thisUpdate', async () => {
			const ca = await crlIssuer();
			await expectRejectedErrorCode(
				createCertificateRevocationList({
					issuer: { commonName: 'RFC 5280 CRL CA' },
					signerPrivateKey: ca.keyPair.privateKey,
					issuerPublicKey: ca.keyPair.publicKey,
					nextUpdate: THIS_UPDATE,
				}),
				'next_update_not_after_this_update',
			);
		});

		it.each([
			['thisUpdate', { thisUpdate: new Date(Number.NaN) }],
			['nextUpdate', { nextUpdate: new Date(Number.NaN) }],
			[
				'revocationDate',
				{
					revokedCertificates: [
						{ serialNumber: Uint8Array.of(1), revocationDate: new Date(Number.NaN) },
					],
				},
			],
			[
				'invalidityDate',
				{
					revokedCertificates: [
						{ serialNumber: Uint8Array.of(1), invalidityDate: new Date(Number.NaN) },
					],
				},
			],
		] as const)('rejects an invalid %s as invalid_date', async (_field, fields) => {
			const ca = await crlIssuer();
			await expectRejectedErrorCode(
				createCertificateRevocationList({
					issuer: { commonName: 'RFC 5280 CRL CA' },
					signerPrivateKey: ca.keyPair.privateKey,
					issuerPublicKey: ca.keyPair.publicKey,
					thisUpdate: THIS_UPDATE,
					nextUpdate: new Date('2025-01-08T00:00:00Z'),
					...fields,
				}),
				'invalid_date',
			);
		});

		it('accepts nextUpdate one second after thisUpdate', async () => {
			const ca = await crlIssuer();
			const nextUpdate = new Date(THIS_UPDATE.getTime() + 1_000);
			const crl = await createCertificateRevocationList({
				issuer: { commonName: 'RFC 5280 CRL CA' },
				signerPrivateKey: ca.keyPair.privateKey,
				issuerPublicKey: ca.keyPair.publicKey,
				thisUpdate: THIS_UPDATE,
				nextUpdate,
			});
			expect(parseCertificateRevocationListDerOrThrow(crl.der).nextUpdate).toEqual(nextUpdate);
		});
	});
});

const SECOND_MS = 1_000;
const HOUR_MS = 60 * 60 * SECOND_MS;
const DAY_MS = 24 * HOUR_MS;
const CA_NAME = 'RFC 5280 CRL CA';

const shift = (from: Date, ms: number): Date => new Date(from.getTime() + ms);

function evaluationTime(): Date {
	return new Date(Math.floor((Date.now() + 5 * SECOND_MS) / SECOND_MS) * SECOND_MS);
}

interface CrlFields {
	readonly thisUpdate: Date;
	readonly nextUpdate: Date;
	readonly crlNumber: number;
	readonly baseCrlNumber?: number;
	readonly revokesLeaf?: boolean;
	readonly revocationDate?: Date;
	readonly withoutNextUpdate?: boolean;
}

async function crlPki() {
	const ca = await crlIssuer();
	const leafKeys = await generateKeyPair();
	const leaf = await createCertificate({
		issuer: { commonName: CA_NAME },
		subject: { commonName: 'rfc5280-crl-leaf.example' },
		publicKey: leafKeys.publicKey,
		signerPrivateKey: ca.keyPair.privateKey,
		issuerPublicKey: ca.keyPair.publicKey,
	});
	const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
	const chain: readonly ParsedCertificate[] = [
		parsedLeaf,
		unwrap(parseCertificatePem(ca.certificate.pem)),
	];
	const issueCrl = async (fields: CrlFields): Promise<Uint8Array> => {
		const crl = await createCertificateRevocationList({
			issuer: { commonName: CA_NAME },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			thisUpdate: fields.thisUpdate,
			nextUpdate: fields.nextUpdate,
			crlNumber: fields.crlNumber,
			...(fields.baseCrlNumber === undefined ? {} : { baseCrlNumber: fields.baseCrlNumber }),
			...(fields.revokesLeaf === true
				? {
						revokedCertificates: [
							{
								serialNumber: hexToBytes(parsedLeaf.serialNumberHex),
								revocationDate: fields.revocationDate ?? fields.thisUpdate,
							},
						],
					}
				: {}),
		});
		return fields.withoutNextUpdate === true
			? withoutCrlNextUpdate(crl.der, ca.keyPair.privateKey)
			: crl.der;
	};
	return { ca, leaf, chain, issueCrl };
}

async function leafRevocation(
	chain: readonly ParsedCertificate[],
	crls: readonly Uint8Array[],
	at: Date,
	policy?: RevocationPolicy,
) {
	const result = await checkChainRevocation({
		chain,
		crls,
		at,
		policy: { mode: 'soft-fail', ...policy },
	});
	return result.value.certificates[0];
}

async function staleCode(result: ReturnType<typeof validateCertificateRevocationList>) {
	const settled = await result;
	return settled.ok ? 'ok' : settled.code;
}

describe('RFC 5280 §3.3 L708-713 "suitably recent" and PKITS §4.4: how recent CRL data must be is local policy (maxAgeMs)', () => {
	it('prints the sentences this suite relies on', () => {
		expect(printed(708, 712)).toContain(
			"When a certificate-using system uses a certificate (e.g., for verifying a remote user's digital signature), that system not only checks the certificate signature and validity but also acquires a suitably recent CRL and checks that the certificate serial number is not on that CRL.",
		);
		expect(printed(712, 713)).toContain(
			'The meaning of "suitably recent" may vary with local policy, but it usually means the most recently issued CRL.',
		);
	});

	it('§5.1.2.5 L3275 "not specified by this profile": without maxAgeMs a CRL that omits nextUpdate stays usable', async () => {
		const { ca, issueCrl } = await crlPki();
		const crl = await issueCrl({
			thisUpdate: THIS_UPDATE,
			nextUpdate: shift(THIS_UPDATE, DAY_MS),
			crlNumber: 1,
			withoutNextUpdate: true,
		});
		expect(
			await staleCode(
				validateCertificateRevocationList({
					crl,
					issuerCertificate: ca.certificate.pem,
					at: new Date('2100-01-01T00:00:00Z'),
				}),
			),
		).toBe('ok');
	});

	it('accepts a CRL whose age equals maxAgeMs and rejects one a millisecond older', async () => {
		const { ca, issueCrl } = await crlPki();
		const crl = await issueCrl({
			thisUpdate: THIS_UPDATE,
			nextUpdate: shift(THIS_UPDATE, DAY_MS),
			crlNumber: 1,
			withoutNextUpdate: true,
		});
		const validate = (at: Date, maxAgeMs: number) =>
			staleCode(
				validateCertificateRevocationList({
					crl,
					issuerCertificate: ca.certificate.pem,
					at,
					maxAgeMs,
				}),
			);
		expect(await validate(shift(THIS_UPDATE, HOUR_MS), HOUR_MS)).toBe('ok');
		expect(await validate(shift(THIS_UPDATE, HOUR_MS + 1), HOUR_MS)).toBe('stale_crl');
		expect(await validate(THIS_UPDATE, 0)).toBe('ok');
		expect(await validate(shift(THIS_UPDATE, 1), 0)).toBe('stale_crl');
	});

	it('clockSkewMs widens maxAgeMs by the same amount', async () => {
		const { ca, issueCrl } = await crlPki();
		const crl = await issueCrl({
			thisUpdate: THIS_UPDATE,
			nextUpdate: shift(THIS_UPDATE, DAY_MS),
			crlNumber: 1,
			withoutNextUpdate: true,
		});
		const validate = (at: Date, clockSkewMs?: number) =>
			staleCode(
				validateCertificateRevocationList({
					crl,
					issuerCertificate: ca.certificate.pem,
					at,
					maxAgeMs: HOUR_MS,
					...(clockSkewMs === undefined ? {} : { clockSkewMs }),
				}),
			);
		expect(await validate(shift(THIS_UPDATE, HOUR_MS + 1))).toBe('stale_crl');
		expect(await validate(shift(THIS_UPDATE, HOUR_MS + 60 * SECOND_MS), 60 * SECOND_MS)).toBe('ok');
		expect(await validate(shift(THIS_UPDATE, HOUR_MS + 60 * SECOND_MS + 1), 60 * SECOND_MS)).toBe(
			'stale_crl',
		);
	});

	it('bounds a CRL whose nextUpdate is still in the future', async () => {
		const { ca, issueCrl } = await crlPki();
		const crl = await issueCrl({
			thisUpdate: THIS_UPDATE,
			nextUpdate: shift(THIS_UPDATE, 30 * DAY_MS),
			crlNumber: 1,
		});
		const at = shift(THIS_UPDATE, 2 * DAY_MS);
		const validate = (maxAgeMs?: number) =>
			staleCode(
				validateCertificateRevocationList({
					crl,
					issuerCertificate: ca.certificate.pem,
					at,
					...(maxAgeMs === undefined ? {} : { maxAgeMs }),
				}),
			);
		expect(await validate()).toBe('ok');
		expect(await validate(DAY_MS)).toBe('stale_crl');
	});

	it('checkCertificateRevocation reports stale_crl evidence for a CRL older than crlMaxAgeMs', async () => {
		const { ca, leaf, issueCrl } = await crlPki();
		const crl = await issueCrl({
			thisUpdate: THIS_UPDATE,
			nextUpdate: shift(THIS_UPDATE, 30 * DAY_MS),
			crlNumber: 1,
		});
		const check = async (crlMaxAgeMs?: number) =>
			unwrap(
				await checkCertificateRevocation({
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					evidence: [{ kind: 'crl', crl }],
					at: shift(THIS_UPDATE, 2 * DAY_MS),
					...(crlMaxAgeMs === undefined ? {} : { crlMaxAgeMs }),
				}),
			);
		expect((await check()).status).toBe('good');
		const bounded = await check(DAY_MS);
		expect(bounded.status).toBe('indeterminate');
		expect(
			bounded.status === 'indeterminate'
				? bounded.details.indeterminateEvidence.map((entry) => entry.code)
				: [],
		).toEqual(['stale_crl']);
	});

	it('verifyCertificateChain denies with revocation_indeterminate when the only CRL exceeds crlMaxAgeMs', async () => {
		const { ca, leaf, issueCrl } = await crlPki();
		const at = evaluationTime();
		const crl = await issueCrl({
			thisUpdate: shift(at, -2 * DAY_MS),
			nextUpdate: shift(at, 7 * DAY_MS),
			crlNumber: 1,
		});
		const verify = (crlMaxAgeMs?: number) =>
			verifyCertificateChain({
				leaf: leaf.der,
				roots: [ca.certificate.der],
				at,
				revocation: {
					crls: [crl],
					policy: { mode: 'hard-fail', ...(crlMaxAgeMs === undefined ? {} : { crlMaxAgeMs }) },
				},
			});
		expect((await verify()).ok).toBe(true);
		const bounded = await verify(DAY_MS);
		expect(bounded.ok ? undefined : bounded.error.code).toBe('revocation_indeterminate');
	});

	it('clockSkewMs on the chain policy widens crlMaxAgeMs', async () => {
		const { chain, issueCrl } = await crlPki();
		const at = evaluationTime();
		const crl = await issueCrl({
			thisUpdate: shift(at, -(DAY_MS + 30 * SECOND_MS)),
			nextUpdate: shift(at, 7 * DAY_MS),
			crlNumber: 1,
		});
		const strict = await leafRevocation(chain, [crl], at, { crlMaxAgeMs: DAY_MS });
		expect(strict?.indeterminateReasons).toContain('crl_expired');
		const skewed = await leafRevocation(chain, [crl], at, {
			crlMaxAgeMs: DAY_MS,
			clockSkewMs: 60 * SECOND_MS,
		});
		expect(skewed?.status).toBe('good');
	});

	it('reports the freshest good CRL whether or not it carries nextUpdate', async () => {
		const { chain, issueCrl } = await crlPki();
		const at = evaluationTime();
		const older = shift(at, -2 * HOUR_MS);
		const newer = shift(at, -HOUR_MS);
		for (const [withNextUpdate, withoutNextUpdate] of [
			[older, newer],
			[newer, older],
		] as const) {
			const bounded = await issueCrl({
				thisUpdate: withNextUpdate,
				nextUpdate: shift(at, DAY_MS),
				crlNumber: 1,
			});
			const open = await issueCrl({
				thisUpdate: withoutNextUpdate,
				nextUpdate: shift(at, DAY_MS),
				crlNumber: 2,
				withoutNextUpdate: true,
			});
			for (const crls of [
				[bounded, open],
				[open, bounded],
			]) {
				const status = await leafRevocation(chain, crls, at);
				expect(status?.status).toBe('good');
				expect(status?.source?.thisUpdate).toEqual(newer);
			}
		}
	});

	it('crlMaxAgeMs reaches the CRLs that check a delegated CRL signer', async () => {
		const at = evaluationTime();
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'RFC 5280 Signer Root' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const intermediateKeys = await generateKeyPair();
		const intermediate = await createCertificate({
			issuer: { commonName: 'RFC 5280 Signer Root' },
			subject: { commonName: 'RFC 5280 Signer Intermediate' },
			publicKey: intermediateKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerPublicKey: root.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const signerKeys = await generateKeyPair();
		const signer = await createCertificate({
			issuer: { commonName: 'RFC 5280 Signer Intermediate' },
			subject: { commonName: 'RFC 5280 Signer Intermediate' },
			publicKey: signerKeys.publicKey,
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			extensions: { keyUsage: ['cRLSign'] },
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'RFC 5280 Signer Intermediate' },
			subject: { commonName: 'rfc5280-signer-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			extensions: { keyUsage: ['digitalSignature'] },
		});
		const signerRevokedByOldCrl = await createCertificateRevocationList({
			issuer: { commonName: 'RFC 5280 Signer Intermediate' },
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			thisUpdate: shift(at, -10 * DAY_MS),
			nextUpdate: shift(at, 10 * DAY_MS),
			revokedCertificates: [
				{
					serialNumber: hexToBytes(unwrap(parseCertificatePem(signer.pem)).serialNumberHex),
					revocationDate: shift(at, -10 * DAY_MS),
					reasonCode: 'keyCompromise',
				},
			],
		});
		const leafCrl = await createCertificateRevocationList({
			issuer: { commonName: 'RFC 5280 Signer Intermediate' },
			signerPrivateKey: signerKeys.privateKey,
			issuerPublicKey: signerKeys.publicKey,
			thisUpdate: shift(at, -HOUR_MS),
			nextUpdate: shift(at, HOUR_MS),
		});
		const result = await checkChainRevocation({
			chain: [
				unwrap(parseCertificatePem(leaf.pem)),
				unwrap(parseCertificatePem(intermediate.pem)),
				unwrap(parseCertificatePem(root.certificate.pem)),
			],
			crls: [signerRevokedByOldCrl.der, leafCrl.der],
			extraCertificates: [signer.pem],
			at,
			policy: { mode: 'soft-fail', crlMaxAgeMs: DAY_MS },
		});
		const leafStatus = result.value.certificates[0];
		expect(leafStatus?.status).toBe('good');
		expect(leafStatus?.source?.signerCertificate?.serialNumberHex).toBe(
			unwrap(parseCertificatePem(signer.pem)).serialNumberHex,
		);
	});

	describe('delegated OCSP responder CRLs', () => {
		async function delegatedResponse() {
			const pki = await crlPki();
			const responderKeys = await generateKeyPair();
			const responder = await createCertificate({
				issuer: { commonName: CA_NAME },
				subject: { commonName: 'RFC 5280 CRL responder' },
				publicKey: responderKeys.publicKey,
				signerPrivateKey: pki.ca.keyPair.privateKey,
				issuerPublicKey: pki.ca.keyPair.publicKey,
				extensions: { extendedKeyUsage: ['ocspSigning'] },
			});
			const response = await createOcspResponse({
				signerPrivateKey: responderKeys.privateKey,
				signerCertificate: responder.pem,
				includedCertificates: [responder.pem],
				responses: [
					{
						certificate: pki.leaf.pem,
						issuerCertificate: pki.ca.certificate.pem,
						certStatus: 'good',
					},
				],
			});
			const at = evaluationTime();
			const crl = await pki.issueCrl({
				thisUpdate: shift(at, -2 * DAY_MS),
				nextUpdate: shift(at, 7 * DAY_MS),
				crlNumber: 1,
			});
			return { ...pki, response: response.der, crl, at };
		}

		it('responderRevocationCrlMaxAgeMs turns an old responder CRL into missing evidence', async () => {
			const { ca, response, crl, at } = await delegatedResponse();
			const validate = (responderRevocationCrlMaxAgeMs?: number) =>
				validateOcspResponse({
					response,
					issuerCertificate: ca.certificate.pem,
					responderRevocationPolicy: 'require-evidence',
					responderRevocationCrls: [crl],
					at,
					...(responderRevocationCrlMaxAgeMs === undefined
						? {}
						: { responderRevocationCrlMaxAgeMs }),
				});
			expect((await validate()).ok).toBe(true);
			const bounded = await validate(DAY_MS);
			expect(bounded.ok ? undefined : bounded.code).toBe('responder_revocation_unknown');
		});

		it('rejects a negative responderRevocationCrlMaxAgeMs with RangeError before reading the response', async () => {
			const { ca, crl, at } = await delegatedResponse();
			await expectRejectedWith(
				validateOcspResponse({
					response: Uint8Array.of(0x00),
					issuerCertificate: ca.certificate.pem,
					responderRevocationCrls: [crl],
					responderRevocationCrlMaxAgeMs: -1,
					at,
				}),
				RangeError,
			);
		});

		it('crlMaxAgeMs on the chain policy reaches delegated OCSP responder CRLs', async () => {
			const { chain, response, crl, at } = await delegatedResponse();
			const check = (crlMaxAgeMs?: number) =>
				checkChainRevocation({
					chain,
					crls: [crl],
					ocspResponses: [response],
					at,
					policy: {
						mode: 'soft-fail',
						ocspResponderRevocation: 'require-evidence',
						prefer: 'ocsp',
						...(crlMaxAgeMs === undefined ? {} : { crlMaxAgeMs }),
					},
				});
			expect((await check()).value.certificates[0]?.source?.kind).toBe('ocsp');
			const bounded = (await check(DAY_MS)).value.certificates[0];
			expect(bounded?.status).toBe('indeterminate');
			expect(bounded?.indeterminateReasons).toContain('ocsp_responder_indeterminate');
			expect(bounded?.indeterminateReasons).toContain('crl_expired');
		});
	});
});

describe('RFC 5280 §5.2.4 L3572-3582: only a current delta CRL applies, and the latest thisUpdate SHOULD win', () => {
	it('prints the sentences this suite enforces', () => {
		const section = printed(3572, 3582);
		expect(section).toContain(
			'A delta CRL is considered to be the current one if the current time is between the times contained in the thisUpdate and nextUpdate fields',
		);
		expect(section).toContain(
			'If more than one current delta CRL for a given scope is encountered, the application SHOULD consider the one with the latest value in thisUpdate to be the most current one.',
		);
	});

	it('ignores an expired delta CRL and evaluates a current base CRL alone', async () => {
		const { chain, issueCrl } = await crlPki();
		const at = evaluationTime();
		const base = await issueCrl({
			thisUpdate: shift(at, -HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 10,
		});
		const expiredDelta = await issueCrl({
			thisUpdate: shift(at, -3 * HOUR_MS),
			nextUpdate: shift(at, -2 * HOUR_MS),
			crlNumber: 11,
			baseCrlNumber: 10,
		});
		const status = await leafRevocation(chain, [base, expiredDelta], at);
		expect(status?.status).toBe('good');
		expect(status?.source?.thisUpdate).toEqual(shift(at, -HOUR_MS));
	});

	it('ignores a delta CRL older than crlMaxAgeMs and evaluates a fresh base CRL alone', async () => {
		const { chain, issueCrl } = await crlPki();
		const at = evaluationTime();
		const base = await issueCrl({
			thisUpdate: shift(at, -HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 10,
		});
		const oldDelta = await issueCrl({
			thisUpdate: shift(at, -2 * DAY_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 11,
			baseCrlNumber: 10,
		});
		const status = await leafRevocation(chain, [base, oldDelta], at, { crlMaxAgeMs: DAY_MS });
		expect(status?.status).toBe('good');
	});

	it('never treats a delta CRL without nextUpdate as current', async () => {
		const { ca, leaf, chain, issueCrl } = await crlPki();
		const at = evaluationTime();
		const base = await issueCrl({
			thisUpdate: shift(at, -HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 10,
		});
		const openDelta = await issueCrl({
			thisUpdate: shift(at, -HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 11,
			baseCrlNumber: 10,
			revokesLeaf: true,
			withoutNextUpdate: true,
		});
		const direct = await checkCertificateRevocationAgainstCrl({
			certificate: leaf.pem,
			issuerCertificate: ca.certificate.pem,
			crl: base,
			deltaCrl: openDelta,
			at,
		});
		expect(direct.ok ? direct.value.status : direct.code).toBe('stale_crl');
		const status = await leafRevocation(chain, [base, openDelta], at);
		expect(status?.status).toBe('good');
	});

	it('applies the current delta CRL with the latest thisUpdate', async () => {
		const { chain, issueCrl } = await crlPki();
		const at = evaluationTime();
		const base = await issueCrl({
			thisUpdate: shift(at, -3 * HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 10,
		});
		const earlierDelta = await issueCrl({
			thisUpdate: shift(at, -2 * HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 11,
			baseCrlNumber: 10,
		});
		const latestDelta = await issueCrl({
			thisUpdate: shift(at, -HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 12,
			baseCrlNumber: 10,
			revokesLeaf: true,
		});
		for (const crls of [
			[base, earlierDelta, latestDelta],
			[base, latestDelta, earlierDelta],
		]) {
			const status = await leafRevocation(chain, crls, at);
			expect(status?.status).toBe('revoked');
			expect(status?.source?.thisUpdate).toEqual(shift(at, -HOUR_MS));
		}
	});

	it('§5.2.3 (CRL numbers increase monotonically): of two current delta CRLs issued in the same second, applies the higher-numbered one', async () => {
		const { chain, issueCrl } = await crlPki();
		const at = evaluationTime();
		const base = await issueCrl({
			thisUpdate: shift(at, -3 * HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 10,
		});
		const olderDelta = await issueCrl({
			thisUpdate: shift(at, -HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 11,
			baseCrlNumber: 10,
		});
		const newerDelta = await issueCrl({
			thisUpdate: shift(at, -HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 12,
			baseCrlNumber: 10,
			revokesLeaf: true,
		});
		for (const crls of [
			[base, olderDelta, newerDelta],
			[base, newerDelta, olderDelta],
		]) {
			const status = await leafRevocation(chain, crls, at);
			expect(status?.status).toBe('revoked');
		}
	});

	it('X.509 Annex E.5.2 (paraphrase, delta issued after the base in use): ignores a delta CRL whose number does not exceed the base CRL number', async () => {
		const { chain, issueCrl } = await crlPki();
		const at = evaluationTime();
		const base = await issueCrl({
			thisUpdate: shift(at, -HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 10,
		});
		const priorDelta = await issueCrl({
			thisUpdate: shift(at, -HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 10,
			baseCrlNumber: 9,
			revokesLeaf: true,
		});
		const status = await leafRevocation(chain, [base, priorDelta], at);
		expect(status?.status).toBe('good');
	});

	it('X.509 Annex E.5.2 (paraphrase, delta issued after the base in use, by CRL number or thisUpdate): rejects a delta CRL whose thisUpdate precedes a not-yet-valid complete CRL', async () => {
		const { ca, leaf, chain, issueCrl } = await crlPki();
		const at = evaluationTime();
		const futureBase = await issueCrl({
			thisUpdate: shift(at, HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 10,
		});
		const delta = await issueCrl({
			thisUpdate: shift(at, -HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 11,
			baseCrlNumber: 10,
		});
		const direct = await checkCertificateRevocationAgainstCrl({
			certificate: leaf.pem,
			issuerCertificate: ca.certificate.pem,
			crl: futureBase,
			deltaCrl: delta,
			at,
		});
		expect(direct.ok).toBe(false);
		if (!direct.ok) {
			expect(direct.code).toBe('non_applicable');
			expect(direct.details).toEqual({ reason: 'delta_crl_incompatible' });
		}
		const status = await leafRevocation(chain, [futureBase, delta], at);
		expect(status?.status).toBe('indeterminate');
	});

	it("X.509 Annex E.5.2 (paraphrase, delta issued after the base in use; an equal thisUpdate is UNSPECIFIED): accepts a delta CRL whose thisUpdate equals the base CRL's", async () => {
		const { ca, leaf, chain, issueCrl } = await crlPki();
		const at = evaluationTime();
		const base = await issueCrl({
			thisUpdate: shift(at, -HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 10,
		});
		const sameTimeDelta = await issueCrl({
			thisUpdate: shift(at, -HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 11,
			baseCrlNumber: 10,
			revokesLeaf: true,
		});
		const direct = await checkCertificateRevocationAgainstCrl({
			certificate: leaf.pem,
			issuerCertificate: ca.certificate.pem,
			crl: base,
			deltaCrl: sameTimeDelta,
			at,
		});
		expect(direct.ok ? direct.value.status : direct.code).toBe('revoked');
		const status = await leafRevocation(chain, [base, sameTimeDelta], at);
		expect(status?.status).toBe('revoked');
	});

	it('X.509 Annex E.5.2 (paraphrase, delta issued after the base in use, by CRL number or thisUpdate): a delta CRL issued before the base does not sink a current base CRL', async () => {
		const { chain, issueCrl } = await crlPki();
		const at = evaluationTime();
		const base = await issueCrl({
			thisUpdate: shift(at, -HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 10,
		});
		const earlierDelta = await issueCrl({
			thisUpdate: shift(at, -2 * HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 11,
			baseCrlNumber: 10,
			revokesLeaf: true,
		});
		const status = await leafRevocation(chain, [base, earlierDelta], at);
		expect(status?.status).toBe('good');
		expect(status?.source?.thisUpdate).toEqual(shift(at, -HOUR_MS));
	});
});

describe('RFC 5280 §6.3.3(a)(1)(i) L5128-5132 "a delta CRL with a next update value that is after the current time" and §5.2.4 L3467-3479: a current delta CRL updates an expired complete CRL', () => {
	it('prints the sentences this suite relies on', () => {
		expect(printed(5128, 5132)).toContain(
			'(i) If use-deltas is set and either the certificate or the CRL contains the freshest CRL extension, obtain a delta CRL with a next update value that is after the current time and can be used to update the locally cached CRL as specified in Section 5.2.4.',
		);
		expect(printed(3467, 3468)).toContain(
			'In addition, the resulting locally constructed CRL has the thisUpdate and nextUpdate times specified in',
		);
		expect(printed(3479, 3479)).toContain(
			'the corresponding fields of the delta CRL used in its construction.',
		);
	});

	async function expiredBaseWithCurrentDelta() {
		const pki = await crlPki();
		const at = evaluationTime();
		const base = await pki.issueCrl({
			thisUpdate: shift(at, -10 * DAY_MS),
			nextUpdate: shift(at, -DAY_MS),
			crlNumber: 10,
		});
		const delta = await pki.issueCrl({
			thisUpdate: shift(at, -HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 11,
			baseCrlNumber: 10,
		});
		return { ...pki, at, base, delta };
	}

	it('checkCertificateRevocationAgainstCrl measures freshness and maxAgeMs on the delta CRL', async () => {
		const { ca, leaf, at, base, delta } = await expiredBaseWithCurrentDelta();
		const check = (deltaCrl?: Uint8Array) =>
			checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: base,
				...(deltaCrl === undefined ? {} : { deltaCrl }),
				at,
				maxAgeMs: DAY_MS,
			});
		const alone = await check();
		expect(alone.ok ? alone.value.status : alone.code).toBe('stale_crl');
		const updated = await check(delta);
		expect(updated.ok ? updated.value.status : updated.code).toBe('good');
	});

	it('checkChainRevocation reports good from an expired base CRL with a current delta CRL', async () => {
		const { chain, at, base, delta } = await expiredBaseWithCurrentDelta();
		expect((await leafRevocation(chain, [base], at))?.indeterminateReasons).toContain(
			'crl_expired',
		);
		const status = await leafRevocation(chain, [base, delta], at, { crlMaxAgeMs: DAY_MS });
		expect(status?.status).toBe('good');
		expect(status?.source?.thisUpdate).toEqual(shift(at, -HOUR_MS));
	});
});

describe('RFC 5280 §6.3.3(j) L5278-5282: a listed serial is revoked, and steps (i)-(k) compare no revocationDate with the validation time', () => {
	it('prints the sentences this suite relies on', () => {
		expect(printed(5278, 5282)).toContain(
			'If (cert_status is UNREVOKED), then search for the certificate on the complete CRL. If an entry is found that matches the certificate issuer and serial number as described in Section 5.3.3, then set the cert_status variable to the indicated reason as described in step (i).',
		);
		expect(printed(3294, 3295)).toContain(
			'The date on which the revocation occurred is specified.',
		);
	});

	it('reports revoked for an entry whose revocationDate is later than the validation time', async () => {
		const { ca, leaf, chain, issueCrl } = await crlPki();
		const at = evaluationTime();
		const revocationDate = shift(at, 7 * DAY_MS);
		const crl = await issueCrl({
			thisUpdate: shift(at, -HOUR_MS),
			nextUpdate: shift(at, DAY_MS),
			crlNumber: 1,
			revokesLeaf: true,
			revocationDate,
		});
		const direct = await checkCertificateRevocationAgainstCrl({
			certificate: leaf.pem,
			issuerCertificate: ca.certificate.pem,
			crl,
			at,
		});
		expect(direct).toMatchObject({ ok: true, value: { status: 'revoked', revocationDate } });
		const status = await leafRevocation(chain, [crl], at);
		expect(status?.status).toBe('revoked');
	});
});

const TO_BE_REVOKED = '2.5.29.58';

function generalizedTime(date: Date): Uint8Array {
	const digits = date.toISOString().replace(/[-:T]/g, '').slice(0, 14);
	return tlv(0x18, new TextEncoder().encode(`${digits}Z`));
}

function toBeRevokedValue(revocationTime: Date, serialNumberHex: string): Uint8Array {
	return sequence([
		sequence([generalizedTime(revocationTime), tlv(0xa0, integer(hexToBytes(serialNumberHex)))]),
	]);
}

describe('RFC 5280 §5.2 L3324-3327: a CRL extension the application cannot process, here X.509 toBeRevoked (2.5.29.58), which no RFC profiles', () => {
	it('prints the sentences this suite relies on', () => {
		expect(printed(3324, 3327)).toContain(
			'If a CRL contains a critical extension that the application cannot process, then the application MUST NOT use that CRL to determine the status of certificates.',
		);
		expect(printed(3326, 3327)).toContain(
			'However, applications may ignore unrecognized non-critical extensions.',
		);
	});

	async function crlWithToBeRevoked(critical: boolean) {
		const { ca, leaf, chain, issueCrl } = await crlPki();
		const at = evaluationTime();
		const [parsedLeaf] = chain;
		if (parsedLeaf === undefined) throw new Error('missing leaf');
		const crl = await withCrlExtension(
			await issueCrl({
				thisUpdate: shift(at, -HOUR_MS),
				nextUpdate: shift(at, DAY_MS),
				crlNumber: 1,
			}),
			ca.keyPair.privateKey,
			TO_BE_REVOKED,
			toBeRevokedValue(shift(at, -30 * SECOND_MS), parsedLeaf.serialNumberHex),
			critical,
		);
		return { ca, leaf, chain, at, crl };
	}

	it('does not use a CRL that carries toBeRevoked marked critical', async () => {
		const { ca, leaf, chain, at, crl } = await crlWithToBeRevoked(true);
		const direct = await checkCertificateRevocationAgainstCrl({
			certificate: leaf.pem,
			issuerCertificate: ca.certificate.pem,
			crl,
			at,
		});
		expect(direct.ok).toBe(false);
		const status = await leafRevocation(chain, [crl], at);
		expect(status?.status).toBe('indeterminate');
	});

	it('ignores toBeRevoked marked non-critical and uses the rest of the CRL', async () => {
		const { ca, leaf, chain, at, crl } = await crlWithToBeRevoked(false);
		const direct = await checkCertificateRevocationAgainstCrl({
			certificate: leaf.pem,
			issuerCertificate: ca.certificate.pem,
			crl,
			at,
		});
		expect(direct).toMatchObject({ ok: true, value: { status: 'good' } });
		const status = await leafRevocation(chain, [crl], at);
		expect(status?.status).toBe('good');
	});
});
