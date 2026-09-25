import { describe, expect, it } from 'bun:test';
import {
	checkChainRevocation,
	createCertificate,
	createSelfSignedCertificate,
	generateKeyPair,
	isResultError,
	parseCertificateDer,
	parseCertificateDerOrThrow,
	verifyCertificateChain,
} from '#micro509';
import { nullValue, octetString, sequence } from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import {
	encodeAuthorityInfoAccess,
	encodeCrlDistributionPoints,
	encodeExtension,
} from '#micro509/x509';
import {
	appendCertificateExtensions,
	createSelfSignedCertificateWithRawExtensions,
	flattenedText,
	rfcDir,
} from '#test/helpers';

const rfc9608 = await flattenedText(`${rfcDir}/rfc9608.txt`);

const CA_NAME = 'RFC 9608 CA';

async function issuingCa() {
	return createSelfSignedCertificate({
		subject: { commonName: CA_NAME },
		extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
	});
}

type Ca = Awaited<ReturnType<typeof issuingCa>>;

async function issueLeaf(
	ca: Ca,
	extensions: Parameters<typeof createCertificate>[0]['extensions'],
): Promise<Uint8Array> {
	const keys = await generateKeyPair();
	const leaf = await createCertificate({
		issuer: { commonName: CA_NAME },
		subject: { commonName: 'rfc9608-leaf.example' },
		publicKey: keys.publicKey,
		signerPrivateKey: ca.keyPair.privateKey,
		issuerPublicKey: ca.keyPair.publicKey,
		...(extensions === undefined ? {} : { extensions }),
	});
	return leaf.der;
}

function builderErrorCode(run: () => Promise<unknown>): Promise<string | undefined> {
	return run().then(
		() => undefined,
		(error: unknown) => (isResultError(error) ? error.code : undefined),
	);
}

const CRL_DISTRIBUTION_POINT = {
	distributionPoint: {
		type: 'fullName',
		fullName: [{ type: 'uri', value: 'http://example.test/ca.crl' }],
	},
} as const;

describe('RFC 9608 §2: the noRevAvail certificate extension', () => {
	it('prints the sentences this suite relies on', () => {
		expect(rfc9608).toContain('This extension MUST NOT be present in CA public key certificates.');
		expect(rfc9608).toContain(
			'When present, conforming CAs MUST mark this extension as non-critical.',
		);
		expect(rfc9608).toContain("syntax NULL (i.e. '0500'H is the DER encoding)");
	});

	it('encodes id-ce-noRevAvail as a non-critical NULL and parses it back', async () => {
		const ca = await issuingCa();
		const leaf = parseCertificateDerOrThrow(await issueLeaf(ca, { noRevAvail: true }));
		expect(leaf.noRevAvail).toBe(true);
		const extension = leaf.extensions.find((entry) => entry.oid === OIDS.noRevAvail);
		expect(extension?.critical).toBe(false);
		expect(extension?.valueHex).toBe('0500');
	});

	it('omits the extension unless asked for it', async () => {
		const ca = await issuingCa();
		const leaf = parseCertificateDerOrThrow(await issueLeaf(ca, { noRevAvail: false }));
		expect(leaf.noRevAvail).toBeUndefined();
		expect(leaf.extensions.some((entry) => entry.oid === OIDS.noRevAvail)).toBe(false);
	});

	it('rejects a critical noRevAvail supplied through customExtensions', async () => {
		const ca = await issuingCa();
		expect(
			await builderErrorCode(() =>
				issueLeaf(ca, {
					customExtensions: [{ oid: OIDS.noRevAvail, value: nullValue(), critical: true }],
				}),
			),
		).toBe('extension_must_be_non_critical');
	});

	it('refuses to parse a noRevAvail whose value is not NULL', async () => {
		const ca = await issuingCa();
		const der = await appendCertificateExtensions(
			await issueLeaf(ca, undefined),
			ca.keyPair.privateKey,
			[encodeExtension(OIDS.noRevAvail, octetString(Uint8Array.of(1)), false)],
		);
		expect(parseCertificateDer(der).ok).toBe(false);
	});
});

describe('RFC 9608 §3: a noRevAvail certificate carries no CA flag and no revocation pointers', () => {
	it('prints the sentences this suite relies on', () => {
		expect(rfc9608).toContain('Certificates for CAs MUST NOT include the noRevAvail extension.');
		expect(rfc9608).toContain(
			'If any of the above are violated in a certificate, then the relying party MUST consider the certificate invalid.',
		);
	});

	it('refuses to build a noRevAvail certificate that conflicts with §3', async () => {
		const ca = await issuingCa();
		const conflicts: Parameters<typeof issueLeaf>[1][] = [
			{ noRevAvail: true, basicConstraints: { ca: true } },
			{ noRevAvail: true, crlDistributionPoints: [CRL_DISTRIBUTION_POINT] },
			{
				noRevAvail: true,
				customExtensions: [{ oid: OIDS.freshestCRL, value: sequence([]) }],
			},
			{
				noRevAvail: true,
				authorityInfoAccess: [
					{ method: 'ocsp', location: { type: 'uri', value: 'http://ocsp.example.test' } },
				],
			},
			{
				basicConstraints: { ca: true },
				customExtensions: [{ oid: OIDS.noRevAvail, value: nullValue() }],
			},
			{
				noRevAvail: true,
				authorityInfoAccess: [
					{
						method: { type: 'oid', value: OIDS.ocspAccessMethod },
						location: { type: 'uri', value: 'http://ocsp.example.test' },
					},
				],
			},
			{
				noRevAvail: true,
				authorityInfoAccess: [],
				customExtensions: [
					{
						oid: OIDS.authorityInfoAccess,
						value: encodeAuthorityInfoAccess([
							{ method: 'ocsp', location: { type: 'uri', value: 'http://ocsp.example.test' } },
						]),
					},
				],
			},
		];
		for (const extensions of conflicts) {
			expect(await builderErrorCode(() => issueLeaf(ca, extensions))).toBe('no_rev_avail_conflict');
		}
	});

	it('builds a noRevAvail certificate that names only a caIssuers location', async () => {
		const ca = await issuingCa();
		const leaf = parseCertificateDerOrThrow(
			await issueLeaf(ca, {
				noRevAvail: true,
				authorityInfoAccess: [
					{ method: 'caIssuers', location: { type: 'uri', value: 'http://example.test/ca.cer' } },
				],
			}),
		);
		expect(leaf.noRevAvail).toBe(true);
	});

	it('rejects a chain whose leaf pairs noRevAvail with a revocation pointer', async () => {
		const ca = await issuingCa();
		const distributionPoints = encodeCrlDistributionPoints([CRL_DISTRIBUTION_POINT]);
		const conflicting = [
			encodeExtension(OIDS.cRLDistributionPoints, distributionPoints, false),
			encodeExtension(OIDS.freshestCRL, distributionPoints, false),
			encodeExtension(
				OIDS.authorityInfoAccess,
				encodeAuthorityInfoAccess([
					{ method: 'ocsp', location: { type: 'uri', value: 'http://ocsp.example.test' } },
				]),
				false,
			),
		];
		for (const conflict of conflicting) {
			const der = await appendCertificateExtensions(
				await issueLeaf(ca, undefined),
				ca.keyPair.privateKey,
				[encodeExtension(OIDS.noRevAvail, nullValue(), false), conflict],
			);
			const result = await verifyCertificateChain({
				leaf: der,
				roots: [ca.certificate.der],
			});
			expect(result).toMatchObject({ ok: false, code: 'no_rev_avail_conflict', index: 0 });
		}
	});

	it('rejects a chain whose CA certificate carries noRevAvail', async () => {
		const ca = await createSelfSignedCertificateWithRawExtensions({
			subject: { commonName: CA_NAME },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				customExtensions: [{ oid: OIDS.noRevAvail, value: nullValue() }],
			},
		});
		const result = await verifyCertificateChain({
			leaf: await issueLeaf(ca, undefined),
			roots: [ca.certificate.der],
		});
		expect(result).toMatchObject({ ok: false, code: 'no_rev_avail_conflict', index: 1 });
	});

	it('accepts a chain whose leaf carries noRevAvail alone, marked critical or not', async () => {
		const ca = await issuingCa();
		const plain = await issueLeaf(ca, { noRevAvail: true });
		const critical = await appendCertificateExtensions(
			await issueLeaf(ca, undefined),
			ca.keyPair.privateKey,
			[encodeExtension(OIDS.noRevAvail, nullValue(), true)],
		);
		for (const leaf of [plain, critical]) {
			const result = await verifyCertificateChain({ leaf, roots: [ca.certificate.der] });
			expect(result.ok).toBe(true);
		}
	});
});

describe('RFC 9608 §4: revocation checking is skipped for noRevAvail and ocsp-nocheck', () => {
	it('prints the sentences this suite relies on', () => {
		expect(rfc9608).toContain(
			'If the noRevAvail certificate extension specified in this document is present or the ocsp-nocheck certificate extension [RFC6960] is present, then Step (a)(3) is skipped.',
		);
	});

	it('skips a noRevAvail or ocsp-nocheck leaf under a hard-fail policy with no evidence', async () => {
		const ca = await issuingCa();
		const exempt = [
			{ extensions: { noRevAvail: true }, skipReason: 'no_rev_avail' },
			{
				extensions: { customExtensions: [{ oid: OIDS.ocspNoCheck, value: nullValue() }] },
				skipReason: 'ocsp_nocheck',
			},
		] as const;
		for (const { extensions, skipReason } of exempt) {
			const leaf = parseCertificateDerOrThrow(await issueLeaf(ca, extensions));
			const result = await checkChainRevocation({
				chain: [leaf, parseCertificateDerOrThrow(ca.certificate.der)],
				policy: { mode: 'hard-fail' },
			});
			expect(result.value.decision).toBe('allow');
			expect(result.value.certificates).toEqual([
				{ certificate: leaf, status: 'skipped', skipReason },
			]);
		}
	});

	it('does not exempt a certificate whose ocsp-nocheck value is not NULL', async () => {
		const ca = await issuingCa();
		const leaf = parseCertificateDerOrThrow(
			await issueLeaf(ca, {
				customExtensions: [{ oid: OIDS.ocspNoCheck, value: octetString(Uint8Array.of(1)) }],
			}),
		);
		const result = await checkChainRevocation({
			chain: [leaf, parseCertificateDerOrThrow(ca.certificate.der)],
			policy: { mode: 'hard-fail' },
		});
		expect(result.value.decision).toBe('deny');
		expect(result.value.certificates[0]?.status).toBe('indeterminate');
	});

	it('still denies a leaf without either extension when no evidence is supplied', async () => {
		const ca = await issuingCa();
		const leaf = parseCertificateDerOrThrow(await issueLeaf(ca, undefined));
		const result = await checkChainRevocation({
			chain: [leaf, parseCertificateDerOrThrow(ca.certificate.der)],
			policy: { mode: 'hard-fail' },
		});
		expect(result.value.decision).toBe('deny');
		expect(result.value.certificates[0]?.status).toBe('indeterminate');
	});

	it('lets verifyCertificateChain pass a noRevAvail leaf under hard-fail revocation', async () => {
		const ca = await issuingCa();
		const result = await verifyCertificateChain({
			leaf: await issueLeaf(ca, { noRevAvail: true }),
			roots: [ca.certificate.der],
			revocation: { policy: { mode: 'hard-fail' } },
		});
		expect(result.ok).toBe(true);
	});
});
