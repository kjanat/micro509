import { describe, expect, it } from 'bun:test';
import {
	checkCertificateRevocation,
	checkChainRevocation,
	createCertificate,
	createOcspResponse,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificatePem,
	unwrap,
	validateOcspResponse,
	verifyCertificateChain,
} from '#micro509';
import { rfcDir } from '#test/helpers';

const rfcLines = async (rfc: string): Promise<readonly string[]> =>
	(await Bun.file(`${rfcDir}/${rfc}.txt`).text()).split('\n');

const rfc9919Lines = await rfcLines('rfc9919');
const rfc6960Lines = await rfcLines('rfc6960');

const printed = (lines: readonly string[], from: number, to: number): string =>
	lines
		.slice(from - 1, to)
		.join(' ')
		.replace(/\s+/g, ' ')
		.trim();

const HOUR_MS = 60 * 60 * 1_000;
const FAR_FUTURE = new Date('2100-01-01T00:00:00Z');

function evaluationTime(): Date {
	return new Date(Math.floor(Date.now() / 1_000) * 1_000);
}

async function ocspPki(withNextUpdate: boolean) {
	const ca = await createSelfSignedCertificate({
		subject: { commonName: 'RFC 9919 CA' },
		extensions: {
			basicConstraints: { ca: true, pathLength: 0 },
			keyUsage: ['keyCertSign', 'cRLSign'],
		},
	});
	const leafKeys = await generateKeyPair();
	const leaf = await createCertificate({
		issuer: { commonName: 'RFC 9919 CA' },
		subject: { commonName: 'rfc9919-leaf.example' },
		publicKey: leafKeys.publicKey,
		signerPrivateKey: ca.keyPair.privateKey,
		issuerPublicKey: ca.keyPair.publicKey,
	});
	const at = evaluationTime();
	const thisUpdate = new Date(at.getTime() - HOUR_MS);
	const response = await createOcspResponse({
		signerPrivateKey: ca.keyPair.privateKey,
		signerCertificate: ca.certificate.pem,
		producedAt: thisUpdate,
		responses: [
			{
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				certStatus: 'good',
				thisUpdate,
				...(withNextUpdate ? { nextUpdate: new Date(at.getTime() + HOUR_MS) } : {}),
			},
		],
	});
	const chain = [
		unwrap(parseCertificatePem(leaf.pem)),
		unwrap(parseCertificatePem(ca.certificate.pem)),
	];
	return { ca, leaf, chain, response: response.der, at };
}

describe('RFC 6960 §4.2.2.1 L856-864 "If nextUpdate is not set, the responder is indicating that newer revocation information is available all the time."', () => {
	it('prints the sentences this suite relies on', () => {
		const section = printed(rfc6960Lines, 856, 864);
		expect(section).toContain(
			'Responses whose nextUpdate value is earlier than the local system time value SHOULD be considered unreliable',
		);
		expect(section).toContain(
			'If nextUpdate is not set, the responder is indicating that newer revocation information is available all the time.',
		);
	});

	it('the default profile accepts a response without nextUpdate at a far-future time', async () => {
		const { ca, response } = await ocspPki(false);
		const result = await validateOcspResponse({
			response,
			issuerCertificate: ca.certificate.pem,
			at: FAR_FUTURE,
		});
		expect(result.ok).toBe(true);
		expect(result.ok ? result.value.responses?.[0]?.nextUpdate : undefined).toBeUndefined();
		const explicit = await validateOcspResponse({
			response,
			issuerCertificate: ca.certificate.pem,
			at: FAR_FUTURE,
			profile: 'rfc6960',
		});
		expect(explicit.ok).toBe(true);
	});
});

describe('RFC 9919 §5 L466-469 "If the nextUpdate field is absent, the client MUST reject the response."', () => {
	it('prints the sentences this suite enforces', () => {
		const section = printed(rfc9919Lines, 466, 469);
		expect(section).toContain('Clients MUST check for the existence of the nextUpdate field');
		expect(section).toContain(
			'If the nextUpdate field is absent, the client MUST reject the response.',
		);
	});

	it("profile: 'rfc9919' rejects a response without nextUpdate with next_update_missing", async () => {
		const { ca, response, at } = await ocspPki(false);
		const result = await validateOcspResponse({
			response,
			issuerCertificate: ca.certificate.pem,
			at,
			profile: 'rfc9919',
		});
		expect(result.ok ? 'ok' : result.code).toBe('next_update_missing');
	});

	it("profile: 'rfc9919' accepts a current response that carries nextUpdate", async () => {
		const { ca, response, at } = await ocspPki(true);
		const result = await validateOcspResponse({
			response,
			issuerCertificate: ca.certificate.pem,
			at,
			profile: 'rfc9919',
		});
		expect(result.ok).toBe(true);
	});

	it('checkCertificateRevocation with ocspProfile rfc9919 reports next_update_missing evidence', async () => {
		const { ca, leaf, response, at } = await ocspPki(false);
		const check = async (ocspProfile?: 'rfc6960' | 'rfc9919') =>
			unwrap(
				await checkCertificateRevocation({
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					evidence: [{ kind: 'ocsp', response }],
					at,
					...(ocspProfile === undefined ? {} : { ocspProfile }),
				}),
			);
		expect((await check()).status).toBe('good');
		const strict = await check('rfc9919');
		expect(strict.status).toBe('indeterminate');
		expect(
			strict.status === 'indeterminate'
				? strict.details.indeterminateEvidence.map((entry) => entry.code)
				: [],
		).toEqual(['next_update_missing']);
	});

	it('checkChainRevocation with policy.ocspProfile rfc9919 reports ocsp_next_update_missing', async () => {
		const { chain, response, at } = await ocspPki(false);
		const check = async (ocspProfile?: 'rfc6960' | 'rfc9919') =>
			(
				await checkChainRevocation({
					chain,
					ocspResponses: [response],
					at,
					policy: { mode: 'soft-fail', ...(ocspProfile === undefined ? {} : { ocspProfile }) },
				})
			).value.certificates[0];
		expect((await check())?.status).toBe('good');
		const strict = await check('rfc9919');
		expect(strict?.status).toBe('indeterminate');
		expect(strict?.indeterminateReasons).toContain('ocsp_next_update_missing');
	});

	it('verifyCertificateChain denies under hard-fail when revocation.policy.ocspProfile is rfc9919', async () => {
		const { ca, leaf, response, at } = await ocspPki(false);
		const verify = (ocspProfile?: 'rfc6960' | 'rfc9919') =>
			verifyCertificateChain({
				leaf: leaf.der,
				roots: [ca.certificate.der],
				at,
				revocation: {
					ocspResponses: [response],
					policy: { mode: 'hard-fail', ...(ocspProfile === undefined ? {} : { ocspProfile }) },
				},
			});
		expect((await verify()).ok).toBe(true);
		const strict = await verify('rfc9919');
		expect(strict.ok ? undefined : strict.error.code).toBe('revocation_indeterminate');
	});
});

describe('RFC 9919 §1 L157-168: the profile applies to OCSP clients that adopt it, so micro509 makes it opt-in', () => {
	it('prints the sentences on adoption and out-of-band conformance', () => {
		expect(printed(rfc9919Lines, 157, 162)).toContain(
			'It is intended that the normative requirements defined in this profile will be adopted by OCSP clients and OCSP responders operating in very large-scale (high-volume) PKI environments or PKI environments that require a lightweight solution to minimize bandwidth and client-side processing power (or both), as described above.',
		);
		expect(printed(rfc9919Lines, 165, 168)).toContain(
			'Thus, clients may need to use out-of-band mechanisms (e.g., agreed upon arrangements between operators of OCSP responders and OCSP clients) to determine whether a responder conforms to the profile defined in this document.',
		);
	});

	it('omitting profile keeps the RFC 6960 behaviour for the same response', async () => {
		const { ca, response, at } = await ocspPki(false);
		const general = await validateOcspResponse({
			response,
			issuerCertificate: ca.certificate.pem,
			at,
		});
		const profiled = await validateOcspResponse({
			response,
			issuerCertificate: ca.certificate.pem,
			at,
			profile: 'rfc9919',
		});
		expect(general.ok).toBe(true);
		expect(profiled.ok ? 'ok' : profiled.code).toBe('next_update_missing');
	});
});
