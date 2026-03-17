import { describe, expect, it } from 'bun:test';
import { readFile } from 'node:fs/promises';
import {
	checkCertificateRevocationAgainstCrl,
	type ParsedCertificate,
	type ParsedCertificateRevocationList,
	parseCertificateDer,
	parseCertificateRevocationListDer,
	verifyCertificateChain,
} from 'micro509';
import { compareDistinguishedNames } from '#micro509/internal/shared/dn.ts';
import { PKITS_CASES, type PkitsCase } from './fixtures/pkits/manifest.ts';

const PKITS_VALIDATION_TIME = new Date('2011-04-15T00:00:00Z');
const REVOCATION_SECTIONS = new Set(['4.4', '4.14', '4.15']);
const REVOCATION_TEST_NUMBERS = new Set(['4.7.4', '4.7.5']);

const certificateDerCache = new Map<string, Promise<Uint8Array>>();
const parsedCertificateCache = new Map<string, Promise<ParsedCertificate>>();
const parsedCrlCache = new Map<string, Promise<ParsedCertificateRevocationList>>();

function shouldEvaluateRevocation(pkitsCase: PkitsCase): boolean {
	return (
		REVOCATION_SECTIONS.has(pkitsCase.section) || REVOCATION_TEST_NUMBERS.has(pkitsCase.testNumber)
	);
}

async function readPkitsFixture(path: string): Promise<Uint8Array> {
	return new Uint8Array(await readFile(new URL(path, import.meta.url)));
}

async function readPkitsCertificateDer(name: string): Promise<Uint8Array> {
	const cached = certificateDerCache.get(name);
	if (cached !== undefined) {
		return cached;
	}
	const pending = readPkitsFixture(`./fixtures/pkits/certs/${name}.crt`);
	certificateDerCache.set(name, pending);
	return await pending;
}

async function readPkitsParsedCertificate(name: string): Promise<ParsedCertificate> {
	const cached = parsedCertificateCache.get(name);
	if (cached !== undefined) {
		return cached;
	}
	const pending = readPkitsCertificateDer(name).then((der) => parseCertificateDer(der));
	parsedCertificateCache.set(name, pending);
	return await pending;
}

async function readPkitsParsedCrl(name: string): Promise<ParsedCertificateRevocationList> {
	const cached = parsedCrlCache.get(name);
	if (cached !== undefined) {
		return cached;
	}
	const pending = readPkitsFixture(`./fixtures/pkits/crls/${name}.crl`).then((der) =>
		parseCertificateRevocationListDer(der),
	);
	parsedCrlCache.set(name, pending);
	return await pending;
}

async function evaluatePkitsRevocation(
	chain: readonly ParsedCertificate[],
	crlNames: readonly string[],
	allCertificates: readonly ParsedCertificate[],
): Promise<boolean> {
	const parsedCrls = (await Promise.allSettled(crlNames.map((name) => readPkitsParsedCrl(name))))
		.filter(
			(result): result is PromiseFulfilledResult<ParsedCertificateRevocationList> =>
				result.status === 'fulfilled',
		)
		.map((result) => result.value);
	const completeCrls = parsedCrls.filter((crl) => crl.baseCrlNumber === undefined);
	const deltaCrls = parsedCrls.filter((crl) => crl.baseCrlNumber !== undefined);

	for (let certificateIndex = 0; certificateIndex < chain.length - 1; certificateIndex += 1) {
		const certificate = chain[certificateIndex];
		const issuerCertificate = chain[certificateIndex + 1];
		if (certificate === undefined || issuerCertificate === undefined) {
			return false;
		}

		const certificateStatus = await evaluatePkitsCertificateRevocation(
			certificate,
			issuerCertificate,
			completeCrls,
			deltaCrls,
			allCertificates,
		);
		if (certificateStatus !== 'good') {
			return false;
		}
	}

	return true;
}

async function evaluatePkitsCertificateRevocation(
	certificate: ParsedCertificate,
	issuerCertificate: ParsedCertificate,
	completeCrls: readonly ParsedCertificateRevocationList[],
	deltaCrls: readonly ParsedCertificateRevocationList[],
	allCertificates: readonly ParsedCertificate[],
): Promise<'good' | 'revoked' | 'unknown'> {
	let sawGood = false;

	for (const crl of completeCrls) {
		const result = await evaluatePkitsCrlWithIssuerCandidates(
			certificate,
			issuerCertificate,
			allCertificates,
			crl,
			undefined,
		);
		if (!result.ok) {
			continue;
		}
		if (result.value.status === 'revoked') {
			return 'revoked';
		}
		sawGood = true;
	}

	for (const crl of completeCrls) {
		for (const deltaCrl of deltaCrls) {
			const result = await evaluatePkitsCrlWithIssuerCandidates(
				certificate,
				issuerCertificate,
				allCertificates,
				crl,
				deltaCrl,
			);
			if (!result.ok) {
				continue;
			}
			if (result.value.status === 'revoked') {
				return 'revoked';
			}
			sawGood = true;
		}
	}

	return sawGood ? 'good' : 'unknown';
}

async function evaluatePkitsCrlWithIssuerCandidates(
	certificate: ParsedCertificate,
	fallbackIssuer: ParsedCertificate,
	allCertificates: readonly ParsedCertificate[],
	crl: ParsedCertificateRevocationList,
	deltaCrl: ParsedCertificateRevocationList | undefined,
) {
	const issuerCandidates = allCertificates.filter(
		(candidate) =>
			compareDistinguishedNames(candidate.subject, crl.issuer) &&
			(crl.authorityKeyIdentifier === undefined ||
				candidate.subjectKeyIdentifier === crl.authorityKeyIdentifier),
	);
	const allowsAlternateCrlIssuer =
		crl.issuingDistributionPoint?.indirectCrl === true ||
		(certificate.crlDistributionPoints?.some(
			(distributionPoint) => distributionPoint.crlIssuer !== undefined,
		) ??
			false) ||
		!compareDistinguishedNames(fallbackIssuer.subject, crl.issuer);
	const candidates = allowsAlternateCrlIssuer
		? [fallbackIssuer, ...issuerCandidates]
		: [fallbackIssuer];
	for (const issuerCandidate of candidates) {
		const result = await checkCertificateRevocationAgainstCrl({
			certificate,
			issuerCertificate: issuerCandidate,
			crl,
			...(deltaCrl === undefined ? {} : { deltaCrl }),
			at: PKITS_VALIDATION_TIME,
		});
		if (result.ok) {
			return result;
		}
	}
	return {
		ok: false as const,
	};
}

describe('PKITS harness', () => {
	const pkitsCases: readonly PkitsCase[] = PKITS_CASES;
	const casesBySection = new Map<string, PkitsCase[]>();
	for (const pkitsCase of pkitsCases) {
		const sectionCases = casesBySection.get(pkitsCase.section);
		if (sectionCases === undefined) {
			casesBySection.set(pkitsCase.section, [pkitsCase]);
			continue;
		}
		sectionCases.push(pkitsCase);
	}

	for (const [section, sectionCases] of casesBySection) {
		describe(section, () => {
			for (const pkitsCase of sectionCases) {
				it(`${pkitsCase.testNumber} ${pkitsCase.title}`, async () => {
					const leafName = pkitsCase.certs[pkitsCase.certs.length - 1];
					const rootName = pkitsCase.certs[0];
					if (leafName === undefined || rootName === undefined) {
						throw new Error(`PKITS case ${pkitsCase.testNumber} is missing leaf or root`);
					}

					const [leaf, root, intermediates] = await Promise.all([
						readPkitsCertificateDer(leafName),
						readPkitsCertificateDer(rootName),
						Promise.all(
							pkitsCase.certs
								.slice(1, -1)
								.map((certificateName: string) => readPkitsCertificateDer(certificateName)),
						),
					]);

					const verifyResult = await verifyCertificateChain({
						leaf,
						intermediates,
						roots: [root],
						at: PKITS_VALIDATION_TIME,
						...(pkitsCase.initialPolicySet === undefined
							? {}
							: { initialPolicySet: pkitsCase.initialPolicySet }),
						...(pkitsCase.requireExplicitPolicy === undefined
							? {}
							: { requireExplicitPolicy: pkitsCase.requireExplicitPolicy }),
						...(pkitsCase.inhibitPolicyMapping === undefined
							? {}
							: { inhibitPolicyMapping: pkitsCase.inhibitPolicyMapping }),
						...(pkitsCase.inhibitAnyPolicy === undefined
							? {}
							: { inhibitAnyPolicy: pkitsCase.inhibitAnyPolicy }),
					});
					const chainValidated = verifyResult.ok;
					if (!shouldEvaluateRevocation(pkitsCase)) {
						expect(chainValidated).toBe(pkitsCase.shouldValidate);
						return;
					}
					if (!verifyResult.ok) {
						expect(chainValidated).toBe(pkitsCase.shouldValidate);
						return;
					}
					const allCertificates = await Promise.all(
						pkitsCase.certs.map((certificateName: string) =>
							readPkitsParsedCertificate(certificateName),
						),
					);
					const revocationResult =
						pkitsCase.crls.length > 0
							? await evaluatePkitsRevocation(
									verifyResult.value.chain,
									pkitsCase.crls,
									allCertificates,
								)
							: true;
					expect(revocationResult).toBe(pkitsCase.shouldValidate);
				});
			}
		});
	}
});
