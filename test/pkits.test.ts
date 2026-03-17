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
const REVOCATION_SECTIONS = new Set(['4.4', '4.5', '4.14', '4.15']);
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

// ReasonFlags from RFC 5280 §4.2.1.14 — onlySomeReasons uses this bitmap.
// Note: 'unspecified' (CRLReason 0) is NOT in ReasonFlags, so we exclude it.
const ALL_REASON_FLAGS = new Set([
	'keyCompromise',
	'cACompromise',
	'affiliationChanged',
	'superseded',
	'cessationOfOperation',
	'certificateHold',
	'privilegeWithdrawn',
	'aACompromise',
]);

async function evaluatePkitsCertificateRevocation(
	certificate: ParsedCertificate,
	issuerCertificate: ParsedCertificate,
	completeCrls: readonly ParsedCertificateRevocationList[],
	deltaCrls: readonly ParsedCertificateRevocationList[],
	allCertificates: readonly ParsedCertificate[],
): Promise<'good' | 'revoked' | 'unknown'> {
	let sawGood = false;
	const crlsWithAppliedDelta = new Set<ParsedCertificateRevocationList>();
	const coveredReasons = new Set<string>();

	// Process delta+complete pairs first — delta CRLs may contain removeFromCRL entries
	// that override revocations in the base CRL (e.g., suspension lifted)
	for (const deltaCrl of deltaCrls) {
		for (const crl of completeCrls) {
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
			// Mark this base CRL as having a delta applied — don't re-check it alone
			crlsWithAppliedDelta.add(crl);
			// Track which reasons this CRL covers
			const crlReasons = result.value.crl.issuingDistributionPoint?.onlySomeReasons?.flags;
			if (crlReasons === undefined) {
				for (const reason of ALL_REASON_FLAGS) coveredReasons.add(reason);
			} else {
				for (const reason of crlReasons) coveredReasons.add(reason);
			}
			if (result.value.status === 'revoked') {
				return 'revoked';
			}
			sawGood = true;
		}
	}

	// Fall back to complete CRLs alone only if no applicable delta CRL was paired
	for (const crl of completeCrls) {
		if (crlsWithAppliedDelta.has(crl)) {
			continue;
		}
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
		// Track which reasons this CRL covers
		const crlReasons = result.value.crl.issuingDistributionPoint?.onlySomeReasons?.flags;
		if (crlReasons === undefined) {
			for (const reason of ALL_REASON_FLAGS) coveredReasons.add(reason);
		} else {
			for (const reason of crlReasons) coveredReasons.add(reason);
		}
		if (result.value.status === 'revoked') {
			return 'revoked';
		}
		sawGood = true;
	}

	// Only return 'good' if all revocation reasons have been covered
	if (sawGood) {
		for (const reason of ALL_REASON_FLAGS) {
			if (!coveredReasons.has(reason)) {
				return 'unknown';
			}
		}
		return 'good';
	}
	return 'unknown';
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
		!compareDistinguishedNames(fallbackIssuer.subject, crl.issuer) ||
		// Self-issued cert case: subjects match but keys differ
		(crl.authorityKeyIdentifier !== undefined &&
			fallbackIssuer.subjectKeyIdentifier !== crl.authorityKeyIdentifier);
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
