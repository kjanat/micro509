import { describe, expect, it } from 'bun:test';
import { readdir, readFile } from 'node:fs/promises';
import {
	checkChainRevocation,
	type ParsedCertificate,
	type ParsedCertificateRevocationList,
	parseCertificateDer,
	parseCertificateRevocationListDer,
	verifyCertificateChain,
} from 'micro509';
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

let allPkitsCertificatesCache: ParsedCertificate[] | null = null;

async function loadAllPkitsCertificates(): Promise<ParsedCertificate[]> {
	if (allPkitsCertificatesCache !== null) {
		return allPkitsCertificatesCache;
	}

	const certDir = new URL('./fixtures/pkits/certs/', import.meta.url);
	const files = await readdir(certDir);
	const results = await Promise.allSettled(
		files
			.filter((f) => f.endsWith('.crt'))
			.map(async (f) => {
				const name = f.replace('.crt', '');
				return readPkitsParsedCertificate(name);
			}),
	);
	const certs = results
		.filter((r): r is PromiseFulfilledResult<ParsedCertificate> => r.status === 'fulfilled')
		.map((r) => r.value);

	allPkitsCertificatesCache = certs;
	return certs;
}

async function evaluatePkitsRevocation(
	chain: readonly ParsedCertificate[],
	crlNames: readonly string[],
): Promise<boolean> {
	const crlResults = await Promise.allSettled(crlNames.map(readPkitsParsedCrl));
	const crls = crlResults
		.filter(
			(r): r is PromiseFulfilledResult<ParsedCertificateRevocationList> => r.status === 'fulfilled',
		)
		.map((r) => r.value);

	const result = await checkChainRevocation({
		chain,
		crls,
		extraCertificates: await loadAllPkitsCertificates(),
		policy: { mode: 'hard-fail' },
		at: PKITS_VALIDATION_TIME,
	});

	return result.value.decision === 'allow';
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
					const revocationResult =
						pkitsCase.crls.length > 0
							? await evaluatePkitsRevocation(verifyResult.value.chain, pkitsCase.crls)
							: true;
					expect(revocationResult).toBe(pkitsCase.shouldValidate);
				});
			}
		});
	}
});
