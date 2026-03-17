import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

interface PkitsCaseRecord {
	readonly section: string;
	readonly testNumber: string;
	readonly title: string;
	readonly certs: readonly string[];
	readonly crls: readonly string[];
	readonly shouldValidate: boolean;
	readonly initialPolicySet?: readonly string[] | 'any';
	readonly requireExplicitPolicy?: boolean;
	readonly inhibitPolicyMapping?: boolean;
	readonly inhibitAnyPolicy?: boolean;
	readonly expectedUserConstrainedPolicies?: readonly string[];
}

const POLICY_NAME_TO_OID = {
	anyPolicy: '2.5.29.32.0',
	'NIST-test-policy-1': '2.16.840.1.101.3.2.1.48.1',
	'NIST-test-policy-2': '2.16.840.1.101.3.2.1.48.2',
	'NIST-test-policy-3': '2.16.840.1.101.3.2.1.48.3',
	'NIST-test-policy-4': '2.16.840.1.101.3.2.1.48.4',
	'NIST-test-policy-5': '2.16.840.1.101.3.2.1.48.5',
	'NIST-test-policy-6': '2.16.840.1.101.3.2.1.48.6',
} as const;

function mapPolicyName(policy: string): string {
	switch (policy) {
		case 'anyPolicy':
			return POLICY_NAME_TO_OID.anyPolicy;
		case 'NIST-test-policy-1':
			return POLICY_NAME_TO_OID['NIST-test-policy-1'];
		case 'NIST-test-policy-2':
			return POLICY_NAME_TO_OID['NIST-test-policy-2'];
		case 'NIST-test-policy-3':
			return POLICY_NAME_TO_OID['NIST-test-policy-3'];
		case 'NIST-test-policy-4':
			return POLICY_NAME_TO_OID['NIST-test-policy-4'];
		case 'NIST-test-policy-5':
			return POLICY_NAME_TO_OID['NIST-test-policy-5'];
		case 'NIST-test-policy-6':
			return POLICY_NAME_TO_OID['NIST-test-policy-6'];
		default:
			throw new Error(`Unknown PKITS policy token: ${policy}`);
	}
}

function parseQuotedNames(lines: readonly string[], startIndex: number): readonly string[] {
	const names: string[] = [];
	for (let lineIndex = startIndex; lineIndex < lines.length; lineIndex += 1) {
		const line = lines[lineIndex]?.trim();
		if (line === undefined) {
			break;
		}
		for (const match of line.matchAll(/"([^"]+)"/g)) {
			const name = match[1];
			if (name !== undefined) {
				names.push(name);
			}
		}
		if (line.endsWith('};')) {
			break;
		}
	}
	return names;
}

function mapPolicyNames(rawPolicies: string): readonly string[] | 'any' {
	const policies = rawPolicies
		.split(',')
		.map((policy) => policy.trim())
		.filter((policy) => policy.length > 0);
	const firstPolicy = policies[0];
	if (policies.length === 1 && firstPolicy === 'anyPolicy') {
		return 'any';
	}
	return policies.map((policy) => mapPolicyName(policy));
}

function formatCaseRecord(pkitsCase: PkitsCaseRecord): string {
	return JSON.stringify(pkitsCase, null, '\t')
		.replaceAll('"section"', 'section')
		.replaceAll('"testNumber"', 'testNumber')
		.replaceAll('"title"', 'title')
		.replaceAll('"certs"', 'certs')
		.replaceAll('"crls"', 'crls')
		.replaceAll('"shouldValidate"', 'shouldValidate')
		.replaceAll('"initialPolicySet"', 'initialPolicySet')
		.replaceAll('"requireExplicitPolicy"', 'requireExplicitPolicy')
		.replaceAll('"inhibitPolicyMapping"', 'inhibitPolicyMapping')
		.replaceAll('"inhibitAnyPolicy"', 'inhibitAnyPolicy')
		.replaceAll('"expectedUserConstrainedPolicies"', 'expectedUserConstrainedPolicies');
}

async function main(): Promise<void> {
	const fixtureRoot = import.meta.dir;
	const upstreamPath = path.join(fixtureRoot, 'upstream', 'pkits_testcases-inl.h');
	const manifestPath = path.join(fixtureRoot, 'manifest.ts');
	const source = await readFile(upstreamPath, 'utf8');
	const lines = source.split(/\r?\n/u);
	const cases: PkitsCaseRecord[] = [];

	for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
		const commentLine = lines[lineIndex]?.trim();
		const commentMatch = commentLine?.match(
			/^\/\/ (?<testNumber>\d+\.\d+\.\d+(?:\.\d+)?) (?<title>.+?)(?: \(Subpart \d+\))?$/u,
		);
		if (commentMatch === null || commentMatch === undefined) {
			continue;
		}
		if (!lines[lineIndex + 1]?.includes('WRAPPED_TYPED_TEST_P(')) {
			continue;
		}

		const title = commentMatch.groups?.title;
		if (title === undefined) {
			throw new Error(`Malformed PKITS comment line: ${commentLine}`);
		}

		let certs: readonly string[] = [];
		let crls: readonly string[] = [];
		let emittedTestNumber = commentMatch.groups?.testNumber ?? '';
		let shouldValidate: boolean | undefined;
		let initialPolicySet: readonly string[] | 'any' | undefined;
		let requireExplicitPolicy: boolean | undefined;
		let inhibitPolicyMapping: boolean | undefined;
		let inhibitAnyPolicy: boolean | undefined;
		let expectedUserConstrainedPolicies: readonly string[] | undefined;

		for (lineIndex += 2; lineIndex < lines.length; lineIndex += 1) {
			const line = lines[lineIndex]?.trim();
			if (line === undefined) {
				break;
			}
			if (line.startsWith('const char* const certs[] = {')) {
				certs = parseQuotedNames(lines, lineIndex);
				continue;
			}
			if (line.startsWith('const char* const crls[] = {')) {
				crls = parseQuotedNames(lines, lineIndex);
				continue;
			}
			if (line.startsWith('info.test_number = ')) {
				emittedTestNumber = line.match(/"([^"]+)"/u)?.[1] ?? emittedTestNumber;
				continue;
			}
			if (line.startsWith('info.should_validate = ')) {
				shouldValidate = line.includes('true');
				continue;
			}
			if (line.startsWith('info.SetInitialPolicySet(')) {
				const rawPolicies = line.match(/"([^"]*)"/u)?.[1];
				if (rawPolicies === undefined) {
					throw new Error(`Missing policy set on line: ${line}`);
				}
				initialPolicySet = mapPolicyNames(rawPolicies);
				continue;
			}
			if (line.startsWith('info.SetInitialExplicitPolicy(')) {
				requireExplicitPolicy = line.includes('true');
				continue;
			}
			if (line.startsWith('info.SetInitialPolicyMappingInhibit(')) {
				inhibitPolicyMapping = line.includes('true');
				continue;
			}
			if (line.startsWith('info.SetInitialInhibitAnyPolicy(')) {
				inhibitAnyPolicy = line.includes('true');
				continue;
			}
			if (line.startsWith('info.SetUserConstrainedPolicySet(')) {
				const rawPolicies = line.match(/"([^"]*)"/u)?.[1];
				if (rawPolicies === undefined) {
					throw new Error(`Missing constrained policy set on line: ${line}`);
				}
				const mappedPolicies = mapPolicyNames(rawPolicies);
				expectedUserConstrainedPolicies =
					mappedPolicies === 'any' ? ['2.5.29.32.0'] : mappedPolicies;
				continue;
			}
			if (line === 'this->RunTest(certs, crls, info);') {
				break;
			}
		}

		if (shouldValidate === undefined) {
			throw new Error(`Missing should_validate for PKITS case ${emittedTestNumber}`);
		}

		cases.push({
			section: emittedTestNumber.split('.').slice(0, 2).join('.'),
			testNumber: emittedTestNumber,
			title,
			certs,
			crls,
			shouldValidate,
			...(initialPolicySet === undefined ? {} : { initialPolicySet }),
			...(requireExplicitPolicy === undefined ? {} : { requireExplicitPolicy }),
			...(inhibitPolicyMapping === undefined ? {} : { inhibitPolicyMapping }),
			...(inhibitAnyPolicy === undefined ? {} : { inhibitAnyPolicy }),
			...(expectedUserConstrainedPolicies === undefined ? {} : { expectedUserConstrainedPolicies }),
		});
	}

	const manifest = `// Auto-generated by test/fixtures/pkits/generate-manifest.ts.\n// Do not edit by hand.\n\nexport interface PkitsCase {\n\treadonly section: string;\n\treadonly testNumber: string;\n\treadonly title: string;\n\treadonly certs: readonly string[];\n\treadonly crls: readonly string[];\n\treadonly shouldValidate: boolean;\n\treadonly initialPolicySet?: readonly string[] | 'any';\n\treadonly requireExplicitPolicy?: boolean;\n\treadonly inhibitPolicyMapping?: boolean;\n\treadonly inhibitAnyPolicy?: boolean;\n\treadonly expectedUserConstrainedPolicies?: readonly string[];\n}\n\nexport const PKITS_CASES = [\n${cases.map((pkitsCase) => `\t${formatCaseRecord(pkitsCase)}`).join(',\n')}\n] as const satisfies readonly PkitsCase[];\n`;

	await writeFile(manifestPath, manifest);
}

await main();
