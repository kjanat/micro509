import { describe, expect, it } from 'bun:test';
import { readFile } from 'node:fs/promises';
import type { VerifyErrorCode } from '#micro509';
import { verifyCertificateChain } from '#micro509';

const PKITS_VALIDATION_TIME = new Date('2011-04-15T00:00:00Z');
const NIST_TEST_POLICY_1 = '2.16.840.1.101.3.2.1.48.1';
const NIST_TEST_POLICY_2 = '2.16.840.1.101.3.2.1.48.2';
const NIST_TEST_POLICY_4 = '2.16.840.1.101.3.2.1.48.4';

interface PkitsHarnessCase {
	readonly section: string;
	readonly title: string;
	readonly certs: readonly string[];
	readonly shouldValidate: boolean;
	readonly expectedCode?: VerifyErrorCode;
	readonly initialPolicySet?: readonly string[];
	readonly inhibitAnyPolicy?: boolean;
	readonly expectedUserConstrainedPolicies?: readonly string[];
}

const PKITS_CASES: readonly PkitsHarnessCase[] = [
	{
		section: '4.1.1',
		title: 'valid certificate path',
		certs: ['TrustAnchorRootCertificate', 'GoodCACert', 'ValidCertificatePathTest1EE'],
		shouldValidate: true,
	},
	{
		section: '4.6.5',
		title: 'path length exceeded',
		certs: [
			'TrustAnchorRootCertificate',
			'pathLenConstraint0CACert',
			'pathLenConstraint0subCACert',
			'InvalidpathLenConstraintTest5EE',
		],
		shouldValidate: false,
		expectedCode: 'path_length_exceeded',
	},
	{
		section: '4.9.1',
		title: 'requireExplicitPolicy valid chain',
		certs: [
			'TrustAnchorRootCertificate',
			'requireExplicitPolicy10CACert',
			'requireExplicitPolicy10subCACert',
			'requireExplicitPolicy10subsubCACert',
			'requireExplicitPolicy10subsubsubCACert',
			'ValidrequireExplicitPolicyTest1EE',
		],
		shouldValidate: true,
	},
	{
		section: '4.10.12',
		title: 'policy mapping with initial policy set',
		certs: ['TrustAnchorRootCertificate', 'P12Mapping1to3CACert', 'ValidPolicyMappingTest12EE'],
		shouldValidate: true,
		initialPolicySet: [NIST_TEST_POLICY_1],
		expectedUserConstrainedPolicies: [NIST_TEST_POLICY_1],
	},
	{
		section: '4.10.13',
		title: 'policy mapping rejects unsatisfied initial policy set',
		certs: [
			'TrustAnchorRootCertificate',
			'P1anyPolicyMapping1to2CACert',
			'ValidPolicyMappingTest13EE',
		],
		shouldValidate: false,
		expectedCode: 'explicit_policy_required',
		initialPolicySet: [NIST_TEST_POLICY_2],
	},
	{
		section: '4.11.4',
		title: 'inhibitPolicyMapping valid chain',
		certs: [
			'TrustAnchorRootCertificate',
			'inhibitPolicyMapping1P12CACert',
			'inhibitPolicyMapping1P12subCACert',
			'inhibitPolicyMapping1P12subsubCACert',
			'ValidinhibitPolicyMappingTest4EE',
		],
		shouldValidate: true,
		expectedUserConstrainedPolicies: [NIST_TEST_POLICY_4],
	},
	{
		section: '4.12.3',
		title: 'initial inhibitAnyPolicy blocks the mapped chain',
		certs: [
			'TrustAnchorRootCertificate',
			'inhibitAnyPolicy1CACert',
			'inhibitAnyPolicy1subCA1Cert',
			'inhibitAnyPolicyTest3EE',
		],
		shouldValidate: false,
		expectedCode: 'explicit_policy_required',
		inhibitAnyPolicy: true,
	},
	{
		section: '4.13.21',
		title: 'RFC822 name constraints valid chain',
		certs: [
			'TrustAnchorRootCertificate',
			'nameConstraintsRFC822CA1Cert',
			'ValidRFC822nameConstraintsTest21EE',
		],
		shouldValidate: true,
	},
	{
		section: '4.13.28',
		title: 'combined DN and RFC822 name constraints invalid chain',
		certs: [
			'TrustAnchorRootCertificate',
			'nameConstraintsDN1CACert',
			'nameConstraintsDN1subCA3Cert',
			'InvalidDNandRFC822nameConstraintsTest28EE',
		],
		shouldValidate: false,
		expectedCode: 'name_constraints_violated',
	},
] as const;

async function readPkitsCertificate(name: string): Promise<Uint8Array> {
	const url = new URL(`./fixtures/pkits/certs/${name}.crt`, import.meta.url);
	return new Uint8Array(await readFile(url));
}

describe('PKITS harness', () => {
	for (const pkitsCase of PKITS_CASES) {
		it(`${pkitsCase.section} ${pkitsCase.title}`, async () => {
			const leafName = pkitsCase.certs[pkitsCase.certs.length - 1];
			const rootName = pkitsCase.certs[0];
			if (leafName === undefined || rootName === undefined) {
				throw new Error(`PKITS case ${pkitsCase.section} is missing leaf or root`);
			}

			const [leaf, root, intermediates] = await Promise.all([
				readPkitsCertificate(leafName),
				readPkitsCertificate(rootName),
				Promise.all(
					pkitsCase.certs
						.slice(1, -1)
						.map((certificateName) => readPkitsCertificate(certificateName)),
				),
			]);

			const result = await verifyCertificateChain({
				leaf,
				intermediates,
				roots: [root],
				at: PKITS_VALIDATION_TIME,
				...(pkitsCase.initialPolicySet === undefined
					? {}
					: { initialPolicySet: pkitsCase.initialPolicySet }),
				...(pkitsCase.inhibitAnyPolicy === undefined
					? {}
					: { inhibitAnyPolicy: pkitsCase.inhibitAnyPolicy }),
			});

			expect(result.ok).toBe(pkitsCase.shouldValidate);
			if (!result.ok && pkitsCase.expectedCode !== undefined) {
				expect(result.code).toBe(pkitsCase.expectedCode);
			} else if (result.ok && pkitsCase.expectedUserConstrainedPolicies !== undefined) {
				expect(
					result.value.policyValidation.userConstrainedPolicies.map(
						(policy) => policy.policyIdentifier,
					),
				).toEqual([...pkitsCase.expectedUserConstrainedPolicies]);
			}
		});
	}
});
