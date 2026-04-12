import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificatePem,
	validateCandidatePath,
} from 'micro509';
import { OIDS } from '#micro509/internal/asn1/oids.ts';

type PolicyIdentifier = string;

interface PolicyFixtureIntermediate {
	readonly commonName: string;
	readonly certificatePolicies: readonly PolicyIdentifier[];
	readonly policyMappings?: readonly {
		readonly issuerDomainPolicy: PolicyIdentifier;
		readonly subjectDomainPolicy: PolicyIdentifier;
	}[];
	readonly policyConstraints?: {
		readonly requireExplicitPolicy?: number;
		readonly inhibitPolicyMapping?: number;
	};
	readonly inhibitAnyPolicySkipCerts?: number;
}

function toCertificatePolicies(policyIdentifiers: readonly PolicyIdentifier[]) {
	return policyIdentifiers.map((policyIdentifier) => ({ policyIdentifier }));
}

async function issuePolicyFixtureChain(options: {
	readonly intermediates?: readonly PolicyFixtureIntermediate[];
	readonly leafPolicies?: readonly PolicyIdentifier[];
}) {
	const intermediates = options.intermediates ?? [];
	const rootCommonName = 'Policy Fixture Root';
	const root = await createSelfSignedCertificate({
		subject: { commonName: rootCommonName },
		extensions: {
			basicConstraints: { ca: true, pathLength: intermediates.length },
			keyUsage: ['keyCertSign', 'cRLSign'],
		},
	});

	let issuerCommonName = rootCommonName;
	let issuerPrivateKey = root.keyPair.privateKey;
	let issuerPublicKey = root.keyPair.publicKey;
	const intermediatePems: string[] = [];

	for (let index = 0; index < intermediates.length; index += 1) {
		const intermediateSpec = intermediates[index];
		if (intermediateSpec === undefined) {
			throw new Error('Missing intermediate fixture spec');
		}
		const intermediateKeys = await generateKeyPair();
		const intermediate = await createCertificate({
			issuer: { commonName: issuerCommonName },
			subject: { commonName: intermediateSpec.commonName },
			publicKey: intermediateKeys.publicKey,
			signerPrivateKey: issuerPrivateKey,
			issuerPublicKey: issuerPublicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: intermediates.length - index - 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
				certificatePolicies: toCertificatePolicies(intermediateSpec.certificatePolicies),
				...(intermediateSpec.policyMappings === undefined
					? {}
					: { policyMappings: intermediateSpec.policyMappings }),
				...(intermediateSpec.policyConstraints === undefined
					? {}
					: { policyConstraints: intermediateSpec.policyConstraints }),
				...(intermediateSpec.inhibitAnyPolicySkipCerts === undefined
					? {}
					: { inhibitAnyPolicy: { skipCerts: intermediateSpec.inhibitAnyPolicySkipCerts } }),
			},
		});
		intermediatePems.push(intermediate.pem);
		issuerCommonName = intermediateSpec.commonName;
		issuerPrivateKey = intermediateKeys.privateKey;
		issuerPublicKey = intermediateKeys.publicKey;
	}

	const leafKeys = await generateKeyPair();
	const leaf = await createCertificate({
		issuer: { commonName: issuerCommonName },
		subject: { commonName: 'policy-fixture-leaf' },
		publicKey: leafKeys.publicKey,
		signerPrivateKey: issuerPrivateKey,
		issuerPublicKey: issuerPublicKey,
		extensions: {
			keyUsage: ['digitalSignature'],
			...(options.leafPolicies === undefined
				? {}
				: { certificatePolicies: toCertificatePolicies(options.leafPolicies) }),
		},
	});

	return [
		parseCertificatePem(leaf.pem),
		...intermediatePems.toReversed().map((pem) => parseCertificatePem(pem)),
		parseCertificatePem(root.certificate.pem),
	] as const;
}

describe('policy fixtures', () => {
	it('covers mapped-policy success and mapping inhibition failures', async () => {
		const chain = await issuePolicyFixtureChain({
			intermediates: [
				{
					commonName: 'Policy Mapping Intermediate',
					certificatePolicies: [OIDS.anyPolicy],
					policyMappings: [{ issuerDomainPolicy: '1.2.3.4', subjectDomainPolicy: '1.2.3.5' }],
				},
			],
			leafPolicies: ['1.2.3.5'],
		});

		const allowed = await validateCandidatePath({
			chain,
			initialPolicySet: ['1.2.3.4'],
		});
		expect(allowed).toMatchObject({
			ok: true,
			policyValidation: {
				authorityConstrainedPolicies: [{ policyIdentifier: '1.2.3.5' }],
				userConstrainedPolicies: [{ policyIdentifier: '1.2.3.4' }],
			},
		});

		const blocked = await validateCandidatePath({
			chain,
			initialPolicySet: ['1.2.3.4'],
			inhibitPolicyMapping: true,
		});
		expect(blocked).toMatchObject({
			ok: false,
			code: 'initial_policy_set_not_satisfied',
			details: {
				expected: '1.2.3.4',
				actual: '<none>',
			},
		});
	});

	it('ignores tampered policy mappings that use anyPolicy', async () => {
		const chain = await issuePolicyFixtureChain({
			intermediates: [
				{
					commonName: 'Tampered Mapping Intermediate',
					certificatePolicies: [OIDS.anyPolicy],
				},
			],
			leafPolicies: ['1.2.3.5'],
		});

		const leaf = chain[0];
		const intermediate = chain[1];
		const root = chain[2];
		if (leaf === undefined || intermediate === undefined || root === undefined) {
			throw new Error('Missing policy fixture certificate');
		}
		const tamperedChain = [
			leaf,
			{
				...intermediate,
				policyMappings: [{ issuerDomainPolicy: OIDS.anyPolicy, subjectDomainPolicy: '1.2.3.5' }],
			},
			root,
		];

		const result = await validateCandidatePath({
			chain: tamperedChain,
			inhibitPolicyMapping: true,
		});
		expect(result).toMatchObject({
			ok: true,
			policyValidation: {
				authorityConstrainedPolicies: [{ policyIdentifier: '1.2.3.5' }],
				userConstrainedPolicies: [{ policyIdentifier: '1.2.3.5' }],
			},
		});
	});

	it('ignores tampered negative requireExplicitPolicy values', async () => {
		const chain = await issuePolicyFixtureChain({
			intermediates: [
				{
					commonName: 'Negative Explicit Intermediate',
					certificatePolicies: ['1.2.3.4'],
				},
			],
		});

		const leaf = chain[0];
		const intermediate = chain[1];
		const root = chain[2];
		if (leaf === undefined || intermediate === undefined || root === undefined) {
			throw new Error('Missing policy fixture certificate');
		}
		const tamperedChain = [
			leaf,
			{
				...intermediate,
				policyConstraints: { requireExplicitPolicy: -1 },
			},
			root,
		];

		const result = await validateCandidatePath({
			chain: tamperedChain,
			requireExplicitPolicy: true,
		});
		expect(result).toMatchObject({
			ok: false,
			code: 'explicit_policy_required',
		});
	});

	it('ignores tampered fractional requireExplicitPolicy values', async () => {
		const chain = await issuePolicyFixtureChain({
			intermediates: [
				{
					commonName: 'Fractional Explicit Intermediate',
					certificatePolicies: ['1.2.3.4'],
				},
			],
		});

		const leaf = chain[0];
		const intermediate = chain[1];
		const root = chain[2];
		if (leaf === undefined || intermediate === undefined || root === undefined) {
			throw new Error('Missing policy fixture certificate');
		}
		const tamperedChain = [
			leaf,
			{
				...intermediate,
				policyConstraints: { requireExplicitPolicy: 0.5 },
			},
			root,
		];

		const result = await validateCandidatePath({
			chain: tamperedChain,
			requireExplicitPolicy: true,
		});
		expect(result).toMatchObject({
			ok: false,
			code: 'explicit_policy_required',
		});
	});

	it('ignores tampered negative inhibitAnyPolicy values', async () => {
		const chain = await issuePolicyFixtureChain({
			intermediates: [
				{
					commonName: 'Negative AnyPolicy Intermediate',
					certificatePolicies: ['1.2.3.4'],
				},
			],
			leafPolicies: [OIDS.anyPolicy],
		});

		const leaf = chain[0];
		const intermediate = chain[1];
		const root = chain[2];
		if (leaf === undefined || intermediate === undefined || root === undefined) {
			throw new Error('Missing policy fixture certificate');
		}
		const tamperedChain = [
			leaf,
			{
				...intermediate,
				inhibitAnyPolicy: { skipCerts: -1 },
			},
			root,
		];

		const result = await validateCandidatePath({
			chain: tamperedChain,
			initialPolicySet: ['1.2.3.4'],
		});
		expect(result).toMatchObject({
			ok: true,
			policyValidation: {
				userConstrainedPolicies: [{ policyIdentifier: '1.2.3.4' }],
			},
		});
	});

	it('ignores tampered fractional inhibitAnyPolicy values', async () => {
		const chain = await issuePolicyFixtureChain({
			intermediates: [
				{
					commonName: 'Fractional AnyPolicy Stage One',
					certificatePolicies: ['1.2.3.4'],
				},
				{
					commonName: 'Fractional AnyPolicy Stage Two',
					certificatePolicies: ['1.2.3.4'],
				},
			],
			leafPolicies: [OIDS.anyPolicy],
		});

		const leaf = chain[0];
		const stageTwo = chain[1];
		const stageOne = chain[2];
		const root = chain[3];
		if (
			leaf === undefined ||
			stageTwo === undefined ||
			stageOne === undefined ||
			root === undefined
		) {
			throw new Error('Missing policy fixture certificate');
		}
		const tamperedChain = [
			leaf,
			stageTwo,
			{
				...stageOne,
				inhibitAnyPolicy: { skipCerts: 0.5 },
			},
			root,
		];

		const result = await validateCandidatePath({
			chain: tamperedChain,
			initialPolicySet: ['1.2.3.4'],
		});
		expect(result).toMatchObject({
			ok: true,
			policyValidation: {
				userConstrainedPolicies: [{ policyIdentifier: '1.2.3.4' }],
			},
		});
	});

	it('ignores tampered negative inhibitPolicyMapping values', async () => {
		const chain = await issuePolicyFixtureChain({
			intermediates: [
				{
					commonName: 'Negative Mapping Constraint Stage One',
					certificatePolicies: ['1.2.3.4'],
				},
				{
					commonName: 'Negative Mapping Constraint Stage Two',
					certificatePolicies: [OIDS.anyPolicy],
					policyMappings: [{ issuerDomainPolicy: '1.2.3.4', subjectDomainPolicy: '1.2.3.5' }],
				},
			],
			leafPolicies: ['1.2.3.5'],
		});

		const leaf = chain[0];
		const stageTwo = chain[1];
		const stageOne = chain[2];
		const root = chain[3];
		if (
			leaf === undefined ||
			stageTwo === undefined ||
			stageOne === undefined ||
			root === undefined
		) {
			throw new Error('Missing policy fixture certificate');
		}
		const tamperedChain = [
			leaf,
			stageTwo,
			{
				...stageOne,
				policyConstraints: { inhibitPolicyMapping: -1 },
			},
			root,
		];

		const result = await validateCandidatePath({
			chain: tamperedChain,
			initialPolicySet: ['1.2.3.4'],
		});
		expect(result).toMatchObject({
			ok: true,
			policyValidation: {
				userConstrainedPolicies: [{ policyIdentifier: '1.2.3.4' }],
			},
		});
	});

	it('ignores tampered fractional inhibitPolicyMapping values', async () => {
		const chain = await issuePolicyFixtureChain({
			intermediates: [
				{
					commonName: 'Fractional Mapping Constraint Stage One',
					certificatePolicies: ['1.2.3.4'],
				},
				{
					commonName: 'Fractional Mapping Constraint Stage Two',
					certificatePolicies: ['1.2.3.4'],
				},
				{
					commonName: 'Fractional Mapping Constraint Stage Three',
					certificatePolicies: [OIDS.anyPolicy],
					policyMappings: [{ issuerDomainPolicy: '1.2.3.4', subjectDomainPolicy: '1.2.3.5' }],
				},
			],
			leafPolicies: ['1.2.3.5'],
		});

		const leaf = chain[0];
		const stageThree = chain[1];
		const stageTwo = chain[2];
		const stageOne = chain[3];
		const root = chain[4];
		if (
			leaf === undefined ||
			stageThree === undefined ||
			stageTwo === undefined ||
			stageOne === undefined ||
			root === undefined
		) {
			throw new Error('Missing policy fixture certificate');
		}
		const tamperedChain = [
			leaf,
			stageThree,
			stageTwo,
			{
				...stageOne,
				policyConstraints: { inhibitPolicyMapping: 0.5 },
			},
			root,
		];

		const result = await validateCandidatePath({
			chain: tamperedChain,
			initialPolicySet: ['1.2.3.4'],
		});
		expect(result).toMatchObject({
			ok: true,
			policyValidation: {
				userConstrainedPolicies: [{ policyIdentifier: '1.2.3.4' }],
			},
		});
	});

	it('covers explicit-policy and anyPolicy rejection fixtures', async () => {
		const explicitPolicyChain = await issuePolicyFixtureChain({});
		const explicitPolicyFailure = await validateCandidatePath({
			chain: explicitPolicyChain,
			requireExplicitPolicy: true,
		});
		expect(explicitPolicyFailure).toMatchObject({
			ok: false,
			code: 'explicit_policy_required',
		});

		const anyPolicyChain = await issuePolicyFixtureChain({
			leafPolicies: [OIDS.anyPolicy],
		});
		const anyPolicyAllowed = await validateCandidatePath({
			chain: anyPolicyChain,
			initialPolicySet: ['1.2.3.8'],
		});
		expect(anyPolicyAllowed).toMatchObject({
			ok: true,
			policyValidation: {
				authorityConstrainedPolicies: [{ policyIdentifier: OIDS.anyPolicy }],
				userConstrainedPolicies: [{ policyIdentifier: '1.2.3.8' }],
			},
		});

		const anyPolicyBlocked = await validateCandidatePath({
			chain: anyPolicyChain,
			initialPolicySet: ['1.2.3.8'],
			inhibitAnyPolicy: true,
		});
		expect(anyPolicyBlocked).toMatchObject({
			ok: false,
			code: 'initial_policy_set_not_satisfied',
			details: {
				expected: '1.2.3.8',
				actual: '<none>',
			},
		});
	});

	it('covers worst-case policy-mapping fanout with deduped leaf policies', async () => {
		const chain = await issuePolicyFixtureChain({
			intermediates: [
				{
					commonName: 'Policy Fanout Stage One',
					certificatePolicies: [OIDS.anyPolicy],
					policyMappings: [
						{ issuerDomainPolicy: '1.2.3.1', subjectDomainPolicy: '1.2.3.11' },
						{ issuerDomainPolicy: '1.2.3.1', subjectDomainPolicy: '1.2.3.12' },
						{ issuerDomainPolicy: '1.2.3.1', subjectDomainPolicy: '1.2.3.13' },
						{ issuerDomainPolicy: '1.2.3.2', subjectDomainPolicy: '1.2.3.11' },
						{ issuerDomainPolicy: '1.2.3.2', subjectDomainPolicy: '1.2.3.12' },
						{ issuerDomainPolicy: '1.2.3.2', subjectDomainPolicy: '1.2.3.13' },
						{ issuerDomainPolicy: '1.2.3.3', subjectDomainPolicy: '1.2.3.11' },
						{ issuerDomainPolicy: '1.2.3.3', subjectDomainPolicy: '1.2.3.12' },
						{ issuerDomainPolicy: '1.2.3.3', subjectDomainPolicy: '1.2.3.13' },
					],
				},
				{
					commonName: 'Policy Fanout Stage Two',
					certificatePolicies: ['1.2.3.11', '1.2.3.12', '1.2.3.13'],
					policyMappings: [
						{ issuerDomainPolicy: '1.2.3.11', subjectDomainPolicy: '1.2.3.21' },
						{ issuerDomainPolicy: '1.2.3.11', subjectDomainPolicy: '1.2.3.22' },
						{ issuerDomainPolicy: '1.2.3.11', subjectDomainPolicy: '1.2.3.23' },
						{ issuerDomainPolicy: '1.2.3.12', subjectDomainPolicy: '1.2.3.21' },
						{ issuerDomainPolicy: '1.2.3.12', subjectDomainPolicy: '1.2.3.22' },
						{ issuerDomainPolicy: '1.2.3.12', subjectDomainPolicy: '1.2.3.23' },
						{ issuerDomainPolicy: '1.2.3.13', subjectDomainPolicy: '1.2.3.21' },
						{ issuerDomainPolicy: '1.2.3.13', subjectDomainPolicy: '1.2.3.22' },
						{ issuerDomainPolicy: '1.2.3.13', subjectDomainPolicy: '1.2.3.23' },
					],
				},
			],
			leafPolicies: ['1.2.3.21', '1.2.3.22', '1.2.3.23'],
		});

		const result = await validateCandidatePath({
			chain,
			initialPolicySet: ['1.2.3.1', '1.2.3.2', '1.2.3.3'],
		});
		expect(result).toMatchObject({
			ok: true,
			policyValidation: {
				authorityConstrainedPolicies: [
					{ policyIdentifier: '1.2.3.21' },
					{ policyIdentifier: '1.2.3.22' },
					{ policyIdentifier: '1.2.3.23' },
				],
				userConstrainedPolicies: [
					{ policyIdentifier: '1.2.3.1' },
					{ policyIdentifier: '1.2.3.2' },
					{ policyIdentifier: '1.2.3.3' },
				],
			},
		});
	});
});
