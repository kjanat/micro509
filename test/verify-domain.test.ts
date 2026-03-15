import { describe, expect, it } from 'bun:test';
import type {
	GeneralSubtree,
	MatchableServiceIdentityInput,
	ParsedCertificate,
	PolicyQualifierInfo,
	PolicyValidationInput,
	Result,
} from '#micro509/verify/index.ts';
import * as verify from '#micro509/verify/index.ts';

function assertVerifyDomainTypes(_input: {
	readonly subtree?: GeneralSubtree;
	readonly parsed?: ParsedCertificate;
	readonly qualifier?: PolicyQualifierInfo;
	readonly result?: Result<string, number>;
}): void {}

describe('verify domain', () => {
	it('exposes the consolidated advanced verification surface', () => {
		const serviceIdentity: MatchableServiceIdentityInput = {
			type: 'dns',
			value: 'example.com',
		};
		const policy: PolicyValidationInput = {
			requireExplicitPolicy: true,
		};

		assertVerifyDomainTypes({});

		expect(serviceIdentity.type).toBe('dns');
		expect(policy.requireExplicitPolicy).toBe(true);
		expect(typeof verify.verifyCertificateChain).toBe('function');
		expect(typeof verify.validateCandidatePath).toBe('function');
		expect(typeof verify.validateForTlsServer).toBe('function');
		expect(typeof verify.matchServiceIdentity).toBe('function');
		expect(typeof verify.matchCertificateServiceIdentity).toBe('function');
		expect(typeof verify.checkExtendedKeyUsage).toBe('function');
	});
});
