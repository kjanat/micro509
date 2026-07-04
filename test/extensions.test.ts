import { describe, expect, it } from 'bun:test';
import type {
	CertificatePolicies,
	InhibitAnyPolicy,
	PolicyConstraints,
	PolicyMappings,
	PolicyQualifierInfo,
} from '#micro509';
import { OIDS } from '#micro509/internal/asn1/oids.ts';

describe('policy extension surface', () => {
	it('exports policy extension OIDs', () => {
		expect(OIDS.certificatePolicies).toBe('2.5.29.32');
		expect(OIDS.policyMappings).toBe('2.5.29.33');
		expect(OIDS.policyConstraints).toBe('2.5.29.36');
		expect(OIDS.inhibitAnyPolicy).toBe('2.5.29.54');
		expect(OIDS.anyPolicy).toBe('2.5.29.32.0');
		expect(OIDS.cpsPolicyQualifier).toBe('1.3.6.1.5.5.7.2.1');
		expect(OIDS.userNoticePolicyQualifier).toBe('1.3.6.1.5.5.7.2.2');
	});

	it('exports stable policy extension types', () => {
		const qualifiers: readonly PolicyQualifierInfo[] = [
			{ type: 'cps', uri: 'https://example.com/cps' },
			{
				type: 'userNotice',
				noticeRef: {
					organization: 'Example PKI',
					noticeNumbers: [1, 2],
				},
				explicitText: 'For testing only',
			},
			{
				type: 'oid',
				oid: '1.2.3.4.5',
				qualifierDer: Uint8Array.of(0x05, 0x00),
			},
		];
		const certificatePolicies: CertificatePolicies = [
			{
				policyIdentifier: OIDS.anyPolicy,
				policyQualifiers: qualifiers,
			},
		];
		const policyMappings: PolicyMappings = [
			{
				issuerDomainPolicy: '1.2.3.4.1',
				subjectDomainPolicy: '1.2.3.4.2',
			},
		];
		const policyConstraints: PolicyConstraints = {
			requireExplicitPolicy: 1,
			inhibitPolicyMapping: 2,
		};
		const inhibitAnyPolicy: InhibitAnyPolicy = { skipCerts: 3 };

		expect(certificatePolicies[0]?.policyIdentifier).toBe(OIDS.anyPolicy);
		expect(policyMappings[0]?.subjectDomainPolicy).toBe('1.2.3.4.2');
		expect(policyConstraints.inhibitPolicyMapping).toBe(2);
		expect(inhibitAnyPolicy.skipCerts).toBe(3);
	});
});
