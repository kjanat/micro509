import { describe, expect, it } from 'bun:test';
import type {
	CheckCertificateRevocationInput,
	ParsedCertificateRevocationList,
	ParsedOcspResponse,
} from '#micro509/revocation/index.ts';
import * as revocation from '#micro509/revocation/index.ts';

function assertRevocationDomainTypes(_input: {
	readonly check?: CheckCertificateRevocationInput;
	readonly crl?: ParsedCertificateRevocationList;
	readonly ocsp?: ParsedOcspResponse;
}): void {}

describe('revocation domain', () => {
	it('exposes the consolidated advanced revocation surface', () => {
		const input: CheckCertificateRevocationInput = {
			certificate: new Uint8Array(),
			issuerCertificate: new Uint8Array(),
		};

		assertRevocationDomainTypes({});

		expect(input.evidence).toBeUndefined();
		expect(typeof revocation.checkCertificateRevocation).toBe('function');
		expect(typeof revocation.resolveOcspResponderCandidates).toBe('function');
		expect(typeof revocation.createCertificateRevocationList).toBe('function');
		expect(typeof revocation.validateCertificateRevocationList).toBe('function');
		expect(typeof revocation.createOcspRequest).toBe('function');
		expect(typeof revocation.validateOcspResponse).toBe('function');
	});
});
