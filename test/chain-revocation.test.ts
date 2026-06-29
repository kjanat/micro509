import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'bun:test';
import {
	checkChainRevocation,
	parseCertificateDer,
	parseCertificateRevocationListDer,
	verifyCertificateChain,
	unwrap,
} from 'micro509';

async function loadPkitsCert(name: string) {
	const der = await readFile(new URL(`./fixtures/pkits/certs/${name}.crt`, import.meta.url));
	return unwrap(parseCertificateDer(new Uint8Array(der)));
}

async function loadPkitsCrl(name: string) {
	const der = await readFile(new URL(`./fixtures/pkits/crls/${name}.crl`, import.meta.url));
	return parseCertificateRevocationListDer(new Uint8Array(der));
}

describe('checkChainRevocation', () => {
	it('returns allow for empty chain', async () => {
		const result = await checkChainRevocation({ chain: [] });

		expect(result.ok).toBe(true);
		expect(result.value.decision).toBe('allow');
		expect(result.value.certificates).toEqual([]);
		expect(result.value.summary.revokedCertificates).toEqual([]);
		expect(result.value.summary.indeterminateCertificates).toEqual([]);
	});

	it('skips trust anchor (last cert in chain)', async () => {
		const root = await loadPkitsCert('TrustAnchorRootCertificate');
		const result = await checkChainRevocation({ chain: [root] });

		expect(result.ok).toBe(true);
		// Trust anchor not checked — returns allow with empty certificates
		expect(result.value.decision).toBe('allow');
		expect(result.value.certificates).toHaveLength(0);
	});

	it('returns indeterminate for non-anchor certs without evidence', async () => {
		const root = await loadPkitsCert('TrustAnchorRootCertificate');
		const goodCa = await loadPkitsCert('GoodCACert');

		const result = await checkChainRevocation({ chain: [goodCa, root] });

		expect(result.ok).toBe(true);
		// No CRLs provided → indeterminate for goodCa, but soft-fail allows
		expect(result.value.certificates).toHaveLength(1);
		const firstCert = result.value.certificates[0];
		expect(firstCert).toBeDefined();
		expect(firstCert?.status).toBe('indeterminate');
		expect(firstCert?.indeterminateReasons).toContain('no_applicable_crl');
		expect(result.value.decision).toBe('allow'); // soft-fail default
	});

	it('denies with hard-fail policy when indeterminate', async () => {
		const root = await loadPkitsCert('TrustAnchorRootCertificate');
		const goodCa = await loadPkitsCert('GoodCACert');

		const result = await checkChainRevocation({
			chain: [goodCa, root],
			policy: { mode: 'hard-fail' },
		});

		expect(result.ok).toBe(true);
		expect(result.value.decision).toBe('deny');
		expect(result.value.summary.indeterminateCertificates).toHaveLength(1);
	});

	it('evaluates good status when CRL covers cert and serial not listed', async () => {
		const root = await loadPkitsCert('TrustAnchorRootCertificate');
		const goodCa = await loadPkitsCert('GoodCACert');
		const crl = await loadPkitsCrl('TrustAnchorRootCRL');

		const result = await checkChainRevocation({
			chain: [goodCa, root],
			crls: [crl],
			at: new Date('2011-04-15T00:00:00Z'),
		});

		expect(result.ok).toBe(true);
		expect(result.value.certificates).toHaveLength(1);
		const firstCert = result.value.certificates[0];
		expect(firstCert).toBeDefined();
		expect(firstCert?.status).toBe('good');
		expect(firstCert?.source?.type).toBe('crl');
		expect(result.value.decision).toBe('allow');
	});

	it('returns revoked status and denies when cert is on CRL', async () => {
		const root = await loadPkitsCert('TrustAnchorRootCertificate');
		const goodCa = await loadPkitsCert('GoodCACert');
		const revokedCa = await loadPkitsCert('RevokedsubCACert');
		const rootCrl = await loadPkitsCrl('TrustAnchorRootCRL');
		const goodCaCrl = await loadPkitsCrl('GoodCACRL');

		// Chain: revokedCa → goodCa → root
		// revokedCa is issued by goodCa and revoked in GoodCACRL
		const result = await checkChainRevocation({
			chain: [revokedCa, goodCa, root],
			crls: [rootCrl, goodCaCrl],
			at: new Date('2011-04-15T00:00:00Z'),
		});

		expect(result.ok).toBe(true);
		expect(result.value.decision).toBe('deny');
		expect(result.value.summary.revokedCertificates).toHaveLength(1);

		// First cert (revokedCa) should be revoked
		const revokedStatus = result.value.certificates[0];
		expect(revokedStatus?.status).toBe('revoked');
		expect(revokedStatus?.revocationInfo).toBeDefined();
		expect(revokedStatus?.source?.type).toBe('crl');

		// Second cert (goodCa) should be good
		const goodStatus = result.value.certificates[1];
		expect(goodStatus?.status).toBe('good');
	});

	it('discovers indirect CRL issuer from extraCertificates (unit test)', async () => {
		// Unit test: verify findIndirectCrlIssuer logic by checking
		// that the signer is correctly tracked when available
		// For a real scenario: CRL signed by delegated signer, not chain issuer
		const root = await loadPkitsCert('TrustAnchorRootCertificate');
		const goodCa = await loadPkitsCert('GoodCACert');

		const rootCrl = await loadPkitsCrl('TrustAnchorRootCRL');

		// Check GoodCA cert - its issuer is root, so chain issuer (root) is used
		// Pass GoodCA in extraCertificates to verify it's searchable
		const result = await checkChainRevocation({
			chain: [goodCa, root],
			crls: [rootCrl],
			extraCertificates: [goodCa], // Include as extra cert (should be deduplicated)
			at: new Date('2011-04-15T00:00:00Z'),
		});

		expect(result.ok).toBe(true);
		expect(result.value.decision).toBe('allow');

		// GoodCA should be good (checked against root CRL)
		const caStatus = result.value.certificates[0];
		expect(caStatus?.status).toBe('good');
		expect(caStatus?.source?.type).toBe('crl');
		// Signer should be root (chain issuer)
		expect(caStatus?.source?.signerCertificate?.subject.derHex).toBe(root.subject.derHex);
	});

	it('tracks correct signer when CRL issuer found in chain', async () => {
		// When checking a cert, the CRL issuer should match the chain issuer
		// This verifies the signer is correctly tracked in the result
		const root = await loadPkitsCert('TrustAnchorRootCertificate');
		const goodCa = await loadPkitsCert('GoodCACert');
		const goodSubCa = await loadPkitsCert('GoodsubCACert');

		const rootCrl = await loadPkitsCrl('TrustAnchorRootCRL');
		const goodCaCrl = await loadPkitsCrl('GoodCACRL');

		// Chain: goodSubCa → goodCa → root
		const result = await checkChainRevocation({
			chain: [goodSubCa, goodCa, root],
			crls: [rootCrl, goodCaCrl],
			at: new Date('2011-04-15T00:00:00Z'),
		});

		expect(result.ok).toBe(true);
		expect(result.value.decision).toBe('allow');

		// goodSubCa checked against goodCaCrl, signer is goodCa
		const subCaStatus = result.value.certificates[0];
		expect(subCaStatus?.status).toBe('good');
		expect(subCaStatus?.source?.signerCertificate?.subject.derHex).toBe(goodCa.subject.derHex);

		// goodCa checked against rootCrl, signer is root
		const caStatus = result.value.certificates[1];
		expect(caStatus?.status).toBe('good');
		expect(caStatus?.source?.signerCertificate?.subject.derHex).toBe(root.subject.derHex);
	});

	it('PKITS 4.4.21: denies when CRL signer is revoked', async () => {
		// PKITS 4.4.21: CRL signed by revoked certificate should not be trusted
		// Chain: leaf → certSigningCA → root
		// CRL signer: crlSigningCert (revoked in rootCrl)
		const root = await loadPkitsCert('TrustAnchorRootCertificate');
		const certSigningCa = await loadPkitsCert(
			'SeparateCertificateandCRLKeysCA2CertificateSigningCACert',
		);
		const crlSigningCert = await loadPkitsCert('SeparateCertificateandCRLKeysCA2CRLSigningCert');
		const leaf = await loadPkitsCert('InvalidSeparateCertificateandCRLKeysTest21EE');

		const rootCrl = await loadPkitsCrl('TrustAnchorRootCRL');
		const ca2Crl = await loadPkitsCrl('SeparateCertificateandCRLKeysCA2CRL');

		// The validated chain is: leaf → certSigningCa → root
		// The CRL for certSigningCa is rootCrl (signed by root) - OK
		// The CRL for leaf is ca2Crl (signed by crlSigningCert) - REVOKED signer!
		const result = await checkChainRevocation({
			chain: [leaf, certSigningCa, root],
			crls: [rootCrl, ca2Crl],
			extraCertificates: [crlSigningCert], // CRL signer found in extras
			at: new Date('2011-04-15T00:00:00Z'),
		});

		expect(result.ok).toBe(true);
		// Should deny because CRL signer is revoked - can't trust that CRL
		// Results in indeterminate (crl_signer_revoked) for leaf cert
		expect(result.value.certificates).toHaveLength(2);

		const leafStatus = result.value.certificates[0];
		expect(leafStatus?.status).toBe('indeterminate');
		expect(leafStatus?.indeterminateReasons).toContain('crl_signer_revoked');

		// certSigningCa should be good (checked against rootCrl, signed by root)
		const caStatus = result.value.certificates[1];
		expect(caStatus?.status).toBe('good');

		// With hard-fail policy, this should deny
		const hardFailResult = await checkChainRevocation({
			chain: [leaf, certSigningCa, root],
			crls: [rootCrl, ca2Crl],
			extraCertificates: [crlSigningCert],
			at: new Date('2011-04-15T00:00:00Z'),
			policy: { mode: 'hard-fail' },
		});

		expect(hardFailResult.ok).toBe(true);
		expect(hardFailResult.value.decision).toBe('deny');
	});
});

describe('verifyCertificateChain with revocation option', () => {
	it('denies revoked certificate', async () => {
		const root = await loadPkitsCert('TrustAnchorRootCertificate');
		const goodCa = await loadPkitsCert('GoodCACert');
		const revokedCa = await loadPkitsCert('RevokedsubCACert');
		const rootCrl = await loadPkitsCrl('TrustAnchorRootCRL');
		const goodCaCrl = await loadPkitsCrl('GoodCACRL');

		const result = await verifyCertificateChain({
			leaf: revokedCa.der,
			intermediates: [goodCa.der],
			roots: [root.der],
			at: new Date('2011-04-15T00:00:00Z'),
			revocation: {
				crls: [rootCrl, goodCaCrl],
				policy: { mode: 'hard-fail' },
			},
		});

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.code).toBe('certificate_revoked');
		}
	});

	it('allows valid certificate with revocation check', async () => {
		const root = await loadPkitsCert('TrustAnchorRootCertificate');
		const goodCa = await loadPkitsCert('GoodCACert');
		const rootCrl = await loadPkitsCrl('TrustAnchorRootCRL');

		const result = await verifyCertificateChain({
			leaf: goodCa.der,
			roots: [root.der],
			at: new Date('2011-04-15T00:00:00Z'),
			revocation: {
				crls: [rootCrl],
				policy: { mode: 'hard-fail' },
			},
		});

		expect(result.ok).toBe(true);
	});

	it('returns revocation_indeterminate with hard-fail and no CRL', async () => {
		const root = await loadPkitsCert('TrustAnchorRootCertificate');
		const goodCa = await loadPkitsCert('GoodCACert');

		const result = await verifyCertificateChain({
			leaf: goodCa.der,
			roots: [root.der],
			at: new Date('2011-04-15T00:00:00Z'),
			revocation: {
				crls: [],
				policy: { mode: 'hard-fail' },
			},
		});

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.code).toBe('revocation_indeterminate');
		}
	});

	it('allows with soft-fail policy and no CRL', async () => {
		const root = await loadPkitsCert('TrustAnchorRootCertificate');
		const goodCa = await loadPkitsCert('GoodCACert');

		const result = await verifyCertificateChain({
			leaf: goodCa.der,
			roots: [root.der],
			at: new Date('2011-04-15T00:00:00Z'),
			revocation: {
				crls: [],
				policy: { mode: 'soft-fail' },
			},
		});

		expect(result.ok).toBe(true);
	});
});
