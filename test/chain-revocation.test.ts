import { describe, expect, it } from 'bun:test';
import { readFile } from 'node:fs/promises';
import {
	checkChainRevocation,
	createCertificate,
	createCertificateRevocationList,
	createOcspResponse,
	createSelfSignedCertificate,
	generateKeyPair,
	parseCertificateDer,
	parseCertificatePem,
	parseCertificateRevocationListDerOrThrow,
	unwrap,
	verifyCertificateChain,
} from '#micro509';
import { hexToBytes } from '#test/helpers';

async function loadPkitsCert(name: string) {
	const der = await readFile(new URL(`./fixtures/pkits/certs/${name}.crt`, import.meta.url));
	return unwrap(parseCertificateDer(new Uint8Array(der)));
}

async function loadPkitsCrl(name: string) {
	const der = await readFile(new URL(`./fixtures/pkits/crls/${name}.crl`, import.meta.url));
	return parseCertificateRevocationListDerOrThrow(new Uint8Array(der));
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
		// No CRLs provided → indeterminate for goodCa; hard-fail default denies
		expect(result.value.certificates).toHaveLength(1);
		const firstCert = result.value.certificates[0];
		expect(firstCert).toBeDefined();
		expect(firstCert?.status).toBe('indeterminate');
		expect(firstCert?.indeterminateReasons).toContain('no_applicable_crl');
		expect(result.value.decision).toBe('deny'); // hard-fail default
	});

	it('denies by default when indeterminate (hard-fail is the default)', async () => {
		const root = await loadPkitsCert('TrustAnchorRootCertificate');
		const goodCa = await loadPkitsCert('GoodCACert');

		const result = await checkChainRevocation({
			chain: [goodCa, root],
		});

		expect(result.ok).toBe(true);
		expect(result.value.decision).toBe('deny');
		expect(result.value.summary.indeterminateCertificates).toHaveLength(1);
	});

	it('allows indeterminate under explicit soft-fail', async () => {
		const root = await loadPkitsCert('TrustAnchorRootCertificate');
		const goodCa = await loadPkitsCert('GoodCACert');

		const result = await checkChainRevocation({
			chain: [goodCa, root],
			policy: { mode: 'soft-fail' },
		});

		expect(result.ok).toBe(true);
		expect(result.value.decision).toBe('allow');
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
		expect(firstCert?.source?.kind).toBe('crl');
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
		expect(revokedStatus?.source?.kind).toBe('crl');

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
		expect(caStatus?.source?.kind).toBe('crl');
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

const HOUR_MS = 60 * 60 * 1000;

/** DER time encoding truncates to whole seconds. */
function derSeconds(date: Date): number {
	return Math.floor(date.getTime() / 1000) * 1000;
}

async function createOcspChainFixture() {
	const caName = 'OCSP Chain CA';
	const ca = await createSelfSignedCertificate({
		subject: { commonName: caName },
		extensions: {
			basicConstraints: { ca: true, pathLength: 1 },
			keyUsage: ['keyCertSign', 'cRLSign'],
		},
	});
	const leafKeys = await generateKeyPair();
	const leaf = await createCertificate({
		issuer: { commonName: caName },
		subject: { commonName: 'ocsp-chain-leaf.example' },
		publicKey: leafKeys.publicKey,
		signerPrivateKey: ca.keyPair.privateKey,
		issuerPublicKey: ca.keyPair.publicKey,
	});
	const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
	const parsedCa = unwrap(parseCertificatePem(ca.certificate.pem));
	// Tests create OCSP responses after this fixture returns; producedAt is
	// stamped then (whole-second DER precision). Evaluate slightly in the
	// future so producedAt can never exceed `at` on slow runners.
	const at = new Date(Date.now() + 5_000);
	return {
		caName,
		ca,
		leaf,
		chain: [parsedLeaf, parsedCa] as const,
		parsedLeaf,
		at,
		fresh: {
			thisUpdate: new Date(at.getTime() - HOUR_MS),
			nextUpdate: new Date(at.getTime() + HOUR_MS),
		},
	};
}

describe('checkChainRevocation with OCSP evidence', () => {
	it('returns good status from a validated OCSP response', async () => {
		const { ca, leaf, chain, at, fresh } = await createOcspChainFixture();
		const response = await createOcspResponse({
			signerPrivateKey: ca.keyPair.privateKey,
			signerCertificate: ca.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'good',
					...fresh,
				},
			],
		});

		const result = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [response.der],
			at,
		});

		expect(result.ok).toBe(true);
		expect(result.value.decision).toBe('allow');
		const leafStatus = result.value.certificates[0];
		expect(leafStatus?.status).toBe('good');
		expect(leafStatus?.source?.kind).toBe('ocsp');
	});

	it('denies when a validated OCSP response reports revoked', async () => {
		const { ca, leaf, chain, at, fresh } = await createOcspChainFixture();
		const revokedAt = new Date(at.getTime() - HOUR_MS);
		const response = await createOcspResponse({
			signerPrivateKey: ca.keyPair.privateKey,
			signerCertificate: ca.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'revoked',
					revokedAt,
					revocationReasonCode: 1,
					...fresh,
				},
			],
		});

		const result = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [response.der],
			at,
		});

		expect(result.ok).toBe(true);
		expect(result.value.decision).toBe('deny');
		const leafStatus = result.value.certificates[0];
		expect(leafStatus?.status).toBe('revoked');
		expect(leafStatus?.source?.kind).toBe('ocsp');
		expect(leafStatus?.revocationInfo?.reason).toBe('keyCompromise');
		// DER time encoding truncates to whole seconds
		expect(leafStatus?.revocationInfo?.revocationDate.getTime()).toBe(
			Math.floor(revokedAt.getTime() / 1000) * 1000,
		);
	});

	it('treats OCSP unknown status as indeterminate', async () => {
		const { ca, leaf, chain, at, fresh } = await createOcspChainFixture();
		const response = await createOcspResponse({
			signerPrivateKey: ca.keyPair.privateKey,
			signerCertificate: ca.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'unknown',
					...fresh,
				},
			],
		});

		const softFail = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [response.der],
			at,
			policy: { mode: 'soft-fail' },
		});
		expect(softFail.value.decision).toBe('allow');
		expect(softFail.value.certificates[0]?.status).toBe('indeterminate');
		expect(softFail.value.certificates[0]?.indeterminateReasons).toContain('ocsp_status_unknown');

		const hardFail = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [response.der],
			at,
		});
		expect(hardFail.value.decision).toBe('deny');
	});

	it('treats an expired OCSP response as indeterminate', async () => {
		const { ca, leaf, chain, at } = await createOcspChainFixture();
		const response = await createOcspResponse({
			signerPrivateKey: ca.keyPair.privateKey,
			signerCertificate: ca.certificate.pem,
			producedAt: new Date(at.getTime() - 3 * HOUR_MS),
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'good',
					thisUpdate: new Date(at.getTime() - 3 * HOUR_MS),
					nextUpdate: new Date(at.getTime() - 2 * HOUR_MS),
				},
			],
		});

		const result = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [response.der],
			at,
		});

		expect(result.value.certificates[0]?.status).toBe('indeterminate');
		expect(result.value.certificates[0]?.indeterminateReasons).toContain('ocsp_response_expired');
	});

	it('fails closed: CRL revoked verdict wins over OCSP good even with prefer ocsp', async () => {
		const { caName, ca, leaf, chain, parsedLeaf, at, fresh } = await createOcspChainFixture();
		const response = await createOcspResponse({
			signerPrivateKey: ca.keyPair.privateKey,
			signerCertificate: ca.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'good',
					...fresh,
				},
			],
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: caName },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			...fresh,
			revokedCertificates: [
				{
					serialNumber: hexToBytes(parsedLeaf.serialNumberHex),
					revocationDate: fresh.thisUpdate,
					reasonCode: 'keyCompromise',
				},
			],
		});

		const result = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [response.der],
			crls: [crl.der],
			at,
			policy: { prefer: 'ocsp' },
		});

		expect(result.value.decision).toBe('deny');
		const leafStatus = result.value.certificates[0];
		expect(leafStatus?.status).toBe('revoked');
		expect(leafStatus?.source?.kind).toBe('crl');
	});

	it('honors prefer when both sources report good', async () => {
		const { caName, ca, leaf, chain, at, fresh } = await createOcspChainFixture();
		const response = await createOcspResponse({
			signerPrivateKey: ca.keyPair.privateKey,
			signerCertificate: ca.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'good',
					...fresh,
				},
			],
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: caName },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			...fresh,
		});

		const preferOcsp = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [response.der],
			crls: [crl.der],
			at,
		});
		expect(preferOcsp.value.certificates[0]?.source?.kind).toBe('ocsp');

		const preferCrl = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [response.der],
			crls: [crl.der],
			at,
			policy: { prefer: 'crl' },
		});
		expect(preferCrl.value.certificates[0]?.source?.kind).toBe('crl');
	});

	it('best-available reports the fresher CRL over a staler OCSP response', async () => {
		const { caName, ca, leaf, chain, at, fresh } = await createOcspChainFixture();
		// Valid but 12h-old OCSP evidence vs a 1h-old CRL
		const stale = {
			thisUpdate: new Date(at.getTime() - 12 * HOUR_MS),
			nextUpdate: new Date(at.getTime() + HOUR_MS),
		};
		const response = await createOcspResponse({
			signerPrivateKey: ca.keyPair.privateKey,
			signerCertificate: ca.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'good',
					...stale,
				},
			],
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: caName },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			...fresh,
		});

		const bestAvailable = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [response.der],
			crls: [crl.der],
			at,
		});
		expect(bestAvailable.value.certificates[0]?.status).toBe('good');
		expect(bestAvailable.value.certificates[0]?.source?.kind).toBe('crl');
		expect(bestAvailable.value.certificates[0]?.source?.thisUpdate?.getTime()).toBe(
			derSeconds(fresh.thisUpdate),
		);

		// Explicit prefer still overrides freshness
		const preferOcsp = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [response.der],
			crls: [crl.der],
			at,
			policy: { prefer: 'ocsp' },
		});
		expect(preferOcsp.value.certificates[0]?.source?.kind).toBe('ocsp');
	});

	it('best-available reports the fresher OCSP response over a staler CRL', async () => {
		const { caName, ca, leaf, chain, at, fresh } = await createOcspChainFixture();
		const response = await createOcspResponse({
			signerPrivateKey: ca.keyPair.privateKey,
			signerCertificate: ca.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'good',
					...fresh,
				},
			],
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: caName },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			thisUpdate: new Date(at.getTime() - 12 * HOUR_MS),
			nextUpdate: new Date(at.getTime() + HOUR_MS),
		});

		const result = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [response.der],
			crls: [crl.der],
			at,
		});
		expect(result.value.certificates[0]?.status).toBe('good');
		expect(result.value.certificates[0]?.source?.kind).toBe('ocsp');
		expect(result.value.certificates[0]?.source?.thisUpdate?.getTime()).toBe(
			derSeconds(fresh.thisUpdate),
		);
	});

	it('best-available fails closed: staler CRL revoked beats fresher OCSP good', async () => {
		const { caName, ca, leaf, chain, parsedLeaf, at, fresh } = await createOcspChainFixture();
		const response = await createOcspResponse({
			signerPrivateKey: ca.keyPair.privateKey,
			signerCertificate: ca.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'good',
					...fresh,
				},
			],
		});
		const staleThisUpdate = new Date(at.getTime() - 12 * HOUR_MS);
		const crl = await createCertificateRevocationList({
			issuer: { commonName: caName },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			thisUpdate: staleThisUpdate,
			nextUpdate: new Date(at.getTime() + HOUR_MS),
			revokedCertificates: [
				{
					serialNumber: hexToBytes(parsedLeaf.serialNumberHex),
					revocationDate: staleThisUpdate,
					reasonCode: 'keyCompromise',
				},
			],
		});

		const result = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [response.der],
			crls: [crl.der],
			at,
		});
		expect(result.value.decision).toBe('deny');
		expect(result.value.certificates[0]?.status).toBe('revoked');
		expect(result.value.certificates[0]?.source?.kind).toBe('crl');
	});

	it('reports the signer of the freshest good CRL when multiple CRLs apply', async () => {
		const { caName, ca, chain, parsedLeaf, at, fresh } = await createOcspChainFixture();
		// Delegate CRL signer: same DN as the CA, different key (PKITS
		// separate-certificate-and-CRL-keys pattern)
		const delegateKeys = await generateKeyPair();
		const delegate = await createCertificate({
			issuer: { commonName: caName },
			subject: { commonName: caName },
			publicKey: delegateKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: { keyUsage: ['cRLSign'] },
		});
		const parsedDelegate = unwrap(parseCertificatePem(delegate.pem));

		// Fresh CRL from the delegate, stale CRL from the chain CA — the
		// reported signer must belong to the CRL whose freshness won, no
		// matter the processing order.
		const freshDelegateCrl = await createCertificateRevocationList({
			issuer: { commonName: caName },
			signerPrivateKey: delegateKeys.privateKey,
			issuerPublicKey: delegateKeys.publicKey,
			...fresh,
		});
		const staleCaCrl = await createCertificateRevocationList({
			issuer: { commonName: caName },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			thisUpdate: new Date(at.getTime() - 12 * HOUR_MS),
			nextUpdate: new Date(at.getTime() + HOUR_MS),
		});

		// Delegate CRL first, CA CRL last: a naive "last good signer" would
		// report the CA while freshness came from the delegate.
		const result = await checkChainRevocation({
			chain: [...chain],
			crls: [freshDelegateCrl.der, staleCaCrl.der],
			extraCertificates: [delegate.pem],
			at,
		});
		const leafStatus = result.value.certificates[0];
		expect(leafStatus?.status).toBe('good');
		expect(leafStatus?.source?.kind).toBe('crl');
		expect(leafStatus?.source?.signerCertificate?.serialNumberHex).toBe(
			parsedDelegate.serialNumberHex,
		);
		// The reported timestamp is the delegate CRL's, not the stale CA CRL's
		expect(leafStatus?.source?.thisUpdate?.getTime()).toBe(derSeconds(fresh.thisUpdate));
		expect(leafStatus?.certificate.serialNumberHex).toBe(parsedLeaf.serialNumberHex);
	});

	it('best-available counts an applied delta CRL as the CRL freshness', async () => {
		const { caName, ca, leaf, chain, at } = await createOcspChainFixture();
		// OCSP evidence is 6h old; the base CRL is 12h old but its delta is 1h
		// old — the delta freshness must win for the CRL source.
		const response = await createOcspResponse({
			signerPrivateKey: ca.keyPair.privateKey,
			signerCertificate: ca.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'good',
					thisUpdate: new Date(at.getTime() - 6 * HOUR_MS),
					nextUpdate: new Date(at.getTime() + HOUR_MS),
				},
			],
		});
		const baseCrl = await createCertificateRevocationList({
			issuer: { commonName: caName },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 5,
			thisUpdate: new Date(at.getTime() - 12 * HOUR_MS),
			nextUpdate: new Date(at.getTime() + HOUR_MS),
		});
		const deltaThisUpdate = new Date(at.getTime() - HOUR_MS);
		const deltaCrl = await createCertificateRevocationList({
			issuer: { commonName: caName },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 6,
			baseCrlNumber: 5,
			thisUpdate: deltaThisUpdate,
			nextUpdate: new Date(at.getTime() + HOUR_MS),
		});

		const result = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [response.der],
			crls: [baseCrl.der, deltaCrl.der],
			at,
		});
		expect(result.value.certificates[0]?.status).toBe('good');
		expect(result.value.certificates[0]?.source?.kind).toBe('crl');
		// The winning timestamp is the delta CRL's, not the 12h-old base's
		expect(result.value.certificates[0]?.source?.thisUpdate?.getTime()).toBe(
			derSeconds(deltaThisUpdate),
		);
	});

	it('accepts a locally trusted responder via trustedOcspResponders', async () => {
		const { ca, leaf, chain, at, fresh } = await createOcspChainFixture();
		// Responder from an unrelated CA — only local trust can authorize it
		const outsiderCa = await createSelfSignedCertificate({
			subject: { commonName: 'Outsider CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const responderKeys = await generateKeyPair();
		const responder = await createCertificate({
			issuer: { commonName: 'Outsider CA' },
			subject: { commonName: 'Externally Trusted Responder' },
			publicKey: responderKeys.publicKey,
			signerPrivateKey: outsiderCa.keyPair.privateKey,
			issuerPublicKey: outsiderCa.keyPair.publicKey,
		});
		const response = await createOcspResponse({
			signerPrivateKey: responderKeys.privateKey,
			signerCertificate: responder.pem,
			includedCertificates: [responder.pem],
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'good',
					...fresh,
				},
			],
		});

		const untrusted = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [response.der],
			at,
		});
		expect(untrusted.value.certificates[0]?.status).toBe('indeterminate');
		expect(untrusted.value.certificates[0]?.indeterminateReasons).toContain(
			'ocsp_responder_not_authorized',
		);

		const trusted = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [response.der],
			trustedOcspResponders: [responder.pem],
			at,
		});
		expect(trusted.value.certificates[0]?.status).toBe('good');
		expect(trusted.value.certificates[0]?.source?.kind).toBe('ocsp');
	});

	it('validates a delegated responder provided via extraCertificates', async () => {
		const { caName, ca, leaf, chain, at, fresh } = await createOcspChainFixture();
		const responderKeys = await generateKeyPair();
		const responder = await createCertificate({
			issuer: { commonName: caName },
			subject: { commonName: 'Delegated OCSP Responder' },
			publicKey: responderKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: { extendedKeyUsage: ['ocspSigning'] },
		});
		// No embedded certificates — discovery must fall back to extraCertificates
		const response = await createOcspResponse({
			signerPrivateKey: responderKeys.privateKey,
			signerCertificate: responder.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'good',
					...fresh,
				},
			],
		});

		const withoutExtras = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [response.der],
			at,
		});
		expect(withoutExtras.value.certificates[0]?.status).toBe('indeterminate');

		const withExtras = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [response.der],
			extraCertificates: [responder.pem],
			at,
		});
		expect(withExtras.value.certificates[0]?.status).toBe('good');
		expect(withExtras.value.certificates[0]?.source?.kind).toBe('ocsp');
	});

	it('records parse errors for malformed OCSP responses', async () => {
		const { chain, at } = await createOcspChainFixture();
		const result = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [Uint8Array.of(0x30, 0x00)],
			at,
		});

		expect(result.value.certificates[0]?.status).toBe('indeterminate');
		expect(result.value.executionErrors?.some((e) => e.kind === 'parse_error')).toBe(true);
	});

	it('verifyCertificateChain denies via OCSP revocation evidence', async () => {
		const { ca, leaf, at, fresh } = await createOcspChainFixture();
		const response = await createOcspResponse({
			signerPrivateKey: ca.keyPair.privateKey,
			signerCertificate: ca.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'revoked',
					revokedAt: fresh.thisUpdate,
					...fresh,
				},
			],
		});

		const result = await verifyCertificateChain({
			leaf: leaf.pem,
			roots: [ca.certificate.pem],
			at,
			revocation: {
				ocspResponses: [response.der],
				policy: { mode: 'hard-fail' },
			},
		});

		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.code).toBe('certificate_revoked');
		}
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
