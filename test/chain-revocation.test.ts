import { describe, expect, it } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { URL } from 'node:url';
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
	trustAnchorFromCertificate,
	unwrap,
	verifyCertificateChain,
} from '#micro509';
import { explicitContext, octetString, sequence, tlv, utcTime } from '#micro509/internal/asn1/der';
import {
	childAt,
	constructedChildren,
	expectRejectedWith,
	FAR_FUTURE_NEXT_UPDATE,
	fieldAt,
	hexToBytes,
	OCSP_NOCHECK_EXTENSION,
	rewriteCertificateSubject,
	sliceElement,
	withRevokedEntryReasonCode,
} from '#test/helpers';

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

	it('reports incomplete reason coverage when the matched distribution point limits reasons', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Partial Reason CA' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Partial Reason CA' },
			subject: { commonName: 'partial-reason.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerCertificate: ca.certificate.der,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							type: 'fullName',
							fullName: [{ type: 'uri', value: 'http://example.test/partial.crl' }],
						},
						reasons: ['keyCompromise'],
					},
				],
			},
		});
		const crl = await createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: 'Partial Reason CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerCertificate: ca.certificate.der,
			nextUpdate: FAR_FUTURE_NEXT_UPDATE,
		});

		const result = await checkChainRevocation({
			chain: [
				unwrap(parseCertificatePem(leaf.pem)),
				unwrap(parseCertificatePem(ca.certificate.pem)),
			],
			crls: [crl.pem],
		});

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		const leafStatus = result.value.certificates[0];
		expect(leafStatus?.status).toBe('indeterminate');
		expect(leafStatus?.indeterminateReasons).toContain('reason_coverage_incomplete');
		expect(result.value.decision).toBe('deny');
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

	it('refuses a CRL signer that a CRL lists with an unrecognized reason under reject', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Split Keys Root' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const issueUnderRoot = async (keyUsage: readonly ('keyCertSign' | 'cRLSign')[]) => {
			const keyPair = await generateKeyPair();
			const certificate = await createCertificate({
				issuer: { commonName: 'Split Keys Root' },
				subject: { commonName: 'Split Keys CA' },
				publicKey: keyPair.publicKey,
				signerPrivateKey: root.keyPair.privateKey,
				issuerCertificate: root.certificate.der,
				extensions: { basicConstraints: { ca: true }, keyUsage: [...keyUsage] },
			});
			return { keyPair, certificate: unwrap(parseCertificatePem(certificate.pem)) };
		};
		const ca = await issueUnderRoot(['keyCertSign']);
		const crlSigner = await issueUnderRoot(['cRLSign']);
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Split Keys CA' },
			subject: { commonName: 'split-keys.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerCertificate: ca.certificate,
		});
		const leafCrl = await createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: 'Split Keys CA' },
			signerPrivateKey: crlSigner.keyPair.privateKey,
			issuerCertificate: crlSigner.certificate,
			nextUpdate: FAR_FUTURE_NEXT_UPDATE,
		});
		const rootCrl = await createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: 'Split Keys Root' },
			signerPrivateKey: root.keyPair.privateKey,
			issuerCertificate: root.certificate.der,
			revokedCertificates: [
				{
					serialNumber: hexToBytes(crlSigner.certificate.serialNumberHex),
					reasonCode: 'keyCompromise',
				},
			],
			nextUpdate: FAR_FUTURE_NEXT_UPDATE,
		});
		const unrecognizedRootCrl = await withRevokedEntryReasonCode(
			rootCrl.der,
			root.keyPair.privateKey,
			7,
		);
		const check = (unrecognizedReasonCode: 'revoked' | 'reject') =>
			checkChainRevocation({
				chain: [
					unwrap(parseCertificatePem(leaf.pem)),
					ca.certificate,
					unwrap(parseCertificatePem(root.certificate.pem)),
				],
				crls: [unrecognizedRootCrl, leafCrl.der],
				extraCertificates: [crlSigner.certificate],
				policy: { unrecognizedReasonCode },
			});

		const byDefault = await check('revoked');
		expect(byDefault.value.decision).toBe('deny');
		expect(byDefault.value.certificates[0]?.indeterminateReasons).toContain('crl_signer_revoked');
		expect(byDefault.value.certificates[1]?.status).toBe('good');

		const rejected = await check('reject');
		expect(rejected.value.decision).toBe('deny');
		expect(rejected.value.certificates[0]?.status).toBe('indeterminate');
		expect(rejected.value.certificates[0]?.indeterminateReasons).toContain(
			'crl_signer_indeterminate',
		);
		expect(rejected.value.certificates[1]?.status).toBe('good');
	});

	it('rejects a forged CRL whose signer does not chain to the trust anchor', async () => {
		const anchorName = 'Revocation Anchor CA';
		const realCa = await createSelfSignedCertificate({
			subject: { commonName: anchorName },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		// Same subject DN as the real CA, unrelated key. The forged CRL it signs
		// therefore reads as a direct CRL for the leaf's issuer.
		const forgedSigner = await createSelfSignedCertificate({
			subject: { commonName: anchorName },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: anchorName },
			subject: { commonName: 'revoked-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: realCa.keyPair.privateKey,
			issuerCertificate: realCa.certificate.der,
		});
		const at = new Date(Date.now() + 5_000);
		const forgedCrl = await createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: anchorName },
			signerPrivateKey: forgedSigner.keyPair.privateKey,
			issuerCertificate: forgedSigner.certificate.der,
			thisUpdate: new Date(at.getTime() - HOUR_MS),
			nextUpdate: new Date(at.getTime() + HOUR_MS),
			revokedCertificates: [],
		});

		const result = await checkChainRevocation({
			chain: [
				unwrap(parseCertificatePem(leaf.pem)),
				unwrap(parseCertificatePem(realCa.certificate.pem)),
			],
			crls: [forgedCrl.der],
			extraCertificates: [forgedSigner.certificate.pem],
			at,
			policy: { mode: 'soft-fail' },
		});

		expect(result.ok).toBe(true);
		const leafStatus = result.value.certificates[0];
		expect(leafStatus?.status).toBe('indeterminate');
		expect(leafStatus?.indeterminateReasons).toContain('crl_signer_not_authorized');
	});

	it('ignores rejected reason codes from an untrusted CRL signer before and after trusted evidence', async () => {
		const { caName, ca, chain, parsedLeaf, at, fresh } = await createOcspChainFixture();
		const forgedSigner = await createSelfSignedCertificate({
			subject: { commonName: caName },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const forgedCrl = await createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: caName },
			signerPrivateKey: forgedSigner.keyPair.privateKey,
			issuerCertificate: forgedSigner.certificate.der,
			...fresh,
			revokedCertificates: [
				{
					serialNumber: hexToBytes(parsedLeaf.serialNumberHex),
					revocationDate: fresh.thisUpdate,
					reasonCode: 'keyCompromise',
				},
			],
		});
		const rejectedCrl = await withRevokedEntryReasonCode(
			forgedCrl.der,
			forgedSigner.keyPair.privateKey,
			7,
		);
		const goodCrl = await createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: caName },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerCertificate: ca.certificate.der,
			...fresh,
			revokedCertificates: [],
		});
		for (const crls of [
			[rejectedCrl, goodCrl.der],
			[goodCrl.der, rejectedCrl],
		]) {
			const result = await checkChainRevocation({
				chain: [...chain],
				crls,
				extraCertificates: [forgedSigner.certificate.pem],
				at,
				policy: { unrecognizedReasonCode: 'reject' },
			});
			expect(result.value.certificates[0]?.status).toBe('good');
			expect(result.value.decision).toBe('allow');
		}
	});

	it('authorizes a delegated CRL signer issued by a chain intermediate', async () => {
		const at = new Date(Date.now() + 5_000);
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Delegated Root' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const intermediateKeys = await generateKeyPair();
		const intermediate = await createCertificate({
			issuer: { commonName: 'Delegated Root' },
			subject: { commonName: 'Delegated Intermediate' },
			publicKey: intermediateKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerCertificate: root.certificate.der,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		// Delegated CRL signer issued by the intermediate, sharing the
		// intermediate subject DN so its CRL applies to the leaf directly. Its
		// path to the anchor runs signer -> intermediate -> root, so the
		// intermediate must come from the validated chain.
		const signerKeys = await generateKeyPair();
		const signer = await createCertificate({
			issuer: { commonName: 'Delegated Intermediate' },
			subject: { commonName: 'Delegated Intermediate' },
			publicKey: signerKeys.publicKey,
			signerPrivateKey: intermediateKeys.privateKey,
			issuerCertificate: intermediate.der,
			extensions: { keyUsage: ['cRLSign'] },
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Delegated Intermediate' },
			subject: { commonName: 'delegated-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: intermediateKeys.privateKey,
			issuerCertificate: intermediate.der,
			extensions: { keyUsage: ['digitalSignature'] },
		});
		const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
		const crl = await createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: 'Delegated Intermediate' },
			signerPrivateKey: signerKeys.privateKey,
			issuerCertificate: signer.der,
			thisUpdate: new Date(at.getTime() - HOUR_MS),
			nextUpdate: new Date(at.getTime() + HOUR_MS),
			revokedCertificates: [
				{
					serialNumber: hexToBytes(parsedLeaf.serialNumberHex),
					revocationDate: new Date(at.getTime() - HOUR_MS),
					reasonCode: 'keyCompromise',
				},
			],
		});

		const result = await checkChainRevocation({
			chain: [
				parsedLeaf,
				unwrap(parseCertificatePem(intermediate.pem)),
				unwrap(parseCertificatePem(root.certificate.pem)),
			],
			crls: [crl.der],
			extraCertificates: [signer.pem],
			at,
			policy: { mode: 'soft-fail' },
		});
		expect(result.ok).toBe(true);
		expect(result.value.decision).toBe('deny');
		expect(result.value.certificates[0]?.status).toBe('revoked');
	});

	it('holds a delegated CRL signer indeterminate until its own CRLs cover every reason', async () => {
		const at = new Date(Date.now() + 5_000);
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Signer Scope Root' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 2 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const intermediateKeys = await generateKeyPair();
		const intermediate = await createCertificate({
			issuer: { commonName: 'Signer Scope Root' },
			subject: { commonName: 'Signer Scope Intermediate' },
			publicKey: intermediateKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerCertificate: root.certificate.der,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		// The delegated signer's own issuer stays out of the validated chain, so
		// its revocation status has to come from a CRL rather than from chain
		// membership.
		const signerCaKeys = await generateKeyPair();
		const signerCa = await createCertificate({
			issuer: { commonName: 'Signer Scope Root' },
			subject: { commonName: 'Signer Scope CRL CA' },
			publicKey: signerCaKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerCertificate: root.certificate.der,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const signerKeys = await generateKeyPair();
		const signer = await createCertificate({
			issuer: { commonName: 'Signer Scope CRL CA' },
			subject: { commonName: 'Signer Scope Intermediate' },
			publicKey: signerKeys.publicKey,
			signerPrivateKey: signerCaKeys.privateKey,
			issuerCertificate: signerCa.der,
			extensions: { keyUsage: ['cRLSign'] },
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Signer Scope Intermediate' },
			subject: { commonName: 'signer-scope-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: intermediateKeys.privateKey,
			issuerCertificate: intermediate.der,
			extensions: { keyUsage: ['digitalSignature'] },
		});
		const leafCrl = await createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: 'Signer Scope Intermediate' },
			signerPrivateKey: signerKeys.privateKey,
			issuerCertificate: signer.der,
			thisUpdate: new Date(at.getTime() - HOUR_MS),
			nextUpdate: new Date(at.getTime() + HOUR_MS),
		});
		const chain = [
			unwrap(parseCertificatePem(leaf.pem)),
			unwrap(parseCertificatePem(intermediate.pem)),
			unwrap(parseCertificatePem(root.certificate.pem)),
		];
		const extraCertificates = [signer.pem, signerCa.pem];

		const scopedSignerCrl = await createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: 'Signer Scope CRL CA' },
			signerPrivateKey: signerCaKeys.privateKey,
			issuerCertificate: signerCa.der,
			thisUpdate: new Date(at.getTime() - HOUR_MS),
			nextUpdate: new Date(at.getTime() + HOUR_MS),
			issuingDistributionPoint: { onlySomeReasons: ['keyCompromise'] },
		});
		const scoped = await checkChainRevocation({
			chain,
			crls: [leafCrl.der, scopedSignerCrl.der],
			extraCertificates,
			at,
			policy: { mode: 'soft-fail' },
		});
		expect(scoped.ok).toBe(true);
		if (!scoped.ok) return;
		expect(scoped.value.certificates[0]?.status).toBe('indeterminate');
		expect(scoped.value.certificates[0]?.indeterminateReasons).toContain(
			'crl_signer_indeterminate',
		);
		expect(scoped.value.executionErrors).toBeUndefined();

		const fullSignerCrl = await createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: 'Signer Scope CRL CA' },
			signerPrivateKey: signerCaKeys.privateKey,
			issuerCertificate: signerCa.der,
			thisUpdate: new Date(at.getTime() - HOUR_MS),
			nextUpdate: new Date(at.getTime() + HOUR_MS),
		});
		const full = await checkChainRevocation({
			chain,
			crls: [leafCrl.der, fullSignerCrl.der],
			extraCertificates,
			at,
			policy: { mode: 'soft-fail' },
		});
		expect(full.ok).toBe(true);
		if (!full.ok) return;
		expect(full.value.certificates[0]?.status).toBe('good');
	});

	it.each([
		{ exemption: 'none', status: 'indeterminate' },
		{ exemption: 'noRevAvail', status: 'good' },
		{ exemption: 'nocheck', status: 'good' },
	] as const)(
		'exempts a delegated CRL signer carrying $exemption from its own revocation check (RFC 9608 §4)',
		async ({ exemption, status }) => {
			const at = new Date(Date.now() + 5_000);
			const root = await createSelfSignedCertificate({
				subject: { commonName: 'Exempt Signer Root' },
				extensions: {
					basicConstraints: { ca: true, pathLength: 2 },
					keyUsage: ['keyCertSign', 'cRLSign'],
				},
			});
			const issueCa = async (commonName: string) => {
				const keys = await generateKeyPair();
				const certificate = await createCertificate({
					issuer: { commonName: 'Exempt Signer Root' },
					subject: { commonName },
					publicKey: keys.publicKey,
					signerPrivateKey: root.keyPair.privateKey,
					issuerCertificate: root.certificate.der,
					extensions: {
						basicConstraints: { ca: true, pathLength: 0 },
						keyUsage: ['keyCertSign', 'cRLSign'],
					},
				});
				return { keys, certificate };
			};
			const intermediate = await issueCa('Exempt Signer Intermediate');
			const signerCa = await issueCa('Exempt Signer CRL CA');
			const signerKeys = await generateKeyPair();
			const signer = await createCertificate({
				issuer: { commonName: 'Exempt Signer CRL CA' },
				subject: { commonName: 'Exempt Signer Intermediate' },
				publicKey: signerKeys.publicKey,
				signerPrivateKey: signerCa.keys.privateKey,
				issuerCertificate: signerCa.certificate.der,
				extensions: {
					keyUsage: ['cRLSign'],
					...(exemption === 'noRevAvail' ? { noRevAvail: true } : {}),
					...(exemption === 'nocheck' ? { customExtensions: [OCSP_NOCHECK_EXTENSION] } : {}),
				},
			});
			const leafKeys = await generateKeyPair();
			const leaf = await createCertificate({
				issuer: { commonName: 'Exempt Signer Intermediate' },
				subject: { commonName: 'exempt-signer-leaf' },
				publicKey: leafKeys.publicKey,
				signerPrivateKey: intermediate.keys.privateKey,
				issuerCertificate: intermediate.certificate.der,
				extensions: { keyUsage: ['digitalSignature'] },
			});
			const leafCrl = await createCertificateRevocationList({
				crlNumber: 1,
				issuer: { commonName: 'Exempt Signer Intermediate' },
				signerPrivateKey: signerKeys.privateKey,
				issuerCertificate: signer.der,
				thisUpdate: new Date(at.getTime() - HOUR_MS),
				nextUpdate: new Date(at.getTime() + HOUR_MS),
			});
			const result = await checkChainRevocation({
				chain: [
					unwrap(parseCertificatePem(leaf.pem)),
					unwrap(parseCertificatePem(intermediate.certificate.pem)),
					unwrap(parseCertificatePem(root.certificate.pem)),
				],
				crls: [leafCrl.der],
				extraCertificates: [signer.pem, signerCa.certificate.pem],
				at,
				policy: { mode: 'soft-fail' },
			});
			expect(result.ok).toBe(true);
			if (!result.ok) return;
			expect(result.value.certificates[0]?.status).toBe(status);
		},
	);

	it.each([
		{ delta: false, status: 'good', reasons: undefined },
		{
			delta: true,
			status: 'indeterminate',
			reasons: ['no_applicable_ocsp', 'crl_signer_revoked'],
		},
	] as const)(
		'applies a delta CRL that revokes a delegated CRL signer (delta $delta)',
		async ({ delta, status, reasons }) => {
			const at = new Date(Date.now() + 5_000);
			const root = await createSelfSignedCertificate({
				subject: { commonName: 'Delta Signer Root' },
				extensions: {
					basicConstraints: { ca: true, pathLength: 2 },
					keyUsage: ['keyCertSign', 'cRLSign'],
				},
			});
			const issueCa = async (commonName: string) => {
				const keys = await generateKeyPair();
				const certificate = await createCertificate({
					issuer: { commonName: 'Delta Signer Root' },
					subject: { commonName },
					publicKey: keys.publicKey,
					signerPrivateKey: root.keyPair.privateKey,
					issuerCertificate: root.certificate.der,
					extensions: {
						basicConstraints: { ca: true, pathLength: 0 },
						keyUsage: ['keyCertSign', 'cRLSign'],
					},
				});
				return { keys, certificate };
			};
			const intermediate = await issueCa('Delta Signer Intermediate');
			const signerCa = await issueCa('Delta Signer CRL CA');
			const signerKeys = await generateKeyPair();
			const signer = await createCertificate({
				issuer: { commonName: 'Delta Signer CRL CA' },
				subject: { commonName: 'Delta Signer Intermediate' },
				publicKey: signerKeys.publicKey,
				signerPrivateKey: signerCa.keys.privateKey,
				issuerCertificate: signerCa.certificate.der,
				extensions: { keyUsage: ['cRLSign'] },
			});
			const leafKeys = await generateKeyPair();
			const leaf = await createCertificate({
				issuer: { commonName: 'Delta Signer Intermediate' },
				subject: { commonName: 'delta-signer-leaf' },
				publicKey: leafKeys.publicKey,
				signerPrivateKey: intermediate.keys.privateKey,
				issuerCertificate: intermediate.certificate.der,
				extensions: { keyUsage: ['digitalSignature'] },
			});
			const window = {
				thisUpdate: new Date(at.getTime() - HOUR_MS),
				nextUpdate: new Date(at.getTime() + HOUR_MS),
			};
			const leafCrl = await createCertificateRevocationList({
				crlNumber: 1,
				issuer: { commonName: 'Delta Signer Intermediate' },
				signerPrivateKey: signerKeys.privateKey,
				issuerCertificate: signer.der,
				...window,
			});
			const signerCaCrl = (fields: { crlNumber: number; baseCrlNumber?: number }) =>
				createCertificateRevocationList({
					issuer: { commonName: 'Delta Signer CRL CA' },
					signerPrivateKey: signerCa.keys.privateKey,
					issuerCertificate: signerCa.certificate.der,
					...window,
					...fields,
					...(fields.baseCrlNumber === undefined
						? {}
						: {
								revokedCertificates: [
									{
										serialNumber: hexToBytes(
											unwrap(parseCertificatePem(signer.pem)).serialNumberHex,
										),
										reasonCode: 'keyCompromise' as const,
									},
								],
							}),
				});
			const signerBase = await signerCaCrl({ crlNumber: 1 });
			const signerDelta = await signerCaCrl({ crlNumber: 2, baseCrlNumber: 1 });
			const result = await checkChainRevocation({
				chain: [
					unwrap(parseCertificatePem(leaf.pem)),
					unwrap(parseCertificatePem(intermediate.certificate.pem)),
					unwrap(parseCertificatePem(root.certificate.pem)),
				],
				crls: [leafCrl.der, signerBase.der, ...(delta ? [signerDelta.der] : [])],
				extraCertificates: [signer.pem, signerCa.certificate.pem],
				at,
				policy: { mode: 'soft-fail' },
			});
			expect(result.ok).toBe(true);
			if (!result.ok) return;
			expect(result.value.certificates[0]?.status).toBe(status);
			expect(result.value.certificates[0]?.indeterminateReasons).toEqual(reasons);
		},
	);

	it.each([
		{ deltas: 'none', status: 'good', reasons: undefined },
		{
			deltas: 'revoking',
			status: 'indeterminate',
			reasons: ['no_applicable_ocsp', 'crl_signer_revoked'],
		},
		{
			deltas: 'four forged before revoking',
			status: 'indeterminate',
			reasons: ['no_applicable_ocsp', 'crl_signer_indeterminate'],
		},
		{ deltas: 'four forged', status: 'good', reasons: undefined },
	] as const)(
		'checks a CRL signer issued by a chain CA against $deltas delta CRLs',
		async ({ deltas, status, reasons }) => {
			const at = new Date(Date.now() + 5_000);
			const pointName = (name: string) => ({
				type: 'fullName' as const,
				fullName: [{ type: 'uri' as const, value: `http://example.test/${name}.crl` }],
			});
			const root = await createSelfSignedCertificate({
				subject: { commonName: 'In-Chain Delta Root' },
				extensions: {
					basicConstraints: { ca: true, pathLength: 1 },
					keyUsage: ['keyCertSign', 'cRLSign'],
				},
			});
			const intermediateKeys = await generateKeyPair();
			const intermediate = await createCertificate({
				issuer: { commonName: 'In-Chain Delta Root' },
				subject: { commonName: 'In-Chain Delta Intermediate' },
				publicKey: intermediateKeys.publicKey,
				signerPrivateKey: root.keyPair.privateKey,
				issuerCertificate: root.certificate.der,
				extensions: {
					basicConstraints: { ca: true, pathLength: 0 },
					keyUsage: ['keyCertSign', 'cRLSign'],
				},
			});
			const signerKeys = await generateKeyPair();
			const signer = await createCertificate({
				issuer: { commonName: 'In-Chain Delta Intermediate' },
				subject: { commonName: 'In-Chain Delta Intermediate' },
				publicKey: signerKeys.publicKey,
				signerPrivateKey: intermediateKeys.privateKey,
				issuerCertificate: intermediate.der,
				extensions: {
					keyUsage: ['cRLSign'],
					crlDistributionPoints: [{ distributionPoint: pointName('signer') }],
				},
			});
			const leafKeys = await generateKeyPair();
			const leaf = await createCertificate({
				issuer: { commonName: 'In-Chain Delta Intermediate' },
				subject: { commonName: 'in-chain-delta-leaf' },
				publicKey: leafKeys.publicKey,
				signerPrivateKey: intermediateKeys.privateKey,
				issuerCertificate: intermediate.der,
				extensions: {
					keyUsage: ['digitalSignature'],
					crlDistributionPoints: [{ distributionPoint: pointName('leaf') }],
				},
			});
			const crl = (
				signerPrivateKey: CryptoKey,
				issuerCertificate: Uint8Array,
				fields: {
					readonly scope: string;
					readonly crlNumber: number;
					readonly baseCrlNumber?: number;
					readonly revokes?: string;
					readonly thisUpdate: Date;
				},
			) =>
				createCertificateRevocationList({
					issuer: { commonName: 'In-Chain Delta Intermediate' },
					signerPrivateKey,
					issuerCertificate,
					crlNumber: fields.crlNumber,
					...(fields.baseCrlNumber === undefined ? {} : { baseCrlNumber: fields.baseCrlNumber }),
					thisUpdate: fields.thisUpdate,
					nextUpdate: new Date(at.getTime() + HOUR_MS),
					issuingDistributionPoint: { distributionPoint: pointName(fields.scope) },
					...(fields.revokes === undefined
						? {}
						: {
								revokedCertificates: [
									{
										serialNumber: hexToBytes(fields.revokes),
										reasonCode: 'keyCompromise' as const,
									},
								],
							}),
				});
			const older = new Date(at.getTime() - 2 * HOUR_MS);
			const newer = new Date(at.getTime() - HOUR_MS);
			const signerSerial = unwrap(parseCertificatePem(signer.pem)).serialNumberHex;
			const leafCrl = await crl(signerKeys.privateKey, signer.der, {
				scope: 'leaf',
				crlNumber: 1,
				thisUpdate: older,
			});
			const signerBase = await crl(intermediateKeys.privateKey, intermediate.der, {
				scope: 'signer',
				crlNumber: 1,
				thisUpdate: older,
			});
			const revokingDelta = await crl(intermediateKeys.privateKey, intermediate.der, {
				scope: 'signer',
				crlNumber: 2,
				baseCrlNumber: 1,
				revokes: signerSerial,
				thisUpdate: older,
			});
			const attacker = await generateKeyPair();
			const forged = await Promise.all(
				Array.from({ length: 4 }, (_, index) =>
					crl(attacker.privateKey, intermediate.der, {
						scope: 'signer',
						crlNumber: 10 + index,
						baseCrlNumber: 1,
						thisUpdate: newer,
					}),
				),
			);
			const deltaDers =
				deltas === 'none'
					? []
					: deltas === 'revoking'
						? [revokingDelta.der]
						: deltas === 'four forged'
							? forged.map((delta) => delta.der)
							: [...forged.map((delta) => delta.der), revokingDelta.der];
			const result = await checkChainRevocation({
				chain: [
					unwrap(parseCertificatePem(leaf.pem)),
					unwrap(parseCertificatePem(intermediate.pem)),
					unwrap(parseCertificatePem(root.certificate.pem)),
				],
				crls: [leafCrl.der, signerBase.der, ...deltaDers],
				extraCertificates: [signer.pem],
				at,
				policy: { mode: 'soft-fail' },
			});
			expect(result.ok).toBe(true);
			if (!result.ok) return;
			expect(result.value.certificates[0]?.status).toBe(status);
			expect(result.value.certificates[0]?.indeterminateReasons).toEqual(reasons);
		},
	);

	it.each([
		{ rogue: false, status: 'indeterminate' },
		{ rogue: true, status: 'indeterminate' },
	] as const)(
		"checks a CRL signer against its validated issuer's CRLs (rogue same-name issuer $rogue)",
		async ({ rogue, status }) => {
			const at = new Date(Date.now() + 5_000);
			const pointName = (name: string) => ({
				type: 'fullName' as const,
				fullName: [{ type: 'uri' as const, value: `http://example.test/${name}.crl` }],
			});
			const caExtensions = {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			} as const;
			const root = await createSelfSignedCertificate({
				subject: { commonName: 'Signer Issuer Root' },
				extensions: {
					basicConstraints: { ca: true, pathLength: 1 },
					keyUsage: ['keyCertSign', 'cRLSign'],
				},
			});
			const underRoot = async (commonName: string, signerPrivateKey: CryptoKey) => {
				const keys = await generateKeyPair();
				const der = (
					await createCertificate({
						issuer: { commonName: 'Signer Issuer Root' },
						subject: { commonName },
						publicKey: keys.publicKey,
						signerPrivateKey,
						issuerCertificate: root.certificate.der,
						extensions: caExtensions,
					})
				).der;
				return { keys, der };
			};
			const intermediate = await underRoot('Signer Issuer Intermediate', root.keyPair.privateKey);
			const signerCa = await underRoot('Signer Issuer CRL CA', root.keyPair.privateKey);
			const attacker = await generateKeyPair();
			const rogueCa = await underRoot('Signer Issuer CRL CA', attacker.privateKey);
			const signerKeys = await generateKeyPair();
			const signer = await createCertificate({
				issuer: { commonName: 'Signer Issuer CRL CA' },
				subject: { commonName: 'Signer Issuer Intermediate' },
				publicKey: signerKeys.publicKey,
				signerPrivateKey: signerCa.keys.privateKey,
				issuerCertificate: signerCa.der,
				extensions: {
					keyUsage: ['cRLSign'],
					crlDistributionPoints: [{ distributionPoint: pointName('signer') }],
				},
			});
			const leafKeys = await generateKeyPair();
			const leaf = await createCertificate({
				issuer: { commonName: 'Signer Issuer Intermediate' },
				subject: { commonName: 'signer-issuer-leaf' },
				publicKey: leafKeys.publicKey,
				signerPrivateKey: intermediate.keys.privateKey,
				issuerCertificate: intermediate.der,
				extensions: {
					keyUsage: ['digitalSignature'],
					crlDistributionPoints: [{ distributionPoint: pointName('leaf') }],
				},
			});
			const window = {
				thisUpdate: new Date(at.getTime() - HOUR_MS),
				nextUpdate: new Date(at.getTime() + HOUR_MS),
			};
			const leafCrl = await createCertificateRevocationList({
				crlNumber: 1,
				issuer: { commonName: 'Signer Issuer Intermediate' },
				signerPrivateKey: signerKeys.privateKey,
				issuerCertificate: signer.der,
				issuingDistributionPoint: { distributionPoint: pointName('leaf') },
				...window,
			});
			const signerCaCrl = (
				signerPrivateKey: CryptoKey,
				issuerCertificate: Uint8Array,
				revokes: boolean,
			) =>
				createCertificateRevocationList({
					crlNumber: 1,
					issuer: { commonName: 'Signer Issuer CRL CA' },
					signerPrivateKey,
					issuerCertificate,
					issuingDistributionPoint: { distributionPoint: pointName('signer') },
					...window,
					...(revokes
						? {
								revokedCertificates: [
									{
										serialNumber: hexToBytes(
											unwrap(parseCertificatePem(signer.pem)).serialNumberHex,
										),
										reasonCode: 'keyCompromise' as const,
									},
								],
							}
						: {}),
				});
			const revoking = await signerCaCrl(signerCa.keys.privateKey, signerCa.der, true);
			const forged = await signerCaCrl(attacker.privateKey, rogueCa.der, false);
			const result = await checkChainRevocation({
				chain: [
					unwrap(parseCertificatePem(leaf.pem)),
					unwrap(parseCertificateDer(intermediate.der)),
					unwrap(parseCertificatePem(root.certificate.pem)),
				],
				crls: [leafCrl.der, revoking.der, ...(rogue ? [forged.der] : [])],
				extraCertificates: [...(rogue ? [rogueCa.der] : []), signerCa.der, signer.pem],
				at,
				policy: { mode: 'soft-fail' },
			});
			expect(result.ok).toBe(true);
			if (!result.ok) return;
			expect(result.value.certificates[0]?.status).toBe(status);
			expect(result.value.certificates[0]?.indeterminateReasons).toEqual([
				'no_applicable_ocsp',
				'crl_signer_revoked',
			]);
		},
	);

	it('tries a later authorized signer when an earlier same-key candidate is unusable', async () => {
		const at = new Date(Date.now() + 5_000);
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'Shadow Root' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const caKeys = await generateKeyPair();
		const issuerCa = await createCertificate({
			issuer: { commonName: 'Shadow Root' },
			subject: { commonName: 'Shadow CA' },
			publicKey: caKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerCertificate: root.certificate.der,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		// Two CRL signers sharing one key and the CA's subject DN, issued by the
		// CA. The first is expired; only the second is a usable signer.
		const signerKeys = await generateKeyPair();
		const expiredSigner = await createCertificate({
			issuer: { commonName: 'Shadow CA' },
			subject: { commonName: 'Shadow CA' },
			publicKey: signerKeys.publicKey,
			signerPrivateKey: caKeys.privateKey,
			issuerCertificate: issuerCa.der,
			validity: {
				notBefore: new Date(at.getTime() - 400 * 24 * HOUR_MS),
				notAfter: new Date(at.getTime() - HOUR_MS),
			},
			extensions: { keyUsage: ['cRLSign'] },
		});
		const validSigner = await createCertificate({
			issuer: { commonName: 'Shadow CA' },
			subject: { commonName: 'Shadow CA' },
			publicKey: signerKeys.publicKey,
			signerPrivateKey: caKeys.privateKey,
			issuerCertificate: issuerCa.der,
			validity: {
				notBefore: new Date(at.getTime() - HOUR_MS),
				notAfter: new Date(at.getTime() + 400 * 24 * HOUR_MS),
			},
			extensions: { keyUsage: ['cRLSign'] },
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Shadow CA' },
			subject: { commonName: 'shadow-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: caKeys.privateKey,
			issuerCertificate: issuerCa.der,
			extensions: { keyUsage: ['digitalSignature'] },
		});
		const parsedLeaf = unwrap(parseCertificatePem(leaf.pem));
		const crl = await createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: 'Shadow CA' },
			signerPrivateKey: signerKeys.privateKey,
			issuerCertificate: validSigner.der,
			thisUpdate: new Date(at.getTime() - HOUR_MS),
			nextUpdate: new Date(at.getTime() + HOUR_MS),
			revokedCertificates: [
				{
					serialNumber: hexToBytes(parsedLeaf.serialNumberHex),
					revocationDate: new Date(at.getTime() - HOUR_MS),
					reasonCode: 'keyCompromise',
				},
			],
		});

		const result = await checkChainRevocation({
			chain: [
				parsedLeaf,
				unwrap(parseCertificatePem(issuerCa.pem)),
				unwrap(parseCertificatePem(root.certificate.pem)),
			],
			crls: [crl.der],
			extraCertificates: [expiredSigner.pem, validSigner.pem],
			at,
			policy: { mode: 'soft-fail' },
		});
		expect(result.ok).toBe(true);
		expect(result.value.decision).toBe('deny');
		expect(result.value.certificates[0]?.status).toBe('revoked');
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
		issuerCertificate: ca.certificate.der,
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

	it('denies on revoked OCSP evidence regardless of response ordering', async () => {
		const { ca, leaf, chain, at, fresh } = await createOcspChainFixture();
		const good = await createOcspResponse({
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
		const revoked = await createOcspResponse({
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

		for (const ocspResponses of [
			[good.der, revoked.der],
			[revoked.der, good.der],
		]) {
			const result = await checkChainRevocation({
				chain: [...chain],
				ocspResponses,
				at,
			});

			expect(result.ok).toBe(true);
			expect(result.value.decision).toBe('deny');
			expect(result.value.certificates[0]?.status).toBe('revoked');
			expect(result.value.certificates[0]?.source?.kind).toBe('ocsp');
		}
	});

	it('allows newer good OCSP evidence to clear an older certificate hold', async () => {
		const { ca, leaf, chain, at } = await createOcspChainFixture();
		const holdThisUpdate = new Date(at.getTime() - 2 * HOUR_MS);
		const goodThisUpdate = new Date(at.getTime() - HOUR_MS);
		const nextUpdate = new Date(at.getTime() + HOUR_MS);
		const hold = await createOcspResponse({
			signerPrivateKey: ca.keyPair.privateKey,
			signerCertificate: ca.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'revoked',
					revokedAt: holdThisUpdate,
					revocationReasonCode: 6,
					thisUpdate: holdThisUpdate,
					nextUpdate,
				},
			],
		});
		const good = await createOcspResponse({
			signerPrivateKey: ca.keyPair.privateKey,
			signerCertificate: ca.certificate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: ca.certificate.pem,
					certStatus: 'good',
					thisUpdate: goodThisUpdate,
					nextUpdate,
				},
			],
		});

		for (const ocspResponses of [
			[good.der, hold.der],
			[hold.der, good.der],
		]) {
			const result = await checkChainRevocation({
				chain: [...chain],
				ocspResponses,
				at,
			});

			expect(result.ok).toBe(true);
			expect(result.value.decision).toBe('allow');
			const leafStatus = result.value.certificates[0];
			expect(leafStatus?.status).toBe('good');
			if (leafStatus?.status !== 'good') return;
			expect(leafStatus.source.thisUpdate?.getTime()).toBe(
				Math.floor(goodThisUpdate.getTime() / 1000) * 1000,
			);
		}
	});

	it('reports a certificate hold that is fresher than the good OCSP evidence', async () => {
		const { ca, leaf, chain, at } = await createOcspChainFixture();
		const goodThisUpdate = new Date(at.getTime() - 2 * HOUR_MS);
		const holdThisUpdate = new Date(at.getTime() - HOUR_MS);
		const nextUpdate = new Date(at.getTime() + HOUR_MS);
		const respond = (thisUpdate: Date, hold: boolean) =>
			createOcspResponse({
				signerPrivateKey: ca.keyPair.privateKey,
				signerCertificate: ca.certificate.pem,
				responses: [
					hold
						? {
								certificate: leaf.pem,
								issuerCertificate: ca.certificate.pem,
								certStatus: 'revoked',
								revokedAt: thisUpdate,
								revocationReasonCode: 6,
								thisUpdate,
								nextUpdate,
							}
						: {
								certificate: leaf.pem,
								issuerCertificate: ca.certificate.pem,
								certStatus: 'good',
								thisUpdate,
								nextUpdate,
							},
				],
			});

		const result = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [
				(await respond(goodThisUpdate, false)).der,
				(await respond(holdThisUpdate, true)).der,
			],
			at,
		});

		expect(result.value.decision).toBe('deny');
		expect(result.value.certificates[0]).toMatchObject({
			status: 'revoked',
			source: { kind: 'ocsp' },
			revocationInfo: { reason: 'certificateHold' },
		});
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
			crlNumber: 1,
			issuer: { commonName: caName },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerCertificate: ca.certificate.der,
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

	it('reports an unrecognized CRLReason as revoked, or under reject as indeterminate over good evidence', async () => {
		const { caName, ca, leaf, chain, parsedLeaf, at, fresh } = await createOcspChainFixture();
		const ocsp = (certStatus: 'good' | 'revoked') =>
			createOcspResponse({
				signerPrivateKey: ca.keyPair.privateKey,
				signerCertificate: ca.certificate.pem,
				responses: [
					certStatus === 'good'
						? { certificate: leaf.pem, issuerCertificate: ca.certificate.pem, certStatus, ...fresh }
						: {
								certificate: leaf.pem,
								issuerCertificate: ca.certificate.pem,
								certStatus,
								revokedAt: fresh.thisUpdate,
								revocationReasonCode: 11,
								...fresh,
							},
				],
			});
		const crl = (revoked: boolean) =>
			createCertificateRevocationList({
				crlNumber: 1,
				issuer: { commonName: caName },
				signerPrivateKey: ca.keyPair.privateKey,
				issuerCertificate: ca.certificate.der,
				...fresh,
				revokedCertificates: [
					{
						serialNumber: revoked ? hexToBytes(parsedLeaf.serialNumberHex) : Uint8Array.of(0x7f),
						revocationDate: fresh.thisUpdate,
						reasonCode: 'keyCompromise',
					},
				],
			});
		const unrecognizedCrl = await withRevokedEntryReasonCode(
			(await crl(true)).der,
			ca.keyPair.privateKey,
			7,
		);
		const goodCrl = (await crl(false)).der;
		const unrecognizedOcsp = (await ocsp('revoked')).der;
		const goodOcsp = (await ocsp('good')).der;
		const cases = [
			{
				crls: [unrecognizedCrl],
				ocspResponses: [goodOcsp],
				source: 'crl',
				code: 7n,
				reason: 'crl_reason_code_unrecognized',
			},
			{
				crls: [goodCrl],
				ocspResponses: [unrecognizedOcsp],
				source: 'ocsp',
				code: 11n,
				reason: 'ocsp_reason_code_unrecognized',
			},
		] as const;

		for (const { crls, ocspResponses, source, code, reason } of cases) {
			const byDefault = await checkChainRevocation({
				chain: [...chain],
				crls: [...crls],
				ocspResponses: [...ocspResponses],
				at,
			});
			expect(byDefault.value.decision).toBe('deny');
			expect(byDefault.value.certificates[0]).toMatchObject({
				status: 'revoked',
				source: { kind: source },
				revocationInfo: { reason: { type: 'unrecognized', code } },
			});

			const rejected = await checkChainRevocation({
				chain: [...chain],
				crls: [...crls],
				ocspResponses: [...ocspResponses],
				at,
				policy: { unrecognizedReasonCode: 'reject' },
			});
			expect(rejected.value.decision).toBe('deny');
			expect(rejected.value.certificates[0]?.status).toBe('indeterminate');
			expect(rejected.value.certificates[0]?.indeterminateReasons).toContain(reason);
		}
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
			crlNumber: 1,
			issuer: { commonName: caName },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerCertificate: ca.certificate.der,
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
			crlNumber: 1,
			issuer: { commonName: caName },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerCertificate: ca.certificate.der,
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
			crlNumber: 1,
			issuer: { commonName: caName },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerCertificate: ca.certificate.der,
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
			crlNumber: 1,
			issuer: { commonName: caName },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerCertificate: ca.certificate.der,
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
			issuerCertificate: ca.certificate.der,
			extensions: { keyUsage: ['cRLSign'] },
		});
		const parsedDelegate = unwrap(parseCertificatePem(delegate.pem));

		// Fresh CRL from the delegate, stale CRL from the chain CA — the
		// reported signer must belong to the CRL whose freshness won, no
		// matter the processing order.
		const freshDelegateCrl = await createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: caName },
			signerPrivateKey: delegateKeys.privateKey,
			issuerCertificate: delegate.der,
			...fresh,
		});
		const staleCaCrl = await createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: caName },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerCertificate: ca.certificate.der,
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
			issuerCertificate: ca.certificate.der,
			crlNumber: 5,
			thisUpdate: new Date(at.getTime() - 12 * HOUR_MS),
			nextUpdate: new Date(at.getTime() + HOUR_MS),
		});
		const deltaThisUpdate = new Date(at.getTime() - HOUR_MS);
		const deltaCrl = await createCertificateRevocationList({
			issuer: { commonName: caName },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerCertificate: ca.certificate.der,
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
			issuerCertificate: outsiderCa.certificate.der,
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
			trustedOcspResponders: [
				{
					issuerCertificate: ca.certificate.pem,
					responderCertificate: responder.pem,
				},
			],
			at,
		});
		expect(trusted.value.certificates[0]?.status).toBe('good');
		expect(trusted.value.certificates[0]?.source?.kind).toBe('ocsp');
	});

	it('does not trust an issuer-scoped responder for another issuer in the chain', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'OCSP Scope Root' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const intermediateKeys = await generateKeyPair();
		const intermediate = await createCertificate({
			issuer: { commonName: 'OCSP Scope Root' },
			subject: { commonName: 'OCSP Scope Intermediate' },
			publicKey: intermediateKeys.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerCertificate: root.certificate.der,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'OCSP Scope Intermediate' },
			subject: { commonName: 'ocsp-scope-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: intermediateKeys.privateKey,
			issuerCertificate: intermediate.der,
		});
		const responder = await createSelfSignedCertificate({
			subject: { commonName: 'Intermediate Scoped Responder' },
		});
		const at = new Date(Date.now() + 5_000);
		const response = await createOcspResponse({
			signerPrivateKey: responder.keyPair.privateKey,
			signerCertificate: responder.certificate.pem,
			includedCertificates: [responder.certificate.pem],
			responses: [
				{
					certificate: intermediate.pem,
					issuerCertificate: root.certificate.pem,
					certStatus: 'good',
					thisUpdate: new Date(at.getTime() - HOUR_MS),
					nextUpdate: new Date(at.getTime() + HOUR_MS),
				},
			],
		});

		const result = await checkChainRevocation({
			chain: [
				unwrap(parseCertificatePem(leaf.pem)),
				unwrap(parseCertificatePem(intermediate.pem)),
				unwrap(parseCertificatePem(root.certificate.pem)),
			],
			ocspResponses: [response.der],
			trustedOcspResponders: [
				{
					issuerCertificate: intermediate.pem,
					responderCertificate: responder.certificate.pem,
				},
			],
			at,
		});

		expect(result.value.certificates[1]?.status).toBe('indeterminate');
		expect(result.value.certificates[1]?.indeterminateReasons).toContain(
			'ocsp_responder_not_authorized',
		);
	});

	it('validates a delegated responder provided via extraCertificates', async () => {
		const { caName, ca, leaf, chain, at, fresh } = await createOcspChainFixture();
		const responderKeys = await generateKeyPair();
		const responder = await createCertificate({
			issuer: { commonName: caName },
			subject: { commonName: 'Delegated OCSP Responder' },
			publicKey: responderKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerCertificate: ca.certificate.der,
			extensions: { extendedKeyUsage: ['ocspSigning'], customExtensions: [OCSP_NOCHECK_EXTENSION] },
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

	it.each([
		{ delta: false, embedded: true, status: 'good', reasons: undefined },
		{
			delta: true,
			embedded: true,
			status: 'indeterminate',
			reasons: ['ocsp_responder_revoked', 'no_applicable_crl'],
		},
		{ delta: false, embedded: false, status: 'good', reasons: undefined },
		{
			delta: true,
			embedded: false,
			status: 'indeterminate',
			reasons: ['ocsp_responder_revoked', 'no_applicable_crl'],
		},
	] as const)(
		'applies a delta CRL that revokes a delegated responder (delta $delta, embedded $embedded)',
		async ({ delta, embedded, status, reasons }) => {
			const { caName, ca, leaf, chain, at, fresh } = await createOcspChainFixture();
			const scope = {
				distributionPoint: {
					type: 'fullName' as const,
					fullName: [{ type: 'uri' as const, value: 'http://example.test/responder.crl' }],
				},
			};
			const responderKeys = await generateKeyPair();
			const responder = await createCertificate({
				issuer: { commonName: caName },
				subject: { commonName: 'Delta-Revoked OCSP Responder' },
				publicKey: responderKeys.publicKey,
				signerPrivateKey: ca.keyPair.privateKey,
				issuerCertificate: ca.certificate.der,
				extensions: {
					extendedKeyUsage: ['ocspSigning'],
					crlDistributionPoints: [scope],
				},
			});
			const crl = (crlNumber: number, baseCrlNumber?: number) =>
				createCertificateRevocationList({
					crlNumber,
					...(baseCrlNumber === undefined
						? {}
						: {
								baseCrlNumber,
								revokedCertificates: [
									{
										serialNumber: hexToBytes(
											unwrap(parseCertificatePem(responder.pem)).serialNumberHex,
										),
										reasonCode: 'keyCompromise' as const,
									},
								],
							}),
					issuer: { commonName: caName },
					signerPrivateKey: ca.keyPair.privateKey,
					issuerCertificate: ca.certificate.der,
					issuingDistributionPoint: scope,
					...fresh,
				});
			const response = await createOcspResponse({
				signerPrivateKey: responderKeys.privateKey,
				signerCertificate: responder.pem,
				...(embedded ? { includedCertificates: [responder.pem] } : {}),
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
				crls: [(await crl(1)).der, ...(delta ? [(await crl(2, 1)).der] : [])],
				ocspResponses: [response.der],
				...(embedded ? {} : { extraCertificates: [ca.certificate.pem, responder.pem] }),
				at,
				policy: { mode: 'soft-fail' },
			});
			expect(result.value.certificates[0]?.status).toBe(status);
			expect(result.value.certificates[0]?.indeterminateReasons).toEqual(reasons);
		},
	);

	it('records parse errors for malformed OCSP responses', async () => {
		const { chain, at } = await createOcspChainFixture();
		const result = await checkChainRevocation({
			chain: [...chain],
			ocspResponses: [Uint8Array.of(0x30, 0x00)],
			at,
		});

		expect(result.value.certificates[0]?.status).toBe('indeterminate');
		expect(result.value.executionErrors).toMatchObject([
			{ kind: 'parse_error', code: 'malformed' },
		]);
	});

	it('records the decode refusal for CRL and OCSP evidence over a micro509 limit', async () => {
		const { chain, at } = await createOcspChainFixture();
		const overlongArc = tlv(0x06, Uint8Array.of(0x2a, ...new Array<number>(64).fill(0xff), 0x7f));
		const crl = sequence([
			sequence([tlv(0x02, Uint8Array.of(1)), sequence([overlongArc]), sequence([]), utcTime(at)]),
			sequence([overlongArc]),
			tlv(0x03, Uint8Array.of(0)),
		]);
		const ocspResponse = sequence([
			tlv(0x0a, Uint8Array.of(0)),
			explicitContext(0, sequence([overlongArc, octetString(Uint8Array.of())])),
		]);
		const result = await checkChainRevocation({
			chain: [...chain],
			crls: [crl],
			ocspResponses: [ocspResponse],
			at,
		});

		expect(result.value.certificates[0]?.status).toBe('indeterminate');
		expect(result.value.executionErrors).toMatchObject([
			{ kind: 'parse_error', code: 'limit_exceeded' },
			{ kind: 'parse_error', code: 'limit_exceeded' },
		]);
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

describe('checkChainRevocation CRL maximum age policy', () => {
	it('treats a CRL older than crlMaxAgeMs as unusable evidence', async () => {
		const caName = 'Chain Max Age CA';
		const ca = await createSelfSignedCertificate({
			subject: { commonName: caName },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: caName },
			subject: { commonName: 'chain-max-age-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerCertificate: ca.certificate.der,
		});
		const crl = await createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: caName },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerCertificate: ca.certificate.der,
			thisUpdate: new Date('2020-01-01T00:00:00Z'),
			nextUpdate: FAR_FUTURE_NEXT_UPDATE,
		});
		const chain = [
			unwrap(parseCertificatePem(leaf.pem)),
			unwrap(parseCertificatePem(ca.certificate.pem)),
		];
		const at = new Date('2100-01-01T00:00:00Z');

		const unbounded = await checkChainRevocation({ chain, crls: [crl.pem], at });
		expect(unbounded.value.decision).toBe('allow');
		expect(unbounded.value.certificates[0]?.status).toBe('good');

		const bounded = await checkChainRevocation({
			chain,
			crls: [crl.pem],
			at,
			policy: { crlMaxAgeMs: 365 * 24 * 60 * 60 * 1000 },
		});
		expect(bounded.value.decision).toBe('deny');
		expect(bounded.value.certificates[0]?.status).toBe('indeterminate');
		expect(bounded.value.certificates[0]?.indeterminateReasons).toContain('crl_expired');
	});
});

/**
 * Root R as a bare trust anchor over CA C and leaf L. `crlSigner` shares C's
 * name and carries cRLSign under a key of its own, and `responder` is an
 * ocspSigning responder; R issues both.
 */
async function createBareAnchorFixture() {
	const rootName = 'Bare Anchor Root';
	const caName = 'Bare Anchor CA';
	const root = await createSelfSignedCertificate({
		subject: { commonName: rootName },
		extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
	});
	const issueUnderRoot = async (
		commonName: string,
		extensions: Parameters<typeof createCertificate>[0]['extensions'],
	) => {
		const keyPair = await generateKeyPair();
		const certificate = await createCertificate({
			issuer: { commonName: rootName },
			subject: { commonName },
			publicKey: keyPair.publicKey,
			signerPrivateKey: root.keyPair.privateKey,
			issuerCertificate: root.certificate.der,
			...(extensions === undefined ? {} : { extensions }),
		});
		return { keyPair, certificate };
	};
	const ca = await issueUnderRoot(caName, {
		basicConstraints: { ca: true },
		keyUsage: ['keyCertSign', 'cRLSign'],
	});
	const crlSigner = await issueUnderRoot(caName, {
		basicConstraints: { ca: true },
		keyUsage: ['cRLSign'],
	});
	const responder = await issueUnderRoot('Bare Anchor OCSP Responder', {
		extendedKeyUsage: ['ocspSigning'],
		customExtensions: [OCSP_NOCHECK_EXTENSION],
	});
	const leafKeys = await generateKeyPair();
	const leaf = await createCertificate({
		issuer: { commonName: caName },
		subject: { commonName: 'bare-anchor-leaf.example' },
		publicKey: leafKeys.publicKey,
		signerPrivateKey: ca.keyPair.privateKey,
		issuerCertificate: ca.certificate.der,
	});
	const at = new Date(Date.now() + 5_000);
	const fresh = {
		thisUpdate: new Date(at.getTime() - HOUR_MS),
		nextUpdate: new Date(at.getTime() + HOUR_MS),
	};
	const rootCrl = (revoked: readonly Uint8Array[]) =>
		createCertificateRevocationList({
			crlNumber: 1,
			issuer: { commonName: rootName },
			signerPrivateKey: root.keyPair.privateKey,
			issuerCertificate: root.certificate.der,
			revokedCertificates: revoked.map((serialNumber) => ({ serialNumber })),
			thisUpdate: fresh.thisUpdate,
			nextUpdate: fresh.nextUpdate,
		});
	const caCrl = await createCertificateRevocationList({
		crlNumber: 1,
		issuer: { commonName: caName },
		signerPrivateKey: ca.keyPair.privateKey,
		issuerCertificate: ca.certificate.der,
		thisUpdate: fresh.thisUpdate,
		nextUpdate: fresh.nextUpdate,
	});
	const caOcsp = (
		certStatus: 'good' | 'revoked',
		signer: 'root' | 'responder',
		embedSigner = false,
	) => {
		const signerCertificate = signer === 'root' ? root.certificate.der : responder.certificate.der;
		return createOcspResponse({
			signerPrivateKey: signer === 'root' ? root.keyPair.privateKey : responder.keyPair.privateKey,
			signerCertificate,
			...(embedSigner ? { includedCertificates: [signerCertificate] } : {}),
			responses: [
				{
					certificate: ca.certificate.der,
					issuerCertificate: root.certificate.der,
					...(certStatus === 'revoked'
						? { certStatus, revokedAt: fresh.thisUpdate }
						: { certStatus }),
					...fresh,
				},
			],
		});
	};
	const parsedCa = unwrap(parseCertificateDer(ca.certificate.der));
	return {
		trustAnchor: trustAnchorFromCertificate(unwrap(parseCertificateDer(root.certificate.der))),
		root,
		rootName,
		caName,
		ca,
		crlSigner,
		responder,
		leaf,
		chain: [unwrap(parseCertificateDer(leaf.der)), parsedCa],
		caSerial: hexToBytes(parsedCa.serialNumberHex),
		at,
		fresh,
		rootCrl,
		caCrl,
		caOcsp,
	};
}

describe('checkChainRevocation below a bare trust anchor (RFC 5280 §6.1.3 (a)(3))', () => {
	it('checks the certificate the anchor issued and leaves it unchecked without the anchor', async () => {
		const { trustAnchor, chain, at, caCrl } = await createBareAnchorFixture();
		const withoutAnchor = await checkChainRevocation({ chain, crls: [caCrl.der], at });
		expect(withoutAnchor.value.certificates).toHaveLength(1);
		const withAnchor = await checkChainRevocation({ chain, crls: [caCrl.der], at, trustAnchor });
		expect(withAnchor.value.certificates).toHaveLength(2);
		expect(withAnchor.value.certificates[1]).toMatchObject({
			status: 'indeterminate',
			indeterminateReasons: expect.arrayContaining(['no_applicable_crl']),
		});
		expect(withAnchor.value.decision).toBe('deny');
	});

	it('accepts a CRL the anchor key signs and reports no signer certificate', async () => {
		const { trustAnchor, chain, at, rootCrl, caCrl } = await createBareAnchorFixture();
		const result = await checkChainRevocation({
			chain,
			crls: [(await rootCrl([])).der, caCrl.der],
			at,
			trustAnchor,
		});
		expect(result.value.decision).toBe('allow');
		expect(result.value.certificates[1]).toMatchObject({
			status: 'good',
			source: { kind: 'crl' },
		});
		expect(result.value.certificates[1]?.source?.signerCertificate).toBeUndefined();
	});

	it.each([
		{
			evidence: 'an anchor-signed CRL',
			revocation: async (fixture: Awaited<ReturnType<typeof createBareAnchorFixture>>) => ({
				crls: [(await fixture.rootCrl([fixture.caSerial])).der, fixture.caCrl.der],
			}),
		},
		{
			evidence: 'an anchor-signed OCSP response',
			revocation: async (fixture: Awaited<ReturnType<typeof createBareAnchorFixture>>) => ({
				crls: [fixture.caCrl.der],
				ocspResponses: [(await fixture.caOcsp('revoked', 'root')).der],
			}),
		},
	])('rejects a revoked anchor-issued CA through $evidence', async ({ revocation }) => {
		const fixture = await createBareAnchorFixture();
		const result = await verifyCertificateChain({
			leaf: fixture.leaf.der,
			intermediates: [fixture.ca.certificate.der],
			roots: [],
			trustAnchors: [fixture.trustAnchor],
			at: fixture.at,
			revocation: await revocation(fixture),
		});
		expect(result).toMatchObject({ ok: false, code: 'certificate_revoked', index: 1 });
	});

	it.each([
		{ signer: 'root', embedded: false, extra: false },
		{ signer: 'root', embedded: true, extra: false },
		{ signer: 'responder', embedded: true, extra: false },
		{ signer: 'responder', embedded: false, extra: true },
	] as const)(
		'accepts a good OCSP response signed by the $signer key (embedded $embedded, extra $extra)',
		async ({ signer, embedded, extra }) => {
			const fixture = await createBareAnchorFixture();
			const result = await checkChainRevocation({
				chain: fixture.chain,
				crls: [fixture.caCrl.der],
				ocspResponses: [(await fixture.caOcsp('good', signer, embedded)).der],
				extraCertificates: extra ? [fixture.responder.certificate.der] : [],
				at: fixture.at,
				trustAnchor: fixture.trustAnchor,
			});
			expect(result.value.certificates[1]).toMatchObject({
				status: 'good',
				source: { kind: 'ocsp' },
			});
			expect(result.value.decision).toBe('allow');
		},
	);

	it.each([{ withAnchorCertificate: false }, { withAnchorCertificate: true }])(
		'authorizes a separate CRL signer that the anchor certifies (anchor certificate among extras: $withAnchorCertificate)',
		async ({ withAnchorCertificate }) => {
			const { trustAnchor, root, crlSigner, chain, at, fresh, rootCrl } =
				await createBareAnchorFixture();
			const leafCrl = await createCertificateRevocationList({
				crlNumber: 1,
				issuer: { commonName: 'Bare Anchor CA' },
				signerPrivateKey: crlSigner.keyPair.privateKey,
				issuerCertificate: crlSigner.certificate.der,
				thisUpdate: fresh.thisUpdate,
				nextUpdate: fresh.nextUpdate,
			});
			const input = {
				chain,
				extraCertificates: [
					crlSigner.certificate.der,
					...(withAnchorCertificate ? [root.certificate.der] : []),
				],
				at,
				trustAnchor,
			};
			const good = await checkChainRevocation({
				...input,
				crls: [leafCrl.der, (await rootCrl([])).der],
			});
			expect(good.value.certificates[0]).toMatchObject({ status: 'good' });
			expect(good.value.decision).toBe('allow');
			const signerRevoked = await checkChainRevocation({
				...input,
				crls: [
					leafCrl.der,
					(
						await rootCrl([
							hexToBytes(unwrap(parseCertificateDer(crlSigner.certificate.der)).serialNumberHex),
						])
					).der,
				],
			});
			expect(signerRevoked.value.certificates[0]).toMatchObject({
				status: 'indeterminate',
				indeterminateReasons: expect.arrayContaining(['crl_signer_revoked']),
			});
		},
	);

	it('honors a responder trusted for the anchor certificate', async () => {
		const { trustAnchor, root, ca, chain, at, fresh, caCrl } = await createBareAnchorFixture();
		const responder = await createSelfSignedCertificate({
			subject: { commonName: 'Locally Trusted Responder' },
			extensions: { extendedKeyUsage: ['ocspSigning'] },
		});
		const response = await createOcspResponse({
			signerPrivateKey: responder.keyPair.privateKey,
			signerCertificate: responder.certificate.der,
			responses: [
				{
					certificate: ca.certificate.der,
					issuerCertificate: root.certificate.der,
					certStatus: 'good',
					...fresh,
				},
			],
		});
		const input = { chain, crls: [caCrl.der], ocspResponses: [response.der], at, trustAnchor };
		expect((await checkChainRevocation(input)).value.certificates[1]?.status).toBe('indeterminate');
		const trusted = await checkChainRevocation({
			...input,
			trustedOcspResponders: [
				{
					issuerCertificate: root.certificate.der,
					responderCertificate: responder.certificate.der,
				},
			],
		});
		expect(trusted.value.certificates[1]).toMatchObject({
			status: 'good',
			source: { kind: 'ocsp' },
		});
	});

	it('accepts an indirect CRL the anchor issues for a deeper certificate', async () => {
		const { trustAnchor, root, rootName, caName, ca, at, fresh, rootCrl } =
			await createBareAnchorFixture();
		const uri = 'http://example.test/bare-anchor-indirect.crl';
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: caName },
			subject: { commonName: 'bare-anchor-indirect.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerCertificate: ca.certificate.der,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: { type: 'fullName', fullName: [{ type: 'uri', value: uri }] },
						crlIssuer: [{ type: 'directoryName', derHex: trustAnchor.subject.derHex }],
					},
				],
			},
		});
		const indirectCrl = await createCertificateRevocationList({
			crlNumber: 2,
			issuer: { commonName: rootName },
			signerPrivateKey: root.keyPair.privateKey,
			issuerCertificate: root.certificate.der,
			thisUpdate: fresh.thisUpdate,
			nextUpdate: fresh.nextUpdate,
			issuingDistributionPoint: {
				distributionPoint: { type: 'fullName', fullName: [{ type: 'uri', value: uri }] },
				indirectCrl: true,
			},
		});
		const result = await checkChainRevocation({
			chain: [
				unwrap(parseCertificateDer(leaf.der)),
				unwrap(parseCertificateDer(ca.certificate.der)),
			],
			crls: [indirectCrl.der, (await rootCrl([])).der],
			at,
			trustAnchor,
		});
		expect(result.value.certificates[0]).toMatchObject({ status: 'good', source: { kind: 'crl' } });
		expect(result.value.decision).toBe('allow');
	});

	it('hashes the issuer name of the checked certificate into the CertID (RFC 6960 §4.1.1)', async () => {
		const { root, chain, at, caCrl, caOcsp } = await createBareAnchorFixture();
		const tbs = childAt(root.certificate.der, 0);
		const subject = sliceElement(tbs, fieldAt(tbs, 5));
		const [attribute] = constructedChildren(childAt(subject, 0));
		if (attribute === undefined) throw new Error('expected a subject attribute');
		const value = fieldAt(attribute, 1);
		const reencoded = sequence([
			tlv(
				0x31,
				sequence([childAt(attribute, 0), tlv(value.tag === 0x0c ? 0x13 : 0x0c, value.value)]),
			),
		]);
		const reencodedRoot = unwrap(
			parseCertificateDer(rewriteCertificateSubject(root.certificate.der, reencoded)),
		);
		const trustAnchor = trustAnchorFromCertificate(reencodedRoot);
		expect(trustAnchor.subject.derHex).not.toBe(chain[1]?.issuer.derHex);
		const result = await checkChainRevocation({
			chain,
			crls: [caCrl.der],
			ocspResponses: [(await caOcsp('good', 'root')).der],
			at,
			trustAnchor,
		});
		expect(result.value.certificates[1]).toMatchObject({
			status: 'good',
			source: { kind: 'ocsp' },
		});
	});

	it.each([
		{ problem: 'ends with the anchor certificate', withRoot: true, otherAnchor: false },
		{ problem: 'names another issuer', withRoot: false, otherAnchor: true },
	])('rejects a trustAnchor when the chain $problem', async ({ withRoot, otherAnchor }) => {
		const { trustAnchor, root, chain, at } = await createBareAnchorFixture();
		const other = otherAnchor
			? trustAnchorFromCertificate(
					unwrap(
						parseCertificateDer(
							(await createSelfSignedCertificate({ subject: { commonName: 'Unrelated Root' } }))
								.certificate.der,
						),
					),
				)
			: trustAnchor;
		await expectRejectedWith(
			checkChainRevocation({
				chain: withRoot ? [...chain, unwrap(parseCertificateDer(root.certificate.der))] : chain,
				at,
				trustAnchor: other,
			}),
			RangeError,
		);
	});

	it('leaves a self-signed leaf that is the anchor certificate out of revocation', async () => {
		const { trustAnchor, root, at } = await createBareAnchorFixture();
		expect(
			await verifyCertificateChain({
				leaf: root.certificate.der,
				roots: [],
				trustAnchors: [trustAnchor],
				allowSelfSignedLeaf: true,
				at,
				revocation: { policy: { mode: 'hard-fail' } },
			}),
		).toMatchObject({ ok: true, value: { anchorCertificateInChain: false, trustAnchor } });
	});
});
