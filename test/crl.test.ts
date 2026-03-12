import { describe, expect, it } from 'bun:test';
import {
	checkCertificateRevocationAgainstCrl,
	createCertificate,
	createCertificateRevocationList,
	createSelfSignedCertificate,
	generateKeyPair,
	isCertificateRevoked,
	parseCertificatePem,
	parseCertificateRevocationListDer,
	parseCertificateRevocationListPem,
	pemDecode,
	validateCertificateRevocationList,
	verifyCertificateRevocationList,
} from '#micro509';
import { addRevokedEntryCertificateIssuers, hexToBytes } from './helpers.ts';

describe('crl', () => {
	it('creates, parses, and verifies CRLs', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'CRL Issuer' },
			subject: { commonName: 'revoked.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const parsedLeaf = parseCertificatePem(leaf.pem);
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'CRL Issuer' },
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			crlNumber: 7,
			revokedCertificates: [{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) }],
		});
		const parsedCrl = parseCertificateRevocationListPem(crl.pem);
		expect(parsedCrl.issuer.commonName).toBe('CRL Issuer');
		expect(parsedCrl.crlNumber).toBe(7);
		expect(parsedCrl.revokedCertificates).toHaveLength(1);
		expect(isCertificateRevoked(parsedLeaf.serialNumberHex, parsedCrl)).toBe(true);
		expect(await verifyCertificateRevocationList(crl.pem, issuer.certificate.pem)).toMatchObject({
			ok: true,
		});

		const wrongSigner = await generateKeyPair();
		const badCrl = await createCertificateRevocationList({
			issuer: { commonName: 'CRL Issuer' },
			signerPrivateKey: wrongSigner.privateKey,
			revokedCertificates: [{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) }],
		});
		expect(await verifyCertificateRevocationList(badCrl.der, issuer.certificate.der)).toMatchObject(
			{
				ok: false,
				code: 'signature_invalid',
			},
		);
	});

	it('parses CRL entry extensions and delta CRL indicator', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Delta CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta CRL Issuer' },
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			crlNumber: 9,
			baseCrlNumber: 8,
			issuingDistributionPoint: {
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/idp.crl' }],
				},
				onlyContainsUserCerts: true,
				onlySomeReasons: ['keyCompromise', 'cessationOfOperation'],
				indirectCrl: true,
			},
			freshestCrlDistributionPoints: [
				{
					distributionPoint: {
						fullName: [{ type: 'uri', value: 'http://example.test/freshest.crl' }],
					},
				},
			],
			revokedCertificates: [
				{
					serialNumber: Uint8Array.of(0x01),
					reasonCode: 'keyCompromise',
					invalidityDate: new Date('2024-01-01T00:00:00Z'),
				},
			],
		});
		const parsed = parseCertificateRevocationListPem(crl.pem);
		expect(parsed.baseCrlNumber).toBe(8);
		expect(parsed.issuingDistributionPoint).toEqual({
			distributionPoint: {
				fullName: [{ type: 'uri', value: 'http://example.test/idp.crl' }],
			},
			onlyContainsUserCerts: true,
			onlySomeReasons: ['keyCompromise', 'cessationOfOperation'],
			indirectCrl: true,
		});
		expect(parsed.freshestCrlDistributionPoints).toEqual([
			{
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/freshest.crl' }],
				},
			},
		]);
		expect(parsed.revokedCertificates[0]).toMatchObject({
			serialNumberHex: '01',
			reasonCode: 'keyCompromise',
		});
		expect(parsed.revokedCertificates[0]?.invalidityDate?.toISOString()).toBe(
			'2024-01-01T00:00:00.000Z',
		);
	});

	it('parses structured issuing and freshest distribution points', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Structured CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Structured CRL Issuer' },
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					relativeName: [
						{ type: 'organizationalUnit', value: 'CRLs' },
						{ type: 'commonName', value: 'ca-scope' },
					],
				},
				onlyContainsCACerts: true,
				onlySomeReasons: ['cACompromise', 'superseded'],
			},
			freshestCrlDistributionPoints: [
				{
					distributionPoint: {
						fullName: [
							{ type: 'uri', value: 'http://example.test/delta.crl' },
							{ type: 'dns', value: 'delta.example.test' },
						],
					},
					reasons: ['cACompromise'],
					crlIssuer: [{ type: 'dns', value: 'delta-issuer.example.test' }],
				},
				{
					distributionPoint: {
						relativeName: [{ type: 'commonName', value: 'delta-relative' }],
					},
				},
			],
		});

		const parsed = parseCertificateRevocationListPem(crl.pem);
		expect(parsed.issuingDistributionPoint).toMatchObject({
			distributionPoint: {
				relativeName: {
					values: {
						organizationalUnit: 'CRLs',
						commonName: 'ca-scope',
					},
				},
			},
			onlyContainsCACerts: true,
			onlySomeReasons: ['cACompromise', 'superseded'],
		});
		expect(parsed.freshestCrlDistributionPoints).toHaveLength(2);
		expect(parsed.freshestCrlDistributionPoints?.[0]).toEqual({
			distributionPoint: {
				fullName: [
					{ type: 'uri', value: 'http://example.test/delta.crl' },
					{ type: 'dns', value: 'delta.example.test' },
				],
			},
			reasons: ['cACompromise'],
			crlIssuer: [{ type: 'dns', value: 'delta-issuer.example.test' }],
		});
		expect(parsed.freshestCrlDistributionPoints?.[1]).toMatchObject({
			distributionPoint: {
				relativeName: {
					values: { commonName: 'delta-relative' },
				},
			},
		});
	});

	it('roundtrips issuing distribution points without a named scope', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Scope Only CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Scope Only CRL Issuer' },
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			issuingDistributionPoint: {
				onlyContainsAttributeCerts: true,
				indirectCrl: true,
			},
		});

		const parsed = parseCertificateRevocationListPem(crl.pem);
		expect(parsed.issuingDistributionPoint).toEqual({
			onlyContainsAttributeCerts: true,
			indirectCrl: true,
		});
	});

	it('validates CRL with issuer linkage and freshness', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'CRL Validate CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const otherCa = await createSelfSignedCertificate({
			subject: { commonName: 'Other CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const now = new Date();
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'CRL Validate CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			thisUpdate: now,
			nextUpdate: new Date(now.getTime() + 3_600_000),
		});
		// Valid case
		const valid = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: ca.certificate.pem,
			at: now,
		});
		expect(valid.ok).toBe(true);
		// Wrong issuer
		const wrongIssuer = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: otherCa.certificate.pem,
			at: now,
		});
		expect(wrongIssuer.ok).toBe(false);
		if (!wrongIssuer.ok) {
			expect(wrongIssuer.code).toBe('issuer_mismatch');
		}
		// Stale CRL (well past nextUpdate)
		const stale = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: ca.certificate.pem,
			at: new Date(now.getTime() + 7_200_000),
		});
		expect(stale.ok).toBe(false);
		if (!stale.ok) {
			expect(stale.code).toBe('stale_crl');
		}
		// Barely stale CRL rescued by clock skew tolerance
		// Use 5s margin to avoid ASN.1 second-truncation races
		const staleWithSkew = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: ca.certificate.pem,
			at: new Date(now.getTime() + 3_605_000),
			clockSkewMs: 10_000,
		});
		expect(staleWithSkew.ok).toBe(true);
	});

	it('validates CRL with AKI mismatch', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'AKI CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const otherCa = await createSelfSignedCertificate({
			subject: { commonName: 'AKI CRL CA' }, // Same name, different key
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'AKI CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const result = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: otherCa.certificate.pem,
		});
		expect(result.ok).toBe(false);
	});

	it('checks CRL distribution-point applicability before revocation lookup', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Scoped CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Scoped CRL CA' },
			subject: { commonName: 'scoped.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							fullName: [{ type: 'uri', value: 'http://example.test/leaf.crl' }],
						},
					},
				],
			},
		});
		const parsedLeaf = parseCertificatePem(leaf.pem);
		const matchingCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Scoped CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/leaf.crl' }],
				},
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: matchingCrl.pem,
			}),
		).toMatchObject({ ok: true, status: 'good' });

		const mismatchedCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Scoped CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/other.crl' }],
				},
			},
			revokedCertificates: [{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) }],
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: parsedLeaf,
				issuerCertificate: ca.certificate.pem,
				crl: mismatchedCrl.pem,
			}),
		).toEqual({
			ok: false,
			code: 'non_applicable',
			message: 'certificate distribution points do not match the CRL issuing distribution point',
			details: { reason: 'distribution_point_mismatch' },
		});
	});

	it('checks CRL reason and certificate-type scope', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Reason Scope CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Reason Scope CA' },
			subject: { commonName: 'reason-leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							fullName: [{ type: 'uri', value: 'http://example.test/reasons.crl' }],
						},
						reasons: ['keyCompromise'],
					},
				],
			},
		});
		const parsedLeaf = parseCertificatePem(leaf.pem);
		const reasonMismatchCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Reason Scope CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/reasons.crl' }],
				},
				onlySomeReasons: ['cessationOfOperation'],
			},
			revokedCertificates: [{ serialNumber: hexToBytes(parsedLeaf.serialNumberHex) }],
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: parsedLeaf,
				issuerCertificate: ca.certificate.pem,
				crl: reasonMismatchCrl.pem,
			}),
		).toEqual({
			ok: false,
			code: 'non_applicable',
			message: 'certificate distribution point reasons do not overlap the CRL reason scope',
			details: { reason: 'reasons_mismatch' },
		});

		const caKeys = await generateKeyPair();
		const subordinateCa = await createCertificate({
			issuer: { commonName: 'Reason Scope CA' },
			subject: { commonName: 'Subordinate Reason CA' },
			publicKey: caKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
				crlDistributionPoints: [
					{
						distributionPoint: {
							fullName: [{ type: 'uri', value: 'http://example.test/ca-only.crl' }],
						},
					},
				],
			},
		});
		const caOnlyCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Reason Scope CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/ca-only.crl' }],
				},
				onlyContainsCACerts: true,
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: parsedLeaf,
				issuerCertificate: ca.certificate.pem,
				crl: caOnlyCrl.pem,
			}),
		).toEqual({
			ok: false,
			code: 'non_applicable',
			message: 'CRL only applies to CA certificates',
			details: { reason: 'certificate_scope_mismatch' },
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: subordinateCa.pem,
				issuerCertificate: ca.certificate.pem,
				crl: caOnlyCrl.pem,
			}),
		).toMatchObject({ ok: true, status: 'good' });
	});

	it('rejects direct CRLs with mismatched issuers and unsupported alternate CRL issuers', async () => {
		const certIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Certificate Issuer CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crlIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Different CRL Issuer CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Certificate Issuer CA' },
			subject: { commonName: 'issuer-mismatch.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: certIssuer.keyPair.privateKey,
			issuerPublicKey: certIssuer.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							fullName: [{ type: 'uri', value: 'http://example.test/direct.crl' }],
						},
					},
				],
			},
		});
		const mismatchedCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Different CRL Issuer CA' },
			signerPrivateKey: crlIssuer.keyPair.privateKey,
			issuerPublicKey: crlIssuer.keyPair.publicKey,
		});

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: crlIssuer.certificate.pem,
				crl: mismatchedCrl.pem,
			}),
		).toEqual({
			ok: false,
			code: 'non_applicable',
			message: 'CRL issuer does not match certificate issuer for direct CRL processing',
			details: { reason: 'issuer_mismatch' },
		});

		const alternateIssuerLeafKeys = await generateKeyPair();
		const alternateIssuerLeaf = await createCertificate({
			issuer: { commonName: 'Certificate Issuer CA' },
			subject: { commonName: 'alternate-crl-issuer.example' },
			publicKey: alternateIssuerLeafKeys.publicKey,
			signerPrivateKey: certIssuer.keyPair.privateKey,
			issuerPublicKey: certIssuer.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							fullName: [{ type: 'uri', value: 'http://example.test/direct.crl' }],
						},
						crlIssuer: [{ type: 'dns', value: 'alternate.example.test' }],
					},
				],
			},
		});
		const directCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Certificate Issuer CA' },
			signerPrivateKey: certIssuer.keyPair.privateKey,
			issuerPublicKey: certIssuer.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/direct.crl' }],
				},
			},
		});

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: alternateIssuerLeaf.pem,
				issuerCertificate: certIssuer.certificate.pem,
				crl: directCrl.pem,
			}),
		).toEqual({
			ok: false,
			code: 'non_applicable',
			message:
				'certificate distribution points that name alternate CRL issuers are not supported yet',
			details: { reason: 'indirect_crl_unsupported' },
		});
	});

	it('rejects attribute-only and end-entity-only CRL scopes when the certificate type mismatches', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Scope Mismatch CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 1 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Scope Mismatch CA' },
			subject: { commonName: 'attribute-only.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const subordinateCaKeys = await generateKeyPair();
		const subordinateCa = await createCertificate({
			issuer: { commonName: 'Scope Mismatch CA' },
			subject: { commonName: 'Scope Mismatch Subordinate CA' },
			publicKey: subordinateCaKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const attributeOnlyCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Scope Mismatch CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				onlyContainsAttributeCerts: true,
			},
		});
		const userOnlyCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Scope Mismatch CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				onlyContainsUserCerts: true,
			},
		});

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: attributeOnlyCrl.pem,
			}),
		).toEqual({
			ok: false,
			code: 'non_applicable',
			message: 'attribute-certificate-only CRLs are not applicable to public-key certificates',
			details: { reason: 'certificate_scope_mismatch' },
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: subordinateCa.pem,
				issuerCertificate: ca.certificate.pem,
				crl: userOnlyCrl.pem,
			}),
		).toEqual({
			ok: false,
			code: 'non_applicable',
			message: 'CRL only applies to end-entity certificates',
			details: { reason: 'certificate_scope_mismatch' },
		});
	});

	it('checks CRLs without certificate distribution points and signer permissions', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Full Scope CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Full Scope CRL CA' },
			subject: { commonName: 'full-scope.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const fullScopeCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Full Scope CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: fullScopeCrl.pem,
			}),
		).toMatchObject({ ok: true, status: 'good' });

		const reasonScopedCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Full Scope CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				onlySomeReasons: ['keyCompromise'],
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: reasonScopedCrl.pem,
			}),
		).toMatchObject({ ok: true, status: 'good' });

		const scopedCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Full Scope CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/scoped.crl' }],
				},
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: scopedCrl.pem,
			}),
		).toEqual({
			ok: false,
			code: 'non_applicable',
			message: 'certificates without CRL distribution points only accept full-scope CRLs',
			details: { reason: 'distribution_point_mismatch' },
		});

		const signerWithoutCrlSign = await createSelfSignedCertificate({
			subject: { commonName: 'No CRL Sign CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const noCrlSign = await createCertificateRevocationList({
			issuer: { commonName: 'No CRL Sign CA' },
			signerPrivateKey: signerWithoutCrlSign.keyPair.privateKey,
			issuerPublicKey: signerWithoutCrlSign.keyPair.publicKey,
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: signerWithoutCrlSign.certificate.pem,
				crl: noCrlSign.pem,
			}),
		).toEqual({
			ok: false,
			code: 'crl_sign_not_permitted',
			message: 'issuer certificate key usage does not permit CRL signing',
		});

		expect(
			await validateCertificateRevocationList({
				crl: noCrlSign.pem,
				issuerCertificate: signerWithoutCrlSign.certificate.pem,
			}),
		).toEqual({
			ok: false,
			code: 'crl_sign_not_permitted',
			message: 'issuer certificate key usage does not permit CRL signing',
		});
	});

	it('reports unsupported indirect and primary delta CRLs as non-applicable', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Unsupported CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Unsupported CRL CA' },
			subject: { commonName: 'unsupported.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							fullName: [{ type: 'uri', value: 'http://example.test/unsupported.crl' }],
						},
					},
				],
			},
		});
		const indirectCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Unsupported CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/unsupported.crl' }],
				},
				indirectCrl: true,
			},
			revokedCertificates: [
				{ serialNumber: hexToBytes(parseCertificatePem(leaf.pem).serialNumberHex) },
			],
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: indirectCrl.pem,
			}),
		).toMatchObject({
			ok: true,
			status: 'revoked',
		});

		const unsupportedNamedIssuerCrl = await addRevokedEntryCertificateIssuers(
			indirectCrl.der,
			ca.keyPair.privateKey,
			[
				{
					entryIndex: 0,
					names: [{ type: 'dns', value: 'unsupported.example.test' }],
				},
			],
		);
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: unsupportedNamedIssuerCrl,
			}),
		).toEqual({
			ok: false,
			code: 'non_applicable',
			message: 'indirect CRL entry certificateIssuer must include a directoryName',
			details: { reason: 'indirect_crl_unsupported' },
		});

		const deltaCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Unsupported CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			baseCrlNumber: 1,
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: deltaCrl.pem,
			}),
		).toEqual({
			ok: false,
			code: 'non_applicable',
			message: 'delta CRLs are not applicable until delta merge support is implemented',
			details: { reason: 'delta_crl_unsupported' },
		});
	});

	it('merges delta CRL revocation entries over the complete CRL view', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Delta Merge CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Delta Merge CA' },
			subject: { commonName: 'delta-merge.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const parsedLeaf = parseCertificatePem(leaf.pem);
		const completeCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Merge CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 5,
		});
		const deltaCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Merge CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 6,
			baseCrlNumber: 5,
			revokedCertificates: [
				{
					serialNumber: hexToBytes(parsedLeaf.serialNumberHex),
					reasonCode: 'keyCompromise',
				},
			],
		});

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: completeCrl.pem,
				deltaCrl: deltaCrl.pem,
			}),
		).toMatchObject({
			ok: true,
			status: 'revoked',
			reasonCode: 'keyCompromise',
			value: { crlNumber: 5 },
		});
	});

	it('uses removeFromCRL only to clear certificateHold entries from the complete CRL', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Delta Remove CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const heldLeafKeys = await generateKeyPair();
		const heldLeaf = await createCertificate({
			issuer: { commonName: 'Delta Remove CA' },
			subject: { commonName: 'delta-held.example' },
			publicKey: heldLeafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const compromisedLeafKeys = await generateKeyPair();
		const compromisedLeaf = await createCertificate({
			issuer: { commonName: 'Delta Remove CA' },
			subject: { commonName: 'delta-compromised.example' },
			publicKey: compromisedLeafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const expiredLeafKeys = await generateKeyPair();
		const expiredLeaf = await createCertificate({
			issuer: { commonName: 'Delta Remove CA' },
			subject: { commonName: 'delta-expired.example' },
			publicKey: expiredLeafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			validity: {
				notBefore: new Date('2025-01-01T00:00:00Z'),
				notAfter: new Date('2025-01-02T00:00:00Z'),
			},
		});
		const parsedHeldLeaf = parseCertificatePem(heldLeaf.pem);
		const parsedCompromisedLeaf = parseCertificatePem(compromisedLeaf.pem);
		const parsedExpiredLeaf = parseCertificatePem(expiredLeaf.pem);
		const completeCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Remove CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 10,
			thisUpdate: new Date('2025-01-01T00:00:00Z'),
			nextUpdate: new Date('2025-01-10T00:00:00Z'),
			revokedCertificates: [
				{
					serialNumber: hexToBytes(parsedHeldLeaf.serialNumberHex),
					reasonCode: 'certificateHold',
				},
				{
					serialNumber: hexToBytes(parsedCompromisedLeaf.serialNumberHex),
					reasonCode: 'keyCompromise',
				},
				{
					serialNumber: hexToBytes(parsedExpiredLeaf.serialNumberHex),
					reasonCode: 'keyCompromise',
				},
			],
		});
		const deltaCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Remove CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 11,
			baseCrlNumber: 10,
			thisUpdate: new Date('2025-01-02T00:00:00Z'),
			nextUpdate: new Date('2025-01-10T00:00:00Z'),
			revokedCertificates: [
				{
					serialNumber: hexToBytes(parsedHeldLeaf.serialNumberHex),
					reasonCode: 'removeFromCRL',
				},
				{
					serialNumber: hexToBytes(parsedCompromisedLeaf.serialNumberHex),
					reasonCode: 'removeFromCRL',
				},
				{
					serialNumber: hexToBytes(parsedExpiredLeaf.serialNumberHex),
					reasonCode: 'removeFromCRL',
				},
			],
		});

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: heldLeaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: completeCrl.pem,
				deltaCrl: deltaCrl.pem,
				at: new Date('2025-01-03T00:00:00Z'),
			}),
		).toMatchObject({
			ok: true,
			status: 'good',
			value: { crlNumber: 10 },
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: compromisedLeaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: completeCrl.pem,
				deltaCrl: deltaCrl.pem,
				at: new Date('2025-01-03T00:00:00Z'),
			}),
		).toMatchObject({
			ok: true,
			status: 'revoked',
			reasonCode: 'keyCompromise',
			value: { crlNumber: 10 },
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: expiredLeaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: completeCrl.pem,
				deltaCrl: deltaCrl.pem,
				at: new Date('2025-01-03T00:00:00Z'),
			}),
		).toMatchObject({
			ok: true,
			status: 'good',
			value: { crlNumber: 10 },
		});
	});

	it('rejects stale delta CRLs during merge processing', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Delta Freshness CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Delta Freshness CA' },
			subject: { commonName: 'delta-freshness.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const now = new Date('2026-03-12T12:00:00Z');
		const completeCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Freshness CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 2,
			thisUpdate: new Date('2026-03-12T10:00:00Z'),
			nextUpdate: new Date('2026-03-12T14:00:00Z'),
		});
		const deltaCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Freshness CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 3,
			baseCrlNumber: 2,
			thisUpdate: new Date('2026-03-12T08:00:00Z'),
			nextUpdate: new Date('2026-03-12T09:00:00Z'),
		});

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: completeCrl.pem,
				deltaCrl: deltaCrl.pem,
				at: now,
			}),
		).toEqual({
			ok: false,
			code: 'stale_crl',
			message: 'CRL is not valid at requested time',
		});
	});

	it('rejects delta CRLs whose scope drifts from the complete CRL', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Delta Scope CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Delta Scope CA' },
			subject: { commonName: 'delta-scope.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							fullName: [{ type: 'uri', value: 'http://example.test/delta-scope-a.crl' }],
						},
					},
				],
			},
		});
		const completeCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Scope CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 7,
			issuingDistributionPoint: {
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/delta-scope-a.crl' }],
				},
			},
		});
		const deltaCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Scope CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 8,
			baseCrlNumber: 7,
			issuingDistributionPoint: {
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/delta-scope-b.crl' }],
				},
			},
		});

		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: completeCrl.pem,
				deltaCrl: deltaCrl.pem,
			}),
		).toEqual({
			ok: false,
			code: 'non_applicable',
			message: 'complete and delta CRLs must share the same issuing distribution point scope',
			details: { reason: 'delta_crl_incompatible' },
		});
	});

	it('rejects incompatible delta CRL number combinations', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Delta Compatibility CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Delta Compatibility CA' },
			subject: { commonName: 'delta-compat.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});

		const completeDelta = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Compatibility CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 8,
			baseCrlNumber: 7,
		});
		const normalDelta = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Compatibility CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 9,
			baseCrlNumber: 8,
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: completeDelta.pem,
				deltaCrl: normalDelta.pem,
			}),
		).toEqual({
			ok: false,
			code: 'non_applicable',
			message: 'complete CRL input must not itself be a delta CRL',
			details: { reason: 'delta_crl_incompatible' },
		});

		const complete = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Compatibility CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 8,
		});
		const missingIndicatorDelta = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Compatibility CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 9,
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: complete.pem,
				deltaCrl: missingIndicatorDelta.pem,
			}),
		).toEqual({
			ok: false,
			code: 'non_applicable',
			message: 'delta CRL input must include a delta CRL indicator',
			details: { reason: 'delta_crl_incompatible' },
		});

		const tooNewBaseDelta = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Compatibility CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 10,
			baseCrlNumber: 9,
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: complete.pem,
				deltaCrl: tooNewBaseDelta.pem,
			}),
		).toEqual({
			ok: false,
			code: 'non_applicable',
			message: 'delta CRL base number must not exceed the complete CRL number',
			details: { reason: 'delta_crl_incompatible' },
		});

		const notNewerDelta = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Compatibility CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 8,
			baseCrlNumber: 8,
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: ca.certificate.pem,
				crl: complete.pem,
				deltaCrl: notNewerDelta.pem,
			}),
		).toEqual({
			ok: false,
			code: 'non_applicable',
			message: 'delta CRL number must be newer than the complete CRL number',
			details: { reason: 'delta_crl_incompatible' },
		});
	});

	it('parses revoked entry certificateIssuer extensions', async () => {
		const crlIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Revoked Entry Parser CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const certificateIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Revoked Entry Leaf CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const parsedCertificateIssuer = parseCertificatePem(certificateIssuer.certificate.pem);
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Revoked Entry Parser CA' },
			signerPrivateKey: crlIssuer.keyPair.privateKey,
			issuerPublicKey: crlIssuer.keyPair.publicKey,
			revokedCertificates: [{ serialNumber: Uint8Array.of(0x01) }],
		});
		const modifiedDer = await addRevokedEntryCertificateIssuers(
			crl.der,
			crlIssuer.keyPair.privateKey,
			[
				{
					entryIndex: 0,
					names: [{ type: 'directoryName', derHex: parsedCertificateIssuer.subject.derHex }],
				},
			],
		);
		expect(
			parseCertificateRevocationListDer(modifiedDer).revokedCertificates[0]?.certificateIssuer,
		).toEqual([{ type: 'directoryName', derHex: parsedCertificateIssuer.subject.derHex }]);
	});

	it('checks indirect CRL issuer selection and carried certificateIssuer entries', async () => {
		const crlIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Indirect CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const firstIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Indirect Leaf Issuer A' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const secondIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Indirect Leaf Issuer B' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const parsedCrlIssuer = parseCertificatePem(crlIssuer.certificate.pem);
		const parsedFirstIssuer = parseCertificatePem(firstIssuer.certificate.pem);
		const sharedSerial = Uint8Array.of(0x44);
		const firstLeafKeys = await generateKeyPair();
		const secondLeafKeys = await generateKeyPair();
		const distributionPoints = [
			{
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/indirect.crl' }],
				},
				crlIssuer: [{ type: 'directoryName', derHex: parsedCrlIssuer.subject.derHex }],
			},
		] as const;
		const firstLeaf = await createCertificate({
			issuer: { commonName: 'Indirect Leaf Issuer A' },
			subject: { commonName: 'indirect-a.example' },
			publicKey: firstLeafKeys.publicKey,
			signerPrivateKey: firstIssuer.keyPair.privateKey,
			issuerPublicKey: firstIssuer.keyPair.publicKey,
			serialNumber: sharedSerial,
			extensions: { crlDistributionPoints: distributionPoints },
		});
		const secondLeaf = await createCertificate({
			issuer: { commonName: 'Indirect Leaf Issuer B' },
			subject: { commonName: 'indirect-b.example' },
			publicKey: secondLeafKeys.publicKey,
			signerPrivateKey: secondIssuer.keyPair.privateKey,
			issuerPublicKey: secondIssuer.keyPair.publicKey,
			serialNumber: sharedSerial,
			extensions: { crlDistributionPoints: distributionPoints },
		});
		const baseCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Indirect CRL Issuer' },
			signerPrivateKey: crlIssuer.keyPair.privateKey,
			issuerPublicKey: crlIssuer.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/indirect.crl' }],
				},
				indirectCrl: true,
			},
			revokedCertificates: [
				{ serialNumber: Uint8Array.of(0x01) },
				{ serialNumber: sharedSerial, reasonCode: 'keyCompromise' },
			],
		});
		const indirectCrlDer = await addRevokedEntryCertificateIssuers(
			baseCrl.der,
			crlIssuer.keyPair.privateKey,
			[
				{
					entryIndex: 0,
					names: [{ type: 'directoryName', derHex: parsedFirstIssuer.subject.derHex }],
				},
			],
		);
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: firstLeaf.pem,
				issuerCertificate: crlIssuer.certificate.pem,
				crl: indirectCrlDer,
			}),
		).toMatchObject({ ok: true, status: 'revoked', reasonCode: 'keyCompromise' });
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: secondLeaf.pem,
				issuerCertificate: crlIssuer.certificate.pem,
				crl: indirectCrlDer,
			}),
		).toMatchObject({ ok: true, status: 'good' });
	});

	it('rejects indirect CRLs without matching cRLIssuer distribution points', async () => {
		const crlIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Indirect Applicability CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const certificateIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Indirect Applicability Leaf Issuer' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Indirect Applicability Leaf Issuer' },
			subject: { commonName: 'indirect-applicability.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: certificateIssuer.keyPair.privateKey,
			issuerPublicKey: certificateIssuer.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							fullName: [{ type: 'uri', value: 'http://example.test/indirect-applicability.crl' }],
						},
					},
				],
			},
		});
		const indirectCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Indirect Applicability CRL Issuer' },
			signerPrivateKey: crlIssuer.keyPair.privateKey,
			issuerPublicKey: crlIssuer.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/indirect-applicability.crl' }],
				},
				indirectCrl: true,
			},
		});
		expect(
			await checkCertificateRevocationAgainstCrl({
				certificate: leaf.pem,
				issuerCertificate: crlIssuer.certificate.pem,
				crl: indirectCrl.pem,
			}),
		).toEqual({
			ok: false,
			code: 'non_applicable',
			message: 'certificate distribution points do not authorize this indirect CRL issuer',
			details: { reason: 'issuer_mismatch' },
		});
	});

	it('creates CRL with all revocation reason codes', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Reason CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const reasons = [
			'unspecified',
			'keyCompromise',
			'cACompromise',
			'affiliationChanged',
			'superseded',
			'cessationOfOperation',
			'certificateHold',
			'removeFromCRL',
			'privilegeWithdrawn',
			'aACompromise',
		] as const;
		const revokedCerts = reasons.map((reason, index) => ({
			serialNumber: Uint8Array.of(index + 1),
			reasonCode: reason,
		}));
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Reason CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			revokedCertificates: revokedCerts,
		});
		const parsed = parseCertificateRevocationListPem(crl.pem);
		expect(parsed.revokedCertificates).toHaveLength(reasons.length);
		for (let i = 0; i < reasons.length; i++) {
			expect(parsed.revokedCertificates[i]?.reasonCode).toBe(reasons[i]);
		}
	});

	it('validates CRL with DER sources', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'DER CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const now = new Date();
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'DER CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			thisUpdate: now,
			nextUpdate: new Date(now.getTime() + 3_600_000),
		});
		const caDer = new Uint8Array(pemDecode('CERTIFICATE', ca.certificate.pem));
		// Use DER for both CRL and issuer
		const result = await validateCertificateRevocationList({
			crl: crl.der,
			issuerCertificate: caDer,
			at: now,
		});
		expect(result.ok).toBe(true);
	});

	it('validates CRL with pre-parsed sources', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Parsed CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const now = new Date();
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Parsed CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			thisUpdate: now,
			nextUpdate: new Date(now.getTime() + 3_600_000),
		});
		const parsedCrl = parseCertificateRevocationListPem(crl.pem);
		const parsedCa = parseCertificatePem(ca.certificate.pem);
		const result = await validateCertificateRevocationList({
			crl: parsedCrl,
			issuerCertificate: parsedCa,
			at: now,
		});
		expect(result.ok).toBe(true);
	});

	it('verifyCertificateRevocationList rejects CRL signed by wrong key', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const otherCa = await createSelfSignedCertificate({
			subject: { commonName: 'CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		// Sign CRL with ca but verify with otherCa (same subject, different key)
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const result = await verifyCertificateRevocationList(crl.pem, otherCa.certificate.pem);
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('signature_invalid');
	});

	it('validateCertificateRevocationList rejects signature with wrong key', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'CRL Validate CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const otherCa = await createSelfSignedCertificate({
			subject: { commonName: 'CRL Validate CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		// Create CRL without AKI to bypass AKI check, signed by ca
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'CRL Validate CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			// omit issuerPublicKey → no AKI extension
		});
		const result = await validateCertificateRevocationList({
			crl: crl.pem,
			issuerCertificate: otherCa.certificate.pem,
		});
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.code).toBe('signature_invalid');
	});

	it('rejects empty issuing distribution point fullName values', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Bad Scope CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});

		expect(
			createCertificateRevocationList({
				issuer: { commonName: 'Bad Scope CRL Issuer' },
				signerPrivateKey: issuer.keyPair.privateKey,
				issuerPublicKey: issuer.keyPair.publicKey,
				issuingDistributionPoint: {
					distributionPoint: {
						fullName: [],
					},
				},
			}),
		).rejects.toThrow('DistributionPointName fullName must not be empty');
	});

	it('rejects empty freshest CRL issuer lists', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Bad Freshest CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});

		expect(
			createCertificateRevocationList({
				issuer: { commonName: 'Bad Freshest CRL Issuer' },
				signerPrivateKey: issuer.keyPair.privateKey,
				issuerPublicKey: issuer.keyPair.publicKey,
				freshestCrlDistributionPoints: [{ crlIssuer: [] }],
			}),
		).rejects.toThrow('DistributionPoint crlIssuer must not be empty');
	});

	it('verifies CRL with PEM string sources', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'PEM CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'PEM CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const result = await verifyCertificateRevocationList(crl.pem, ca.certificate.pem);
		expect(result.ok).toBe(true);
	});

	it('parseCertificateRevocationListDer handles IDP with no dist point name (lines 586-587)', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'IDP CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		// Create CRL with IDP extension
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'IDP CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://crl.example.com/crl.pem' }],
				},
			},
		});
		const derBytes = new Uint8Array(pemDecode('X509 CRL', crl.pem));
		// Find the IDP OID bytes (2.5.29.28 = 55 1D 1C) in the CRL DER
		const idpOidBytes = [0x55, 0x1d, 0x1c];
		let idpOffset = -1;
		for (let i = 0; i < derBytes.length - 3; i++) {
			if (
				derBytes[i] === idpOidBytes[0] &&
				derBytes[i + 1] === idpOidBytes[1] &&
				derBytes[i + 2] === idpOidBytes[2]
			) {
				idpOffset = i;
				break;
			}
		}
		expect(idpOffset).not.toBe(-1);
		// Inside the IDP SEQUENCE, the distributionPoint is tagged [0] (0xa0).
		// Find all 0xa0 bytes after the IDP OID. The inner one (inside OCTET STRING > SEQUENCE)
		// is the distributionPoint. Change it to 0x81 (onlyContainsUserCerts [1]).
		// Structure: OID, [BOOL critical], OCTET STRING { SEQUENCE { [0] distributionPoint { ... } } }
		// The first 0xa0 after OID is the outer extension wrapper — we need the one inside SEQUENCE.
		// Count 0xa0 occurrences after OID: skip the first one (or two) and modify the deepest.
		let count = 0;
		let targetOffset = -1;
		for (let i = idpOffset + 3; i < derBytes.length; i++) {
			if (derBytes[i] === 0xa0) {
				count++;
				targetOffset = i;
				// The IDP SEQUENCE contains [0] as distributionPoint — it's nested inside
				// outer wrappers. The deepest [0] within ~30 bytes is the one we want.
				if (count >= 2) break; // second 0xa0 after OID is the inner one
			}
		}
		if (targetOffset !== -1) {
			// Change [0] to [1] (onlyContainsUserCerts) — tag 0xa0 → 0x81
			derBytes[targetOffset] = 0x81;
			const modified = parseCertificateRevocationListDer(derBytes);
			expect(modified.issuingDistributionPoint).toEqual({});
		}
	});

	it('parseCertificateRevocationListDer handles AKI with no keyIdentifier (lines 680-682)', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'AKI CRL CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'AKI CRL CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
		});
		const derBytes = new Uint8Array(pemDecode('X509 CRL', crl.pem));
		// Find AKI OID bytes (2.5.29.35 = 55 1D 23)
		const akiOidBytes = [0x55, 0x1d, 0x23];
		let akiOffset = -1;
		for (let i = 0; i < derBytes.length - 3; i++) {
			if (
				derBytes[i] === akiOidBytes[0] &&
				derBytes[i + 1] === akiOidBytes[1] &&
				derBytes[i + 2] === akiOidBytes[2]
			) {
				akiOffset = i;
				break;
			}
		}
		expect(akiOffset).not.toBe(-1);
		// Find the 0x80 tag (keyIdentifier [0]) after AKI OID and change to 0x82
		// (authorityCertSerialNumber [2]) — which is not 0x80 or 0xa0
		let tagOffset = akiOffset + 3;
		while (tagOffset < derBytes.length && derBytes[tagOffset] !== 0x80) {
			tagOffset++;
		}
		if (tagOffset < derBytes.length) {
			derBytes[tagOffset] = 0x82; // Change keyIdentifier [0] to serialNumber [2]
		}
		const parsed = parseCertificateRevocationListDer(derBytes);
		// AKI was parsed but without keyIdentifier → authorityKeyIdentifier should be undefined
		expect(parsed.authorityKeyIdentifier).toBeUndefined();
	});
});
