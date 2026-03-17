import { describe, expect, it } from 'bun:test';
import {
	checkCertificateRevocation,
	createCertificate,
	createCertificateRevocationList,
	createOcspResponse,
	createSelfSignedCertificate,
	generateKeyPair,
	getCertificateOcspResponderUris,
	parseCertificatePem,
	resolveOcspResponderCandidates,
} from 'micro509';
import { addRevokedEntryCertificateIssuers, hexToBytes, issueChain } from './helpers.ts';

describe('revocation boundary', () => {
	it('returns unknown when no revocation evidence is provided', async () => {
		const { leaf, intermediate } = await issueChain();
		const certificate = parseCertificatePem(leaf.pem);
		const issuerCertificate = parseCertificatePem(intermediate.pem);

		expect(
			await checkCertificateRevocation({
				certificate,
				issuerCertificate,
			}),
		).toEqual({
			ok: true,
			value: {
				status: 'unknown',
				code: 'revocation_evidence_missing',
				message: 'No CRL or OCSP evidence provided',
				details: {
					checkedSources: [],
					indeterminateEvidence: [],
				},
			},
		});
	});

	it('fails closed for malformed certificate input', async () => {
		const { intermediate } = await issueChain();
		const result = await checkCertificateRevocation({
			certificate: Uint8Array.of(0xff, 0xff),
			issuerCertificate: intermediate.pem,
			evidence: [{ kind: 'crl', crl: intermediate.pem }],
		});
		expect(result).toMatchObject({
			ok: true,
			value: {
				status: 'unknown',
				code: 'revocation_status_unknown',
				message: 'Certificate input is malformed',
			},
		});
	});

	it('still reports missing evidence before parsing malformed certificate input', async () => {
		const { intermediate } = await issueChain();
		const result = await checkCertificateRevocation({
			certificate: Uint8Array.of(0xff, 0xff),
			issuerCertificate: intermediate.pem,
			evidence: [],
		});
		expect(result).toMatchObject({
			ok: true,
			value: {
				status: 'unknown',
				code: 'revocation_evidence_missing',
			},
		});
	});

	it('returns revoked when CRL evidence revokes the certificate', async () => {
		const { leaf, intermediate, intermediateKeys } = await issueChain();
		const certificate = parseCertificatePem(leaf.pem);
		const issuerCertificate = parseCertificatePem(intermediate.pem);
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Verify Intermediate CA' },
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			revokedCertificates: [
				{
					serialNumber: hexToBytes(certificate.serialNumberHex),
					reasonCode: 'keyCompromise',
				},
			],
		});

		expect(
			await checkCertificateRevocation({
				certificate,
				issuerCertificate,
				evidence: [
					{
						kind: 'crl',
						crl: crl.pem,
					},
				],
			}),
		).toMatchObject({
			ok: true,
			value: {
				status: 'revoked',
				source: 'crl',
				revocationReason: 'keyCompromise',
			},
		});
	});

	it('returns good when CRL evidence conclusively clears the certificate', async () => {
		const { leaf, intermediate, intermediateKeys } = await issueChain();
		const certificate = parseCertificatePem(leaf.pem);
		const issuerCertificate = parseCertificatePem(intermediate.pem);
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Verify Intermediate CA' },
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			revokedCertificates: [{ serialNumber: Uint8Array.of(0x7f) }],
		});

		expect(
			await checkCertificateRevocation({
				certificate,
				issuerCertificate,
				evidence: [{ kind: 'crl', crl: crl.pem }],
			}),
		).toEqual({
			ok: true,
			value: {
				status: 'good',
				source: 'crl',
				message: 'Certificate is not revoked according to CRL evidence',
			},
		});
	});

	it('returns revoked when a matching scoped complete CRL covers the certificate', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Scoped Revocation CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Scoped Revocation CA' },
			subject: { commonName: 'scoped-revoked.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							fullName: [{ type: 'uri', value: 'http://example.test/revocation-scoped.crl' }],
						},
					},
				],
			},
		});
		const certificate = parseCertificatePem(leaf.pem);
		const crl = await createCertificateRevocationList({
			issuer: { commonName: 'Scoped Revocation CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/revocation-scoped.crl' }],
				},
			},
			revokedCertificates: [
				{
					serialNumber: hexToBytes(certificate.serialNumberHex),
					reasonCode: 'keyCompromise',
				},
			],
		});

		expect(
			await checkCertificateRevocation({
				certificate,
				issuerCertificate: ca.certificate.pem,
				evidence: [{ kind: 'crl', crl: crl.pem }],
			}),
		).toMatchObject({
			ok: true,
			value: {
				status: 'revoked',
				source: 'crl',
				revocationReason: 'keyCompromise',
			},
		});
	});

	it('returns revoked when delta CRL evidence overlays the complete CRL', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Delta Revocation CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Delta Revocation CA' },
			subject: { commonName: 'delta-revoked.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							fullName: [{ type: 'uri', value: 'http://example.test/delta-revocation.crl' }],
						},
					},
				],
			},
		});
		const certificate = parseCertificatePem(leaf.pem);
		const completeCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Revocation CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 4,
			issuingDistributionPoint: {
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/delta-revocation.crl' }],
				},
			},
		});
		const deltaCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Delta Revocation CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			crlNumber: 5,
			baseCrlNumber: 4,
			issuingDistributionPoint: {
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/delta-revocation.crl' }],
				},
			},
			revokedCertificates: [
				{
					serialNumber: hexToBytes(certificate.serialNumberHex),
					reasonCode: 'cessationOfOperation',
				},
			],
		});

		expect(
			await checkCertificateRevocation({
				certificate,
				issuerCertificate: ca.certificate.pem,
				evidence: [{ kind: 'crl', crl: completeCrl.pem, deltaCrl: deltaCrl.pem }],
			}),
		).toMatchObject({
			ok: true,
			value: {
				status: 'revoked',
				source: 'crl',
				revocationReason: 'cessationOfOperation',
			},
		});
	});

	it('returns revoked when indirect CRL evidence names the certificate issuer', async () => {
		const crlIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Indirect Revocation CRL Issuer' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const certificateIssuer = await createSelfSignedCertificate({
			subject: { commonName: 'Indirect Revocation Leaf Issuer' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const parsedCrlIssuer = parseCertificatePem(crlIssuer.certificate.pem);
		const parsedCertificateIssuer = parseCertificatePem(certificateIssuer.certificate.pem);
		const leafKeys = await generateKeyPair();
		const serialNumber = Uint8Array.of(0x44);
		const leaf = await createCertificate({
			issuer: { commonName: 'Indirect Revocation Leaf Issuer' },
			subject: { commonName: 'indirect-revoked.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: certificateIssuer.keyPair.privateKey,
			issuerPublicKey: certificateIssuer.keyPair.publicKey,
			serialNumber,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							fullName: [{ type: 'uri', value: 'http://example.test/indirect-revocation.crl' }],
						},
						crlIssuer: [{ type: 'directoryName', derHex: parsedCrlIssuer.subject.derHex }],
					},
				],
			},
		});
		const baseCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Indirect Revocation CRL Issuer' },
			signerPrivateKey: crlIssuer.keyPair.privateKey,
			issuerPublicKey: crlIssuer.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/indirect-revocation.crl' }],
				},
				indirectCrl: true,
			},
			revokedCertificates: [{ serialNumber, reasonCode: 'keyCompromise' }],
		});
		const indirectCrl = await addRevokedEntryCertificateIssuers(
			baseCrl.der,
			crlIssuer.keyPair.privateKey,
			[
				{
					entryIndex: 0,
					names: [{ type: 'directoryName', derHex: parsedCertificateIssuer.subject.derHex }],
				},
			],
		);

		expect(
			await checkCertificateRevocation({
				certificate: leaf.pem,
				issuerCertificate: crlIssuer.certificate.pem,
				evidence: [{ kind: 'crl', crl: indirectCrl }],
			}),
		).toMatchObject({
			ok: true,
			value: {
				status: 'revoked',
				source: 'crl',
				revocationReason: 'keyCompromise',
			},
		});
	});

	it('returns unknown when scoped CRL evidence does not match certificate distribution points', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Scope Mismatch CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Scope Mismatch CA' },
			subject: { commonName: 'scope-mismatch.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							fullName: [{ type: 'uri', value: 'http://example.test/scope-a.crl' }],
						},
					},
				],
			},
		});
		const certificate = parseCertificatePem(leaf.pem);
		const mismatchedCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Scope Mismatch CA' },
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			issuingDistributionPoint: {
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://example.test/scope-b.crl' }],
				},
			},
			revokedCertificates: [{ serialNumber: hexToBytes(certificate.serialNumberHex) }],
		});

		expect(
			await checkCertificateRevocation({
				certificate,
				issuerCertificate: ca.certificate.pem,
				evidence: [{ kind: 'crl', crl: mismatchedCrl.pem }],
			}),
		).toEqual({
			ok: true,
			value: {
				status: 'unknown',
				code: 'revocation_status_unknown',
				message: 'No revocation evidence established certificate status',
				details: {
					checkedSources: ['crl'],
					indeterminateEvidence: [
						{
							source: 'crl',
							code: 'non_applicable',
							message:
								'certificate distribution points do not match the CRL issuing distribution point',
							reason: 'distribution_point_mismatch',
						},
					],
				},
			},
		});
	});

	it('returns good when OCSP evidence is conclusive and CRL evidence is non-applicable', async () => {
		const { leaf, intermediate, intermediateKeys } = await issueChain();
		const certificate = parseCertificatePem(leaf.pem);
		const issuerCertificate = parseCertificatePem(intermediate.pem);
		const nonApplicableCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Verify Intermediate CA' },
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			issuingDistributionPoint: {
				onlyContainsCACerts: true,
			},
		});
		const ocspResponse = await createOcspResponse({
			signerPrivateKey: intermediateKeys.privateKey,
			signerCertificate: intermediate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: intermediate.pem,
					certStatus: 'good',
				},
			],
		});

		expect(
			await checkCertificateRevocation({
				certificate,
				issuerCertificate,
				evidence: [
					{
						kind: 'crl',
						crl: nonApplicableCrl.pem,
					},
					{
						kind: 'ocsp',
						response: ocspResponse.pem,
					},
				],
			}),
		).toEqual({
			ok: true,
			value: {
				status: 'good',
				source: 'ocsp',
				message: 'Certificate is not revoked according to OCSP evidence',
			},
		});
	});

	it('returns revoked when OCSP evidence revokes the certificate', async () => {
		const { leaf, intermediate, intermediateKeys } = await issueChain();
		const certificate = parseCertificatePem(leaf.pem);
		const issuerCertificate = parseCertificatePem(intermediate.pem);
		const revokedAt = new Date('2024-02-01T00:00:00Z');
		const ocspResponse = await createOcspResponse({
			signerPrivateKey: intermediateKeys.privateKey,
			signerCertificate: intermediate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: intermediate.pem,
					certStatus: 'revoked',
					revokedAt,
					revocationReasonCode: 1,
				},
			],
		});

		expect(
			await checkCertificateRevocation({
				certificate,
				issuerCertificate,
				evidence: [{ kind: 'ocsp', response: ocspResponse.pem }],
			}),
		).toMatchObject({
			ok: true,
			value: {
				status: 'revoked',
				source: 'ocsp',
				revocationReasonCode: 1,
				revokedAt,
			},
		});
	});

	it('returns unknown when OCSP validation itself fails', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Revocation OCSP Issuer' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const responderKeys = await generateKeyPair();
		const responder = await createCertificate({
			issuer: { commonName: 'Revocation OCSP Issuer' },
			subject: { commonName: 'Responder Without EKU' },
			publicKey: responderKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Revocation OCSP Issuer' },
			subject: { commonName: 'ocsp-invalid.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
		});
		const ocspResponse = await createOcspResponse({
			signerPrivateKey: responderKeys.privateKey,
			signerCertificate: responder.pem,
			includedCertificates: [responder.pem],
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: issuer.certificate.pem,
					certStatus: 'good',
				},
			],
		});

		expect(
			await checkCertificateRevocation({
				certificate: parseCertificatePem(leaf.pem),
				issuerCertificate: parseCertificatePem(issuer.certificate.pem),
				evidence: [{ kind: 'ocsp', response: ocspResponse.pem }],
			}),
		).toEqual({
			ok: true,
			value: {
				status: 'unknown',
				code: 'revocation_status_unknown',
				message: 'No revocation evidence established certificate status',
				details: {
					checkedSources: ['ocsp'],
					indeterminateEvidence: [
						{
							source: 'ocsp',
							code: 'ocsp_signing_missing',
							message: 'Delegated OCSP responder lacks ocspSigning EKU',
						},
					],
				},
			},
		});
	});

	it('returns unknown when OCSP response omits the target certificate status', async () => {
		const { leaf, intermediate, intermediateKeys } = await issueChain();
		const otherLeafKeys = await generateKeyPair();
		const otherLeaf = await createCertificate({
			issuer: { commonName: 'Verify Intermediate CA' },
			subject: { commonName: 'other-ocsp-status.example' },
			publicKey: otherLeafKeys.publicKey,
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
		});
		const ocspResponse = await createOcspResponse({
			signerPrivateKey: intermediateKeys.privateKey,
			signerCertificate: intermediate.pem,
			responses: [
				{
					certificate: otherLeaf.pem,
					issuerCertificate: intermediate.pem,
					certStatus: 'good',
				},
			],
		});

		expect(
			await checkCertificateRevocation({
				certificate: parseCertificatePem(leaf.pem),
				issuerCertificate: parseCertificatePem(intermediate.pem),
				evidence: [{ kind: 'ocsp', response: ocspResponse.pem }],
			}),
		).toEqual({
			ok: true,
			value: {
				status: 'unknown',
				code: 'revocation_status_unknown',
				message: 'No revocation evidence established certificate status',
				details: {
					checkedSources: ['ocsp'],
					indeterminateEvidence: [
						{
							source: 'ocsp',
							code: 'certificate_status_missing',
							message:
								'OCSP response does not include certificate status for the target certificate',
						},
					],
				},
			},
		});
	});

	it('returns unknown with indeterminate evidence details when no source is conclusive', async () => {
		const { leaf, intermediate, intermediateKeys } = await issueChain();
		const certificate = parseCertificatePem(leaf.pem);
		const issuerCertificate = parseCertificatePem(intermediate.pem);
		const nonApplicableCrl = await createCertificateRevocationList({
			issuer: { commonName: 'Verify Intermediate CA' },
			signerPrivateKey: intermediateKeys.privateKey,
			issuerPublicKey: intermediateKeys.publicKey,
			issuingDistributionPoint: {
				onlyContainsCACerts: true,
			},
		});
		const unknownOcspResponse = await createOcspResponse({
			signerPrivateKey: intermediateKeys.privateKey,
			signerCertificate: intermediate.pem,
			responses: [
				{
					certificate: leaf.pem,
					issuerCertificate: intermediate.pem,
					certStatus: 'unknown',
				},
			],
		});

		expect(
			await checkCertificateRevocation({
				certificate,
				issuerCertificate,
				evidence: [
					{
						kind: 'crl',
						crl: nonApplicableCrl.pem,
					},
					{
						kind: 'ocsp',
						response: unknownOcspResponse.pem,
					},
				],
			}),
		).toEqual({
			ok: true,
			value: {
				status: 'unknown',
				code: 'revocation_status_unknown',
				message: 'No revocation evidence established certificate status',
				details: {
					checkedSources: ['crl', 'ocsp'],
					indeterminateEvidence: [
						{
							source: 'crl',
							code: 'non_applicable',
							message: 'CRL only applies to CA certificates',
							reason: 'certificate_scope_mismatch',
						},
						{
							source: 'ocsp',
							code: 'certificate_status_unknown',
							message: 'OCSP responder returned certificate status unknown',
						},
					],
				},
			},
		});
	});

	it('discovers OCSP responder URIs from certificate AIA metadata', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'AIA OCSP CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'AIA OCSP CA' },
			subject: { commonName: 'aia-ocsp.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			extensions: {
				authorityInfoAccess: [
					{ method: 'ocsp', uri: 'http://ocsp-1.example.test' },
					{ method: 'caIssuers', uri: 'http://issuer.example.test/ca.der' },
					{ method: 'ocsp', uri: 'http://ocsp-1.example.test' },
					{ method: 'ocsp', uri: 'http://ocsp-2.example.test' },
				],
			},
		});

		expect(getCertificateOcspResponderUris(leaf.pem)).toEqual([
			'http://ocsp-1.example.test',
			'http://ocsp-2.example.test',
		]);
	});

	it('getCertificateOcspResponderUris fails closed for malformed certificate input', () => {
		expect(getCertificateOcspResponderUris(Uint8Array.of(0xff, 0xff))).toEqual([]);
	});

	it('getCertificateOcspResponderUris ignores tampered parsed certificate AIA fields', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Tampered AIA OCSP CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Tampered AIA OCSP CA' },
			subject: { commonName: 'tampered-aia-ocsp.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			extensions: {
				authorityInfoAccess: [{ method: 'ocsp', uri: 'http://real-ocsp.example.test' }],
			},
		});
		const parsedLeaf = parseCertificatePem(leaf.pem);
		const tamperedLeaf = {
			...parsedLeaf,
			authorityInfoAccess: [{ method: 'ocsp' as const, uri: 'http://attacker.example.test' }],
		};

		expect(getCertificateOcspResponderUris(tamperedLeaf)).toEqual([
			'http://real-ocsp.example.test',
		]);
	});

	it('resolves configured responders ahead of AIA discovery', async () => {
		const issuer = await createSelfSignedCertificate({
			subject: { commonName: 'Configured OCSP CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const responderKeys = await generateKeyPair();
		const responder = await createCertificate({
			issuer: { commonName: 'Configured OCSP CA' },
			subject: { commonName: 'Local OCSP Responder' },
			publicKey: responderKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['ocspSigning'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Configured OCSP CA' },
			subject: { commonName: 'configured-ocsp.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: issuer.keyPair.privateKey,
			issuerPublicKey: issuer.keyPair.publicKey,
			extensions: {
				authorityInfoAccess: [
					{ method: 'ocsp', uri: 'http://ocsp-aia.example.test' },
					{ method: 'ocsp', uri: 'http://ocsp-configured.example.test' },
				],
			},
		});

		expect(
			resolveOcspResponderCandidates({
				certificate: parseCertificatePem(leaf.pem),
				configuredResponders: [
					{
						uri: 'http://ocsp-configured.example.test',
						responderCertificate: responder.pem,
					},
					{ uri: 'http://ocsp-local-only.example.test' },
					{ uri: 'http://ocsp-local-only.example.test' },
				],
			}),
		).toEqual([
			{
				source: 'configured',
				uri: 'http://ocsp-configured.example.test',
				responderCertificate: responder.pem,
			},
			{
				source: 'configured',
				uri: 'http://ocsp-local-only.example.test',
			},
			{
				source: 'authorityInfoAccess',
				uri: 'http://ocsp-aia.example.test',
			},
		]);
	});

	it('resolveOcspResponderCandidates preserves configured responders for malformed certificate input', () => {
		expect(
			resolveOcspResponderCandidates({
				certificate: Uint8Array.of(0xff, 0xff),
				configuredResponders: [{ uri: 'http://configured-only.example.test' }],
			}),
		).toEqual([{ source: 'configured', uri: 'http://configured-only.example.test' }]);
	});
});
