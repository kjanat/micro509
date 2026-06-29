import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createCertificateSigningRequest,
	createSelfSignedCertificate,
	decodeExtension,
	decodeExtensions,
	defineExtensionDecoder,
	defineExtensionDecoderMap,
	exportSpkiDer,
	findExtension,
	generateKeyPair,
	parseCertificateDer,
	parseCertificatePem,
	parseCertificateSigningRequestDer,
	parseCertificateSigningRequestPem,
	unwrap,
} from 'micro509';
import { encodeName } from 'micro509/x509';
import {
	bitString,
	concatBytes,
	explicitContext,
	integerFromNumber,
	nullValue,
	objectIdentifier,
	octetString,
	readSequenceChildren,
	sequence,
	setOf,
	time,
	tlv,
} from '#micro509/internal/asn1/der.ts';
import { OIDS } from '#micro509/internal/asn1/oids.ts';
import {
	encodeRsaPssParameters,
	rsaPssParametersForHash,
} from '#micro509/internal/crypto/rsa-pss.ts';
import { parseAuthorityKeyIdentifier, parseNameConstraints } from '#micro509/x509/parse.ts';
import {
	childrenOf,
	importRsaPrivateKeyWithScheme,
	replaceCertificateSignatureAlgorithm,
	rewriteCertificateSignatureAsRsaPss,
	rewriteCsrSignatureAsRsaPss,
	sliceElement,
} from './helpers.ts';

describe('parse', () => {
	it('supports custom extension encode and decode hooks', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'custom-ext.example' },
			extensions: {
				customExtensions: [
					{
						oid: '1.2.3.4.200',
						critical: true,
						value: Uint8Array.of(0x04, 0x03, 0x01, 0x02, 0x03),
					},
					{ oid: '1.2.3.4.201', value: Uint8Array.of(0x04, 0x01, 0xff) },
				],
			},
		});

		const parsed = unwrap(parseCertificatePem(certificate.certificate.pem));
		const extension = findExtension(parsed.extensions, '1.2.3.4.200');
		if (extension === undefined) {
			throw new Error('Missing custom extension');
		}
		expect(extension.critical).toBe(true);
		expect(Array.from(extension.valueDer)).toEqual([0x04, 0x03, 0x01, 0x02, 0x03]);
		expect(
			decodeExtension(parsed.extensions, {
				oid: '1.2.3.4.200',
				decode(input) {
					return Array.from(input.valueDer).join(':');
				},
			}),
		).toBe('4:3:1:2:3');
		expect(
			decodeExtensions(parsed.extensions, [
				{
					oid: '1.2.3.4.200',
					decode(input) {
						return input.valueHex;
					},
				},
				{
					oid: '1.2.3.4.201',
					decode(input) {
						return input.critical ? 'critical' : 'non-critical';
					},
				},
			]),
		).toEqual([
			{ oid: '1.2.3.4.200', critical: true, value: '0403010203' },
			{ oid: '1.2.3.4.201', critical: false, value: 'non-critical' },
		]);

		expect(
			createSelfSignedCertificate({
				subject: { commonName: 'dup-ext.example' },
				extensions: {
					keyUsage: ['digitalSignature'],
					customExtensions: [{ oid: OIDS.keyUsage, value: Uint8Array.of(0x05, 0x00) }],
				},
			}),
		).rejects.toThrow('Duplicate extension OID');
	});

	it('rejects duplicate extension OIDs during certificate parse', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'dup-parse-cert.example' },
			extensions: {
				keyUsage: ['digitalSignature'],
			},
		});
		const duplicated = duplicateCertificateExtension(certificate.certificate.der, OIDS.keyUsage);

		{
			const result = parseCertificateDer(duplicated);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Duplicate extension OID');
			}
		}
	});

	it('rejects duplicate extension OIDs during CSR parse', async () => {
		const keyPair = await generateKeyPair();
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'dup-parse-csr.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
			extensions: {
				keyUsage: ['digitalSignature'],
			},
		});
		const duplicated = duplicateCsrRequestedExtension(csr.der, OIDS.keyUsage);

		{
			const result = parseCertificateSigningRequestDer(duplicated);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Duplicate extension OID');
			}
		}
	});

	it('rejects non-OCTET certificate extension values during parse', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-extnvalue-cert.example' },
			extensions: {
				keyUsage: ['digitalSignature'],
			},
		});
		const malformed = rewriteCertificateExtensionValueTag(
			certificate.certificate.der,
			OIDS.keyUsage,
			0x02,
		);

		{
			const result = parseCertificateDer(malformed);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Extension value must use OCTET STRING');
			}
		}
	});

	it('rejects non-OCTET CSR extension values during parse', async () => {
		const keyPair = await generateKeyPair();
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'bad-extnvalue-csr.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
			extensions: {
				keyUsage: ['digitalSignature'],
			},
		});
		const malformed = rewriteCsrRequestedExtensionValueTag(csr.der, OIDS.keyUsage, 0x02);

		{
			const result = parseCertificateSigningRequestDer(malformed);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Extension value must use OCTET STRING');
			}
		}
	});

	it('rejects malformed certificate extension middle fields during parse', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-ext-middle-cert.example' },
			extensions: {
				keyUsage: ['digitalSignature'],
			},
		});
		const malformed = rewriteCertificateExtensionMiddleFieldTag(
			certificate.certificate.der,
			OIDS.keyUsage,
			0x02,
		);

		{
			const result = parseCertificateDer(malformed);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Extension value must use OCTET STRING');
			}
		}
	});

	it('rejects malformed CSR extension middle fields during parse', async () => {
		const keyPair = await generateKeyPair();
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'bad-ext-middle-csr.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
			extensions: {
				keyUsage: ['digitalSignature'],
			},
		});
		const malformed = rewriteCsrRequestedExtensionMiddleFieldTag(csr.der, OIDS.keyUsage, 0x02);

		{
			const result = parseCertificateSigningRequestDer(malformed);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Extension value must use OCTET STRING');
			}
		}
	});

	it('rejects malformed basicConstraints structures during parse', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-basic-constraints.example' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
			},
		});

		{
			const result = parseCertificateDer(
				rewriteCertificateExtensionValue(
					certificate.certificate.der,
					OIDS.basicConstraints,
					sequence([tlv(0x01, Uint8Array.of(0xff)), tlv(0x01, Uint8Array.of(0x00))]),
				),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('basicConstraints cA must not repeat');
			}
		}

		{
			const result = parseCertificateDer(
				rewriteCertificateExtensionValue(
					certificate.certificate.der,
					OIDS.basicConstraints,
					sequence([tlv(0x02, Uint8Array.of(0x00)), tlv(0x02, Uint8Array.of(0x01))]),
				),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('basicConstraints pathLength must not repeat');
			}
		}

		{
			const result = parseCertificateDer(
				rewriteCertificateExtensionValue(
					certificate.certificate.der,
					OIDS.basicConstraints,
					sequence([tlv(0x02, Uint8Array.of(0x01))]),
				),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('basicConstraints pathLength requires cA = true');
			}
		}

		{
			const result = parseCertificateDer(
				rewriteCertificateExtensionValue(
					certificate.certificate.der,
					OIDS.basicConstraints,
					sequence([tlv(0x02, Uint8Array.of(0x01)), tlv(0x01, Uint8Array.of(0xff))]),
				),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('basicConstraints cA must precede pathLength');
			}
		}

		{
			const result = parseCertificateDer(
				rewriteCertificateExtensionValue(
					certificate.certificate.der,
					OIDS.basicConstraints,
					sequence([tlv(0x80, Uint8Array.of(0x00))]),
				),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Unsupported basicConstraints field tag');
			}
		}

		{
			const result = parseCertificateDer(
				rewriteCertificateExtensionValue(
					certificate.certificate.der,
					OIDS.basicConstraints,
					tlv(0x01, Uint8Array.of(0xff)),
				),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('basicConstraints must use SEQUENCE');
			}
		}
	});

	it('rejects repeated distribution point fields during parse', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-dp-repeat.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.cRLDistributionPoints,
						value: sequence([
							sequence([
								explicitContext(
									0,
									explicitContext(0, tlv(0x86, new TextEncoder().encode('http://one.example/crl'))),
								),
								explicitContext(
									0,
									explicitContext(0, tlv(0x86, new TextEncoder().encode('http://two.example/crl'))),
								),
							]),
						]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(certificate.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'DistributionPoint distributionPoint must not repeat',
				);
			}
		}
	});

	it('rejects distributionPointName wrappers with multiple choices during parse', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-dp-choice.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.cRLDistributionPoints,
						value: sequence([
							sequence([
								explicitContext(
									0,
									concatBytes([
										explicitContext(
											0,
											tlv(0x86, new TextEncoder().encode('http://one.example/crl')),
										),
										explicitContext(1, setOf([])),
									]),
								),
							]),
						]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(certificate.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'distributionPointName must contain exactly one choice',
				);
			}
		}
	});

	it('rejects CRL distribution points that contain only reasons', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-dp-reasons.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.cRLDistributionPoints,
						value: sequence([sequence([tlv(0x81, Uint8Array.of(0x00))])]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(certificate.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'DistributionPoint must include distributionPoint or crlIssuer',
				);
			}
		}
	});

	it('rejects non-INTEGER certificate version and serialNumber tags', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-cert-scalars.example' },
		});
		{
			const result = parseCertificateDer(
				rewriteCertificateVersionIntegerTag(certificate.certificate.der, 0x01),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('version must use INTEGER');
			}
		}
		{
			const result = parseCertificateDer(
				rewriteCertificateSerialNumberTag(certificate.certificate.der, 0x01),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('serialNumber must use INTEGER');
			}
		}
	});

	it('rejects non-INTEGER CSR version tags', async () => {
		const keyPair = await generateKeyPair();
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'bad-csr-version.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
		});
		{
			const result = parseCertificateSigningRequestDer(rewriteCsrVersionTag(csr.der, 0x01));
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('version must use INTEGER');
			}
		}
	});

	it('rejects malformed SubjectPublicKeyInfo shapes in certificate and CSR parse', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-cert-spki.example' },
		});
		const keyPair = await generateKeyPair();
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'bad-csr-spki.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
		});
		{
			const result = parseCertificateDer(
				rewriteCertificateSubjectPublicKeyInfo(
					certificate.certificate.der,
					buildMalformedCertificateSubjectPublicKeyInfoWrongTag(certificate.certificate.der),
				),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('SubjectPublicKeyInfo algorithm must use SEQUENCE');
			}
		}
		{
			const result = parseCertificateSigningRequestDer(
				rewriteCsrSubjectPublicKeyInfo(
					csr.der,
					buildMalformedCsrSubjectPublicKeyInfoExtraField(csr.der),
				),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'SubjectPublicKeyInfo must contain algorithm and subjectPublicKey',
				);
			}
		}
	});

	it('rejects unsupported certificate and CSR version values', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-cert-version.example' },
		});
		const keyPair = await generateKeyPair();
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'bad-csr-version-value.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
		});
		{
			const result = parseCertificateDer(
				rewriteCertificateVersionValue(certificate.certificate.der, Uint8Array.of(0x03)),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Unsupported certificate version: 4');
			}
		}
		{
			const result = parseCertificateSigningRequestDer(
				rewriteCsrVersionValue(csr.der, Uint8Array.of(0x01)),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Unsupported CertificationRequestInfo version: 2');
			}
		}
	});

	it('rejects certificate unique IDs that violate version or BIT STRING rules', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-cert-unique-id.example' },
			extensions: {
				basicConstraints: { ca: true },
			},
		});
		{
			const result = parseCertificateDer(
				insertCertificateTbsFieldBeforeExtensions(
					rewriteCertificateVersionValue(certificate.certificate.der, Uint8Array.of(0x00)),
					tlv(0x81, Uint8Array.of(0x00)),
				),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'issuerUniqueID requires certificate version 2 or 3',
				);
			}
		}
		{
			const result = parseCertificateDer(
				insertCertificateTbsFieldBeforeExtensions(
					rewriteCertificateVersionValue(certificate.certificate.der, Uint8Array.of(0x01)),
					tlv(0x81, Uint8Array.of(0x07, 0x01)),
				),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'issuerUniqueID BIT STRING must not set padding bits',
				);
			}
		}
	});

	it('rejects certificate extensions on versions below v3', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-cert-extension-version.example' },
			extensions: {
				basicConstraints: { ca: true },
			},
		});
		{
			const result = parseCertificateDer(
				rewriteCertificateVersionValue(certificate.certificate.der, Uint8Array.of(0x01)),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('extensions require certificate version 3');
			}
		}
	});

	it('rejects repeated extensionRequest attributes during CSR parse', async () => {
		const keyPair = await generateKeyPair();
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'dup-ext-request-csr.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
			extensions: {
				keyUsage: ['digitalSignature'],
			},
		});
		const duplicated = duplicateCsrExtensionRequestAttribute(csr.der);

		{
			const result = parseCertificateSigningRequestDer(duplicated);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('extensionRequest attribute must not repeat');
			}
		}
	});

	it('rejects multi-valued extensionRequest attributes during CSR parse', async () => {
		const keyPair = await generateKeyPair();
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'multi-value-ext-request-csr.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
			extensions: {
				keyUsage: ['digitalSignature'],
			},
		});
		const duplicated = duplicateCsrExtensionRequestValue(csr.der);

		{
			const result = parseCertificateSigningRequestDer(duplicated);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'extensionRequest attribute must contain exactly one value',
				);
			}
		}
	});

	it('rejects certificate structures with unexpected top-level or TBSCertificate trailing fields', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-cert-trailing-fields.example' },
		});
		{
			const result = parseCertificateDer(
				rewriteCertificateWithExtraTopLevelField(
					certificate.certificate.der,
					tlv(0x05, new Uint8Array()),
				),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Malformed Certificate');
			}
		}
		{
			const result = parseCertificateDer(
				rewriteCertificateTbsWithExtraField(
					certificate.certificate.der,
					tlv(0x84, Uint8Array.of(0x00)),
				),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Unsupported TBSCertificate field tag: 132');
			}
		}
	});

	it('rejects certificates whose outer signatureAlgorithm mismatches the signed TBSCertificate', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-cert-signature-algorithm-mismatch.example' },
			algorithm: { kind: 'rsa', modulusLength: 2048, hash: 'SHA-256' },
		});
		const mismatched = replaceCertificateSignatureAlgorithm(
			certificate.certificate.der,
			sequence([objectIdentifier(OIDS.sha512WithRSAEncryption), nullValue()]),
		);

		{
			const result = parseCertificateDer(mismatched);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'Certificate signatureAlgorithm must match TBSCertificate signature',
				);
			}
		}
	});

	it('rejects certificates whose outer signatureAlgorithm parameters mismatch the signed TBSCertificate', async () => {
		const keyPair = await generateKeyPair({
			kind: 'rsa',
			modulusLength: 2048,
			hash: 'SHA-256',
			scheme: 'pss',
		});
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-cert-signature-parameters-mismatch.example' },
			keyPair,
			signature: { kind: 'rsa-pss' },
		});
		const mismatched = replaceCertificateSignatureAlgorithm(
			certificate.certificate.der,
			sequence([
				objectIdentifier(OIDS.rsassaPss),
				encodeRsaPssParameters(rsaPssParametersForHash('SHA-384')),
			]),
		);

		{
			const result = parseCertificateDer(mismatched);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'Certificate signatureAlgorithm must match TBSCertificate signature',
				);
			}
		}
	});

	it('rejects CSR structures with unexpected top-level or CertificationRequestInfo trailing fields', async () => {
		const keyPair = await generateKeyPair();
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'bad-csr-trailing-fields.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
			extensions: {
				keyUsage: ['digitalSignature'],
			},
		});
		{
			const result = parseCertificateSigningRequestDer(
				rewriteCsrWithExtraTopLevelField(csr.der, tlv(0x05, new Uint8Array())),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Malformed CertificationRequest');
			}
		}
		{
			const result = parseCertificateSigningRequestDer(
				rewriteCsrCriWithExtraField(csr.der, tlv(0x81, Uint8Array.of(0x00))),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Malformed CertificationRequestInfo');
			}
		}
	});

	it('rejects malformed CSR attribute containers', async () => {
		const keyPair = await generateKeyPair();
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'bad-csr-attributes.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
			extensions: {
				keyUsage: ['digitalSignature'],
			},
		});
		{
			const result = parseCertificateSigningRequestDer(rewriteCsrAttributesTag(csr.der, 0xa1));
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('CertificationRequestInfo attributes must use [0]');
			}
		}
		{
			const result = parseCertificateSigningRequestDer(
				rewriteCsrExtensionRequestValuesSetTag(csr.der, 0x30),
			);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('extensionRequest attribute values must use SET');
			}
		}
	});

	it('runs decoder registries directly during parse', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'parse-registry.example' },
			extensions: {
				customExtensions: [{ oid: '1.2.3.4.210', value: Uint8Array.of(0x04, 0x02, 0xaa, 0xbb) }],
			},
		});

		const parsed = unwrap(
			parseCertificatePem(certificate.certificate.pem, {
				decoders: [
					{
						oid: '1.2.3.4.210',
						decode(extension) {
							return extension.valueHex;
						},
					},
				],
			}),
		);

		expect(parsed.decodedExtensions).toEqual([
			{ oid: '1.2.3.4.210', critical: false, value: '0402aabb' },
		]);
		const typedParsed = unwrap(
			parseCertificatePem(certificate.certificate.pem, {
				decoderMap: defineExtensionDecoderMap({
					customText: {
						oid: '1.2.3.4.210',
						decode: (extension: { readonly valueHex: string }) => extension.valueHex,
					},
				}),
			}),
		);
		expect(typedParsed.decodedExtensionMap?.customText).toEqual({
			oid: '1.2.3.4.210',
			critical: false,
			value: '0402aabb',
		});
	});

	it('parses all known EKU types', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'EKU CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'EKU CA' },
			subject: { commonName: 'eku-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				extendedKeyUsage: [
					'serverAuth',
					'clientAuth',
					'codeSigning',
					'emailProtection',
					'timeStamping',
					'ocspSigning',
				],
			},
		});
		const parsed = unwrap(parseCertificatePem(leaf.pem));
		expect(parsed.extendedKeyUsage).toEqual([
			'serverAuth',
			'clientAuth',
			'codeSigning',
			'emailProtection',
			'timeStamping',
			'ocspSigning',
		]);
	});

	it('decodeExtension returns undefined for missing OID', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: 'decode-miss' },
		});
		const parsed = unwrap(parseCertificatePem(certificate.pem));
		expect(
			decodeExtension(parsed.extensions, {
				oid: '1.2.3.4.999.888',
				decode: () => 'should not run',
			}),
		).toBeUndefined();
	});

	it('decodeExtensions skips missing decoders', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: 'decode-skip' },
		});
		const parsed = unwrap(parseCertificatePem(certificate.pem));
		const result = decodeExtensions(parsed.extensions, [
			{ oid: '1.2.3.4.999.777', decode: () => 'never' },
			{ oid: '1.2.3.4.999.888', decode: () => 'never' },
		]);
		expect(result).toEqual([]);
	});

	it('parses all supported name fields', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: {
				country: 'US',
				state: 'CA',
				locality: 'San Francisco',
				street: 'Market St',
				organization: 'Acme',
				organizationalUnit: 'PKI',
				commonName: 'full-name.example',
				givenName: 'Jane',
				surname: 'Doe',
				title: 'Engineer',
				serialNumber: '12345',
				emailAddress: 'jane@example.com',
			},
		});
		const parsed = unwrap(parseCertificatePem(certificate.pem));
		expect(parsed.subject.values).toMatchObject({
			country: 'US',
			state: 'CA',
			locality: 'San Francisco',
			street: 'Market St',
			organization: 'Acme',
			organizationalUnit: 'PKI',
			commonName: 'full-name.example',
			givenName: 'Jane',
			surname: 'Doe',
			title: 'Engineer',
			serialNumber: '12345',
			emailAddress: 'jane@example.com',
		});
	});

	it('parses policy extensions from certificates', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'policy-parse.example' },
			extensions: {
				certificatePolicies: [
					{
						policyIdentifier: '1.2.3.4.1',
						policyQualifiers: [
							{ type: 'cps', uri: 'https://example.com/cps' },
							{
								type: 'userNotice',
								noticeRef: { organization: 'Example Org', noticeNumbers: [7, 9] },
								explicitText: 'policy notice',
							},
							{
								type: 'oid',
								oid: '1.2.3.4.200',
								qualifierDer: Uint8Array.of(0x04, 0x02, 0xde, 0xad),
							},
						],
					},
				],
				policyMappings: [{ issuerDomainPolicy: '1.2.3.4.1', subjectDomainPolicy: '1.2.3.4.2' }],
				policyConstraints: { requireExplicitPolicy: 1, inhibitPolicyMapping: 2 },
				inhibitAnyPolicy: { skipCerts: 3 },
			},
		});

		const parsed = unwrap(parseCertificatePem(certificate.certificate.pem));
		expect(parsed.certificatePolicies).toEqual([
			{
				policyIdentifier: '1.2.3.4.1',
				policyQualifiers: [
					{ type: 'cps', uri: 'https://example.com/cps' },
					{
						type: 'userNotice',
						noticeRef: { organization: 'Example Org', noticeNumbers: [7, 9] },
						explicitText: 'policy notice',
					},
					{
						type: 'oid',
						oid: '1.2.3.4.200',
						qualifierDer: Uint8Array.of(0x04, 0x02, 0xde, 0xad),
					},
				],
			},
		]);
		expect(parsed.policyMappings).toEqual([
			{ issuerDomainPolicy: '1.2.3.4.1', subjectDomainPolicy: '1.2.3.4.2' },
		]);
		expect(parsed.policyConstraints).toEqual({ requireExplicitPolicy: 1, inhibitPolicyMapping: 2 });
		expect(parsed.inhibitAnyPolicy).toEqual({ skipCerts: 3 });
	});

	it('parses policy extensions from CSR requested extensions', async () => {
		const keys = await generateKeyPair();
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'policy-csr-parse.example' },
			publicKey: keys.publicKey,
			signerPrivateKey: keys.privateKey,
			extensions: {
				certificatePolicies: [{ policyIdentifier: '1.2.3.4.1' }],
				policyMappings: [{ issuerDomainPolicy: '1.2.3.4.1', subjectDomainPolicy: '1.2.3.4.2' }],
				policyConstraints: { requireExplicitPolicy: 1 },
				inhibitAnyPolicy: { skipCerts: 4 },
			},
		});

		const parsed = unwrap(parseCertificateSigningRequestPem(csr.pem));
		expect(parsed.certificatePolicies).toEqual([{ policyIdentifier: '1.2.3.4.1' }]);
		expect(parsed.policyMappings).toEqual([
			{ issuerDomainPolicy: '1.2.3.4.1', subjectDomainPolicy: '1.2.3.4.2' },
		]);
		expect(parsed.policyConstraints).toEqual({ requireExplicitPolicy: 1 });
		expect(parsed.inhibitAnyPolicy).toEqual({ skipCerts: 4 });
	});

	it('throws on malformed or truncated DER input', () => {
		{
			const result = parseCertificateDer(new Uint8Array([0x30, 0x03, 0x01]));
			expect(result.ok).toBe(false);
		}
		{
			const result = parseCertificateDer(new Uint8Array([]));
			expect(result.ok).toBe(false);
		}
		{
			const result = parseCertificatePem('not a pem');
			expect(result.ok).toBe(false);
		}
		{
			const result = parseCertificateDer(new Uint8Array([0xff, 0xff]));
			expect(result.ok).toBe(false);
		}
	});

	it('parses and round-trips nameConstraints extension', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'NC Parse Test CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [
						{ base: { type: 'dns', value: 'example.com' } },
						{ base: { type: 'email', value: '.example.org' } },
					],
					excludedSubtrees: [{ base: { type: 'dns', value: 'bad.example.com' } }],
				},
			},
		});
		const parsed = unwrap(parseCertificatePem(root.certificate.pem));
		expect(parsed.nameConstraints).toBeDefined();
		expect(parsed.nameConstraints?.permittedSubtrees).toHaveLength(2);
		expect(parsed.nameConstraints?.excludedSubtrees).toHaveLength(1);
		const permitted = parsed.nameConstraints?.permittedSubtrees;
		expect(permitted?.[0]?.base).toEqual({
			type: 'dns',
			value: 'example.com',
		});
		expect(permitted?.[1]?.base).toEqual({
			type: 'email',
			value: '.example.org',
		});
		const excluded = parsed.nameConstraints?.excludedSubtrees;
		expect(excluded?.[0]?.base).toEqual({
			type: 'dns',
			value: 'bad.example.com',
		});
	});

	it('rejects GeneralSubtree with maximum field during parsing', () => {
		const dnsName = tlv(0x82, new TextEncoder().encode('example.com'));
		const maximum = tlv(0x81, Uint8Array.of(5));
		const subtree = sequence([dnsName, maximum]);
		const permitted = tlv(0xa0, subtree);
		const ncValue = sequence([permitted]);
		expect(() => parseNameConstraints(ncValue)).toThrow(/maximum/i);
	});

	it('rejects GeneralSubtree with non-zero minimum during parsing', () => {
		const dnsName = tlv(0x82, new TextEncoder().encode('example.com'));
		const minimum = tlv(0x80, Uint8Array.of(3));
		const subtree = sequence([dnsName, minimum]);
		const permitted = tlv(0xa0, subtree);
		const ncValue = sequence([permitted]);
		expect(() => parseNameConstraints(ncValue)).toThrow(/minimum/i);
	});

	it('parses certificate with directoryName SAN', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'DirName SAN CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		// Create leaf with directoryName SAN
		const leaf = await createCertificate({
			issuer: { commonName: 'DirName SAN CA' },
			subject: { commonName: 'dirname-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [
					{ type: 'dns', value: 'dirname-leaf.example' },
					{ type: 'directoryName', derHex: '300e310c300a060355040313036f7267' },
				],
			},
		});
		const parsed = unwrap(parseCertificatePem(leaf.pem));
		expect(parsed.subjectAltNames?.some((san) => san.type === 'directoryName')).toBe(true);
		const dirNameSan = parsed.subjectAltNames?.find((san) => san.type === 'directoryName');
		if (dirNameSan?.type === 'directoryName') {
			expect(dirNameSan.derHex).toBeDefined();
		}
	});

	it('parses certificate with unknown SAN type', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Unknown SAN CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Unknown SAN CA' },
			subject: { commonName: 'unknown-san-leaf' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				subjectAltNames: [
					{ type: 'dns', value: 'unknown-san.example' },
					{ type: 'unknown', tag: 0x88, value: Uint8Array.of(0x01, 0x02) },
				],
			},
		});
		const parsed = unwrap(parseCertificatePem(leaf.pem));
		expect(parsed.subjectAltNames?.some((san) => san.type === 'unknown')).toBe(true);
	});

	it('parses SRV-ID subjectAltName otherName values from certificates', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: 'srv-id.example' },
			extensions: {
				subjectAltNames: [{ type: 'srv', value: '_xmpp.example.com' }],
			},
		});

		const parsed = unwrap(parseCertificatePem(certificate.pem));
		expect(parsed.subjectAltNames).toEqual([{ type: 'srv', value: '_xmpp.example.com' }]);
	});

	it('parses SRV-ID subjectAltName otherName values from CSRs', async () => {
		const keys = await generateKeyPair();
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'srv-id-csr.example' },
			publicKey: keys.publicKey,
			signerPrivateKey: keys.privateKey,
			extensions: {
				subjectAltNames: [{ type: 'srv', value: '_imap.example.com' }],
			},
		});

		const parsed = unwrap(parseCertificateSigningRequestPem(csr.pem));
		expect(parsed.subjectAltNames).toEqual([{ type: 'srv', value: '_imap.example.com' }]);
	});

	it('preserves unsupported otherName subjectAltName values as unknown entries', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: 'unknown-othername.example' },
			extensions: {
				subjectAltNames: [
					{
						type: 'unknown',
						tag: 0xa0,
						value: sequence([objectIdentifier('1.2.3.4.5'), tlv(0xa0, integerFromNumber(7))]),
					},
				],
			},
		});

		const parsed = unwrap(parseCertificatePem(certificate.pem));
		expect(parsed.subjectAltNames).toHaveLength(1);
		expect(parsed.subjectAltNames?.[0]).toMatchObject({ type: 'unknown', tag: 0xa0 });
	});

	it('rejects malformed SRV-ID otherName values', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: 'bad-srv-id.example' },
			extensions: {
				subjectAltNames: [
					{
						type: 'unknown',
						tag: 0xa0,
						value: sequence([objectIdentifier(OIDS.idOnDnsSrv), tlv(0xa0, integerFromNumber(7))]),
					},
				],
			},
		});

		{
			const result = parseCertificatePem(certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toMatch(/SRV-ID/i);
			}
		}
	});

	it('rejects SRV-ID otherName values with trailing fields', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: 'bad-srv-id-trailing.example' },
			extensions: {
				subjectAltNames: [
					{
						type: 'unknown',
						tag: 0xa0,
						value: sequence([
							objectIdentifier(OIDS.idOnDnsSrv),
							tlv(0xa0, tlv(0x16, new TextEncoder().encode('_xmpp.example.com'))),
							integerFromNumber(7),
						]),
					},
				],
			},
		});

		{
			const result = parseCertificatePem(certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('otherName must contain exactly');
			}
		}
	});

	it('parses IPv6 name constraints', async () => {
		// IPv6 constraint is 32 bytes: 16 for address + 16 for mask
		const ipv6Address = new Uint8Array(16);
		ipv6Address[0] = 0x20;
		ipv6Address[1] = 0x01;
		const ipv6Mask = new Uint8Array(16);
		ipv6Mask[0] = 0xff;
		ipv6Mask[1] = 0xff;
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'IPv6 NC CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [
						{
							base: {
								type: 'ip',
								addressBytes: ipv6Address,
								maskBytes: ipv6Mask,
							},
						},
					],
				},
			},
		});
		const parsed = unwrap(parseCertificatePem(root.certificate.pem));
		expect(parsed.nameConstraints?.permittedSubtrees).toHaveLength(1);
		const ipForm = parsed.nameConstraints?.permittedSubtrees?.[0]?.base;
		expect(ipForm?.type).toBe('ip');
	});

	it('rejects malformed certificatePolicies during parsing', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-policy-parse.example' },
			extensions: {
				customExtensions: [{ oid: OIDS.certificatePolicies, critical: true, value: sequence([]) }],
			},
		});
		{
			const result = parseCertificatePem(certificate.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('certificatePolicies must not be empty');
			}
		}
	});

	it('rejects anyPolicy in policyMappings during parsing', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-policy-mappings-parse.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.policyMappings,
						critical: true,
						value: sequence([
							sequence([objectIdentifier(OIDS.anyPolicy), objectIdentifier('1.2.3.4.2')]),
						]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(certificate.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('policyMappings must not use anyPolicy');
			}
		}
	});

	it('rejects malformed policy qualifiers during parsing', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-policy-qualifier-parse.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.certificatePolicies,
						critical: true,
						value: sequence([
							sequence([
								objectIdentifier('1.2.3.4.1'),
								sequence([
									sequence([objectIdentifier(OIDS.cpsPolicyQualifier), integerFromNumber(7)]),
								]),
							]),
						]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(certificate.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('cps policy qualifier must use IA5String');
			}
		}
	});

	it('rejects policyInformation with trailing fields and empty qualifier sequences', async () => {
		const trailing = await createSelfSignedCertificate({
			subject: { commonName: 'bad-policy-trailing.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.certificatePolicies,
						critical: true,
						value: sequence([
							sequence([
								objectIdentifier('1.2.3.4.1'),
								sequence([
									sequence([
										objectIdentifier(OIDS.cpsPolicyQualifier),
										tlv(0x16, new TextEncoder().encode('https://example.test/cps')),
									]),
								]),
								integerFromNumber(7),
							]),
						]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(trailing.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('policyInformation has unexpected trailing fields');
			}
		}

		const emptyQualifiers = await createSelfSignedCertificate({
			subject: { commonName: 'bad-policy-empty-qualifiers.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.certificatePolicies,
						critical: true,
						value: sequence([sequence([objectIdentifier('1.2.3.4.1'), sequence([])])]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(emptyQualifiers.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('policyQualifiers must not be empty');
			}
		}
	});

	it('rejects malformed policy qualifier and userNotice structures during parsing', async () => {
		const qualifierTrailing = await createSelfSignedCertificate({
			subject: { commonName: 'bad-policy-qualifier-trailing.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.certificatePolicies,
						critical: true,
						value: sequence([
							sequence([
								objectIdentifier('1.2.3.4.1'),
								sequence([
									sequence([
										objectIdentifier(OIDS.cpsPolicyQualifier),
										tlv(0x16, new TextEncoder().encode('https://example.test/cps')),
										integerFromNumber(1),
									]),
								]),
							]),
						]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(qualifierTrailing.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'policyQualifierInfo has unexpected trailing fields',
				);
			}
		}

		const duplicateNoticeRef = await createSelfSignedCertificate({
			subject: { commonName: 'bad-user-notice-ref.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.certificatePolicies,
						critical: true,
						value: sequence([
							sequence([
								objectIdentifier('1.2.3.4.1'),
								sequence([
									sequence([
										objectIdentifier(OIDS.userNoticePolicyQualifier),
										sequence([
											sequence([
												tlv(0x0c, new TextEncoder().encode('Org A')),
												sequence([integerFromNumber(1)]),
											]),
											sequence([
												tlv(0x0c, new TextEncoder().encode('Org B')),
												sequence([integerFromNumber(2)]),
											]),
										]),
									]),
								]),
							]),
						]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(duplicateNoticeRef.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'userNotice must not contain multiple noticeRef values',
				);
			}
		}

		const duplicateExplicitText = await createSelfSignedCertificate({
			subject: { commonName: 'bad-user-notice-text.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.certificatePolicies,
						critical: true,
						value: sequence([
							sequence([
								objectIdentifier('1.2.3.4.1'),
								sequence([
									sequence([
										objectIdentifier(OIDS.userNoticePolicyQualifier),
										sequence([
											tlv(0x0c, new TextEncoder().encode('first')),
											tlv(0x0c, new TextEncoder().encode('second')),
										]),
									]),
								]),
							]),
						]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(duplicateExplicitText.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'userNotice must not contain multiple explicitText values',
				);
			}
		}
	});

	it('rejects malformed noticeRef, policyMappings, and policyConstraints structures', async () => {
		const noticeRefTrailing = await createSelfSignedCertificate({
			subject: { commonName: 'bad-notice-ref-trailing.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.certificatePolicies,
						critical: true,
						value: sequence([
							sequence([
								objectIdentifier('1.2.3.4.1'),
								sequence([
									sequence([
										objectIdentifier(OIDS.userNoticePolicyQualifier),
										sequence([
											sequence([
												tlv(0x0c, new TextEncoder().encode('Example Org')),
												sequence([integerFromNumber(1)]),
												integerFromNumber(2),
											]),
										]),
									]),
								]),
							]),
						]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(noticeRefTrailing.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('noticeRef has unexpected trailing fields');
			}
		}

		const emptyMappings = await createSelfSignedCertificate({
			subject: { commonName: 'bad-empty-mappings.example' },
			extensions: {
				customExtensions: [{ oid: OIDS.policyMappings, critical: true, value: sequence([]) }],
			},
		});
		{
			const result = parseCertificatePem(emptyMappings.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('policyMappings must not be empty');
			}
		}

		const trailingMapping = await createSelfSignedCertificate({
			subject: { commonName: 'bad-trailing-mapping.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.policyMappings,
						critical: true,
						value: sequence([
							sequence([
								objectIdentifier('1.2.3.4.1'),
								objectIdentifier('1.2.3.4.2'),
								integerFromNumber(1),
							]),
						]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(trailingMapping.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'policyMappings entry has unexpected trailing fields',
				);
			}
		}

		const duplicateRequire = await createSelfSignedCertificate({
			subject: { commonName: 'bad-policy-constraints-require.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.policyConstraints,
						critical: true,
						value: sequence([tlv(0x80, Uint8Array.of(0x00)), tlv(0x80, Uint8Array.of(0x01))]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(duplicateRequire.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'policyConstraints must not repeat requireExplicitPolicy',
				);
			}
		}

		const unsupportedPolicyConstraint = await createSelfSignedCertificate({
			subject: { commonName: 'bad-policy-constraints-tag.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.policyConstraints,
						critical: true,
						value: sequence([tlv(0x82, Uint8Array.of(0x00))]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(unsupportedPolicyConstraint.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Unsupported policyConstraints field tag: 130');
			}
		}

		const duplicateInhibit = await createSelfSignedCertificate({
			subject: { commonName: 'bad-policy-constraints-inhibit.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.policyConstraints,
						critical: true,
						value: sequence([tlv(0x81, Uint8Array.of(0x00)), tlv(0x81, Uint8Array.of(0x01))]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(duplicateInhibit.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'policyConstraints must not repeat inhibitPolicyMapping',
				);
			}
		}

		const emptyAia = await createSelfSignedCertificate({
			subject: { commonName: 'bad-empty-aia.example' },
			extensions: {
				customExtensions: [{ oid: OIDS.authorityInfoAccess, critical: true, value: sequence([]) }],
			},
		});
		{
			const result = parseCertificatePem(emptyAia.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('authorityInfoAccess must not be empty');
			}
		}

		const trailingAia = await createSelfSignedCertificate({
			subject: { commonName: 'bad-trailing-aia.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.authorityInfoAccess,
						critical: true,
						value: sequence([
							sequence([
								objectIdentifier(OIDS.ocspAccessMethod),
								tlv(0x86, new TextEncoder().encode('http://example.test/ocsp')),
								integerFromNumber(1),
							]),
						]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(trailingAia.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'authorityInfoAccess entry must contain method and location only',
				);
			}
		}

		const badMethodAia = await createSelfSignedCertificate({
			subject: { commonName: 'bad-method-aia.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.authorityInfoAccess,
						critical: true,
						value: sequence([
							sequence([
								integerFromNumber(1),
								tlv(0x86, new TextEncoder().encode('http://example.test/ocsp')),
							]),
						]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(badMethodAia.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'authorityInfoAccess method must use OBJECT IDENTIFIER',
				);
			}
		}

		const setWrappedAia = await createSelfSignedCertificate({
			subject: { commonName: 'bad-set-aia.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.authorityInfoAccess,
						critical: true,
						value: setOf([
							sequence([
								objectIdentifier(OIDS.ocspAccessMethod),
								tlv(0x86, new TextEncoder().encode('http://example.test/ocsp')),
							]),
						]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(setWrappedAia.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('authorityInfoAccess must use SEQUENCE');
			}
		}

		const badNoticeNumbersTag = await createSelfSignedCertificate({
			subject: { commonName: 'bad-notice-numbers-tag.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.certificatePolicies,
						critical: true,
						value: sequence([
							sequence([
								objectIdentifier('1.2.3.4.1'),
								sequence([
									sequence([
										objectIdentifier(OIDS.userNoticePolicyQualifier),
										sequence([
											sequence([
												tlv(0x0c, new TextEncoder().encode('Example Org')),
												integerFromNumber(1),
											]),
										]),
									]),
								]),
							]),
						]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(badNoticeNumbersTag.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('noticeRef noticeNumbers must use SEQUENCE');
			}
		}

		const badNoticeNumberElement = await createSelfSignedCertificate({
			subject: { commonName: 'bad-notice-number-element.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.certificatePolicies,
						critical: true,
						value: sequence([
							sequence([
								objectIdentifier('1.2.3.4.1'),
								sequence([
									sequence([
										objectIdentifier(OIDS.userNoticePolicyQualifier),
										sequence([
											sequence([
												tlv(0x0c, new TextEncoder().encode('Example Org')),
												sequence([tlv(0x01, Uint8Array.of(0xff))]),
											]),
										]),
									]),
								]),
							]),
						]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(badNoticeNumberElement.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('noticeRef noticeNumber must use INTEGER');
			}
		}
	});

	it('rejects malformed distributionPointName, SRV-ID, and unsupported DisplayText tags', async () => {
		const badDistributionPointName = await createSelfSignedCertificate({
			subject: { commonName: 'bad-dp-name.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.cRLDistributionPoints,
						critical: true,
						value: sequence([sequence([tlv(0xa0, Uint8Array.of(0x82, 0x01, 0x61))])]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(badDistributionPointName.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Unsupported distributionPointName tag: 130');
			}
		}

		const badSrvId = await createSelfSignedCertificate({
			subject: { commonName: 'bad-srv-id.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.subjectAltName,
						critical: true,
						value: sequence([
							tlv(
								0xa0,
								sequence([
									objectIdentifier(OIDS.idOnDnsSrv),
									tlv(0x81, new TextEncoder().encode('_xmpp.example.test')),
								]),
							),
						]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(badSrvId.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('SRV-ID otherName value must use explicit [0]');
			}
		}

		const badDisplayText = await createSelfSignedCertificate({
			subject: { commonName: 'bad-display-text.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.certificatePolicies,
						critical: true,
						value: sequence([
							sequence([
								objectIdentifier('1.2.3.4.1'),
								sequence([
									sequence([
										objectIdentifier(OIDS.userNoticePolicyQualifier),
										sequence([tlv(0x02, Uint8Array.of(0x01))]),
									]),
								]),
							]),
						]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(badDisplayText.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Unsupported DisplayText tag: 2');
			}
		}
	});

	it('rejects empty CRLDistributionPoints and empty fullName GeneralNames during parse', async () => {
		const emptyDistributionPoints = await createSelfSignedCertificate({
			subject: { commonName: 'bad-empty-dp.example' },
			extensions: {
				customExtensions: [
					{ oid: OIDS.cRLDistributionPoints, critical: true, value: sequence([]) },
				],
			},
		});
		{
			const result = parseCertificatePem(emptyDistributionPoints.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('CRLDistributionPoints must not be empty');
			}
		}

		const emptyFullName = await createSelfSignedCertificate({
			subject: { commonName: 'bad-empty-fullname.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.cRLDistributionPoints,
						critical: true,
						value: sequence([sequence([explicitContext(0, explicitContext(0, sequence([])))])]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(emptyFullName.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'distributionPointName fullName must contain GeneralName entries',
				);
			}
		}

		const setWrappedDistributionPoint = await createSelfSignedCertificate({
			subject: { commonName: 'bad-set-dp.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.cRLDistributionPoints,
						critical: true,
						value: sequence([setOf([])]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(setWrappedDistributionPoint.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('DistributionPoint must use SEQUENCE');
			}
		}
	});

	it('preserves x400Address and ediPartyName name constraints', () => {
		const result = parseNameConstraints(
			sequence([
				tlv(
					0xa0,
					concatBytes([
						sequence([tlv(0xa3, Uint8Array.of(0x01, 0x02))]),
						sequence([tlv(0xa5, Uint8Array.of(0x03, 0x04))]),
					]),
				),
			]),
		);
		expect(result.permittedSubtrees).toEqual([
			{ base: { type: 'x400Address', value: Uint8Array.of(0x01, 0x02) } },
			{ base: { type: 'ediPartyName', value: Uint8Array.of(0x03, 0x04) } },
		]);
	});

	it('rejects unsupported name constraint GeneralName tags', () => {
		expect(() =>
			parseNameConstraints(sequence([tlv(0xa0, sequence([tlv(0x89, Uint8Array.of(0x05, 0x06))]))])),
		).toThrow('Unsupported name constraint GeneralName tag');
	});

	it('rejects empty policy noticeNumbers during parsing', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-policy-notice-parse.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.certificatePolicies,
						critical: true,
						value: sequence([
							sequence([
								objectIdentifier('1.2.3.4.1'),
								sequence([
									sequence([
										objectIdentifier(OIDS.userNoticePolicyQualifier),
										sequence([
											sequence([tlv(0x0c, new TextEncoder().encode('Example Org')), sequence([])]),
										]),
									]),
								]),
							]),
						]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(certificate.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('noticeRef noticeNumbers must not be empty');
			}
		}
	});

	it('parses BMPString DisplayText in certificate policies', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bmp-policy-parse.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.certificatePolicies,
						critical: true,
						value: sequence([
							sequence([
								objectIdentifier('1.2.3.4.1'),
								sequence([
									sequence([
										objectIdentifier(OIDS.userNoticePolicyQualifier),
										sequence([tlv(0x1e, Uint8Array.of(0x00, 0x4f, 0x00, 0x4b))]),
									]),
								]),
							]),
						]),
					},
				],
			},
		});

		expect(unwrap(parseCertificatePem(certificate.certificate.pem)).certificatePolicies).toEqual([
			{
				policyIdentifier: '1.2.3.4.1',
				policyQualifiers: [{ type: 'userNotice', explicitText: 'OK' }],
			},
		]);
	});

	it('rejects malformed BMPString DisplayText in certificate policies', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-bmp-policy-parse.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.certificatePolicies,
						critical: true,
						value: sequence([
							sequence([
								objectIdentifier('1.2.3.4.1'),
								sequence([
									sequence([
										objectIdentifier(OIDS.userNoticePolicyQualifier),
										sequence([tlv(0x1e, Uint8Array.of(0x00, 0x4f, 0x00))]),
									]),
								]),
							]),
						]),
					},
				],
			},
		});

		{
			const result = parseCertificatePem(certificate.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Invalid BMPString length');
			}
		}
	});

	it('rejects non-integer inhibitAnyPolicy during parsing', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-inhibit-any-policy-parse.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.inhibitAnyPolicy,
						critical: true,
						value: tlv(0x01, Uint8Array.of(0x00)),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(certificate.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('inhibitAnyPolicy must be an INTEGER');
			}
		}
	});

	it('rejects empty policyConstraints during parsing', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'bad-policy-constraints-parse.example' },
			extensions: {
				customExtensions: [
					{
						oid: OIDS.policyConstraints,
						critical: true,
						value: sequence([]),
					},
				],
			},
		});
		{
			const result = parseCertificatePem(certificate.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain(
					'policyConstraints must set requireExplicitPolicy or inhibitPolicyMapping',
				);
			}
		}
	});

	it('parses nameConstraints with directoryName form', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'DirName NC CA' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [
						{
							base: { type: 'directoryName', derHex: '300e310c300a060355040313036f7267' },
						},
					],
				},
			},
		});
		const parsed = unwrap(parseCertificatePem(root.certificate.pem));
		expect(parsed.nameConstraints?.permittedSubtrees).toHaveLength(1);
		expect(parsed.nameConstraints?.permittedSubtrees?.[0]?.base.type).toBe('directoryName');
	});

	// -----------------------------------------------------------------------
	// parseNameConstraints error paths via crafted DER
	// -----------------------------------------------------------------------

	it('parseNameConstraints throws on non-zero minimum', () => {
		// GeneralSubtree with minimum [0] = 1 (must be 0)
		const subtree = sequence([
			tlv(0x82, new TextEncoder().encode('example.com')), // DNS base
			tlv(0x80, Uint8Array.of(0x01)), // minimum = 1 (invalid)
		]);
		const nameConstraints = sequence([
			tlv(0xa0, subtree), // permittedSubtrees
		]);
		expect(() => parseNameConstraints(nameConstraints)).toThrow('minimum must be 0');
	});

	it('parseNameConstraints throws on maximum present', () => {
		const subtree = sequence([
			tlv(0x82, new TextEncoder().encode('example.com')),
			tlv(0x80, Uint8Array.of(0x00)), // minimum = 0 (valid)
			tlv(0x81, Uint8Array.of(0x05)), // maximum = 5 (not supported)
		]);
		const nameConstraints = sequence([tlv(0xa0, subtree)]);
		expect(() => parseNameConstraints(nameConstraints)).toThrow('maximum is not supported');
	});

	it('parseNameConstraints throws on invalid IP constraint length', () => {
		// IP with 3 bytes (not 8 or 32)
		const subtree = sequence([tlv(0x87, Uint8Array.of(0x01, 0x02, 0x03))]);
		const nameConstraints = sequence([tlv(0xa0, subtree)]);
		expect(() => parseNameConstraints(nameConstraints)).toThrow('Invalid IP name constraint');
	});

	it('parseNameConstraints throws on repeated subtree containers', () => {
		const nameConstraints = sequence([
			tlv(0xa0, sequence([tlv(0x82, new TextEncoder().encode('first.example'))])),
			tlv(0xa0, sequence([tlv(0x82, new TextEncoder().encode('second.example'))])),
		]);
		expect(() => parseNameConstraints(nameConstraints)).toThrow(
			'permittedSubtrees must not repeat',
		);
	});

	it('parseNameConstraints throws on empty GeneralSubtrees containers', () => {
		const nameConstraints = sequence([tlv(0xa0, new Uint8Array())]);
		expect(() => parseNameConstraints(nameConstraints)).toThrow(
			'GeneralSubtrees must not be empty',
		);
	});

	it('parseNameConstraints throws on empty GeneralSubtree sequences', () => {
		const nameConstraints = sequence([tlv(0xa0, sequence([]))]);
		expect(() => parseNameConstraints(nameConstraints)).toThrow('GeneralSubtree base is required');
	});

	it('parseNameConstraints throws on repeated minimum fields', () => {
		const subtree = sequence([
			tlv(0x82, new TextEncoder().encode('example.com')),
			tlv(0x80, Uint8Array.of(0x00)),
			tlv(0x80, Uint8Array.of(0x00)),
		]);
		const nameConstraints = sequence([tlv(0xa0, subtree)]);
		expect(() => parseNameConstraints(nameConstraints)).toThrow('minimum must not repeat');
	});

	it('parseNameConstraints throws on unsupported top-level fields', () => {
		const nameConstraints = sequence([tlv(0xa2, sequence([]))]);
		expect(() => parseNameConstraints(nameConstraints)).toThrow(
			'Unsupported nameConstraints field tag',
		);
	});

	it('parseNameConstraints preserves unsupported GeneralName types', () => {
		// registeredID [8] is classified explicitly for later fail-closed validation.
		const subtree = sequence([
			tlv(0x88, Uint8Array.of(0x55, 0x04, 0x03)), // OID bytes for tag 0x88
		]);
		const nameConstraints = sequence([tlv(0xa0, subtree)]);
		const result = parseNameConstraints(nameConstraints);
		expect(result.permittedSubtrees).toHaveLength(1);
		expect(result.permittedSubtrees?.[0]?.base).toEqual({
			type: 'registeredID',
			value: '2.5.4.3',
		});
	});

	// -----------------------------------------------------------------------
	// defineExtensionDecoder identity function
	// -----------------------------------------------------------------------

	it('defineExtensionDecoder returns the decoder unchanged', () => {
		const decoder = defineExtensionDecoder({
			oid: '1.2.3.4.999',
			decode: (ext) => ext.valueDer,
		});
		expect(decoder.oid).toBe('1.2.3.4.999');
	});

	// -----------------------------------------------------------------------
	// CSR parsing without extensions
	// -----------------------------------------------------------------------

	it('parses CSR without extensions attribute', async () => {
		const keys = await generateKeyPair();
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'no-ext-csr.example' },
			publicKey: keys.publicKey,
			signerPrivateKey: keys.privateKey,
		});
		const parsed = unwrap(parseCertificateSigningRequestPem(csr.pem));
		expect(parsed.subject.values.commonName).toBe('no-ext-csr.example');
		// No extensions → requestedExtensions should be empty
		expect(parsed.requestedExtensions).toHaveLength(0);
	});

	it('parses certificate without extensions field', async () => {
		const keys = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const signatureAlgorithm = sequence([
			objectIdentifier(OIDS.sha256WithRSAEncryption),
			nullValue(),
		]);
		const name = encodeName({ commonName: 'no-ext-cert.example' });
		const spki = await exportSpkiDer(keys.publicKey);
		const tbsCertificate = sequence([
			integerFromNumber(1),
			signatureAlgorithm,
			name,
			sequence([time(new Date('2024-01-01T00:00:00Z')), time(new Date('2025-01-01T00:00:00Z'))]),
			name,
			spki,
		]);
		const der = sequence([tbsCertificate, signatureAlgorithm, bitString(Uint8Array.of(0x00))]);
		const parsed = unwrap(parseCertificateDer(der));
		expect(parsed.subject.values.commonName).toBe('no-ext-cert.example');
		expect(parsed.extensions).toHaveLength(0);
	});

	it('preserves raw algorithm parameters in parsed certificates', async () => {
		const rsaCertificate = await createSelfSignedCertificate({
			subject: { commonName: 'algo-params-rsa.example' },
			keyPair: await generateKeyPair({ kind: 'rsa', modulusLength: 2048 }),
		});
		const parsedRsa = unwrap(parseCertificateDer(rsaCertificate.certificate.der));
		expect(parsedRsa.signatureAlgorithmParametersDer).toEqual(nullValue());
		expect(parsedRsa.publicKeyAlgorithmParametersDer).toEqual(nullValue());
		expect(parsedRsa.signatureAlgorithmOid).toBe(OIDS.sha256WithRSAEncryption);
		expect(parsedRsa.signatureAlgorithmName).toBe('RSA PKCS#1 v1.5 with SHA-256');
		expect(parsedRsa.publicKeyAlgorithmOid).toBe(OIDS.rsaEncryption);
		expect(parsedRsa.publicKeyAlgorithmName).toBe('RSA');

		const ecCertificate = await createSelfSignedCertificate({
			subject: { commonName: 'algo-params-ec.example' },
			keyPair: await generateKeyPair({ kind: 'ecdsa', curve: 'P-384' }),
		});
		const parsedEc = unwrap(parseCertificateDer(ecCertificate.certificate.der));
		expect(parsedEc.signatureAlgorithmParametersDer).toBeUndefined();
		expect(parsedEc.signatureAlgorithmName).toBe('ECDSA with SHA-384');
		expect(parsedEc.publicKeyAlgorithmParametersDer).toEqual(objectIdentifier(OIDS.secp384r1));
		expect(parsedEc.publicKeyParametersOid).toBe(OIDS.secp384r1);
		expect(parsedEc.publicKeyAlgorithmName).toBe('EC P-384');
	});

	it('parses CSR without attributes field', async () => {
		const keys = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const signatureAlgorithm = sequence([
			objectIdentifier(OIDS.sha256WithRSAEncryption),
			nullValue(),
		]);
		const spki = await exportSpkiDer(keys.publicKey);
		const certificationRequestInfo = sequence([
			integerFromNumber(0),
			encodeName({ commonName: 'bare-csr.example' }),
			spki,
		]);
		const der = sequence([
			certificationRequestInfo,
			signatureAlgorithm,
			bitString(Uint8Array.of(0x00)),
		]);
		const parsed = unwrap(parseCertificateSigningRequestDer(der));
		expect(parsed.subject.values.commonName).toBe('bare-csr.example');
		expect(parsed.requestedExtensions).toHaveLength(0);
	});

	it('preserves raw algorithm parameters in parsed CSRs', async () => {
		const keyPair = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'algo-params-csr.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
		});
		const parsed = unwrap(parseCertificateSigningRequestDer(csr.der));
		expect(parsed.signatureAlgorithmParametersDer).toEqual(nullValue());
		expect(parsed.publicKeyAlgorithmParametersDer).toEqual(nullValue());
		expect(parsed.signatureAlgorithmOid).toBe(OIDS.sha256WithRSAEncryption);
		expect(parsed.signatureAlgorithmName).toBe('RSA PKCS#1 v1.5 with SHA-256');
		expect(parsed.publicKeyAlgorithmOid).toBe(OIDS.rsaEncryption);
		expect(parsed.publicKeyAlgorithmName).toBe('RSA');
	});

	it('describes RSA-PSS algorithms for parsed certificates and CSRs', async () => {
		const keyPair = await generateKeyPair({
			kind: 'rsa',
			modulusLength: 2048,
			hash: 'SHA-384',
		});
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'rsa-pss-parse.example' },
			keyPair,
		});
		const csr = await createCertificateSigningRequest({
			subject: { commonName: 'rsa-pss-csr-parse.example' },
			publicKey: keyPair.publicKey,
			signerPrivateKey: keyPair.privateKey,
		});
		const rsaPssPrivateKey = await importRsaPrivateKeyWithScheme(
			keyPair.privateKey,
			'SHA-384',
			'pss',
		);
		const rsaPssParameters = {
			hash: 'SHA-384',
			mgfHash: 'SHA-384',
			saltLength: 48,
			trailerField: 1,
		} as const;

		const parsedCertificate = unwrap(
			parseCertificateDer(
				await rewriteCertificateSignatureAsRsaPss(
					certificate.certificate.der,
					rsaPssPrivateKey,
					rsaPssParameters,
				),
			),
		);
		expect(parsedCertificate.signatureAlgorithmName).toBe('RSA-PSS with SHA-384');
		expect(parsedCertificate.publicKeyAlgorithmName).toBe('RSA');

		const parsedCsr = unwrap(
			parseCertificateSigningRequestDer(
				await rewriteCsrSignatureAsRsaPss(csr.der, rsaPssPrivateKey, rsaPssParameters),
			),
		);
		expect(parsedCsr.signatureAlgorithmName).toBe('RSA-PSS with SHA-384');
		expect(parsedCsr.publicKeyAlgorithmName).toBe('RSA');
	});

	it('rejects malformed AlgorithmIdentifier with extra elements', async () => {
		const keys = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const malformedSignatureAlgorithm = sequence([
			objectIdentifier(OIDS.sha256WithRSAEncryption),
			nullValue(),
			nullValue(),
		]);
		const name = encodeName({ commonName: 'malformed-alg-id.example' });
		const spki = await exportSpkiDer(keys.publicKey);
		const tbsCertificate = sequence([
			integerFromNumber(1),
			malformedSignatureAlgorithm,
			name,
			sequence([time(new Date('2024-01-01T00:00:00Z')), time(new Date('2025-01-01T00:00:00Z'))]),
			name,
			spki,
		]);
		const der = sequence([
			tbsCertificate,
			malformedSignatureAlgorithm,
			bitString(Uint8Array.of(0x00)),
		]);
		{
			const result = parseCertificateDer(der);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Malformed AlgorithmIdentifier');
			}
		}
	});

	// -----------------------------------------------------------------------
	// encodeAsn1Length for length >= 128 (multi-byte length)
	// -----------------------------------------------------------------------

	it('parses name constraint with large directoryName (multi-byte ASN.1 length)', () => {
		// Build a directoryName with content > 127 bytes to exercise encodeAsn1Length >= 128 path
		const longCN = 'x'.repeat(130);
		const cnValue = new TextEncoder().encode(longCN);
		// Build a minimal RDN: SET { SEQUENCE { OID, UTF8String } }
		const rdnSeq = sequence([
			objectIdentifier(OIDS.commonName),
			tlv(0x0c, cnValue), // UTF8String
		]);
		const rdn = setOf([rdnSeq]);
		const dnSequence = sequence([rdn]);
		// Wrap as directoryName [4] IMPLICIT — replace tag 0x30 with 0xa4
		const dnBytes = new Uint8Array(dnSequence);
		dnBytes[0] = 0xa4;
		const subtree = sequence([dnBytes]);
		const nameConstraints = sequence([tlv(0xa0, subtree)]);
		const result = parseNameConstraints(nameConstraints);
		expect(result.permittedSubtrees).toHaveLength(1);
		expect(result.permittedSubtrees?.[0]?.base.type).toBe('directoryName');
	});
});

describe('parse: coverage — error paths', () => {
	it('parseAuthorityInfoAccess throws on non-URI location tag', async () => {
		// Build AIA extension with dNSName (tag 0x82) instead of URI (tag 0x86)
		const ocspOid = '1.3.6.1.5.5.7.48.1'; // id-ad-ocsp
		const aiaValue = sequence([
			sequence([
				objectIdentifier(ocspOid),
				tlv(0x82, new TextEncoder().encode('ocsp.example.com')), // dNSName, not URI
			]),
		]);
		expect(async () => {
			await createSelfSignedCertificate({
				subject: { commonName: 'aia-test.example' },
				extensions: {
					customExtensions: [
						{
							oid: '1.3.6.1.5.5.7.1.1', // authorityInfoAccess
							value: aiaValue,
						},
					],
				},
			}).then((cert) => unwrap(parseCertificatePem(cert.certificate.pem)));
		}).toThrow('Unsupported authorityInfoAccess location tag');
	});

	it('parseAuthorityKeyIdentifier rejects malformed authorityCertIssuer shapes', () => {
		expect(() => parseAuthorityKeyIdentifier(sequence([explicitContext(1, sequence([]))]))).toThrow(
			'authorityKeyIdentifier authorityCertIssuer must contain GeneralName entries',
		);
	});

	it('parseAuthorityKeyIdentifier rejects duplicate or incomplete issuer/serial fields', () => {
		expect(() =>
			parseAuthorityKeyIdentifier(
				sequence([tlv(0x80, Uint8Array.of(0x01)), tlv(0x80, Uint8Array.of(0x02))]),
			),
		).toThrow('keyIdentifier must not repeat');
		expect(() =>
			parseAuthorityKeyIdentifier(
				sequence([tlv(0xa1, Uint8Array.of(0xff)), tlv(0x82, Uint8Array.of(0x01))]),
			),
		).toThrow('High-tag-number DER form is not supported');
		expect(() =>
			parseAuthorityKeyIdentifier(
				sequence([tlv(0x82, Uint8Array.of(0x01)), explicitContext(1, sequence([]))]),
			),
		).toThrow('authorityKeyIdentifier fields must preserve DER order');
		expect(() => parseAuthorityKeyIdentifier(sequence([tlv(0x82, Uint8Array.of(0x01))]))).toThrow(
			'authorityKeyIdentifier fields must preserve DER order',
		);
	});

	it('decodeIpAddress throws on unsupported IP address length', async () => {
		// Create certificate with SAN containing an IP address of wrong length (e.g., 6 bytes)
		// Build SubjectAltName with a 6-byte iPAddress (tag 0x87)
		const sanValue = sequence([
			tlv(0x87, Uint8Array.of(0x0a, 0x00, 0x00, 0x01, 0xff, 0xee)), // 6 bytes — invalid
		]);
		const cert = await createSelfSignedCertificate({
			subject: { commonName: 'bad-ip.example' },
			extensions: {
				customExtensions: [
					{
						oid: '2.5.29.17', // subjectAltNames
						value: sanValue,
					},
				],
			},
		});
		{
			const result = parseCertificatePem(cert.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Unsupported IP address length');
			}
		}
	});

	it('parseKeyUsage throws on BIT STRING with unusedBits > 7', async () => {
		// Build keyUsage extension with unusedBits = 8 (invalid)
		// KeyUsage is a BIT STRING: first byte is unused bits count
		const keyUsageValue = tlv(0x03, Uint8Array.of(8, 0x80)); // unusedBits=8, data=0x80
		const cert = await createSelfSignedCertificate({
			subject: { commonName: 'bad-ku.example' },
			extensions: {
				customExtensions: [
					{
						oid: '2.5.29.15', // keyUsage
						value: keyUsageValue,
						critical: true,
					},
				],
			},
		});
		{
			const result = parseCertificatePem(cert.certificate.pem);
			expect(result.ok).toBe(false);
			if (!result.ok) {
				expect(result.error.message).toContain('Invalid BIT STRING');
			}
		}
	});
});

function duplicateCertificateExtension(certificateDer: Uint8Array, oid: string): Uint8Array {
	const topLevel = readSequenceChildren(certificateDer);
	const tbsCertificate = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertificate === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed Certificate');
	}
	const tbsDer = sliceElement(certificateDer, tbsCertificate);
	const tbsChildren = readSequenceChildren(tbsDer);
	const extensionIndex = tbsChildren.findIndex((child) => child.tag === 0xa3);
	if (extensionIndex === -1) {
		throw new Error('Certificate missing extensions');
	}
	const extensionsWrapper = tbsChildren[extensionIndex];
	if (extensionsWrapper === undefined) {
		throw new Error('Certificate missing extensions wrapper');
	}
	const duplicatedWrapper = duplicateExtensionWrapper(tbsDer, extensionsWrapper, oid);
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === extensionIndex ? duplicatedWrapper : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(certificateDer, signatureAlgorithm),
		sliceElement(certificateDer, signatureValue),
	]);
}

function rewriteCertificateExtensionValue(
	certificateDer: Uint8Array,
	oid: string,
	extensionValueDer: Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(certificateDer);
	const tbsCertificate = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertificate === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed Certificate');
	}
	const tbsDer = sliceElement(certificateDer, tbsCertificate);
	const tbsChildren = readSequenceChildren(tbsDer);
	const extensionIndex = tbsChildren.findIndex((child) => child.tag === 0xa3);
	if (extensionIndex === -1) {
		throw new Error('Certificate missing extensions');
	}
	const extensionsWrapper = tbsChildren[extensionIndex];
	if (extensionsWrapper === undefined) {
		throw new Error('Certificate missing extensions wrapper');
	}
	const sequenceElement = childrenOf(tbsDer, extensionsWrapper)[0];
	if (sequenceElement === undefined) {
		throw new Error('Missing extensions sequence');
	}
	const rebuiltWrapper = tlv(
		0xa3,
		rewriteExtensionSequenceValuePayload(tbsDer, sequenceElement, oid, extensionValueDer),
	);
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === extensionIndex ? rebuiltWrapper : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(certificateDer, signatureAlgorithm),
		sliceElement(certificateDer, signatureValue),
	]);
}

function rewriteCertificateExtensionValueTag(
	certificateDer: Uint8Array,
	oid: string,
	tag: number,
): Uint8Array {
	const topLevel = readSequenceChildren(certificateDer);
	const tbsCertificate = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertificate === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed Certificate');
	}
	const tbsDer = sliceElement(certificateDer, tbsCertificate);
	const tbsChildren = readSequenceChildren(tbsDer);
	const extensionIndex = tbsChildren.findIndex((child) => child.tag === 0xa3);
	if (extensionIndex === -1) {
		throw new Error('Certificate missing extensions');
	}
	const extensionsWrapper = tbsChildren[extensionIndex];
	if (extensionsWrapper === undefined) {
		throw new Error('Certificate missing extensions wrapper');
	}
	const sequenceElement = childrenOf(tbsDer, extensionsWrapper)[0];
	if (sequenceElement === undefined) {
		throw new Error('Missing extensions sequence');
	}
	const rebuiltWrapper = tlv(
		0xa3,
		rewriteExtensionSequenceValueTag(tbsDer, sequenceElement, oid, tag),
	);
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === extensionIndex ? rebuiltWrapper : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(certificateDer, signatureAlgorithm),
		sliceElement(certificateDer, signatureValue),
	]);
}

function rewriteCertificateExtensionMiddleFieldTag(
	certificateDer: Uint8Array,
	oid: string,
	tag: number,
): Uint8Array {
	const topLevel = readSequenceChildren(certificateDer);
	const tbsCertificate = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertificate === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed Certificate');
	}
	const tbsDer = sliceElement(certificateDer, tbsCertificate);
	const tbsChildren = readSequenceChildren(tbsDer);
	const extensionIndex = tbsChildren.findIndex((child) => child.tag === 0xa3);
	if (extensionIndex === -1) {
		throw new Error('Certificate missing extensions');
	}
	const extensionsWrapper = tbsChildren[extensionIndex];
	if (extensionsWrapper === undefined) {
		throw new Error('Certificate missing extensions wrapper');
	}
	const sequenceElement = childrenOf(tbsDer, extensionsWrapper)[0];
	if (sequenceElement === undefined) {
		throw new Error('Missing extensions sequence');
	}
	const rebuiltWrapper = tlv(
		0xa3,
		rewriteExtensionSequenceMiddleFieldTag(tbsDer, sequenceElement, oid, tag),
	);
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === extensionIndex ? rebuiltWrapper : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(certificateDer, signatureAlgorithm),
		sliceElement(certificateDer, signatureValue),
	]);
}

function rewriteCertificateVersionIntegerTag(certificateDer: Uint8Array, tag: number): Uint8Array {
	const topLevel = readSequenceChildren(certificateDer);
	const tbsCertificate = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertificate === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed Certificate');
	}
	const tbsDer = sliceElement(certificateDer, tbsCertificate);
	const tbsChildren = readSequenceChildren(tbsDer);
	const versionWrapper = tbsChildren[0];
	if (versionWrapper?.tag !== 0xa0) {
		throw new Error('Certificate missing explicit version');
	}
	const versionElement = childrenOf(tbsDer, versionWrapper)[0];
	if (versionElement === undefined) {
		throw new Error('Certificate missing version element');
	}
	const rebuiltVersionWrapper = tlv(0xa0, tlv(tag, versionElement.value));
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === 0 ? rebuiltVersionWrapper : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(certificateDer, signatureAlgorithm),
		sliceElement(certificateDer, signatureValue),
	]);
}

function rewriteCertificateVersionValue(
	certificateDer: Uint8Array,
	versionValue: Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(certificateDer);
	const tbsCertificate = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertificate === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed Certificate');
	}
	const tbsDer = sliceElement(certificateDer, tbsCertificate);
	const tbsChildren = readSequenceChildren(tbsDer);
	const versionWrapper = tbsChildren[0];
	if (versionWrapper?.tag !== 0xa0) {
		throw new Error('Certificate missing explicit version');
	}
	const rebuiltVersionWrapper = tlv(0xa0, tlv(0x02, versionValue));
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === 0 ? rebuiltVersionWrapper : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(certificateDer, signatureAlgorithm),
		sliceElement(certificateDer, signatureValue),
	]);
}

function rewriteCertificateSubjectPublicKeyInfo(
	certificateDer: Uint8Array,
	subjectPublicKeyInfoDer: Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(certificateDer);
	const tbsCertificate = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertificate === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed Certificate');
	}
	const tbsDer = sliceElement(certificateDer, tbsCertificate);
	const tbsChildren = readSequenceChildren(tbsDer);
	const serialNumberIndex = tbsChildren[0]?.tag === 0xa0 ? 1 : 0;
	const subjectPublicKeyInfoIndex = serialNumberIndex + 5;
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === subjectPublicKeyInfoIndex ? subjectPublicKeyInfoDer : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(certificateDer, signatureAlgorithm),
		sliceElement(certificateDer, signatureValue),
	]);
}

function buildMalformedCertificateSubjectPublicKeyInfoWrongTag(
	certificateDer: Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(certificateDer);
	const tbsCertificate = topLevel[0];
	if (tbsCertificate === undefined) {
		throw new Error('Malformed Certificate');
	}
	const tbsDer = sliceElement(certificateDer, tbsCertificate);
	const tbsChildren = readSequenceChildren(tbsDer);
	const serialNumberIndex = tbsChildren[0]?.tag === 0xa0 ? 1 : 0;
	const subjectPublicKeyInfo = tbsChildren[serialNumberIndex + 5];
	if (subjectPublicKeyInfo === undefined) {
		throw new Error('Certificate missing subjectPublicKeyInfo');
	}
	const spkiDer = sliceElement(tbsDer, subjectPublicKeyInfo);
	const spkiChildren = readSequenceChildren(spkiDer);
	const algorithm = spkiChildren[0];
	const subjectPublicKey = spkiChildren[1];
	if (algorithm === undefined) {
		throw new Error('SubjectPublicKeyInfo missing algorithm');
	}
	if (subjectPublicKey === undefined) {
		throw new Error('SubjectPublicKeyInfo missing subjectPublicKey');
	}
	return sequence([tlv(0x31, algorithm.value), sliceElement(spkiDer, subjectPublicKey)]);
}

function insertCertificateTbsFieldBeforeExtensions(
	certificateDer: Uint8Array,
	fieldDer: Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(certificateDer);
	const tbsCertificate = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertificate === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed Certificate');
	}
	const tbsDer = sliceElement(certificateDer, tbsCertificate);
	const tbsChildren = readSequenceChildren(tbsDer);
	const extensionIndex = tbsChildren.findIndex((child) => child.tag === 0xa3);
	const rebuiltChildren =
		extensionIndex === -1
			? [...tbsChildren.map((child) => sliceElement(tbsDer, child)), fieldDer]
			: [
					...tbsChildren.slice(0, extensionIndex).map((child) => sliceElement(tbsDer, child)),
					fieldDer,
					...tbsChildren.slice(extensionIndex).map((child) => sliceElement(tbsDer, child)),
				];
	return sequence([
		sequence(rebuiltChildren),
		sliceElement(certificateDer, signatureAlgorithm),
		sliceElement(certificateDer, signatureValue),
	]);
}

function rewriteCertificateSerialNumberTag(certificateDer: Uint8Array, tag: number): Uint8Array {
	const topLevel = readSequenceChildren(certificateDer);
	const tbsCertificate = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertificate === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed Certificate');
	}
	const tbsDer = sliceElement(certificateDer, tbsCertificate);
	const tbsChildren = readSequenceChildren(tbsDer);
	const serialNumberIndex = tbsChildren[0]?.tag === 0xa0 ? 1 : 0;
	const serialNumber = tbsChildren[serialNumberIndex];
	if (serialNumber === undefined) {
		throw new Error('Certificate missing serialNumber');
	}
	const rebuiltTbs = sequence(
		tbsChildren.map((child, index) =>
			index === serialNumberIndex ? tlv(tag, child.value) : sliceElement(tbsDer, child),
		),
	);
	return sequence([
		rebuiltTbs,
		sliceElement(certificateDer, signatureAlgorithm),
		sliceElement(certificateDer, signatureValue),
	]);
}

function rewriteCertificateWithExtraTopLevelField(
	certificateDer: Uint8Array,
	extraFieldDer: Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(certificateDer);
	return sequence([...topLevel.map((child) => sliceElement(certificateDer, child)), extraFieldDer]);
}

function rewriteCertificateTbsWithExtraField(
	certificateDer: Uint8Array,
	extraFieldDer: Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(certificateDer);
	const tbsCertificate = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		tbsCertificate === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed Certificate');
	}
	const tbsDer = sliceElement(certificateDer, tbsCertificate);
	const tbsChildren = readSequenceChildren(tbsDer);
	const rebuiltTbs = sequence([
		...tbsChildren.map((child) => sliceElement(tbsDer, child)),
		extraFieldDer,
	]);
	return sequence([
		rebuiltTbs,
		sliceElement(certificateDer, signatureAlgorithm),
		sliceElement(certificateDer, signatureValue),
	]);
}

function duplicateCsrRequestedExtension(csrDer: Uint8Array, oid: string): Uint8Array {
	const topLevel = readSequenceChildren(csrDer);
	const certificationRequestInfo = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		certificationRequestInfo === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CertificationRequest');
	}
	const criDer = sliceElement(csrDer, certificationRequestInfo);
	const criChildren = readSequenceChildren(criDer);
	const attributesIndex = criChildren.findIndex((child) => child.tag === 0xa0);
	if (attributesIndex === -1) {
		throw new Error('CSR missing attributes');
	}
	const attributes = criChildren[attributesIndex];
	if (attributes === undefined) {
		throw new Error('CSR missing attributes wrapper');
	}
	const attributeElements = childrenOf(criDer, attributes);
	const rebuiltAttributes = tlv(
		0xa0,
		concatBytes(
			attributeElements.map((attribute) => {
				const attributeDer = sliceElement(criDer, attribute);
				const attributeChildren = readSequenceChildren(attributeDer);
				const oidElement = attributeChildren[0];
				const valuesSet = attributeChildren[1];
				if (
					oidElement === undefined ||
					valuesSet === undefined ||
					decodeAttributeOid(attributeDer) !== OIDS.extensionRequest
				) {
					return attributeDer;
				}
				const requestedExtensions = childrenOf(attributeDer, valuesSet)[0];
				if (requestedExtensions === undefined) {
					return attributeDer;
				}
				const duplicatedRequested = duplicateExtensionSequence(
					attributeDer,
					requestedExtensions,
					oid,
				);
				return sequence([sliceElement(attributeDer, oidElement), setOf([duplicatedRequested])]);
			}),
		),
	);
	const rebuiltCri = sequence(
		criChildren.map((child, index) =>
			index === attributesIndex ? rebuiltAttributes : sliceElement(criDer, child),
		),
	);
	return sequence([
		rebuiltCri,
		sliceElement(csrDer, signatureAlgorithm),
		sliceElement(csrDer, signatureValue),
	]);
}

function rewriteCsrRequestedExtensionValueTag(
	csrDer: Uint8Array,
	oid: string,
	tag: number,
): Uint8Array {
	return rewriteCsrAttributes(csrDer, (attributesSource, attributeElements) =>
		concatBytes(
			attributeElements.map((attribute) => {
				const attributeDer = sliceElement(attributesSource, attribute);
				const attributeChildren = readSequenceChildren(attributeDer);
				const oidElement = attributeChildren[0];
				const valuesSet = attributeChildren[1];
				if (
					oidElement === undefined ||
					valuesSet === undefined ||
					decodeAttributeOid(attributeDer) !== OIDS.extensionRequest
				) {
					return attributeDer;
				}
				const requestedExtensions = childrenOf(attributeDer, valuesSet)[0];
				if (requestedExtensions === undefined) {
					return attributeDer;
				}
				const rewrittenRequested = rewriteExtensionSequenceValueTag(
					attributeDer,
					requestedExtensions,
					oid,
					tag,
				);
				return sequence([sliceElement(attributeDer, oidElement), setOf([rewrittenRequested])]);
			}),
		),
	);
}

function rewriteCsrRequestedExtensionMiddleFieldTag(
	csrDer: Uint8Array,
	oid: string,
	tag: number,
): Uint8Array {
	return rewriteCsrAttributes(csrDer, (attributesSource, attributeElements) =>
		concatBytes(
			attributeElements.map((attribute) => {
				const attributeDer = sliceElement(attributesSource, attribute);
				const attributeChildren = readSequenceChildren(attributeDer);
				const oidElement = attributeChildren[0];
				const valuesSet = attributeChildren[1];
				if (
					oidElement === undefined ||
					valuesSet === undefined ||
					decodeAttributeOid(attributeDer) !== OIDS.extensionRequest
				) {
					return attributeDer;
				}
				const requestedExtensions = childrenOf(attributeDer, valuesSet)[0];
				if (requestedExtensions === undefined) {
					return attributeDer;
				}
				const rewrittenRequested = rewriteExtensionSequenceMiddleFieldTag(
					attributeDer,
					requestedExtensions,
					oid,
					tag,
				);
				return sequence([sliceElement(attributeDer, oidElement), setOf([rewrittenRequested])]);
			}),
		),
	);
}

function rewriteCsrVersionTag(csrDer: Uint8Array, tag: number): Uint8Array {
	const topLevel = readSequenceChildren(csrDer);
	const certificationRequestInfo = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		certificationRequestInfo === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CertificationRequest');
	}
	const criDer = sliceElement(csrDer, certificationRequestInfo);
	const criChildren = readSequenceChildren(criDer);
	const versionElement = criChildren[0];
	if (versionElement === undefined) {
		throw new Error('CSR missing version');
	}
	const rebuiltCri = sequence(
		criChildren.map((child, index) =>
			index === 0 ? tlv(tag, child.value) : sliceElement(criDer, child),
		),
	);
	return sequence([
		rebuiltCri,
		sliceElement(csrDer, signatureAlgorithm),
		sliceElement(csrDer, signatureValue),
	]);
}

function rewriteCsrVersionValue(csrDer: Uint8Array, versionValue: Uint8Array): Uint8Array {
	const topLevel = readSequenceChildren(csrDer);
	const certificationRequestInfo = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		certificationRequestInfo === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CertificationRequest');
	}
	const criDer = sliceElement(csrDer, certificationRequestInfo);
	const criChildren = readSequenceChildren(criDer);
	const rebuiltCri = sequence(
		criChildren.map((child, index) =>
			index === 0 ? tlv(0x02, versionValue) : sliceElement(criDer, child),
		),
	);
	return sequence([
		rebuiltCri,
		sliceElement(csrDer, signatureAlgorithm),
		sliceElement(csrDer, signatureValue),
	]);
}

function rewriteCsrSubjectPublicKeyInfo(
	csrDer: Uint8Array,
	subjectPublicKeyInfoDer: Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(csrDer);
	const certificationRequestInfo = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		certificationRequestInfo === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CertificationRequest');
	}
	const criDer = sliceElement(csrDer, certificationRequestInfo);
	const criChildren = readSequenceChildren(criDer);
	const rebuiltCri = sequence(
		criChildren.map((child, index) =>
			index === 2 ? subjectPublicKeyInfoDer : sliceElement(criDer, child),
		),
	);
	return sequence([
		rebuiltCri,
		sliceElement(csrDer, signatureAlgorithm),
		sliceElement(csrDer, signatureValue),
	]);
}

function buildMalformedCsrSubjectPublicKeyInfoExtraField(csrDer: Uint8Array): Uint8Array {
	const topLevel = readSequenceChildren(csrDer);
	const certificationRequestInfo = topLevel[0];
	if (certificationRequestInfo === undefined) {
		throw new Error('Malformed CertificationRequest');
	}
	const criDer = sliceElement(csrDer, certificationRequestInfo);
	const criChildren = readSequenceChildren(criDer);
	const subjectPublicKeyInfo = criChildren[2];
	if (subjectPublicKeyInfo === undefined) {
		throw new Error('CertificationRequest missing subjectPublicKeyInfo');
	}
	const spkiDer = sliceElement(criDer, subjectPublicKeyInfo);
	const spkiChildren = readSequenceChildren(spkiDer);
	return sequence([
		...spkiChildren.map((child) => sliceElement(spkiDer, child)),
		integerFromNumber(0),
	]);
}

function rewriteCsrWithExtraTopLevelField(
	csrDer: Uint8Array,
	extraFieldDer: Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(csrDer);
	return sequence([...topLevel.map((child) => sliceElement(csrDer, child)), extraFieldDer]);
}

function rewriteCsrCriWithExtraField(csrDer: Uint8Array, extraFieldDer: Uint8Array): Uint8Array {
	const topLevel = readSequenceChildren(csrDer);
	const certificationRequestInfo = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		certificationRequestInfo === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CertificationRequest');
	}
	const criDer = sliceElement(csrDer, certificationRequestInfo);
	const criChildren = readSequenceChildren(criDer);
	const rebuiltCri = sequence([
		...criChildren.map((child) => sliceElement(criDer, child)),
		extraFieldDer,
	]);
	return sequence([
		rebuiltCri,
		sliceElement(csrDer, signatureAlgorithm),
		sliceElement(csrDer, signatureValue),
	]);
}

function duplicateCsrExtensionRequestAttribute(csrDer: Uint8Array): Uint8Array {
	return rewriteCsrAttributes(csrDer, (attributesSource, attributeElements) => {
		const extensionRequestAttribute = attributeElements.find(
			(attribute) =>
				decodeAttributeOid(sliceElement(attributesSource, attribute)) === OIDS.extensionRequest,
		);
		if (extensionRequestAttribute === undefined) {
			throw new Error('Missing extensionRequest attribute');
		}
		const duplicate = sliceElement(attributesSource, extensionRequestAttribute);
		return concatBytes([
			...attributeElements.map((attribute) => sliceElement(attributesSource, attribute)),
			duplicate,
		]);
	});
}

function rewriteCsrAttributesTag(csrDer: Uint8Array, tag: number): Uint8Array {
	const topLevel = readSequenceChildren(csrDer);
	const certificationRequestInfo = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		certificationRequestInfo === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CertificationRequest');
	}
	const criDer = sliceElement(csrDer, certificationRequestInfo);
	const criChildren = readSequenceChildren(criDer);
	const attributesIndex = criChildren.findIndex((child) => child.tag === 0xa0);
	if (attributesIndex === -1) {
		throw new Error('CSR missing attributes');
	}
	const attributes = criChildren[attributesIndex];
	if (attributes === undefined) {
		throw new Error('CSR missing attributes wrapper');
	}
	const rebuiltCri = sequence(
		criChildren.map((child, index) =>
			index === attributesIndex ? tlv(tag, child.value) : sliceElement(criDer, child),
		),
	);
	return sequence([
		rebuiltCri,
		sliceElement(csrDer, signatureAlgorithm),
		sliceElement(csrDer, signatureValue),
	]);
}

function rewriteCsrExtensionRequestValuesSetTag(csrDer: Uint8Array, tag: number): Uint8Array {
	return rewriteCsrAttributes(csrDer, (attributesSource, attributeElements) =>
		concatBytes(
			attributeElements.map((attribute) => {
				const attributeDer = sliceElement(attributesSource, attribute);
				if (decodeAttributeOid(attributeDer) !== OIDS.extensionRequest) {
					return attributeDer;
				}
				const attributeChildren = readSequenceChildren(attributeDer);
				const oidElement = attributeChildren[0];
				const valuesSet = attributeChildren[1];
				if (oidElement === undefined || valuesSet === undefined) {
					return attributeDer;
				}
				return sequence([sliceElement(attributeDer, oidElement), tlv(tag, valuesSet.value)]);
			}),
		),
	);
}

function duplicateCsrExtensionRequestValue(csrDer: Uint8Array): Uint8Array {
	return rewriteCsrAttributes(csrDer, (attributesSource, attributeElements) =>
		concatBytes(
			attributeElements.map((attribute) => {
				const attributeDer = sliceElement(attributesSource, attribute);
				if (decodeAttributeOid(attributeDer) !== OIDS.extensionRequest) {
					return attributeDer;
				}
				const attributeChildren = readSequenceChildren(attributeDer);
				const oidElement = attributeChildren[0];
				const valuesSet = attributeChildren[1];
				if (oidElement === undefined || valuesSet === undefined) {
					return attributeDer;
				}
				const requestedExtensions = childrenOf(attributeDer, valuesSet)[0];
				if (requestedExtensions === undefined) {
					return attributeDer;
				}
				const requestedDer = sliceElement(attributeDer, requestedExtensions);
				return sequence([
					sliceElement(attributeDer, oidElement),
					setOf([requestedDer, requestedDer]),
				]);
			}),
		),
	);
}

function rewriteCsrAttributes(
	csrDer: Uint8Array,
	rewrite: (
		attributesSource: Uint8Array,
		attributeElements: readonly ReturnType<typeof readSequenceChildren>[number][],
	) => Uint8Array,
): Uint8Array {
	const topLevel = readSequenceChildren(csrDer);
	const certificationRequestInfo = topLevel[0];
	const signatureAlgorithm = topLevel[1];
	const signatureValue = topLevel[2];
	if (
		certificationRequestInfo === undefined ||
		signatureAlgorithm === undefined ||
		signatureValue === undefined
	) {
		throw new Error('Malformed CertificationRequest');
	}
	const criDer = sliceElement(csrDer, certificationRequestInfo);
	const criChildren = readSequenceChildren(criDer);
	const attributesIndex = criChildren.findIndex((child) => child.tag === 0xa0);
	if (attributesIndex === -1) {
		throw new Error('CSR missing attributes');
	}
	const attributes = criChildren[attributesIndex];
	if (attributes === undefined) {
		throw new Error('CSR missing attributes wrapper');
	}
	const attributeElements = childrenOf(criDer, attributes);
	const rebuiltAttributes = tlv(0xa0, rewrite(criDer, attributeElements));
	const rebuiltCri = sequence(
		criChildren.map((child, index) =>
			index === attributesIndex ? rebuiltAttributes : sliceElement(criDer, child),
		),
	);
	return sequence([
		rebuiltCri,
		sliceElement(csrDer, signatureAlgorithm),
		sliceElement(csrDer, signatureValue),
	]);
}

function duplicateExtensionWrapper(
	source: Uint8Array,
	wrapper: ReturnType<typeof readSequenceChildren>[number],
	oid: string,
): Uint8Array {
	const sequenceElement = childrenOf(source, wrapper)[0];
	if (sequenceElement === undefined) {
		throw new Error('Missing extensions sequence');
	}
	return tlv(0xa3, duplicateExtensionSequence(source, sequenceElement, oid));
}

function duplicateExtensionSequence(
	source: Uint8Array,
	sequenceElement: ReturnType<typeof readSequenceChildren>[number],
	oid: string,
): Uint8Array {
	const entries = childrenOf(source, sequenceElement).map((entry) => sliceElement(source, entry));
	const duplicate = entries.find((entryDer) => hasExtensionOidDer(entryDer, oid));
	if (duplicate === undefined) {
		throw new Error(`Missing extension OID: ${oid}`);
	}
	return sequence([...entries, duplicate]);
}

function rewriteExtensionSequenceValueTag(
	source: Uint8Array,
	sequenceElement: ReturnType<typeof readSequenceChildren>[number],
	oid: string,
	tag: number,
): Uint8Array {
	const entries = childrenOf(source, sequenceElement).map((entry) => {
		const entryDer = sliceElement(source, entry);
		const parts = readSequenceChildren(entryDer);
		const oidElement = parts[0];
		const valueElement = parts[parts.length - 1];
		if (
			oidElement === undefined ||
			valueElement === undefined ||
			decodeExtensionOid(oidElement.value) !== oid
		) {
			return entryDer;
		}
		const middle = parts.slice(1, parts.length - 1).map((part) => sliceElement(entryDer, part));
		return sequence([sliceElement(entryDer, oidElement), ...middle, tlv(tag, valueElement.value)]);
	});
	return sequence(entries);
}

function rewriteExtensionSequenceValuePayload(
	source: Uint8Array,
	sequenceElement: ReturnType<typeof readSequenceChildren>[number],
	oid: string,
	extensionValueDer: Uint8Array,
): Uint8Array {
	const entries = childrenOf(source, sequenceElement).map((entry) => {
		const entryDer = sliceElement(source, entry);
		const parts = readSequenceChildren(entryDer);
		const oidElement = parts[0];
		if (oidElement === undefined || decodeExtensionOid(oidElement.value) !== oid) {
			return entryDer;
		}
		const criticalElement = parts.length === 3 ? parts[1] : undefined;
		return sequence([
			sliceElement(entryDer, oidElement),
			...(criticalElement === undefined ? [] : [sliceElement(entryDer, criticalElement)]),
			octetString(extensionValueDer),
		]);
	});
	return sequence(entries);
}

function rewriteExtensionSequenceMiddleFieldTag(
	source: Uint8Array,
	sequenceElement: ReturnType<typeof readSequenceChildren>[number],
	oid: string,
	tag: number,
): Uint8Array {
	const entries = childrenOf(source, sequenceElement).map((entry) => {
		const entryDer = sliceElement(source, entry);
		const parts = readSequenceChildren(entryDer);
		const oidElement = parts[0];
		const valueElement = parts[parts.length - 1];
		if (
			oidElement === undefined ||
			valueElement === undefined ||
			decodeExtensionOid(oidElement.value) !== oid
		) {
			return entryDer;
		}
		if (parts.length === 2) {
			return sequence([
				sliceElement(entryDer, oidElement),
				tlv(tag, Uint8Array.of(0x00)),
				sliceElement(entryDer, valueElement),
			]);
		}
		const middle = parts[1];
		if (middle === undefined) {
			throw new Error('Malformed Extension');
		}
		return sequence([
			sliceElement(entryDer, oidElement),
			tlv(tag, middle.value),
			sliceElement(entryDer, valueElement),
		]);
	});
	return sequence(entries);
}

function hasExtensionOidDer(extensionDer: Uint8Array, oid: string): boolean {
	const children = readSequenceChildren(extensionDer);
	const oidElement = children[0];
	if (oidElement === undefined || oidElement.tag !== 0x06) {
		return false;
	}
	return decodeExtensionOid(oidElement.value) === oid;
}

function decodeExtensionOid(bytes: Uint8Array): string {
	const first = bytes[0];
	if (first === undefined) {
		throw new Error('OID is empty');
	}
	const values = [Math.floor(first / 40), first % 40];
	let current = 0;
	for (let index = 1; index < bytes.length; index += 1) {
		const next = bytes[index];
		if (next === undefined) {
			throw new Error('Malformed OID');
		}
		current = (current << 7) | (next & 0x7f);
		if ((next & 0x80) === 0) {
			values.push(current);
			current = 0;
		}
	}
	return values.join('.');
}

function decodeAttributeOid(attributeDer: Uint8Array): string {
	const children = readSequenceChildren(attributeDer);
	const oidElement = children[0];
	if (oidElement === undefined || oidElement.tag !== 0x06) {
		throw new Error('Missing attribute OID');
	}
	return decodeExtensionOid(oidElement.value);
}
