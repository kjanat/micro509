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
} from '#micro509';
import {
	bitString,
	concatBytes,
	integerFromNumber,
	nullValue,
	objectIdentifier,
	sequence,
	setOf,
	time,
	tlv,
} from '#micro509/der.ts';
import { encodeName } from '#micro509/name.ts';
import { OIDS } from '#micro509/oids.ts';
import { parseNameConstraints } from '#micro509/parse.ts';

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

		const parsed = parseCertificatePem(certificate.certificate.pem);
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

	it('runs decoder registries directly during parse', async () => {
		const certificate = await createSelfSignedCertificate({
			subject: { commonName: 'parse-registry.example' },
			extensions: {
				customExtensions: [{ oid: '1.2.3.4.210', value: Uint8Array.of(0x04, 0x02, 0xaa, 0xbb) }],
			},
		});

		const parsed = parseCertificatePem(certificate.certificate.pem, {
			decoders: [
				{
					oid: '1.2.3.4.210',
					decode(extension) {
						return extension.valueHex;
					},
				},
			],
		});

		expect(parsed.decodedExtensions).toEqual([
			{ oid: '1.2.3.4.210', critical: false, value: '0402aabb' },
		]);
		const typedParsed = parseCertificatePem(certificate.certificate.pem, {
			decoderMap: defineExtensionDecoderMap({
				customText: {
					oid: '1.2.3.4.210',
					decode: (extension: { readonly valueHex: string }) => extension.valueHex,
				},
			}),
		});
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
		const parsed = parseCertificatePem(leaf.pem);
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
		const parsed = parseCertificatePem(certificate.pem);
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
		const parsed = parseCertificatePem(certificate.pem);
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
		const parsed = parseCertificatePem(certificate.pem);
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

		const parsed = parseCertificatePem(certificate.certificate.pem);
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

		const parsed = parseCertificateSigningRequestPem(csr.pem);
		expect(parsed.certificatePolicies).toEqual([{ policyIdentifier: '1.2.3.4.1' }]);
		expect(parsed.policyMappings).toEqual([
			{ issuerDomainPolicy: '1.2.3.4.1', subjectDomainPolicy: '1.2.3.4.2' },
		]);
		expect(parsed.policyConstraints).toEqual({ requireExplicitPolicy: 1 });
		expect(parsed.inhibitAnyPolicy).toEqual({ skipCerts: 4 });
	});

	it('throws on malformed or truncated DER input', () => {
		expect(() => parseCertificateDer(new Uint8Array([0x30, 0x03, 0x01]))).toThrow();
		expect(() => parseCertificateDer(new Uint8Array([]))).toThrow();
		expect(() => parseCertificatePem('not a pem')).toThrow();
		expect(() => parseCertificateDer(new Uint8Array([0xff, 0xff]))).toThrow();
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
		const parsed = parseCertificatePem(root.certificate.pem);
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
		const parsed = parseCertificatePem(leaf.pem);
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
		const parsed = parseCertificatePem(leaf.pem);
		expect(parsed.subjectAltNames?.some((san) => san.type === 'unknown')).toBe(true);
	});

	it('parses SRV-ID subjectAltName otherName values from certificates', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: 'srv-id.example' },
			extensions: {
				subjectAltNames: [{ type: 'srv', value: '_xmpp.example.com' }],
			},
		});

		const parsed = parseCertificatePem(certificate.pem);
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

		const parsed = parseCertificateSigningRequestPem(csr.pem);
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

		const parsed = parseCertificatePem(certificate.pem);
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

		expect(() => parseCertificatePem(certificate.pem)).toThrow(/SRV-ID/i);
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
		const parsed = parseCertificatePem(root.certificate.pem);
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
		expect(() => parseCertificatePem(certificate.certificate.pem)).toThrow(
			'certificatePolicies must not be empty',
		);
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
		expect(() => parseCertificatePem(certificate.certificate.pem)).toThrow(
			'policyMappings must not use anyPolicy',
		);
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
		expect(() => parseCertificatePem(certificate.certificate.pem)).toThrow(
			'cps policy qualifier must use IA5String',
		);
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
		expect(() => parseCertificatePem(trailing.certificate.pem)).toThrow(
			'policyInformation has unexpected trailing fields',
		);

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
		expect(() => parseCertificatePem(emptyQualifiers.certificate.pem)).toThrow(
			'policyQualifiers must not be empty',
		);
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
		expect(() => parseCertificatePem(qualifierTrailing.certificate.pem)).toThrow(
			'policyQualifierInfo has unexpected trailing fields',
		);

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
		expect(() => parseCertificatePem(duplicateNoticeRef.certificate.pem)).toThrow(
			'userNotice must not contain multiple noticeRef values',
		);

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
		expect(() => parseCertificatePem(duplicateExplicitText.certificate.pem)).toThrow(
			'userNotice must not contain multiple explicitText values',
		);
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
		expect(() => parseCertificatePem(noticeRefTrailing.certificate.pem)).toThrow(
			'noticeRef has unexpected trailing fields',
		);

		const emptyMappings = await createSelfSignedCertificate({
			subject: { commonName: 'bad-empty-mappings.example' },
			extensions: {
				customExtensions: [{ oid: OIDS.policyMappings, critical: true, value: sequence([]) }],
			},
		});
		expect(() => parseCertificatePem(emptyMappings.certificate.pem)).toThrow(
			'policyMappings must not be empty',
		);

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
		expect(() => parseCertificatePem(trailingMapping.certificate.pem)).toThrow(
			'policyMappings entry has unexpected trailing fields',
		);

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
		expect(() => parseCertificatePem(duplicateRequire.certificate.pem)).toThrow(
			'policyConstraints must not repeat requireExplicitPolicy',
		);

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
		expect(() => parseCertificatePem(unsupportedPolicyConstraint.certificate.pem)).toThrow(
			'Unsupported policyConstraints field tag: 130',
		);

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
		expect(() => parseCertificatePem(duplicateInhibit.certificate.pem)).toThrow(
			'policyConstraints must not repeat inhibitPolicyMapping',
		);
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
		expect(() => parseCertificatePem(badDistributionPointName.certificate.pem)).toThrow(
			'Unsupported distributionPointName tag: 130',
		);

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
		expect(() => parseCertificatePem(badSrvId.certificate.pem)).toThrow(
			'SRV-ID otherName value must use explicit [0]',
		);

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
		expect(() => parseCertificatePem(badDisplayText.certificate.pem)).toThrow(
			'Unsupported DisplayText tag: 2',
		);
	});

	it('preserves x400Address and ediPartyName name constraints and drops unknown tags', () => {
		const result = parseNameConstraints(
			sequence([
				tlv(
					0xa0,
					concatBytes([
						sequence([tlv(0xa3, Uint8Array.of(0x01, 0x02))]),
						sequence([tlv(0xa5, Uint8Array.of(0x03, 0x04))]),
						sequence([tlv(0x89, Uint8Array.of(0x05, 0x06))]),
					]),
				),
			]),
		);
		expect(result.permittedSubtrees).toEqual([
			{ base: { type: 'x400Address', value: Uint8Array.of(0x01, 0x02) } },
			{ base: { type: 'ediPartyName', value: Uint8Array.of(0x03, 0x04) } },
		]);
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
		expect(() => parseCertificatePem(certificate.certificate.pem)).toThrow(
			'noticeRef noticeNumbers must not be empty',
		);
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

		expect(parseCertificatePem(certificate.certificate.pem).certificatePolicies).toEqual([
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

		expect(() => parseCertificatePem(certificate.certificate.pem)).toThrow(
			'Invalid BMPString length',
		);
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
		expect(() => parseCertificatePem(certificate.certificate.pem)).toThrow(
			'inhibitAnyPolicy must be an INTEGER',
		);
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
		expect(() => parseCertificatePem(certificate.certificate.pem)).toThrow(
			'policyConstraints must set requireExplicitPolicy or inhibitPolicyMapping',
		);
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
		const parsed = parseCertificatePem(root.certificate.pem);
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
		const parsed = parseCertificateSigningRequestPem(csr.pem);
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
		const parsed = parseCertificateDer(der);
		expect(parsed.subject.values.commonName).toBe('no-ext-cert.example');
		expect(parsed.extensions).toHaveLength(0);
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
		const parsed = parseCertificateSigningRequestDer(der);
		expect(parsed.subject.values.commonName).toBe('bare-csr.example');
		expect(parsed.requestedExtensions).toHaveLength(0);
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
			}).then((cert) => parseCertificatePem(cert.certificate.pem));
		}).toThrow('Unsupported authorityInfoAccess location tag');
	});

	it('parseAuthorityKeyIdentifier returns undefined for AKI without keyIdentifier', async () => {
		// Create certificate without auto-AKI, then add custom AKI with only serialNumber
		// Use createCertificate with a separate issuer to get an AKI, but we need to
		// manually construct a cert DER with custom AKI. Instead, use parseCertificateDer
		// on a manually-tweaked cert.
		//
		// Simplest: create a self-signed cert (which auto-adds AKI with keyId from SKI),
		// then manually rebuild the extension with AKI that has no keyId.
		// But actually, we can just create a CA cert and an issued cert WITHOUT
		// passing issuerPublicKey (which should skip AKI).
		// Actually, createSelfSignedCertificate always adds AKI from its own public key.
		//
		// Let's use a different approach: build a minimal TBS cert DER directly.
		// Actually, the simplest approach is to use createCertificate (not self-signed)
		// and NOT pass issuerPublicKey — but that won't add AKI at all.
		//
		// We need a cert WITH an AKI extension that has no 0x80 child. This requires
		// manually constructing the DER. The function parseAuthorityKeyIdentifier in parse.ts
		// is called during parseCertificateDer, so we need to feed it a DER certificate
		// with a custom AKI. Let's just build a cert, get its DER, and splice in a
		// custom AKI extension.
		//
		// Actually, there's an easier way: create a regular cert with AKI, parse the DER,
		// find the AKI extension, replace its value, then re-parse.
		//
		// Simplest for coverage: test that parseCertificateDer with an AKI extension
		// containing only authorityCertIssuer [1] returns undefined for AKI.
		// Since we can't easily inject custom AKI into a signed cert (signature would
		// break), and parseCertificateDer doesn't verify signature, we CAN modify the
		// DER bytes.
		const keys = await generateKeyPair();
		const cert = await createSelfSignedCertificate({
			subject: { commonName: 'aki-test.example' },
			keyPair: keys,
			extensions: {
				keyUsage: ['digitalSignature'],
			},
		});
		// The AKI extension value is SEQUENCE { [0] keyIdentifier }.
		// We want to replace it with SEQUENCE { [1] authorityCertIssuer }.
		// parseCertificateDer doesn't verify the signature, so we can modify the DER.
		const { pemDecode } = await import('#micro509');
		const derBytes = pemDecode('CERTIFICATE', cert.certificate.pem);
		const der = new Uint8Array(derBytes);
		// Find AKI OID bytes (2.5.29.35 = 55 1D 23) in the DER
		const akiOidBytes = [0x55, 0x1d, 0x23];
		let akiOffset = -1;
		for (let i = 0; i < der.length - 3; i++) {
			if (
				der[i] === akiOidBytes[0] &&
				der[i + 1] === akiOidBytes[1] &&
				der[i + 2] === akiOidBytes[2]
			) {
				akiOffset = i;
				break;
			}
		}
		expect(akiOffset).not.toBe(-1);
		// After the OID, there's an OCTET STRING containing SEQUENCE { [0] keyId }.
		// Find the [0] tag (0x80) after the OID and change it to [1] (0xa1) so it's
		// no longer a keyIdentifier.
		let tagOffset = akiOffset + 3;
		// Skip past the OCTET STRING wrapper to find the 0x80 tag
		while (tagOffset < der.length && der[tagOffset] !== 0x80) {
			tagOffset++;
		}
		if (tagOffset < der.length) {
			der[tagOffset] = 0xa1; // Change [0] to [1] (authorityCertIssuer)
		}
		const parsed = parseCertificateDer(der);
		expect(parsed.authorityKeyIdentifier).toBeUndefined();
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
		expect(() => parseCertificatePem(cert.certificate.pem)).toThrow(
			'Unsupported IP address length',
		);
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
		expect(() => parseCertificatePem(cert.certificate.pem)).toThrow('Invalid BIT STRING');
	});
});
