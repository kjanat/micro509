import { describe, expect, it } from 'bun:test';
import { X509Certificate } from 'node:crypto';
import {
	createCertificate,
	createSelfSignedCertificate,
	findExtension,
	generateKeyPair,
	parseCertificatePem,
	verifyCertificateChain,
} from '#micro509';
import { readElement } from '#micro509/der.ts';
import { OIDS } from '#micro509/oids.ts';
import { childrenOf, decodeObjectIdentifier, hasExtensionOid } from './helpers.ts';

describe('certificate', () => {
	it('creates a self-signed certificate with SANs and exportable keys', async () => {
		const result = await createSelfSignedCertificate({
			subject: {
				commonName: 'example.com',
				organization: 'Acme',
				country: 'US',
			},
			validity: { days: 14 },
			extensions: {
				keyUsage: ['digitalSignature', 'keyEncipherment'],
				subjectAltNames: [
					{ type: 'dns', value: 'example.com' },
					{ type: 'ip', value: '127.0.0.1' },
				],
			},
		});

		const certificate = new X509Certificate(result.certificate.pem);
		expect(result.certificate.pem).toContain('BEGIN CERTIFICATE');
		expect(result.certificate.der.byteLength).toBeGreaterThan(0);
		expect(certificate.subject).toContain('CN=example.com');
		expect(certificate.issuer).toContain('CN=example.com');
		expect(certificate.checkHost('example.com')).toBe('example.com');
		expect(certificate.checkIP('127.0.0.1')).toBe('127.0.0.1');
		expect(await result.keyPair.exportPkcs8Pem()).toContain('BEGIN PRIVATE KEY');
		expect(await result.keyPair.exportSpkiPem()).toContain('BEGIN PUBLIC KEY');
		expect(await result.keyPair.exportPublicJwk()).toHaveProperty('kty');
	});

	it('creates a leaf certificate signed by a CA', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Micro509 Test CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Micro509 Test CA' },
			subject: { commonName: 'leaf.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				keyUsage: ['digitalSignature'],
				extendedKeyUsage: ['serverAuth', { type: 'oid', value: '1.2.3.4.5' }],
				authorityInfoAccess: [
					{ method: 'ocsp', uri: 'http://ocsp.example.test' },
					{ method: 'caIssuers', uri: 'http://issuer.example.test/ca.der' },
				],
				crlDistributionPoints: [
					{
						distributionPoint: {
							fullName: [{ type: 'uri', value: 'http://issuer.example.test/ca.crl' }],
						},
					},
				],
				subjectAltNames: [{ type: 'dns', value: 'leaf.example' }],
			},
		});

		const leafCertificate = new X509Certificate(leaf.pem);
		expect(leafCertificate.issuer).toContain('CN=Micro509 Test CA');
		expect(leafCertificate.checkHost('leaf.example')).toBe('leaf.example');
		expect(
			await verifyCertificateChain({
				leaf: leaf.pem,
				roots: [ca.certificate.pem],
				purpose: 'serverAuth',
				serviceIdentity: { type: 'dns', value: 'leaf.example' },
			}),
		).toMatchObject({ ok: true });
		expect(hasExtensionOid(leaf.der, OIDS.extendedKeyUsage)).toBe(true);
		const parsed = parseCertificatePem(leaf.pem);
		expect(parsed.subject.values.commonName).toBe('leaf.example');
		expect(parsed.issuer.values.commonName).toBe('Micro509 Test CA');
		expect(parsed.subjectAltNames).toEqual([{ type: 'dns', value: 'leaf.example' }]);
		expect(parsed.extendedKeyUsage).toEqual(['serverAuth', { type: 'oid', value: '1.2.3.4.5' }]);
		expect(parsed.authorityInfoAccess).toEqual([
			{ method: 'ocsp', uri: 'http://ocsp.example.test' },
			{ method: 'caIssuers', uri: 'http://issuer.example.test/ca.der' },
		]);
		expect(parsed.crlDistributionPoints).toEqual([
			{
				distributionPoint: {
					fullName: [{ type: 'uri', value: 'http://issuer.example.test/ca.crl' }],
				},
			},
		]);
	});

	it('parses structured CRL distribution points with full and relative names', async () => {
		const ca = await createSelfSignedCertificate({
			subject: { commonName: 'Structured DP CA' },
			extensions: {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign', 'cRLSign'],
			},
		});
		const leafKeys = await generateKeyPair();
		const leaf = await createCertificate({
			issuer: { commonName: 'Structured DP CA' },
			subject: { commonName: 'structured-dp.example' },
			publicKey: leafKeys.publicKey,
			signerPrivateKey: ca.keyPair.privateKey,
			issuerPublicKey: ca.keyPair.publicKey,
			extensions: {
				crlDistributionPoints: [
					{
						distributionPoint: {
							relativeName: [
								{ type: 'organization', value: 'Example PKI' },
								{ type: 'commonName', value: 'leaf-partition' },
							],
						},
						reasons: ['keyCompromise', 'privilegeWithdrawn'],
						crlIssuer: [
							{ type: 'dns', value: 'crl-issuer.example.test' },
							{ type: 'uri', value: 'http://issuer.example.test/alt.crl' },
						],
					},
					{
						distributionPoint: {
							fullName: [
								{ type: 'uri', value: 'http://issuer.example.test/full.crl' },
								{ type: 'dns', value: 'full-crl.example.test' },
							],
						},
					},
				],
				subjectAltNames: [{ type: 'dns', value: 'structured-dp.example' }],
			},
		});

		const parsed = parseCertificatePem(leaf.pem);
		expect(parsed.crlDistributionPoints).toHaveLength(2);
		expect(parsed.crlDistributionPoints?.[0]).toMatchObject({
			distributionPoint: {
				relativeName: {
					values: {
						organization: 'Example PKI',
						commonName: 'leaf-partition',
					},
				},
			},
			reasons: ['keyCompromise', 'privilegeWithdrawn'],
			crlIssuer: [
				{ type: 'dns', value: 'crl-issuer.example.test' },
				{ type: 'uri', value: 'http://issuer.example.test/alt.crl' },
			],
		});
		expect(parsed.crlDistributionPoints?.[1]).toEqual({
			distributionPoint: {
				fullName: [
					{ type: 'uri', value: 'http://issuer.example.test/full.crl' },
					{ type: 'dns', value: 'full-crl.example.test' },
				],
			},
		});
	});

	it('roundtrips CRL distribution points that only name an alternate CRL issuer', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: 'issuer-only-dp.example' },
			extensions: {
				crlDistributionPoints: [
					{
						reasons: ['cACompromise'],
						crlIssuer: [
							{ type: 'dns', value: 'indirect-issuer.example.test' },
							{ type: 'uri', value: 'http://issuer.example.test/indirect.crl' },
						],
					},
				],
			},
		});

		const parsed = parseCertificatePem(certificate.pem);
		expect(parsed.crlDistributionPoints).toEqual([
			{
				reasons: ['cACompromise'],
				crlIssuer: [
					{ type: 'dns', value: 'indirect-issuer.example.test' },
					{ type: 'uri', value: 'http://issuer.example.test/indirect.crl' },
				],
			},
		]);
	});

	it('roundtrips email, URI, and IPv6 SANs through build and parse', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: 'san-variety' },
			extensions: {
				subjectAltNames: [
					{ type: 'email', value: 'user@example.com' },
					{ type: 'uri', value: 'https://example.com/path' },
					{ type: 'ip', value: 'fe80::1' },
				],
			},
		});
		const parsed = parseCertificatePem(certificate.pem);
		expect(parsed.subjectAltNames).toEqual([
			{ type: 'email', value: 'user@example.com' },
			{ type: 'uri', value: 'https://example.com/path' },
			{ type: 'ip', value: 'fe80:0:0:0:0:0:0:1' },
		]);
	});

	it('passes through custom AIA method OIDs', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: 'aia-custom' },
			extensions: {
				authorityInfoAccess: [
					{
						method: { type: 'oid', value: '1.3.6.1.5.5.7.48.99' },
						uri: 'http://custom.example/aia',
					},
				],
			},
		});
		const parsed = parseCertificatePem(certificate.pem);
		expect(parsed.authorityInfoAccess).toEqual([
			{
				method: { type: 'oid', value: '1.3.6.1.5.5.7.48.99' },
				uri: 'http://custom.example/aia',
			},
		]);
	});

	it('round-trips policy extensions through certificate create/parse flows', async () => {
		const { certificate } = await createSelfSignedCertificate({
			subject: { commonName: 'policy-cert.example' },
			extensions: {
				certificatePolicies: [
					{
						policyIdentifier: '1.2.3.4.1',
						policyQualifiers: [
							{ type: 'cps', uri: 'https://example.com/cps' },
							{
								type: 'userNotice',
								noticeRef: {
									organization: 'Example PKI',
									noticeNumbers: [7],
								},
								explicitText: 'policy notice',
							},
						],
					},
				],
				policyMappings: [{ issuerDomainPolicy: '1.2.3.4.1', subjectDomainPolicy: '1.2.3.4.2' }],
				policyConstraints: {
					requireExplicitPolicy: 1,
					inhibitPolicyMapping: 2,
				},
				inhibitAnyPolicy: { skipCerts: 3 },
			},
		});

		const parsed = parseCertificatePem(certificate.pem);
		const certificatePolicies = findExtension(parsed.extensions, OIDS.certificatePolicies);
		const policyMappings = findExtension(parsed.extensions, OIDS.policyMappings);
		const policyConstraints = findExtension(parsed.extensions, OIDS.policyConstraints);
		const inhibitAnyPolicy = findExtension(parsed.extensions, OIDS.inhibitAnyPolicy);

		expect(parsed.certificatePolicies).toEqual([
			{
				policyIdentifier: '1.2.3.4.1',
				policyQualifiers: [
					{ type: 'cps', uri: 'https://example.com/cps' },
					{
						type: 'userNotice',
						noticeRef: {
							organization: 'Example PKI',
							noticeNumbers: [7],
						},
						explicitText: 'policy notice',
					},
				],
			},
		]);
		expect(parsed.policyMappings).toEqual([
			{ issuerDomainPolicy: '1.2.3.4.1', subjectDomainPolicy: '1.2.3.4.2' },
		]);
		expect(parsed.policyConstraints).toEqual({
			requireExplicitPolicy: 1,
			inhibitPolicyMapping: 2,
		});
		expect(parsed.inhibitAnyPolicy).toEqual({ skipCerts: 3 });
		expect(certificatePolicies?.critical).toBe(false);
		expect(policyMappings?.critical).toBe(true);
		expect(policyConstraints?.critical).toBe(true);
		expect(inhibitAnyPolicy?.critical).toBe(true);
		expect(readPolicyInformationOids(certificatePolicies?.valueDer)).toEqual(['1.2.3.4.1']);
		expect(readPolicyQualifierOids(certificatePolicies?.valueDer)).toEqual([
			OIDS.cpsPolicyQualifier,
			OIDS.userNoticePolicyQualifier,
		]);
		expect(readPolicyMappings(policyMappings?.valueDer)).toEqual([['1.2.3.4.1', '1.2.3.4.2']]);
		expect(readImplicitIntegerSequence(policyConstraints?.valueDer)).toEqual([1, 2]);
		expect(readDerInteger(inhibitAnyPolicy?.valueDer)).toBe(3);
	});

	it('rejects notAfter <= notBefore', async () => {
		expect(
			createSelfSignedCertificate({
				subject: { commonName: 'bad-validity' },
				validity: {
					notBefore: new Date('2025-01-02T00:00:00Z'),
					notAfter: new Date('2025-01-01T00:00:00Z'),
				},
			}),
		).rejects.toThrow('notAfter must be after notBefore');
	});

	it('rejects empty subject name', async () => {
		expect(createSelfSignedCertificate({ subject: {} })).rejects.toThrow(
			'Name must contain at least one attribute',
		);
	});

	it('rejects invalid country code length', async () => {
		expect(createSelfSignedCertificate({ subject: { country: 'USA' } })).rejects.toThrow(
			'Country must be a 2-character code',
		);
	});

	it('creates certificates with RSA SHA-384, SHA-512 and ECDSA P-384', async () => {
		const rsaSha384 = await createSelfSignedCertificate({
			subject: { commonName: 'rsa384.example' },
			algorithm: { kind: 'rsa', modulusLength: 2048, hash: 'SHA-384' },
		});
		expect(rsaSha384.certificate.pem).toContain('BEGIN CERTIFICATE');
		const parsed384 = parseCertificatePem(rsaSha384.certificate.pem);
		expect(parsed384.signatureAlgorithmOid).toBe('1.2.840.113549.1.1.12');

		const rsaSha512 = await createSelfSignedCertificate({
			subject: { commonName: 'rsa512.example' },
			algorithm: { kind: 'rsa', modulusLength: 2048, hash: 'SHA-512' },
		});
		const parsed512 = parseCertificatePem(rsaSha512.certificate.pem);
		expect(parsed512.signatureAlgorithmOid).toBe('1.2.840.113549.1.1.13');

		const ecP384 = await createSelfSignedCertificate({
			subject: { commonName: 'ecp384.example' },
			algorithm: { kind: 'ecdsa', namedCurve: 'P-384' },
		});
		const parsedEc384 = parseCertificatePem(ecP384.certificate.pem);
		expect(parsedEc384.signatureAlgorithmOid).toBe('1.2.840.10045.4.3.3');
	});

	it('rejects pathLength without ca:true', async () => {
		expect(
			createSelfSignedCertificate({
				subject: { commonName: 'bad-bc.example' },
				extensions: {
					basicConstraints: { ca: false, pathLength: 1 },
				},
			}),
		).rejects.toThrow('pathLength requires ca=true');
	});

	it('rejects anyPolicy in policyMappings', async () => {
		expect(
			createSelfSignedCertificate({
				subject: { commonName: 'bad-policy-mapping.example' },
				extensions: {
					policyMappings: [
						{
							issuerDomainPolicy: OIDS.anyPolicy,
							subjectDomainPolicy: '1.2.3.4.2',
						},
					],
				},
			}),
		).rejects.toThrow('policyMappings must not use anyPolicy');
	});

	it('rejects empty policyConstraints input', async () => {
		expect(
			createSelfSignedCertificate({
				subject: { commonName: 'bad-policy-constraints.example' },
				extensions: {
					policyConstraints: {},
				},
			}),
		).rejects.toThrow('policyConstraints must set requireExplicitPolicy or inhibitPolicyMapping');
	});

	it('rejects empty structured distribution point names', async () => {
		expect(
			createSelfSignedCertificate({
				subject: { commonName: 'bad-dp.example' },
				extensions: {
					crlDistributionPoints: [{ distributionPoint: { fullName: [] } }],
				},
			}),
		).rejects.toThrow('DistributionPointName fullName must not be empty');
	});

	it('rejects empty structured CRL issuer lists', async () => {
		expect(
			createSelfSignedCertificate({
				subject: { commonName: 'bad-crl-issuer.example' },
				extensions: {
					crlDistributionPoints: [{ crlIssuer: [] }],
				},
			}),
		).rejects.toThrow('DistributionPoint crlIssuer must not be empty');
	});
});

function readPolicyInformationOids(valueDer: Uint8Array | undefined): readonly string[] {
	const extensionValue = requireElementBytes(valueDer, 'policy extension value');
	return childrenOf(extensionValue, readElement(extensionValue)).map((policyInformation) => {
		const oid = childrenOf(extensionValue, policyInformation)[0];
		if (oid === undefined) {
			throw new Error('Missing policyIdentifier');
		}
		return decodeObjectIdentifier(oid.value);
	});
}

function readPolicyQualifierOids(valueDer: Uint8Array | undefined): readonly string[] {
	const extensionValue = requireElementBytes(valueDer, 'policy extension value');
	const policyInformation = childrenOf(extensionValue, readElement(extensionValue))[0];
	if (policyInformation === undefined) {
		throw new Error('Missing policyInformation');
	}
	const qualifiers = childrenOf(extensionValue, policyInformation)[1];
	if (qualifiers === undefined) {
		throw new Error('Missing policyQualifiers');
	}
	return childrenOf(extensionValue, qualifiers).map((qualifier) => {
		const oid = childrenOf(extensionValue, qualifier)[0];
		if (oid === undefined) {
			throw new Error('Missing policyQualifierId');
		}
		return decodeObjectIdentifier(oid.value);
	});
}

function readPolicyMappings(
	valueDer: Uint8Array | undefined,
): readonly (readonly [string, string])[] {
	const extensionValue = requireElementBytes(valueDer, 'policy mappings value');
	return childrenOf(extensionValue, readElement(extensionValue)).map((mapping) => {
		const fields = childrenOf(extensionValue, mapping);
		const issuer = fields[0];
		const subject = fields[1];
		if (issuer === undefined || subject === undefined) {
			throw new Error('Missing policy mapping field');
		}
		return [decodeObjectIdentifier(issuer.value), decodeObjectIdentifier(subject.value)] as const;
	});
}

function readImplicitIntegerSequence(valueDer: Uint8Array | undefined): readonly number[] {
	const extensionValue = requireElementBytes(valueDer, 'policy constraints value');
	return childrenOf(extensionValue, readElement(extensionValue)).map((field) =>
		readUnsignedInteger(field.value),
	);
}

function readDerInteger(valueDer: Uint8Array | undefined): number {
	const extensionValue = requireElementBytes(valueDer, 'integer extension value');
	return readUnsignedInteger(readElement(extensionValue).value);
}

function readUnsignedInteger(bytes: Uint8Array): number {
	let value = 0;
	for (const byte of bytes) {
		value = value * 256 + byte;
	}
	return value;
}

function requireElementBytes(value: Uint8Array | undefined, label: string): Uint8Array {
	if (value === undefined) {
		throw new Error(`Missing ${label}`);
	}
	return value;
}
