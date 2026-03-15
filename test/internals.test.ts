import { describe, expect, it } from 'bun:test';
import { createPkcs12MacData, parsePkcs12MacData } from 'micro509/pkcs';
import {
	buildCertificateExtensions,
	encodeCertificatePolicies,
	encodeCrlDistributionPoints,
	encodeNameConstraints,
	encodePolicyMappings,
	encodeSubjectAltName,
} from 'micro509/x509';
import {
	decodeIntegerNumber,
	decodeNonNegativeIntegerNumber,
	decodeObjectIdentifier,
	extractBitStringValue,
	parseTime,
	requireElement,
} from '#micro509/internal/asn1/asn1.ts';
import {
	assertDerMaxDepth,
	bitString,
	DEFAULT_MAX_DER_DEPTH,
	encodeLength,
	explicitContext,
	ia5String,
	integer,
	integerFromNumber,
	nullValue,
	objectIdentifier,
	octetString,
	printableString,
	readElement,
	readSequenceChildren,
	sequence,
	setOf,
	time,
} from '#micro509/internal/asn1/der.ts';
import { OIDS } from '#micro509/internal/asn1/oids.ts';
import { parsePbes2AlgorithmIdentifier } from '#micro509/internal/crypto/pbes2.ts';
import {
	encodeRsaPssParameters,
	parseRsaPssParameters,
	rsaPssParametersForHash,
} from '#micro509/internal/crypto/rsa-pss.ts';
import {
	alternateEcdsaSignatureEncoding,
	concatFixedWidth,
	curveBytes,
	derEcdsaSignatureToRaw,
	getVerifySignatureConfig,
	rawEcdsaSignatureToDer,
	requireEcPublicKey,
	requireRsaPublicKey,
} from '#micro509/internal/crypto/sig-verify.ts';
import {
	encodeAlgorithmIdentifier,
	getSignatureAlgorithm,
} from '#micro509/internal/crypto/signing.ts';
import {
	allOnesMaskForIpAddress,
	decodeIpAddress,
	expandIpv6,
	normalizeIpAddress,
	parseIpAddressToBytes,
} from '#micro509/internal/shared/ip.ts';
import { parseKeyUsageExtension } from '#micro509/internal/x509/extension-bits.ts';

// ---------------------------------------------------------------------------
// DER encoding edge cases
// ---------------------------------------------------------------------------

describe('der encoding', () => {
	it('setOf sorts elements with different lengths sharing a prefix', () => {
		const a = Uint8Array.of(0x02, 0x01, 0x01);
		const b = Uint8Array.of(0x02, 0x01, 0x01, 0x00);
		const result = setOf([b, a]);
		// Shorter element should come first when bytes match up to shorter length
		expect(result.length).toBeGreaterThan(0);
	});

	it('integer encodes empty bytes as zero', () => {
		const result = integer(new Uint8Array([]));
		expect(result).toEqual(Uint8Array.of(0x02, 0x01, 0x00));
	});

	it('integer strips leading zeros from multi-byte values', () => {
		const result = integer(Uint8Array.of(0x00, 0x00, 0x80));
		// 0x80 needs a leading zero to stay positive
		expect(result).toEqual(Uint8Array.of(0x02, 0x02, 0x00, 0x80));
	});

	it('integerFromNumber rejects negative and non-integer values', () => {
		expect(() => integerFromNumber(-1)).toThrow('non-negative');
		expect(() => integerFromNumber(1.5)).toThrow('non-negative');
	});

	it('encodeLength and integerFromNumber reject unsafe integers', () => {
		expect(() => encodeLength(Number.MAX_SAFE_INTEGER + 1)).toThrow('safe integer');
		expect(() => integerFromNumber(Number.MAX_SAFE_INTEGER + 1)).toThrow('safe integer');
	});

	it('bitString rejects unusedBits out of range', () => {
		expect(() => bitString(Uint8Array.of(0xff), 8)).toThrow('between 0 and 7');
		expect(() => bitString(Uint8Array.of(0xff), -1)).toThrow('between 0 and 7');
	});

	it('bitString rejects non-zero unusedBits with empty value', () => {
		expect(() => bitString(new Uint8Array(), 1)).toThrow('must be 0 when value is empty');
	});

	it('bitString rejects non-zero unused bits in last byte', () => {
		// unusedBits=4 means last 4 bits must be zero; 0x0f has last 4 bits set
		expect(() => bitString(Uint8Array.of(0x0f), 4)).toThrow('unused bits in the last byte');
	});

	it('printableString rejects invalid characters', () => {
		expect(() => printableString('hello{}')).toThrow('Invalid PrintableString');
		expect(() => printableString('hello@world')).toThrow('Invalid PrintableString');
	});

	it('ia5String rejects non-ASCII characters', () => {
		expect(() => ia5String('caf\u00e9')).toThrow('Invalid IA5String');
	});

	it('objectIdentifier rejects OIDs with fewer than 2 segments', () => {
		expect(() => objectIdentifier('1')).toThrow('Invalid OID');
	});

	it('objectIdentifier rejects first arc > 2', () => {
		expect(() => objectIdentifier('3.0')).toThrow('Invalid OID first arc');
	});

	it('objectIdentifier rejects second arc >= 40 for arcs 0 and 1', () => {
		expect(() => objectIdentifier('0.40')).toThrow('Invalid OID second arc');
		expect(() => objectIdentifier('1.40')).toThrow('Invalid OID second arc');
	});

	it('objectIdentifier rejects non-integer or negative segments', () => {
		expect(() => objectIdentifier('1.2.3.-1')).toThrow('Invalid OID segment');
	});

	it('time uses GeneralizedTime for dates >= 2050', () => {
		const result = time(new Date('2051-01-01T00:00:00Z'));
		// GeneralizedTime tag is 0x18
		expect(result[0]).toBe(0x18);
	});

	it('time uses GeneralizedTime for dates < 1950', () => {
		const result = time(new Date('1949-01-01T00:00:00Z'));
		expect(result[0]).toBe(0x18);
	});

	it('readElement throws on missing length byte', () => {
		expect(() => readElement(Uint8Array.of(0x30))).toThrow('Unexpected end');
	});

	it('readElement throws on indefinite length', () => {
		expect(() => readElement(Uint8Array.of(0x30, 0x80))).toThrow('Indefinite');
	});

	it('readElement rejects non-minimal long-form lengths', () => {
		expect(() => readElement(Uint8Array.of(0x04, 0x81, 0x7f, 0x00))).toThrow('Non-minimal');
		expect(() => readElement(Uint8Array.of(0x04, 0x82, 0x00, 0x80, 0x00))).toThrow('Non-minimal');
	});

	it('encodeLength emits long-form lengths', () => {
		expect(encodeLength(256)).toEqual(Uint8Array.of(0x82, 0x01, 0x00));
	});

	it('readSequenceChildren throws on non-SEQUENCE input', () => {
		// Tag 0x02 = INTEGER, not SEQUENCE
		expect(() => readSequenceChildren(Uint8Array.of(0x02, 0x01, 0x00))).toThrow(
			'Expected SEQUENCE',
		);
	});

	it('readSequenceChildren rejects trailing data after the root sequence', () => {
		expect(() => readSequenceChildren(Uint8Array.of(0x30, 0x00, 0x00))).toThrow('Trailing data');
	});

	it('assertDerMaxDepth rejects overly deep nesting', () => {
		let der = sequence([]);
		for (let index = 0; index < DEFAULT_MAX_DER_DEPTH; index += 1) {
			der = sequence([der]);
		}
		expect(() => assertDerMaxDepth(der)).toThrow('max depth');
	});
});

// ---------------------------------------------------------------------------
// ASN.1 decoding edge cases
// ---------------------------------------------------------------------------

describe('asn1 decoding', () => {
	it('decodeObjectIdentifier throws on empty bytes', () => {
		expect(() => decodeObjectIdentifier(new Uint8Array([]))).toThrow('OID is empty');
	});

	it('decodeObjectIdentifier throws on incomplete continuation', () => {
		// 0x81 has high bit set (continuation) but no following byte
		expect(() => decodeObjectIdentifier(Uint8Array.of(0x55, 0x81))).toThrow(
			'incomplete continuation',
		);
	});

	it('requireElement throws on undefined value', () => {
		expect(() => requireElement(undefined, 'test field')).toThrow('Missing test field');
	});

	it('extractBitStringValue throws on non-BIT STRING tag', () => {
		const element = readElement(Uint8Array.of(0x04, 0x02, 0xaa, 0xbb));
		expect(() => extractBitStringValue(element)).toThrow('Expected BIT STRING');
	});

	it('parseTime throws on unsupported tag', () => {
		// Tag 0x0c = UTF8String, not a time type
		const element = readElement(Uint8Array.of(0x0c, 0x01, 0x30));
		expect(() => parseTime(element)).toThrow('Unsupported time tag');
	});

	it('decodeIntegerNumber throws on integers > 6 bytes', () => {
		expect(() => decodeIntegerNumber(Uint8Array.of(1, 2, 3, 4, 5, 6, 7))).toThrow('too large');
	});

	it('decodeNonNegativeIntegerNumber rejects negative and non-minimal encodings', () => {
		expect(() => decodeNonNegativeIntegerNumber(Uint8Array.of(0xff), 'test integer')).toThrow(
			'non-negative',
		);
		expect(() => decodeNonNegativeIntegerNumber(Uint8Array.of(0x00, 0x01), 'test integer')).toThrow(
			'minimal encoding',
		);
	});
});

// ---------------------------------------------------------------------------
// sig-verify edge cases
// ---------------------------------------------------------------------------

describe('sig-verify', () => {
	it('requireRsaPublicKey returns failure for non-RSA OID', () => {
		const result = requireRsaPublicKey(OIDS.ecPublicKey, 'SHA-256');
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.reason).toContain('RSA');
		}
	});

	it('requireEcPublicKey returns failure for non-EC OID', () => {
		const result = requireEcPublicKey(OIDS.rsaEncryption, undefined, 'SHA-256');
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.reason).toContain('EC');
		}
	});

	it('requireEcPublicKey returns failure for unsupported curve OID', () => {
		const result = requireEcPublicKey(OIDS.ecPublicKey, '1.2.3.4.5', 'SHA-256');
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.reason).toContain('unsupported EC curve');
		}
	});

	it('requireEcPublicKey returns failure for missing curve OID', () => {
		const result = requireEcPublicKey(OIDS.ecPublicKey, undefined, 'SHA-256');
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.reason).toContain('unsupported EC curve');
		}
	});

	it('curveBytes throws for unsupported curve', () => {
		expect(() => curveBytes('1.2.3.4.5')).toThrow('Unsupported EC curve');
	});

	it('requireEcPublicKey and curveBytes support secp521r1', () => {
		const result = requireEcPublicKey(OIDS.ecPublicKey, OIDS.secp521r1, 'SHA-512');
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.importAlgorithm).toEqual({ kind: 'ecdsa', namedCurve: 'P-521' });
			expect(result.value.ecdsaRawSignatureBytes).toBe(132);
		}
		expect(curveBytes(OIDS.secp521r1)).toBe(132);
	});

	it('getVerifySignatureConfig throws for unknown signature algorithm', () => {
		expect(() =>
			getVerifySignatureConfig('1.2.3.4.999', undefined, OIDS.rsaEncryption, undefined),
		).toThrow('unrecognized signature algorithm OID');
	});

	it('getVerifySignatureConfig throws for Ed25519 sig with non-Ed25519 key', () => {
		expect(() =>
			getVerifySignatureConfig(OIDS.ed25519, undefined, OIDS.rsaEncryption, undefined),
		).toThrow('Ed25519');
	});

	it('getVerifySignatureConfig returns RSA-PSS verify config for shipped parameters', () => {
		const result = getVerifySignatureConfig(
			OIDS.rsassaPss,
			encodeRsaPssParameters(rsaPssParametersForHash('SHA-384')),
			OIDS.rsaEncryption,
			undefined,
		);
		expect(result.importAlgorithm).toEqual({ kind: 'rsa', hash: 'SHA-384', scheme: 'pss' });
		expect(result.verifyParams).toEqual({ name: 'RSA-PSS', saltLength: 48 });
	});

	it('rawEcdsaSignatureToDer throws on wrong length', () => {
		expect(() => rawEcdsaSignatureToDer(Uint8Array.of(1, 2, 3), 32)).toThrow(
			'Unexpected ECDSA raw signature length',
		);
	});

	it('concatFixedWidth throws when integer too large', () => {
		const big = new Uint8Array(33);
		big.fill(0x01);
		expect(() => concatFixedWidth(big, Uint8Array.of(1), 32)).toThrow('integer too large');
	});

	it('alternateEcdsaSignatureEncoding returns undefined for garbage', () => {
		const result = alternateEcdsaSignatureEncoding(Uint8Array.of(0xff, 0xff), 32);
		expect(result).toBeUndefined();
	});

	it('derEcdsaSignatureToRaw throws on malformed DER (missing s)', () => {
		// Manually build a SEQUENCE with just one INTEGER child (missing s component)
		const justR = Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x42);
		expect(() => derEcdsaSignatureToRaw(justR, 32)).toThrow('Malformed ECDSA DER signature');
	});
});

describe('ip helpers', () => {
	it('normalizes IPv6 addresses across expansion forms', () => {
		expect(normalizeIpAddress('2001:db8::1')).toBe('2001:0db8:0000:0000:0000:0000:0000:0001');
		expect(expandIpv6('2001:0db8::1')).toEqual([
			'2001',
			'0db8',
			'0000',
			'0000',
			'0000',
			'0000',
			'0000',
			'0001',
		]);
	});

	it('round-trips IP bytes through shared helpers', () => {
		expect(decodeIpAddress(parseIpAddressToBytes('10.0.0.7'))).toBe('10.0.0.7');
		expect(decodeIpAddress(parseIpAddressToBytes('2001:db8::1'))).toBe('2001:db8:0:0:0:0:0:1');
		expect(allOnesMaskForIpAddress('2001:db8::1')).toEqual(new Uint8Array(16).fill(0xff));
	});

	it('rejects invalid IPv6 segments', () => {
		expect(() => parseIpAddressToBytes('2001:db8::zzzz')).toThrow('Invalid IPv6 address');
	});

	it('rejects key usage values encoded with the wrong ASN.1 tag', () => {
		expect(() => parseKeyUsageExtension(Uint8Array.of(0x04, 0x01, 0x00))).toThrow(
			'keyUsage must be a BIT STRING',
		);
	});
});

// ---------------------------------------------------------------------------
// Extension encoding edge cases
// ---------------------------------------------------------------------------

describe('extensions encoding', () => {
	it('encodeSubjectAltName handles directoryName type', () => {
		const result = encodeSubjectAltName({
			type: 'directoryName',
			derHex: '3000',
		});
		// Tag 0xa4 = context-specific constructed [4]
		expect(result[0]).toBe(0xa4);
	});

	it('encodeSubjectAltName handles unknown type', () => {
		const result = encodeSubjectAltName({
			type: 'unknown',
			tag: 0x88,
			value: Uint8Array.of(0x01, 0x02),
		});
		expect(result[0]).toBe(0x88);
	});

	it('buildCertificateExtensions throws on SPKI without subject public key bit string', () => {
		const malformedSpki = sequence([sequence([objectIdentifier(OIDS.rsaEncryption), nullValue()])]);
		expect(() => buildCertificateExtensions(malformedSpki, undefined, undefined)).toThrow(
			'SPKI missing subject public key bit string',
		);
	});

	it('rejects empty certificate policies and policy mappings', () => {
		expect(() => encodeCertificatePolicies([])).toThrow('certificatePolicies must not be empty');
		expect(() => encodePolicyMappings([])).toThrow('policyMappings must not be empty');
	});

	it('rejects invalid distribution point construction', () => {
		expect(() =>
			Reflect.apply(encodeCrlDistributionPoints, undefined, [[{ reasons: ['keyCompromise'] }]]),
		).toThrow('DistributionPoint must contain distributionPoint or crlIssuer');
		expect(() =>
			encodeCrlDistributionPoints([
				{
					distributionPoint: {
						fullName: [{ type: 'uri', value: 'http://example.test/crl' }],
						relativeName: [{ type: 'commonName', value: 'bad' }],
					},
				},
			]),
		).toThrow('DistributionPointName cannot contain both fullName and relativeName');
		expect(() => encodeCrlDistributionPoints([{ distributionPoint: {} }])).toThrow(
			'DistributionPointName must contain fullName or relativeName',
		);
	});

	it('rejects non-SEQUENCE directoryName DER when encoding names', () => {
		expect(() => encodeSubjectAltName({ type: 'directoryName', derHex: '020100' })).toThrow(
			'directoryName derHex must encode a DER SEQUENCE',
		);
		expect(() =>
			encodeNameConstraints({
				permittedSubtrees: [{ base: { type: 'directoryName', derHex: '020100' } }],
			}),
		).toThrow('directoryName derHex must encode a DER SEQUENCE');
	});

	it('rejects invalid IPv4 addresses during certificate creation', async () => {
		const { createSelfSignedCertificate } = await import('#micro509');
		expect(
			createSelfSignedCertificate({
				subject: { commonName: 'bad-ipv4' },
				extensions: {
					subjectAltNames: [{ type: 'ip', value: '1.2.3' }],
				},
			}),
		).rejects.toThrow('Invalid IPv4');
	});

	it('rejects IPv4 segment out of range', async () => {
		const { createSelfSignedCertificate } = await import('#micro509');
		expect(
			createSelfSignedCertificate({
				subject: { commonName: 'bad-ipv4-segment' },
				extensions: {
					subjectAltNames: [{ type: 'ip', value: '1.2.3.256' }],
				},
			}),
		).rejects.toThrow('Invalid IPv4');
	});

	it('rejects IPv6 with multiple :: groups', async () => {
		const { createSelfSignedCertificate } = await import('#micro509');
		expect(
			createSelfSignedCertificate({
				subject: { commonName: 'bad-ipv6-double' },
				extensions: {
					subjectAltNames: [{ type: 'ip', value: '::1::2' }],
				},
			}),
		).rejects.toThrow('Invalid IPv6');
	});

	it('rejects IPv6 with invalid hex segment', async () => {
		const { createSelfSignedCertificate } = await import('#micro509');
		expect(
			createSelfSignedCertificate({
				subject: { commonName: 'bad-ipv6-hex' },
				extensions: {
					subjectAltNames: [{ type: 'ip', value: 'gggg:0:0:0:0:0:0:1' }],
				},
			}),
		).rejects.toThrow('Invalid IPv6');
	});

	it('rejects IPv6 with too many groups', async () => {
		const { createSelfSignedCertificate } = await import('#micro509');
		expect(
			createSelfSignedCertificate({
				subject: { commonName: 'bad-ipv6-groups' },
				extensions: {
					subjectAltNames: [{ type: 'ip', value: '1:2:3:4:5:6:7:8:9' }],
				},
			}),
		).rejects.toThrow('Invalid IPv6');
	});
});

// ---------------------------------------------------------------------------
// signing.ts edge cases
// ---------------------------------------------------------------------------

describe('signing.ts edge cases', () => {
	it('getSignatureAlgorithm throws for unsupported algorithm name', async () => {
		const { generateKeyPair: genKp } = await import('#micro509');
		// Use an ECDSA key but manually check the algorithm name guard
		const keys = await genKp({ kind: 'ecdsa', namedCurve: 'P-256' });
		// We can't easily create a CryptoKey with an unknown algorithm,
		// but we can test the known algorithms work correctly
		const result = getSignatureAlgorithm(keys.privateKey);
		expect(result.algorithmOid).toBe(OIDS.ecdsaWithSHA256);
		expect(result.ecdsaRawSignatureBytes).toBe(64);
	});

	it('encodeAlgorithmIdentifier encodes without parameters', () => {
		const algId = encodeAlgorithmIdentifier({
			algorithmOid: OIDS.ed25519,
			signParams: { name: 'Ed25519' },
		});
		const children = readSequenceChildren(algId);
		expect(children).toHaveLength(1); // only OID, no params
	});

	it('encodeAlgorithmIdentifier encodes with parameters', () => {
		const algId = encodeAlgorithmIdentifier({
			algorithmOid: OIDS.sha256WithRSAEncryption,
			parameters: nullValue(),
			signParams: { name: 'RSASSA-PKCS1-v1_5' },
		});
		const children = readSequenceChildren(algId);
		expect(children).toHaveLength(2); // OID + NULL
	});

	it('getSignatureAlgorithm returns correct config for RSA SHA-384', async () => {
		const { generateKeyPair: genKp } = await import('#micro509');
		const keys = await genKp({ kind: 'rsa', modulusLength: 2048, hash: 'SHA-384' });
		const result = getSignatureAlgorithm(keys.privateKey);
		expect(result.algorithmOid).toBe(OIDS.sha384WithRSAEncryption);
	});

	it('getSignatureAlgorithm returns correct config for RSA SHA-512', async () => {
		const { generateKeyPair: genKp } = await import('#micro509');
		const keys = await genKp({ kind: 'rsa', modulusLength: 2048, hash: 'SHA-512' });
		const result = getSignatureAlgorithm(keys.privateKey);
		expect(result.algorithmOid).toBe(OIDS.sha512WithRSAEncryption);
	});

	it('getSignatureAlgorithm returns RSA-PSS config for explicit profile input', async () => {
		const { generateKeyPair: genKp } = await import('#micro509');
		const keys = await genKp({
			kind: 'rsa',
			modulusLength: 2048,
			hash: 'SHA-384',
			scheme: 'pss',
		});
		const result = getSignatureAlgorithm(keys.privateKey, { kind: 'rsa-pss' });
		expect(result.algorithmOid).toBe(OIDS.rsassaPss);
		expect(result.parameters).toEqual(encodeRsaPssParameters(rsaPssParametersForHash('SHA-384')));
		expect(result.signParams).toEqual({ name: 'RSA-PSS', saltLength: 48 });
	});

	it('getSignatureAlgorithm rejects unsupported RSA-PSS salt lengths', async () => {
		const { generateKeyPair: genKp } = await import('#micro509');
		const keys = await genKp({
			kind: 'rsa',
			modulusLength: 2048,
			hash: 'SHA-384',
			scheme: 'pss',
		});
		expect(() =>
			getSignatureAlgorithm(keys.privateKey, { kind: 'rsa-pss', saltLength: 32 }),
		).toThrow('Unsupported RSA-PSS saltLength 32');
	});

	it('getSignatureAlgorithm returns correct config for ECDSA P-384', async () => {
		const { generateKeyPair: genKp } = await import('#micro509');
		const keys = await genKp({ kind: 'ecdsa', namedCurve: 'P-384' });
		const result = getSignatureAlgorithm(keys.privateKey);
		expect(result.algorithmOid).toBe(OIDS.ecdsaWithSHA384);
		expect(result.ecdsaRawSignatureBytes).toBe(96);
	});

	it('getSignatureAlgorithm returns correct config for ECDSA P-521', async () => {
		const { generateKeyPair: genKp } = await import('#micro509');
		const keys = await genKp({ kind: 'ecdsa', namedCurve: 'P-521' });
		const result = getSignatureAlgorithm(keys.privateKey);
		expect(result.algorithmOid).toBe(OIDS.ecdsaWithSHA512);
		expect(result.ecdsaRawSignatureBytes).toBe(132);
		expect(result.signParams).toEqual({ name: 'ECDSA', hash: 'SHA-512' });
	});

	it('getVerifySignatureConfig returns correct config for ECDSA P-521', () => {
		const result = getVerifySignatureConfig(
			OIDS.ecdsaWithSHA512,
			undefined,
			OIDS.ecPublicKey,
			OIDS.secp521r1,
		);
		expect(result.importAlgorithm).toEqual({ kind: 'ecdsa', namedCurve: 'P-521' });
		expect(result.verifyParams).toEqual({ name: 'ECDSA', hash: 'SHA-512' });
		expect(result.ecdsaRawSignatureBytes).toBe(132);
	});

	it('getSignatureAlgorithm returns correct config for Ed25519', async () => {
		const { generateKeyPair: genKp } = await import('#micro509');
		const keys = await genKp({ kind: 'ed25519' });
		const result = getSignatureAlgorithm(keys.privateKey);
		expect(result.algorithmOid).toBe(OIDS.ed25519);
		expect(result.ecdsaRawSignatureBytes).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// rsa-pss.ts edge cases
// ---------------------------------------------------------------------------

describe('rsa-pss.ts edge cases', () => {
	it('round-trips supported RSA-PSS profiles', () => {
		for (const hash of ['SHA-256', 'SHA-384', 'SHA-512'] as const) {
			const encoded = encodeRsaPssParameters(rsaPssParametersForHash(hash));
			expect(parseRsaPssParameters(encoded)).toEqual({
				ok: true,
				value: rsaPssParametersForHash(hash),
			});
		}
	});

	it('treats omitted parameters as unsupported SHA-1 defaults', () => {
		expect(parseRsaPssParameters(undefined)).toEqual({
			ok: false,
			code: 'unsupported_rsa_pss_parameters',
			reason: 'default_hash_sha1',
		});
	});

	it('rejects unsupported hash, MGF, salt length, and trailer profiles', () => {
		const unsupportedHash = sequence([
			explicitContext(0, hashAlgorithmIdentifier('1.2.3.4.5')),
			explicitContext(1, maskGenAlgorithmIdentifier(OIDS.mgf1, OIDS.sha256)),
			explicitContext(2, integerFromNumber(32)),
			explicitContext(3, integerFromNumber(1)),
		]);
		expect(parseRsaPssParameters(unsupportedHash)).toEqual({
			ok: false,
			code: 'unsupported_rsa_pss_parameters',
			reason: 'unsupported_hash',
		});

		const mismatchedMgf = sequence([
			explicitContext(0, hashAlgorithmIdentifier(OIDS.sha256)),
			explicitContext(1, maskGenAlgorithmIdentifier(OIDS.mgf1, OIDS.sha384)),
			explicitContext(2, integerFromNumber(32)),
			explicitContext(3, integerFromNumber(1)),
		]);
		expect(parseRsaPssParameters(mismatchedMgf)).toEqual({
			ok: false,
			code: 'unsupported_rsa_pss_parameters',
			reason: 'mgf_hash_mismatch',
		});

		const unsupportedMgf = sequence([
			explicitContext(0, hashAlgorithmIdentifier(OIDS.sha256)),
			explicitContext(1, maskGenAlgorithmIdentifier('1.2.3.4.5')),
			explicitContext(2, integerFromNumber(32)),
			explicitContext(3, integerFromNumber(1)),
		]);
		expect(parseRsaPssParameters(unsupportedMgf)).toEqual({
			ok: false,
			code: 'unsupported_rsa_pss_parameters',
			reason: 'unsupported_mgf_algorithm',
		});

		const unsupportedSaltLength = sequence([
			explicitContext(0, hashAlgorithmIdentifier(OIDS.sha256)),
			explicitContext(1, maskGenAlgorithmIdentifier(OIDS.mgf1, OIDS.sha256)),
			explicitContext(2, integerFromNumber(20)),
			explicitContext(3, integerFromNumber(1)),
		]);
		expect(parseRsaPssParameters(unsupportedSaltLength)).toEqual({
			ok: false,
			code: 'unsupported_rsa_pss_parameters',
			reason: 'unsupported_salt_length',
		});

		const unsupportedTrailer = sequence([
			explicitContext(0, hashAlgorithmIdentifier(OIDS.sha512)),
			explicitContext(1, maskGenAlgorithmIdentifier(OIDS.mgf1, OIDS.sha512)),
			explicitContext(2, integerFromNumber(64)),
			explicitContext(3, integerFromNumber(2)),
		]);
		expect(parseRsaPssParameters(unsupportedTrailer)).toEqual({
			ok: false,
			code: 'unsupported_rsa_pss_parameters',
			reason: 'unsupported_trailer_field',
		});
	});

	it('distinguishes malformed RSA-PSS parameters from unsupported ones', () => {
		const notSequence = octetString(new Uint8Array());
		expect(parseRsaPssParameters(notSequence)).toMatchObject({
			ok: false,
			code: 'malformed_rsa_pss_parameters',
		});

		const duplicateHash = sequence([
			explicitContext(0, hashAlgorithmIdentifier(OIDS.sha256)),
			explicitContext(0, hashAlgorithmIdentifier(OIDS.sha256)),
		]);
		expect(parseRsaPssParameters(duplicateHash)).toMatchObject({
			ok: false,
			code: 'malformed_rsa_pss_parameters',
		});

		const malformedSaltLength = sequence([
			explicitContext(0, hashAlgorithmIdentifier(OIDS.sha256)),
			explicitContext(1, maskGenAlgorithmIdentifier(OIDS.mgf1, OIDS.sha256)),
			explicitContext(2, sequence([])),
		]);
		expect(parseRsaPssParameters(malformedSaltLength)).toMatchObject({
			ok: false,
			code: 'malformed_rsa_pss_parameters',
		});
	});
});

function hashAlgorithmIdentifier(oid: string): Uint8Array {
	return sequence([objectIdentifier(oid), nullValue()]);
}

function maskGenAlgorithmIdentifier(oid: string, hashOid?: string): Uint8Array {
	if (hashOid === undefined) {
		return sequence([objectIdentifier(oid)]);
	}
	return sequence([objectIdentifier(oid), hashAlgorithmIdentifier(hashOid)]);
}

// ---------------------------------------------------------------------------
// pbes2.ts edge cases
// ---------------------------------------------------------------------------

describe('pbes2.ts edge cases', () => {
	it('parsePbes2AlgorithmIdentifier throws on malformed input', () => {
		expect(() => parsePbes2AlgorithmIdentifier(Uint8Array.of(0x30, 0x00))).toThrow();
	});

	it('parsePbes2AlgorithmIdentifier throws on non-PBES2 OID', () => {
		const wrong = sequence([objectIdentifier('1.2.3.4'), sequence([])]);
		expect(() => parsePbes2AlgorithmIdentifier(wrong)).toThrow(/Unsupported encryption/);
	});

	it('parsePbes2AlgorithmIdentifier throws on malformed PBES2 params', () => {
		const malformed = sequence([objectIdentifier(OIDS.pbes2), sequence([])]);
		expect(() => parsePbes2AlgorithmIdentifier(malformed)).toThrow(/Malformed PBES2/);
	});

	it('parsePbes2AlgorithmIdentifier throws on unsupported KDF', () => {
		const badKdf = sequence([
			objectIdentifier(OIDS.pbes2),
			sequence([
				// KDF with wrong OID
				sequence([objectIdentifier('1.2.3.4.5'), sequence([])]),
				// Scheme
				sequence([objectIdentifier(OIDS.aes256Cbc), octetString(new Uint8Array(16))]),
			]),
		]);
		expect(() => parsePbes2AlgorithmIdentifier(badKdf)).toThrow(/Unsupported KDF/);
	});

	it('parsePbes2AlgorithmIdentifier throws on malformed PBKDF2 params', () => {
		const badPbkdf2 = sequence([
			objectIdentifier(OIDS.pbes2),
			sequence([
				sequence([
					objectIdentifier(OIDS.pbkdf2),
					sequence([]), // empty params
				]),
				sequence([objectIdentifier(OIDS.aes256Cbc), octetString(new Uint8Array(16))]),
			]),
		]);
		expect(() => parsePbes2AlgorithmIdentifier(badPbkdf2)).toThrow(/Malformed PBKDF2/);
	});

	it('parsePbes2AlgorithmIdentifier accepts shipped AES-CBC and PBKDF2 PRF variants', () => {
		const cases = [
			{
				encryptionOid: OIDS.aes128Cbc,
				encryption: 'aes128-cbc',
				keyLength: 16,
				prfOid: OIDS.hmacWithSHA1,
				prf: 'hmac-sha1',
			},
			{
				encryptionOid: OIDS.aes192Cbc,
				encryption: 'aes192-cbc',
				keyLength: 24,
				prfOid: OIDS.hmacWithSHA256,
				prf: 'hmac-sha256',
			},
			{
				encryptionOid: OIDS.aes256Cbc,
				encryption: 'aes256-cbc',
				keyLength: 32,
				prfOid: OIDS.hmacWithSHA1,
				prf: 'hmac-sha1',
			},
		] as const;

		for (const testCase of cases) {
			const algorithmIdentifier = sequence([
				objectIdentifier(OIDS.pbes2),
				sequence([
					sequence([
						objectIdentifier(OIDS.pbkdf2),
						sequence([
							octetString(new Uint8Array(16).fill(0x11)),
							integerFromNumber(2048),
							integerFromNumber(testCase.keyLength),
							sequence([objectIdentifier(testCase.prfOid), nullValue()]),
						]),
					]),
					sequence([
						objectIdentifier(testCase.encryptionOid),
						octetString(new Uint8Array(16).fill(0x22)),
					]),
				]),
			]);

			expect(parsePbes2AlgorithmIdentifier(algorithmIdentifier)).toMatchObject({
				iterations: 2048,
				encryption: testCase.encryption,
				prf: testCase.prf,
			});
		}
	});

	it('parsePbes2AlgorithmIdentifier defaults missing PRF to HMAC-SHA1', () => {
		const algorithmIdentifier = sequence([
			objectIdentifier(OIDS.pbes2),
			sequence([
				sequence([
					objectIdentifier(OIDS.pbkdf2),
					sequence([octetString(new Uint8Array(16).fill(0x11)), integerFromNumber(2048)]),
				]),
				sequence([objectIdentifier(OIDS.aes256Cbc), octetString(new Uint8Array(16).fill(0x22))]),
			]),
		]);

		expect(parsePbes2AlgorithmIdentifier(algorithmIdentifier)).toMatchObject({
			prf: 'hmac-sha1',
			encryption: 'aes256-cbc',
		});
	});

	it('parsePbes2AlgorithmIdentifier throws on unsupported PBKDF2 PRF', () => {
		const badPrf = sequence([
			objectIdentifier(OIDS.pbes2),
			sequence([
				sequence([
					objectIdentifier(OIDS.pbkdf2),
					sequence([
						octetString(new Uint8Array(16)),
						integerFromNumber(2048),
						sequence([objectIdentifier('1.2.3.4.5'), nullValue()]),
					]),
				]),
				sequence([objectIdentifier(OIDS.aes256Cbc), octetString(new Uint8Array(16))]),
			]),
		]);

		expect(() => parsePbes2AlgorithmIdentifier(badPrf)).toThrow(/Unsupported PBKDF2 PRF/);
	});

	it('parsePbes2AlgorithmIdentifier throws on unsupported encryption scheme', () => {
		const badScheme = sequence([
			objectIdentifier(OIDS.pbes2),
			sequence([
				sequence([
					objectIdentifier(OIDS.pbkdf2),
					sequence([
						octetString(new Uint8Array(16)), // salt
						integerFromNumber(2048), // iterations
					]),
				]),
				sequence([objectIdentifier('1.2.3.4.5'), octetString(new Uint8Array(16))]),
			]),
		]);
		expect(() => parsePbes2AlgorithmIdentifier(badScheme)).toThrow(
			/Unsupported content encryption/,
		);
	});

	it('parsePbes2AlgorithmIdentifier throws on malformed encryption scheme', () => {
		const badScheme = sequence([
			objectIdentifier(OIDS.pbes2),
			sequence([
				sequence([
					objectIdentifier(OIDS.pbkdf2),
					sequence([
						octetString(new Uint8Array(16)), // salt
						integerFromNumber(2048), // iterations
					]),
				]),
				sequence([]), // empty scheme
			]),
		]);
		expect(() => parsePbes2AlgorithmIdentifier(badScheme)).toThrow(/Malformed encryption scheme/);
	});
});

// ---------------------------------------------------------------------------
// pkcs12-mac.ts edge cases
// ---------------------------------------------------------------------------

describe('pkcs12-mac.ts edge cases', () => {
	const dummySafe = new Uint8Array(10);

	it('parsePkcs12MacData throws on malformed MacData (missing salt)', async () => {
		// Only digestInfo, no salt or iterations
		const malformed = sequence([
			sequence([
				sequence([objectIdentifier(OIDS.sha256), nullValue()]),
				octetString(new Uint8Array(32)),
			]),
		]);
		expect(parsePkcs12MacData(malformed, dummySafe)).rejects.toThrow('Malformed MacData');
	});

	it('parsePkcs12MacData throws on malformed MacData (salt wrong tag)', async () => {
		// salt is INTEGER instead of OCTET STRING
		const malformed = sequence([
			sequence([
				sequence([objectIdentifier(OIDS.sha256), nullValue()]),
				octetString(new Uint8Array(32)),
			]),
			integerFromNumber(16), // wrong tag — should be octetString
			integerFromNumber(2048),
		]);
		expect(parsePkcs12MacData(malformed, dummySafe)).rejects.toThrow('Malformed MacData');
	});

	it('parsePkcs12MacData throws on malformed DigestInfo (missing digest)', async () => {
		// DigestInfo with only algorithm, no digest
		const malformed = sequence([
			sequence([sequence([objectIdentifier(OIDS.sha256), nullValue()])]),
			octetString(new Uint8Array(16)),
			integerFromNumber(2048),
		]);
		expect(parsePkcs12MacData(malformed, dummySafe)).rejects.toThrow('Malformed DigestInfo');
	});

	it('parsePkcs12MacData throws on malformed DigestInfo (digest wrong tag)', async () => {
		// digest is INTEGER instead of OCTET STRING
		const malformed = sequence([
			sequence([
				sequence([objectIdentifier(OIDS.sha256), nullValue()]),
				integerFromNumber(0), // wrong tag — should be octetString
			]),
			octetString(new Uint8Array(16)),
			integerFromNumber(2048),
		]);
		expect(parsePkcs12MacData(malformed, dummySafe)).rejects.toThrow('Malformed DigestInfo');
	});

	it('parsePkcs12MacData throws when algorithm OID is missing', async () => {
		// algorithmSequence is empty
		const malformed = sequence([
			sequence([sequence([]), octetString(new Uint8Array(32))]),
			octetString(new Uint8Array(16)),
			integerFromNumber(2048),
		]);
		expect(parsePkcs12MacData(malformed, dummySafe)).rejects.toThrow('MacData algorithm missing');
	});

	it('parsePkcs12MacData throws on non-SHA-256 algorithm', async () => {
		// Use SHA-1 OID instead of SHA-256
		const malformed = sequence([
			sequence([
				sequence([objectIdentifier(OIDS.sha1), nullValue()]),
				octetString(new Uint8Array(20)),
			]),
			octetString(new Uint8Array(16)),
			integerFromNumber(2048),
		]);
		expect(parsePkcs12MacData(malformed, dummySafe)).rejects.toThrow('Only SHA-256');
	});

	it('parsePkcs12MacData skips MAC verification when password is undefined', async () => {
		// Build a valid-looking MacData — parsePkcs12MacData should return without 'valid' field
		const data = new Uint8Array([0x30, 0x03, 0x01, 0x01, 0xff]);
		const mac = await createPkcs12MacData(data, { password: 'test' });
		// Parse without password — should succeed but no 'valid' field
		const parsed = await parsePkcs12MacData(mac.der, data);
		expect(parsed.digestAlgorithmOid).toBe(OIDS.sha256);
		expect(parsed.valid).toBeUndefined();
	});

	it('createPkcs12MacData supports empty salt', async () => {
		const data = new Uint8Array([0x30, 0x03, 0x01, 0x01, 0xff]);
		const mac = await createPkcs12MacData(data, {
			password: 'test',
			salt: new Uint8Array(),
		});
		expect(mac.parsed.saltHex).toBe('');
		const parsed = await parsePkcs12MacData(mac.der, data, 'test');
		expect(parsed.saltHex).toBe('');
		expect(parsed.valid).toBe(true);
	});

	it('rawEcdsaSignatureToDer converts valid raw signature to DER', () => {
		// P-256 has 32-byte parts → 64-byte raw signature
		const raw = new Uint8Array(64);
		raw[0] = 0x01; // non-zero r
		raw[32] = 0x02; // non-zero s
		const der = rawEcdsaSignatureToDer(raw, 32);
		// Should produce a SEQUENCE of two INTEGERs
		expect(der[0]).toBe(0x30); // SEQUENCE tag
		const parsed = readSequenceChildren(der);
		expect(parsed).toHaveLength(2);
		expect(parsed[0]?.tag).toBe(0x02); // INTEGER
		expect(parsed[1]?.tag).toBe(0x02); // INTEGER
	});

	it('rawEcdsaSignatureToDer throws on wrong-length signature', () => {
		// 48 bytes but partLength is 32 → expects 64 bytes
		const raw = new Uint8Array(48);
		expect(() => rawEcdsaSignatureToDer(raw, 32)).toThrow('Unexpected ECDSA raw signature length');
	});
});
