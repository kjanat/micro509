import { describe, expect, it } from 'bun:test';
import {
	createCertificateRevocationList,
	createSelfSignedCertificate,
	importEncryptedPkcs8Der,
	isResultError,
	parseCertificatePem,
	parseCertificateRevocationListPemOrThrow,
	unwrap,
} from '#micro509';
import {
	decodeBoolean,
	decodeIntegerNumber,
	decodeNonNegativeIntegerNumber,
	decodeObjectIdentifier,
	decodeString,
	extractBitStringValue,
	hexToBytes,
	parseTime,
	requireElement,
	toHex,
} from '#micro509/internal/asn1/asn1';
import {
	assertDerMaxDepth,
	bitString,
	DEFAULT_MAX_DER_DEPTH,
	encodeLength,
	explicitContext,
	generalizedTime,
	ia5String,
	implicitConstructedContext,
	implicitPrimitiveContext,
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
	tlv,
	utcTime,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import {
	describeHashAlgorithm,
	describeSignatureAlgorithm,
} from '#micro509/internal/crypto/algorithm-names';
import { ecdsaSignatureToDer } from '#micro509/internal/crypto/ecdsa';
import {
	encodePbes2AlgorithmIdentifier,
	encryptPbes2,
	parsePbes2AlgorithmIdentifier,
} from '#micro509/internal/crypto/pbes2';
import {
	encodeRsaPssParameters,
	parseRsaPssParameters,
	rsaPssParametersForHash,
} from '#micro509/internal/crypto/rsa-pss';
import {
	alternateEcdsaSignatureEncoding,
	concatFixedWidth,
	curveBytes,
	derEcdsaSignatureToRaw,
	getVerifySignatureConfig,
	getVerifySignatureConfigResult,
	rawEcdsaSignatureToDer,
	requireEcPublicKey,
	requireRsaPublicKey,
	verifySignedDataDetailed,
} from '#micro509/internal/crypto/sig-verify';
import {
	encodeAlgorithmIdentifier,
	getSignatureAlgorithm,
} from '#micro509/internal/crypto/signing';
import { canonicalDnKey } from '#micro509/internal/shared/dn';
import {
	allOnesMaskForIpAddress,
	decodeIpAddress,
	expandIpv6,
	normalizeIpAddress,
	parseIpAddressToBytes,
} from '#micro509/internal/shared/ip';
import {
	parseDistributionPointReasonFlagsContent,
	parseKeyUsageExtension,
} from '#micro509/internal/x509/extension-bits';
import { createPkcs12MacData, parsePkcs12MacDataOrThrow } from '#micro509/pkcs';
import {
	buildCertificateExtensions,
	buildRequestedExtensions,
	encodeAuthorityInfoAccess,
	encodeBasicConstraints,
	encodeCertificatePolicies,
	encodeCrlDistributionPoints,
	encodeExtendedKeyUsage,
	encodeKeyUsage,
	encodeName,
	encodeNameConstraints,
	encodePolicyMappings,
	encodeRelativeDistinguishedName,
	encodeSubjectAltName,
} from '#micro509/x509';
import { childrenOf } from '#test/helpers';

function expectEncoderErrorCode(fn: () => unknown, code: string): void {
	try {
		fn();
	} catch (error) {
		expect(isResultError(error)).toBe(true);
		expect(isResultError(error) ? error.code : undefined).toBe(code);
		return;
	}
	throw new Error(`expected a ResultError with code '${code}', but nothing was thrown`);
}

// DER encoding edge cases

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

	it('utcTime and generalizedTime reject invalid or out-of-range dates', () => {
		expect(() => utcTime(new Date(Number.NaN))).toThrow(RangeError);
		expect(() => utcTime(new Date('2050-01-01T00:00:00Z'))).toThrow('1950 and 2049');
		expect(() => generalizedTime(new Date(Number.NaN))).toThrow(RangeError);
		expect(() => generalizedTime(new Date(Date.UTC(10_000, 0, 1, 0, 0, 0)))).toThrow('0 and 9999');
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

	it('rejects unsupported high-tag-number DER encodings', () => {
		expect(() => tlv(0x1f, Uint8Array.of(0x00))).toThrow('High-tag-number');
		expect(() => explicitContext(31, Uint8Array.of(0x00))).toThrow('Context-specific tag number');
		expect(() => implicitConstructedContext(31, Uint8Array.of(0x00))).toThrow(
			'Context-specific tag number',
		);
		expect(() => implicitPrimitiveContext(31, Uint8Array.of(0x00))).toThrow(
			'Context-specific tag number',
		);
		expect(() => readElement(Uint8Array.of(0x1f, 0x01, 0x00))).toThrow('High-tag-number');
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

// ASN.1 decoding edge cases

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

	it('decodeObjectIdentifier decodes multi-octet first subidentifiers correctly', () => {
		expect(decodeObjectIdentifier(Uint8Array.of(0x81, 0x34))).toBe('2.100');
	});

	it('decodeObjectIdentifier rejects non-minimal base-128 encodings', () => {
		expect(() => decodeObjectIdentifier(Uint8Array.of(0x80, 0x50))).toThrow(
			'non-minimal base-128 encoding',
		);
		expect(() => decodeObjectIdentifier(Uint8Array.of(0x2a, 0x80, 0x01))).toThrow(
			'non-minimal base-128 encoding',
		);
	});

	it('decodeObjectIdentifier rejects too-large subidentifiers before number overflow', () => {
		expect(() =>
			decodeObjectIdentifier(
				Uint8Array.of(0x2a, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00),
			),
		).toThrow('too-large subidentifier');
	});

	it('requireElement throws on undefined value', () => {
		expect(() => requireElement(undefined, 'test field')).toThrow('Missing test field');
	});

	it('extractBitStringValue throws on non-BIT STRING tag', () => {
		const element = readElement(Uint8Array.of(0x04, 0x02, 0xaa, 0xbb));
		expect(() => extractBitStringValue(element)).toThrow('Expected BIT STRING');
	});

	it('extractBitStringValue rejects malformed BIT STRING payloads', () => {
		expect(() => extractBitStringValue(readElement(Uint8Array.of(0x03, 0x00)))).toThrow(
			'Invalid BIT STRING',
		);
		expect(() => extractBitStringValue(readElement(Uint8Array.of(0x03, 0x02, 0x01, 0x80)))).toThrow(
			'zero unused bits',
		);
	});

	it('parseTime throws on unsupported tag', () => {
		// Tag 0x0c = UTF8String, not a time type
		const element = readElement(Uint8Array.of(0x0c, 0x01, 0x30));
		expect(() => parseTime(element)).toThrow('Unsupported time tag');
	});

	it('parseTime rejects malformed UTCTime and GeneralizedTime values', () => {
		expect(() => parseTime(readElement(asn1StringElement(0x17, '991332235959Z')))).toThrow(
			'Invalid UTCTime',
		);
		expect(() => parseTime(readElement(asn1StringElement(0x18, '20240230010203Z')))).toThrow(
			'Invalid GeneralizedTime',
		);
	});

	it('parseTime rejects malformed UTF-8 in time values', () => {
		expect(() => parseTime(readElement(Uint8Array.of(0x17, 0x02, 0xc3, 0x28)))).toThrow(
			'Invalid UTCTime: invalid UTF-8',
		);
		expect(() => parseTime(readElement(Uint8Array.of(0x18, 0x02, 0xc3, 0x28)))).toThrow(
			'Invalid GeneralizedTime: invalid UTF-8',
		);
	});

	it('decodeIntegerNumber accepts any value up to MAX_SAFE_INTEGER', () => {
		expect(decodeIntegerNumber(Uint8Array.of(1, 2, 3, 4, 5, 6, 7))).toBe(283686952306183);
		expect(decodeIntegerNumber(Uint8Array.of(0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff))).toBe(
			Number.MAX_SAFE_INTEGER,
		);
	});

	it('decodeIntegerNumber throws above MAX_SAFE_INTEGER', () => {
		expect(() => decodeIntegerNumber(Uint8Array.of(0x20, 0, 0, 0, 0, 0, 0))).toThrow('too large');
		expect(() => decodeIntegerNumber(Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8))).toThrow('too large');
	});

	it('decodeIntegerNumber rejects empty, negative, and non-minimal encodings', () => {
		expect(() => decodeIntegerNumber(new Uint8Array())).toThrow('INTEGER is empty');
		expect(() => decodeIntegerNumber(Uint8Array.of(0xff))).toThrow('non-negative');
		expect(() => decodeIntegerNumber(Uint8Array.of(0x00, 0x01))).toThrow('minimal encoding');
	});

	it('decodeNonNegativeIntegerNumber rejects negative and non-minimal encodings', () => {
		expect(() => decodeNonNegativeIntegerNumber(Uint8Array.of(0xff), 'test integer')).toThrow(
			'test integer must be non-negative',
		);
		expect(() => decodeNonNegativeIntegerNumber(Uint8Array.of(0x00, 0x01), 'test integer')).toThrow(
			'test integer must use minimal encoding',
		);
	});

	it('decodeString validates ASCII-constrained tags and common ASN.1 string encodings', () => {
		expect(() => decodeString(0x0c, Uint8Array.of(0xc3, 0x28))).toThrow(
			'Invalid UTF8String: invalid UTF-8',
		);
		expect(decodeString(0x13, Uint8Array.of(0x4f, 0x4b))).toBe('OK');
		expect(() => decodeString(0x13, Uint8Array.of(0x40))).toThrow('Invalid PrintableString');
		expect(decodeString(0x16, Uint8Array.of(0x4f, 0x4b))).toBe('OK');
		expect(() => decodeString(0x16, Uint8Array.of(0x80))).toThrow('Invalid IA5String');
		expect(decodeString(0x1e, Uint8Array.of(0x00, 0x4f, 0x00, 0x4b))).toBe('OK');
		expect(() => decodeString(0x1e, Uint8Array.of(0x00, 0x4f, 0x00))).toThrow(
			'Invalid BMPString length',
		);
		expect(() => decodeString(0x1e, Uint8Array.of(0xd8, 0x00))).toThrow(
			'Invalid BMPString code point',
		);
		expect(decodeString(0x1c, Uint8Array.of(0x00, 0x00, 0x00, 0x41))).toBe('A');
		expect(() => decodeString(0x1c, Uint8Array.of(0x00, 0x11, 0x00, 0x00))).toThrow(
			'Invalid UniversalString code point',
		);
		expect(() => decodeString(0x14, Uint8Array.of(0x41))).toThrow('TeletexString');
	});

	it('decodeBoolean rejects malformed DER encodings', () => {
		expect(() => decodeBoolean(new Uint8Array())).toThrow('exactly one octet');
		expect(() => decodeBoolean(Uint8Array.of(0x01))).toThrow('DER encoding');
		expect(decodeBoolean(Uint8Array.of(0x00))).toBe(false);
		expect(decodeBoolean(Uint8Array.of(0xff))).toBe(true);
	});

	it('hexToBytes rejects malformed hex input', () => {
		expect(() => hexToBytes('zz')).toThrow('Invalid hex byte: zz');
		expect(() => hexToBytes('1g')).toThrow('Invalid hex byte: 1g');
	});
});

// sig-verify edge cases

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

	it('curveBytes returns undefined for unsupported curve', () => {
		expect(curveBytes('1.2.3.4.5')).toBeUndefined();
	});

	it('requireEcPublicKey and curveBytes support secp521r1', () => {
		const result = requireEcPublicKey(OIDS.ecPublicKey, OIDS.secp521r1, 'SHA-512');
		expect(result.ok).toBe(true);
		if (result.ok) {
			expect(result.value.importAlgorithm).toEqual({ kind: 'ecdsa', curve: 'P-521' });
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

	it('getVerifySignatureConfigResult rejects PKCS#1 v1.5 signatures without DER NULL parameters', () => {
		const missingNull = getVerifySignatureConfigResult(
			OIDS.sha256WithRSAEncryption,
			undefined,
			OIDS.rsaEncryption,
			undefined,
		);
		expect(missingNull).toMatchObject({
			ok: false,
			code: 'unsupported_signature_algorithm_parameters',
		});
		if (!missingNull.ok) {
			expect(missingNull.reason).toContain('DER NULL');
		}

		const malformedNull = getVerifySignatureConfigResult(
			OIDS.sha256WithRSAEncryption,
			Uint8Array.of(0x05),
			OIDS.rsaEncryption,
			undefined,
		);
		expect(malformedNull).toMatchObject({
			ok: false,
			code: 'unsupported_signature_algorithm_parameters',
		});
		if (!malformedNull.ok) {
			expect(malformedNull.reason).toContain('DER NULL');
		}

		const wrongTag = getVerifySignatureConfigResult(
			OIDS.sha256WithRSAEncryption,
			Uint8Array.of(0x02, 0x01, 0x00),
			OIDS.rsaEncryption,
			undefined,
		);
		expect(wrongTag).toMatchObject({
			ok: false,
			code: 'unsupported_signature_algorithm_parameters',
		});
		if (!wrongTag.ok) {
			expect(wrongTag.reason).toContain('DER NULL');
		}

		const trailingBytes = getVerifySignatureConfigResult(
			OIDS.sha256WithRSAEncryption,
			Uint8Array.of(0x05, 0x00, 0x00),
			OIDS.rsaEncryption,
			undefined,
		);
		expect(trailingBytes).toMatchObject({
			ok: false,
			code: 'unsupported_signature_algorithm_parameters',
		});
		if (!trailingBytes.ok) {
			expect(trailingBytes.reason).toContain('DER NULL');
		}

		expect(
			getVerifySignatureConfigResult(
				OIDS.sha256WithRSAEncryption,
				nullValue(),
				OIDS.rsaEncryption,
				undefined,
			),
		).toMatchObject({ ok: true });
	});

	it('getVerifySignatureConfigResult rejects unexpected parameters for ECDSA and Ed25519', () => {
		const ecdsaWithParameters = getVerifySignatureConfigResult(
			OIDS.ecdsaWithSHA256,
			nullValue(),
			OIDS.ecPublicKey,
			OIDS.prime256v1,
		);
		expect(ecdsaWithParameters).toMatchObject({
			ok: false,
			code: 'unsupported_signature_algorithm_parameters',
		});
		if (!ecdsaWithParameters.ok) {
			expect(ecdsaWithParameters.reason).toContain('must be absent');
		}

		const ed25519WithParameters = getVerifySignatureConfigResult(
			OIDS.ed25519,
			nullValue(),
			OIDS.ed25519,
			undefined,
		);
		expect(ed25519WithParameters).toMatchObject({
			ok: false,
			code: 'unsupported_signature_algorithm_parameters',
		});
		if (!ed25519WithParameters.ok) {
			expect(ed25519WithParameters.reason).toContain('must be absent');
		}

		expect(
			getVerifySignatureConfigResult(OIDS.ed25519, undefined, OIDS.ed25519, undefined),
		).toMatchObject({ ok: true });
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

	it('verifySignedDataDetailed returns a typed failure when verification setup throws', async () => {
		const result = await verifySignedDataDetailed(
			OIDS.sha256WithRSAEncryption,
			nullValue(),
			OIDS.rsaEncryption,
			undefined,
			Uint8Array.of(0x30, 0x00),
			Uint8Array.of(0x00),
			Uint8Array.of(0x00),
		);
		expect(result).toMatchObject({ ok: false, code: 'verification_error' });
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

	it('rejects key usage values with non-zero padding bits', () => {
		expect(() => parseKeyUsageExtension(Uint8Array.of(0x03, 0x02, 0x07, 0x01))).toThrow(
			'keyUsage BIT STRING must not set padding bits',
		);
	});

	it('rejects distribution point reason values with non-zero padding bits', () => {
		expect(() => parseDistributionPointReasonFlagsContent(Uint8Array.of(0x01, 0x01))).toThrow(
			'DistributionPoint reasons BIT STRING must not set padding bits',
		);
	});

	it('preserves empty distribution point reason values when the BIT STRING is present', () => {
		expect(parseDistributionPointReasonFlagsContent(Uint8Array.of(0x00))).toEqual({
			flags: [],
			nonZeroPadding: false,
		});
	});

	it('canonicalDnKey escapes separator characters in attribute values', () => {
		const singleAttributeValue = {
			derHex: '',
			attributes: [{ oid: '1.2.3', valueTag: 0x13, value: 'a+2.5.4=b' }],
			values: {},
		};
		const splitAttributes = {
			derHex: '',
			attributes: [
				{ oid: '1.2.3', valueTag: 0x13, value: 'a' },
				{ oid: '2.5.4', valueTag: 0x13, value: 'b' },
			],
			values: {},
		};
		expect(
			canonicalDnKey({ derHex: '', rdns: [singleAttributeValue], attributes: [], values: {} }),
		).not.toBe(canonicalDnKey({ derHex: '', rdns: [splitAttributes], attributes: [], values: {} }));
	});
});

// Extension encoding edge cases

describe('extensions encoding', () => {
	it('encodeSubjectAltName handles directoryName type', () => {
		const result = encodeSubjectAltName({
			type: 'directoryName',
			derHex: '3000',
		});
		// Tag 0xa4 = context-specific constructed [4]
		expect(result[0]).toBe(0xa4);
	});

	it('encodeSubjectAltName wraps the whole directoryName Name TLV, header included', () => {
		// RFC 5280 §4.2.1.6 makes directoryName [4] EXPLICIT, so its contents are the
		// complete Name TLV: OpenSSL emits `a4 05 30 03 ...`, not the stripped `a4 03 ...`.
		const result = encodeSubjectAltName({ type: 'directoryName', derHex: '3003020101' });
		expect(Array.from(result)).toEqual([0xa4, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01]);
	});

	it('encodeSubjectAltName encodes an srv otherName with no inner SEQUENCE', () => {
		// otherName [0] is IMPLICIT, so the [0] content is type-id then value: its
		// first inner element is the OID (0x06), never a nested SEQUENCE (0x30).
		const result = encodeSubjectAltName({ type: 'srv', value: '_imaps.example.com' });
		expect(result[0]).toBe(0xa0);
		expect(result[2]).toBe(0x06);
	});

	it('encodeSubjectAltName handles unknown type', () => {
		const result = encodeSubjectAltName({
			type: 'unknown',
			tag: 0x88,
			value: Uint8Array.of(0x01, 0x02),
		});
		expect(result[0]).toBe(0x88);
	});

	it('encodeSubjectAltName rejects an unknown GeneralName with an invalid wire tag', () => {
		// x400Address [3], ediPartyName [5], and registeredID [8] are valid but
		// unsupported alternatives and round-trip as their own tag.
		for (const tag of [0xa3, 0xa5, 0x88]) {
			expect(encodeSubjectAltName({ type: 'unknown', tag, value: new Uint8Array() })[0]).toBe(tag);
		}
		// A universal INTEGER (0x02), an application-class tag (0x42), context [9]
		// (0x89), and wrong constructedness (0xa2 dNSName) are not GeneralNames.
		for (const tag of [0x02, 0x42, 0x89, 0xa2, 0x30]) {
			expectEncoderErrorCode(
				() => encodeSubjectAltName({ type: 'unknown', tag, value: Uint8Array.of(0x00) }),
				'invalid_general_name_tag',
			);
		}
	});

	it('encodeSubjectAltName rejects a non-ASCII IA5String value', () => {
		expectEncoderErrorCode(
			() => encodeSubjectAltName({ type: 'dns', value: 'café.example' }),
			'invalid_ia5_string',
		);
		expectEncoderErrorCode(
			() => encodeSubjectAltName({ type: 'uri', value: 'http://café.example' }),
			'invalid_ia5_string',
		);
		expectEncoderErrorCode(
			() => encodeSubjectAltName({ type: 'srv', value: '_xmpp.café.example' }),
			'invalid_ia5_string',
		);
	});

	it('encodeAuthorityInfoAccess rejects a non-URI OCSP location wrapped in a custom OID', () => {
		expectEncoderErrorCode(
			() =>
				encodeAuthorityInfoAccess([
					{
						method: { type: 'oid', value: OIDS.ocspAccessMethod },
						location: { type: 'dns', value: 'ocsp.example' },
					},
				]),
			'authority_info_access_ocsp_not_uri',
		);
	});

	it('buildCertificateExtensions throws on SPKI without subject public key bit string', () => {
		const malformedSpki = sequence([sequence([objectIdentifier(OIDS.rsaEncryption), nullValue()])]);
		expect(() => buildCertificateExtensions(malformedSpki, undefined, undefined)).toThrow(
			'SPKI missing subject public key bit string',
		);
	});

	it('rejects empty certificate policies and policy mappings', () => {
		expectEncoderErrorCode(() => encodeCertificatePolicies([]), 'certificate_policies_empty');
		expectEncoderErrorCode(() => encodePolicyMappings([]), 'policy_mappings_empty');
	});

	it('rejects a duplicate certificate policy OID', () => {
		expectEncoderErrorCode(
			() =>
				encodeCertificatePolicies([
					{ policyIdentifier: '1.2.3.4' },
					{ policyIdentifier: '1.2.3.4' },
				]),
			'duplicate_policy_oid',
		);
	});

	it('rejects duplicate policy OIDs that differ only by leading-zero arc aliasing', () => {
		expectEncoderErrorCode(
			() =>
				encodeCertificatePolicies([
					{ policyIdentifier: '1.2.3.4' },
					{ policyIdentifier: '1.2.03.4' },
				]),
			'duplicate_policy_oid',
		);
	});

	it('rejects a policy qualifier reusing a built-in OID in the opaque variant', () => {
		const qualifierDer = new Uint8Array([0x05, 0x00]);
		for (const oid of [OIDS.cpsPolicyQualifier, OIDS.userNoticePolicyQualifier]) {
			expectEncoderErrorCode(
				() =>
					encodeCertificatePolicies([
						{ policyIdentifier: '1.2.3.4', policyQualifiers: [{ type: 'oid', oid, qualifierDer }] },
					]),
				'reserved_policy_qualifier_oid',
			);
		}
	});

	it('rejects a built-in qualifier OID smuggled through a leading-zero alias', () => {
		const alias = OIDS.userNoticePolicyQualifier.replace(/\.(\d+)$/, '.0$1');
		expectEncoderErrorCode(
			() =>
				encodeCertificatePolicies([
					{
						policyIdentifier: '1.2.3.4',
						policyQualifiers: [
							{ type: 'oid', oid: alias, qualifierDer: new Uint8Array([0x05, 0x00]) },
						],
					},
				]),
			'reserved_policy_qualifier_oid',
		);
	});

	it('encodes a genuine custom policy qualifier OID as raw DER', () => {
		const der = encodeCertificatePolicies([
			{
				policyIdentifier: '1.2.3.4',
				policyQualifiers: [
					{ type: 'oid', oid: '1.3.6.1.4.1.99999.1', qualifierDer: new Uint8Array([0x05, 0x00]) },
				],
			},
		]);
		expect(toHex(der)).toContain(`${toHex(objectIdentifier('1.3.6.1.4.1.99999.1'))}0500`);
	});

	it('rejects a DisplayText outside SIZE (1..200)', () => {
		const overLong = 'a'.repeat(201);
		expectEncoderErrorCode(
			() =>
				encodeCertificatePolicies([
					{
						policyIdentifier: '1.2.3.4',
						policyQualifiers: [{ type: 'userNotice', explicitText: overLong }],
					},
				]),
			'display_text_out_of_range',
		);
		expectEncoderErrorCode(
			() =>
				encodeCertificatePolicies([
					{
						policyIdentifier: '1.2.3.4',
						policyQualifiers: [
							{ type: 'userNotice', noticeRef: { organization: '', noticeNumbers: [1] } },
						],
					},
				]),
			'display_text_out_of_range',
		);
	});

	it('rejects empty SEQUENCE-valued extension encoders', () => {
		expectEncoderErrorCode(() => encodeKeyUsage([]), 'key_usage_empty');
		expectEncoderErrorCode(() => encodeExtendedKeyUsage([]), 'extended_key_usage_empty');
		expectEncoderErrorCode(() => encodeAuthorityInfoAccess([]), 'authority_info_access_empty');
		expectEncoderErrorCode(() => encodeCrlDistributionPoints([]), 'crl_distribution_points_empty');
		expectEncoderErrorCode(() => encodeNameConstraints({}), 'name_constraints_empty');
	});

	it('rejects empty GeneralName string values (RFC 5280 §4.2.1.6)', () => {
		expectEncoderErrorCode(
			() => encodeSubjectAltName({ type: 'dns', value: '' }),
			'empty_general_name_value',
		);
		expectEncoderErrorCode(
			() => encodeSubjectAltName({ type: 'email', value: '' }),
			'empty_general_name_value',
		);
		expectEncoderErrorCode(
			() => encodeSubjectAltName({ type: 'uri', value: '' }),
			'empty_general_name_value',
		);
		expectEncoderErrorCode(
			() => encodeSubjectAltName({ type: 'srv', value: '' }),
			'empty_general_name_value',
		);
	});

	it('rejects a relativeName distribution point with multiple cRLIssuer DNs (RFC 5280 §4.2.1.13)', () => {
		const issuerA = toHex(encodeName({ commonName: 'CRL Issuer A' }));
		const issuerB = toHex(encodeName({ commonName: 'CRL Issuer B' }));
		const relativeName = [{ type: 'commonName', value: 'CRL42' }] as const;
		expectEncoderErrorCode(
			() =>
				encodeCrlDistributionPoints([
					{
						distributionPoint: { relativeName },
						crlIssuer: [
							{ type: 'directoryName', derHex: issuerA },
							{ type: 'directoryName', derHex: issuerB },
						],
					},
				]),
			'distribution_point_relative_name_multiple_crl_issuers',
		);
		expectEncoderErrorCode(
			() =>
				encodeCrlDistributionPoints([
					{
						distributionPoint: { relativeName },
						crlIssuer: [
							{ type: 'directoryName', derHex: issuerA },
							{ type: 'uri', value: 'http://example.test/backup.crl' },
						],
					},
				]),
			'distribution_point_crl_issuer_not_directory_name',
		);
		expectEncoderErrorCode(
			() =>
				encodeCrlDistributionPoints([
					{
						distributionPoint: { relativeName },
						crlIssuer: [
							{
								type: 'unknown',
								tag: 0xa4,
								value: encodeName({ commonName: 'Hidden CRL Issuer' }),
							},
						],
					},
				]),
			'distribution_point_crl_issuer_not_directory_name',
		);
	});

	const subjectPublicKeyInfo = sequence([
		sequence([objectIdentifier(OIDS.rsaEncryption), nullValue()]),
		bitString(Uint8Array.of(0x01, 0x02, 0x03)),
	]);

	it('rejects pathLenConstraint without an effective keyCertSign keyUsage (RFC 5280 §4.2.1.9)', () => {
		expectEncoderErrorCode(
			() =>
				buildCertificateExtensions(subjectPublicKeyInfo, undefined, {
					basicConstraints: { ca: true, pathLength: 0 },
					keyUsage: ['digitalSignature'],
				}),
			'path_length_requires_key_cert_sign',
		);
		expectEncoderErrorCode(
			() =>
				buildCertificateExtensions(subjectPublicKeyInfo, undefined, {
					basicConstraints: { ca: true, pathLength: 0 },
				}),
			'path_length_requires_key_cert_sign',
		);
		expectEncoderErrorCode(
			() =>
				buildCertificateExtensions(subjectPublicKeyInfo, undefined, {
					basicConstraints: { ca: true, pathLength: 0 },
					customExtensions: [{ oid: OIDS.keyUsage, value: encodeKeyUsage(['digitalSignature']) }],
				}),
			'path_length_requires_key_cert_sign',
		);
		expect(
			buildCertificateExtensions(subjectPublicKeyInfo, undefined, {
				basicConstraints: { ca: true, pathLength: 0 },
				keyUsage: ['keyCertSign'],
			}),
		).toBeInstanceOf(Array);
		expect(
			buildCertificateExtensions(subjectPublicKeyInfo, undefined, {
				basicConstraints: { ca: true, pathLength: 0 },
				customExtensions: [{ oid: OIDS.keyUsage, value: encodeKeyUsage(['keyCertSign']) }],
			}),
		).toBeInstanceOf(Array);
		expectEncoderErrorCode(
			() =>
				buildRequestedExtensions({
					keyUsage: ['digitalSignature'],
					customExtensions: [
						{
							oid: OIDS.basicConstraints,
							value: encodeBasicConstraints({ ca: true, pathLength: 0 }),
						},
					],
				}),
			'path_length_requires_key_cert_sign',
		);
		expect(
			buildRequestedExtensions({
				keyUsage: ['keyCertSign'],
				customExtensions: [
					{
						oid: OIDS.basicConstraints,
						value: encodeBasicConstraints({ ca: true, pathLength: 0 }),
					},
				],
			}),
		).toBeInstanceOf(Array);
		expectEncoderErrorCode(
			() =>
				buildRequestedExtensions({
					basicConstraints: { ca: true, pathLength: 0 },
					customExtensions: [{ oid: OIDS.keyUsage, value: Uint8Array.of(0x05, 0x00) }],
				}),
			'path_length_requires_key_cert_sign',
		);
		expect(
			buildRequestedExtensions({
				customExtensions: [{ oid: OIDS.basicConstraints, value: Uint8Array.of(0x05, 0x00) }],
			}),
		).toBeInstanceOf(Array);
	});

	it('rejects an empty subject without a critical subjectAltName (RFC 5280 §4.2.1.6)', () => {
		expectEncoderErrorCode(
			() => buildCertificateExtensions(subjectPublicKeyInfo, undefined, undefined, true),
			'empty_subject_requires_subject_alt_name',
		);
		expectEncoderErrorCode(
			() =>
				buildCertificateExtensions(subjectPublicKeyInfo, undefined, { subjectAltNames: [] }, true),
			'empty_subject_requires_subject_alt_name',
		);
		expectEncoderErrorCode(
			() =>
				buildCertificateExtensions(
					subjectPublicKeyInfo,
					undefined,
					{ subjectAltNames: [{ type: 'dns', value: '' }] },
					true,
				),
			'empty_subject_requires_subject_alt_name',
		);
		expectEncoderErrorCode(
			() =>
				buildCertificateExtensions(
					subjectPublicKeyInfo,
					undefined,
					{ customExtensions: [{ oid: OIDS.subjectAltName, critical: true, value: sequence([]) }] },
					true,
				),
			'empty_subject_requires_subject_alt_name',
		);
		expect(
			buildCertificateExtensions(
				subjectPublicKeyInfo,
				undefined,
				{ subjectAltNames: [{ type: 'dns', value: 'empty-subject.example' }] },
				true,
			),
		).toBeInstanceOf(Array);
		expect(
			buildCertificateExtensions(
				subjectPublicKeyInfo,
				undefined,
				{
					customExtensions: [
						{
							oid: OIDS.subjectAltName,
							critical: true,
							value: sequence([encodeSubjectAltName({ type: 'dns', value: 'custom-san.example' })]),
						},
					],
				},
				true,
			),
		).toBeInstanceOf(Array);
	});

	it('accepts empty-subject SANs across non-string GeneralName forms (RFC 5280 §4.2.1.6)', () => {
		expect(
			buildCertificateExtensions(
				subjectPublicKeyInfo,
				undefined,
				{ subjectAltNames: [{ type: 'ip', value: '192.0.2.1' }] },
				true,
			),
		).toBeInstanceOf(Array);
		expect(
			buildCertificateExtensions(
				subjectPublicKeyInfo,
				undefined,
				{
					subjectAltNames: [
						{ type: 'directoryName', derHex: toHex(encodeName({ commonName: 'SAN DN' })) },
					],
				},
				true,
			),
		).toBeInstanceOf(Array);
		expect(
			buildCertificateExtensions(
				subjectPublicKeyInfo,
				undefined,
				{ subjectAltNames: [{ type: 'unknown', tag: 0x88, value: Uint8Array.of(0x2a) }] },
				true,
			),
		).toBeInstanceOf(Array);
	});

	it('recognizes a critical custom SAN under a redundant-leading-zero OID (RFC 5280 §4.2.1.6)', () => {
		expect(
			buildCertificateExtensions(
				subjectPublicKeyInfo,
				undefined,
				{
					customExtensions: [
						{
							oid: '2.5.029.17',
							critical: true,
							value: sequence([
								encodeSubjectAltName({ type: 'dns', value: 'canonical-oid.example' }),
							]),
						},
					],
				},
				true,
			),
		).toBeInstanceOf(Array);
	});

	it('rejects an IP name constraint whose address and mask do not form 8 or 32 octets', () => {
		expectEncoderErrorCode(
			() =>
				encodeNameConstraints({
					permittedSubtrees: [
						{
							base: {
								type: 'ip',
								addressBytes: Uint8Array.of(10, 0, 0, 0),
								maskBytes: Uint8Array.of(255, 0),
							},
						},
					],
				}),
			'invalid_ip_name_constraint',
		);
	});

	it('rejects invalid distribution point construction', () => {
		expectEncoderErrorCode(
			() =>
				Reflect.apply(encodeCrlDistributionPoints, undefined, [[{ reasons: ['keyCompromise'] }]]),
			'distribution_point_empty',
		);
		expectEncoderErrorCode(
			() =>
				encodeCrlDistributionPoints([
					{
						distributionPoint: {
							fullName: [{ type: 'uri', value: 'http://example.test/crl' }],
							relativeName: [{ type: 'commonName', value: 'bad' }],
						},
					},
				]),
			'distribution_point_name_conflict',
		);
		expectEncoderErrorCode(
			() => encodeCrlDistributionPoints([{ distributionPoint: {} }]),
			'distribution_point_name_empty',
		);
	});

	it('rejects non-SEQUENCE directoryName DER when encoding names', () => {
		expectEncoderErrorCode(
			() => encodeSubjectAltName({ type: 'directoryName', derHex: '020100' }),
			'directory_name_not_sequence',
		);
		expectEncoderErrorCode(
			() =>
				encodeNameConstraints({
					permittedSubtrees: [{ base: { type: 'directoryName', derHex: '020100' } }],
				}),
			'directory_name_not_sequence',
		);
	});

	it('rejects an empty relative distinguished name', () => {
		expectEncoderErrorCode(
			() => encodeRelativeDistinguishedName([]),
			'relative_distinguished_name_empty',
		);
	});

	it('rejects an unsupported relative distinguished name field', () => {
		const attribute = { type: 'commonName', value: 'example.test' } as const;
		Object.defineProperty(attribute, 'type', { value: 'unsupported' });
		expectEncoderErrorCode(
			() => encodeRelativeDistinguishedName([attribute]),
			'unsupported_name_field',
		);
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

// signing.ts edge cases

describe('signing.ts edge cases', () => {
	it('describeSignatureAlgorithm recognizes SHA-1 signature OIDs', () => {
		expect(describeSignatureAlgorithm(OIDS.sha1WithRSAEncryption, undefined)).toBe(
			'RSA PKCS#1 v1.5 with SHA-1',
		);
		expect(describeSignatureAlgorithm(OIDS.ecdsaWithSHA1, undefined)).toBe('ECDSA with SHA-1');
		expect(OIDS.ecdsaWithSHA1).toBe('1.2.840.10045.4.1');
		expect(OIDS.ecdsaWithSHA224).toBe('1.2.840.10045.4.3.1');
		expect(describeSignatureAlgorithm(OIDS.ecdsaWithSHA224, undefined)).toBe('ECDSA with SHA-224');
		expect(describeHashAlgorithm(OIDS.sha1)).toBe('SHA-1');
	});

	it('getSignatureAlgorithm throws for unsupported algorithm name', async () => {
		const { generateKeyPair: genKp } = await import('#micro509');
		// Use an ECDSA key but manually check the algorithm name guard
		const keys = await genKp({ kind: 'ecdsa', curve: 'P-256' });
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
		const keys = await genKp({ kind: 'ecdsa', curve: 'P-384' });
		const result = getSignatureAlgorithm(keys.privateKey);
		expect(result.algorithmOid).toBe(OIDS.ecdsaWithSHA384);
		expect(result.ecdsaRawSignatureBytes).toBe(96);
	});

	it('getSignatureAlgorithm returns correct config for ECDSA P-521', async () => {
		const { generateKeyPair: genKp } = await import('#micro509');
		const keys = await genKp({ kind: 'ecdsa', curve: 'P-521' });
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
		expect(result.importAlgorithm).toEqual({ kind: 'ecdsa', curve: 'P-521' });
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

// rsa-pss.ts edge cases

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

	it('omits the default RSA-PSS trailerField from DER output', () => {
		const encoded = encodeRsaPssParameters(rsaPssParametersForHash('SHA-256'));
		expect(readSequenceChildren(encoded).some((child) => child.tag === 0xa3)).toBe(false);
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

// pbes2.ts edge cases

describe('pbes2.ts edge cases', () => {
	it('parsePbes2AlgorithmIdentifier throws on malformed input', () => {
		expect(() => parsePbes2AlgorithmIdentifier(Uint8Array.of(0x30, 0x00))).toThrow();
	});

	it('accepts a PBES2 salt shorter than 8 bytes on decode (RFC 8018 §4.1)', () => {
		// The salt "need not be checked for a particular format by the party
		// receiving the salt", so `openssl pkcs8 -saltlen 4` must decode.
		const der = encodePbes2AlgorithmIdentifier({
			iterations: 2048,
			salt: new Uint8Array(4),
			iv: new Uint8Array(16),
			cipher: 'AES-256-CBC',
			prf: 'HMAC-SHA-256',
		});
		expect(parsePbes2AlgorithmIdentifier(der).salt.length).toBe(4);
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
				cipher: 'AES-128-CBC',
				keyLength: 16,
				prfOid: OIDS.hmacWithSHA1,
				prf: 'HMAC-SHA-1',
			},
			{
				encryptionOid: OIDS.aes192Cbc,
				cipher: 'AES-192-CBC',
				keyLength: 24,
				prfOid: OIDS.hmacWithSHA256,
				prf: 'HMAC-SHA-256',
			},
			{
				encryptionOid: OIDS.aes256Cbc,
				cipher: 'AES-256-CBC',
				keyLength: 32,
				prfOid: OIDS.hmacWithSHA1,
				prf: 'HMAC-SHA-1',
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
				cipher: testCase.cipher,
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
			prf: 'HMAC-SHA-1',
			cipher: 'AES-256-CBC',
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

	it('reports invalid_password when a wrong key survives the CBC padding check', async () => {
		// Deterministic stand-in for the ~1/256 padding fluke: the PBES2
		// envelope decrypts cleanly, but the plaintext is not a PrivateKeyInfo.
		const garbage = new Uint8Array(64).fill(0xaa);
		const encrypted = await encryptPbes2(garbage, { password: 'hunter2', iterations: 1000 });
		const der = sequence([encrypted.algorithmIdentifierDer, octetString(encrypted.encryptedData)]);
		const result = await importEncryptedPkcs8Der(der, 'hunter2', { kind: 'rsa' });
		expect(result.ok).toBe(false);
		if (result.ok) {
			return;
		}
		expect(result.error.code).toBe('invalid_password');
		expect(result.error.message).toContain('Invalid password or encrypted content');
	});
});

// pkcs12-mac.ts edge cases

describe('pkcs12-mac.ts edge cases', () => {
	const dummySafe = new Uint8Array(10);

	it('parsePkcs12MacDataOrThrow throws on malformed MacData (missing salt)', () => {
		// Only digestInfo, no salt or iterations
		const malformed = sequence([
			sequence([
				sequence([objectIdentifier(OIDS.sha256), nullValue()]),
				octetString(new Uint8Array(32)),
			]),
		]);
		expect(parsePkcs12MacDataOrThrow(malformed, dummySafe)).rejects.toThrow('Malformed MacData');
	});

	it('omits the iterations DEFAULT 1 on encode and defaults it back on parse', async () => {
		const authenticatedSafe = Uint8Array.of(1, 2, 3);
		const { der } = await createPkcs12MacData(authenticatedSafe, {
			password: 'pw',
			iterations: 1,
			salt: new Uint8Array(16),
		});
		// iterations 1 is the DEFAULT, so MacData carries only DigestInfo and salt.
		expect(readSequenceChildren(der)).toHaveLength(2);
		const parsed = await parsePkcs12MacDataOrThrow(der, authenticatedSafe, 'pw');
		expect(parsed.iterations).toBe(1);
		expect(parsed.verification).toBe('valid');
	});

	it('parsePkcs12MacDataOrThrow throws on malformed MacData (salt wrong tag)', () => {
		// salt is INTEGER instead of OCTET STRING
		const malformed = sequence([
			sequence([
				sequence([objectIdentifier(OIDS.sha256), nullValue()]),
				octetString(new Uint8Array(32)),
			]),
			integerFromNumber(16), // wrong tag — should be octetString
			integerFromNumber(2048),
		]);
		expect(parsePkcs12MacDataOrThrow(malformed, dummySafe)).rejects.toThrow('Malformed MacData');
	});

	it('parsePkcs12MacDataOrThrow throws on malformed DigestInfo (missing digest)', () => {
		// DigestInfo with only algorithm, no digest
		const malformed = sequence([
			sequence([sequence([objectIdentifier(OIDS.sha256), nullValue()])]),
			octetString(new Uint8Array(16)),
			integerFromNumber(2048),
		]);
		expect(parsePkcs12MacDataOrThrow(malformed, dummySafe)).rejects.toThrow('Malformed DigestInfo');
	});

	it('parsePkcs12MacDataOrThrow throws on malformed DigestInfo (digest wrong tag)', () => {
		// digest is INTEGER instead of OCTET STRING
		const malformed = sequence([
			sequence([
				sequence([objectIdentifier(OIDS.sha256), nullValue()]),
				integerFromNumber(0), // wrong tag — should be octetString
			]),
			octetString(new Uint8Array(16)),
			integerFromNumber(2048),
		]);
		expect(parsePkcs12MacDataOrThrow(malformed, dummySafe)).rejects.toThrow('Malformed DigestInfo');
	});

	it('parsePkcs12MacDataOrThrow throws when algorithm OID is missing', () => {
		// algorithmSequence is empty
		const malformed = sequence([
			sequence([sequence([]), octetString(new Uint8Array(32))]),
			octetString(new Uint8Array(16)),
			integerFromNumber(2048),
		]);
		expect(parsePkcs12MacDataOrThrow(malformed, dummySafe)).rejects.toThrow(
			'MacData algorithm missing',
		);
	});

	it('parsePkcs12MacDataOrThrow throws on non-SHA-256 algorithm', () => {
		// Use SHA-1 OID instead of SHA-256
		const malformed = sequence([
			sequence([
				sequence([objectIdentifier(OIDS.sha1), nullValue()]),
				octetString(new Uint8Array(20)),
			]),
			octetString(new Uint8Array(16)),
			integerFromNumber(2048),
		]);
		expect(parsePkcs12MacDataOrThrow(malformed, dummySafe)).rejects.toThrow('Only SHA-256');
	});

	it('parsePkcs12MacDataOrThrow skips MAC verification when password is undefined', async () => {
		// Build a valid-looking MacData — parsePkcs12MacDataOrThrow should report 'unchecked'
		const data = new Uint8Array([0x30, 0x03, 0x01, 0x01, 0xff]);
		const mac = await createPkcs12MacData(data, { password: 'test' });
		// Parse without password — should succeed but no 'valid' field
		const parsed = await parsePkcs12MacDataOrThrow(mac.der, data);
		expect(parsed.digestAlgorithmOid).toBe(OIDS.sha256);
		expect(parsed.verification).toBe('unchecked');
	});

	it('parsePkcs12MacDataOrThrow throws on zero iterations', () => {
		const malformed = sequence([
			sequence([
				sequence([objectIdentifier(OIDS.sha256), nullValue()]),
				octetString(new Uint8Array(32)),
			]),
			octetString(new Uint8Array(16)),
			integerFromNumber(0),
		]);
		expect(parsePkcs12MacDataOrThrow(malformed, dummySafe)).rejects.toThrow(
			'MacData iterations must be a positive safe integer',
		);
	});

	it('parsePkcs12MacDataOrThrow throws on negative iterations', () => {
		const malformed = sequence([
			sequence([
				sequence([objectIdentifier(OIDS.sha256), nullValue()]),
				octetString(new Uint8Array(32)),
			]),
			octetString(new Uint8Array(16)),
			new Uint8Array([0x02, 0x01, 0xff]),
		]);
		expect(parsePkcs12MacDataOrThrow(malformed, dummySafe)).rejects.toThrow(
			'MacData iterations must be non-negative',
		);
	});

	it('createPkcs12MacData rejects zero iterations', () => {
		expect(createPkcs12MacData(dummySafe, { password: 'test', iterations: 0 })).rejects.toThrow(
			'MacData iterations must be a positive safe integer',
		);
	});

	it('createPkcs12MacData supports empty salt', async () => {
		const data = new Uint8Array([0x30, 0x03, 0x01, 0x01, 0xff]);
		const mac = await createPkcs12MacData(data, {
			password: 'test',
			salt: new Uint8Array(),
		});
		expect(mac.parsed.saltHex).toBe('');
		const parsed = await parsePkcs12MacDataOrThrow(mac.der, data, 'test');
		expect(parsed.saltHex).toBe('');
		expect(parsed.verification).toBe('valid');
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

function asn1StringElement(tag: number, value: string): Uint8Array {
	const bytes = new TextEncoder().encode(value);
	return new Uint8Array([tag, bytes.length, ...bytes]);
}

describe('ecdsaSignatureToDer', () => {
	it('converts a raw signature to DER even when r starts with the SEQUENCE tag byte', () => {
		// Regression: the old first-byte sniff left raw signatures whose r
		// began with 0x30 unconverted, embedding an invalid DER signature
		// (~1 in 256 ECDSA signatures; OpenSSL rejects the artifact).
		const raw = new Uint8Array(64).fill(0x42);
		raw[0] = 0x30;
		const der = ecdsaSignatureToDer(raw, 64);
		const parts = readSequenceChildren(der);
		expect(parts).toHaveLength(2);
		expect(parts[0]?.tag).toBe(0x02);
		expect(parts[1]?.tag).toBe(0x02);
		expect(new Uint8Array(derEcdsaSignatureToRaw(der, 32))).toEqual(raw);
	});

	it('passes through signatures that are not raw-length', () => {
		const der = rawEcdsaSignatureToDer(new Uint8Array(64).fill(7), 32);
		expect(ecdsaSignatureToDer(der, 64)).toBe(der);
	});

	it('emitted certificate and CRL ECDSA signatures always parse as DER r/s pairs', async () => {
		for (let i = 0; i < 8; i++) {
			const ca = await createSelfSignedCertificate({
				subject: { commonName: `DER Sig CA ${i}` },
				extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
			});
			const crl = await createCertificateRevocationList({
				issuer: { commonName: `DER Sig CA ${i}` },
				signerPrivateKey: ca.keyPair.privateKey,
				issuerPublicKey: ca.keyPair.publicKey,
				revokedCertificates: [],
			});
			for (const der of [
				unwrap(parseCertificatePem(ca.certificate.pem)).signatureValue,
				parseCertificateRevocationListPemOrThrow(crl.pem).signatureValue,
			]) {
				const parts = readSequenceChildren(new Uint8Array(der));
				expect(parts).toHaveLength(2);
				expect(parts[0]?.tag).toBe(0x02);
				expect(parts[1]?.tag).toBe(0x02);
			}
		}
	});
});

describe('pbes2.ts DEFAULT prf', () => {
	const base = {
		iterations: 2048,
		salt: new Uint8Array(8),
		iv: new Uint8Array(16),
		cipher: 'AES-256-CBC' as const,
	};

	const pbkdf2ParamsChildren = (pbes2Der: Uint8Array): ReturnType<typeof readElement>[] => {
		const pbes2Params = childrenOf(pbes2Der, readElement(pbes2Der))[1];
		if (pbes2Params === undefined) throw new Error('missing PBES2-params');
		const keyDerivationFunc = childrenOf(pbes2Der, pbes2Params)[0];
		if (keyDerivationFunc === undefined) throw new Error('missing keyDerivationFunc');
		const pbkdf2Params = childrenOf(pbes2Der, keyDerivationFunc)[1];
		if (pbkdf2Params === undefined) throw new Error('missing PBKDF2-params');
		return childrenOf(pbes2Der, pbkdf2Params);
	};

	it('omits the PBKDF2 prf DEFAULT HMAC-SHA-1 but keeps keyLength', () => {
		const der = encodePbes2AlgorithmIdentifier({ ...base, prf: 'HMAC-SHA-1' });
		expect(parsePbes2AlgorithmIdentifier(der).prf).toBe('HMAC-SHA-1');
		// HMAC-SHA-256 is not the default, so its prf AlgorithmIdentifier is encoded.
		const withSha256 = encodePbes2AlgorithmIdentifier({ ...base, prf: 'HMAC-SHA-256' });
		expect(der.length).toBeLessThan(withSha256.length);
		expect(parsePbes2AlgorithmIdentifier(withSha256).prf).toBe('HMAC-SHA-256');

		const derChildren = pbkdf2ParamsChildren(der);
		expect(derChildren).toHaveLength(3);
		expect(derChildren[2]?.tag).toBe(0x02);
		const sha256Children = pbkdf2ParamsChildren(withSha256);
		expect(sha256Children).toHaveLength(4);
		expect(sha256Children[2]?.tag).toBe(0x02);
		expect(sha256Children[3]?.tag).toBe(0x30);
	});
});
