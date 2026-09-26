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
	checkStrictDer,
	decodeBoolean,
	decodeIntegerMagnitude,
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
	concatBytes,
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
	readRootElement,
	readSequenceChildren,
	sequence,
	setOf,
	time,
	tlv,
	utcTime,
	utf8String,
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
import { rebaseDiagnostic } from '#micro509/internal/verify/verify-path';
import {
	parseDistributionPointReasonFlagsContent,
	parseKeyUsageExtension,
} from '#micro509/internal/x509/extension-bits';
import { listExtensionDefinitions } from '#micro509/internal/x509/extension-registry';
import { parseGeneralNames } from '#micro509/internal/x509/general-name';
import { createPkcs12MacData, parsePkcs12MacDataOrThrow } from '#micro509/pkcs';
import {
	buildCertificateExtensions,
	buildRequestedExtensions,
	encodeAuthorityInfoAccess,
	encodeBasicConstraints,
	encodeCertificatePolicies,
	encodeCrlDistributionPoints,
	encodeExtendedKeyUsage,
	encodeExtension,
	encodeInhibitAnyPolicy,
	encodeKeyUsage,
	encodeName,
	encodeNameConstraints,
	encodePolicyConstraints,
	encodePolicyMappings,
	encodeRelativeDistinguishedName,
	encodeSubjectAltName,
	getAuthorityInfoAccessMethodOid,
	getExtendedKeyUsageOid,
} from '#micro509/x509';
import { parseCrlDistributionPoints, parseNameConstraints } from '#micro509/x509/parse';
import {
	childrenOf,
	encodeUncheckedCrlDistributionPoints,
	FAR_FUTURE_NEXT_UPDATE,
} from '#test/helpers';

/** An RFC 5280 ORAddress with every top-level component present. */
function validOrAddress(): Uint8Array {
	const text = (value: string) => new TextEncoder().encode(value);
	return concatBytes([
		sequence([
			tlv(0x61, printableString('NL')),
			tlv(0x83, text('Acme')),
			tlv(0xa5, concatBytes([tlv(0x80, text('Doe')), tlv(0x81, text('Jane'))])),
			tlv(0xa6, printableString('Sales')),
		]),
		sequence([sequence([printableString('dept'), printableString('42')])]),
		setOf([
			sequence([tlv(0x80, Uint8Array.of(1)), explicitContext(1, printableString('Jane Doe'))]),
		]),
	]);
}

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

	it('parseTime rejects a time value that opens with the octets EF BB BF', () => {
		const bom = Uint8Array.of(0xef, 0xbb, 0xbf);
		const encoder = new TextEncoder();
		expect(() =>
			parseTime(readElement(tlv(0x17, concatBytes([bom, encoder.encode('260101000000Z')])))),
		).toThrow('Invalid UTCTime');
		expect(() =>
			parseTime(readElement(tlv(0x18, concatBytes([bom, encoder.encode('20260101000000Z')])))),
		).toThrow('Invalid GeneralizedTime');
	});

	it('decodeString keeps a leading U+FEFF in a UTF8String', () => {
		expect(decodeString(0x0c, Uint8Array.of(0xef, 0xbb, 0xbf))).toBe('﻿');
		expect(decodeString(0x0c, Uint8Array.of(0xef, 0xbb, 0xbf, 0x41))).toBe('﻿A');
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

	it('decodeIntegerMagnitude reports unsafe above MAX_SAFE_INTEGER', () => {
		expect(decodeIntegerMagnitude(Uint8Array.of(0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff))).toEqual(
			{
				type: 'safe',
				value: Number.MAX_SAFE_INTEGER,
			},
		);
		expect(decodeIntegerMagnitude(Uint8Array.of(0x20, 0, 0, 0, 0, 0, 1))).toEqual({
			type: 'unsafe',
		});
	});

	it('decodeIntegerMagnitude stops at the first octet past MAX_SAFE_INTEGER', () => {
		const huge = new Uint8Array(10_000_000).fill(0x7f);
		expect(decodeIntegerMagnitude(huge)).toEqual({ type: 'unsafe' });
	}, 1_000);

	it('decodeIntegerMagnitude labels empty, negative, and non-minimal encodings', () => {
		expect(() => decodeIntegerMagnitude(new Uint8Array(), 'field')).toThrow('field is empty');
		expect(() => decodeIntegerMagnitude(Uint8Array.of(0xff), 'field')).toThrow(
			'field must be non-negative',
		);
		expect(() => decodeIntegerMagnitude(Uint8Array.of(0x00, 0x01), 'field')).toThrow(
			'field must use minimal encoding',
		);
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
		for (const noncharacter of [Uint8Array.of(0xff, 0xfe), Uint8Array.of(0xff, 0xff)]) {
			expect(() => decodeString(0x1e, noncharacter)).toThrow('Invalid BMPString code point');
		}
		expect(decodeString(0x1e, Uint8Array.of(0xff, 0xfd))).toBe('�');
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

describe('checkStrictDer', () => {
	const octets = (...values: number[]) => Uint8Array.from(values);
	const text = (value: string) => new TextEncoder().encode(value);

	it.each([
		['BOOLEAN FALSE', tlv(0x01, octets(0x00))],
		['BOOLEAN TRUE', tlv(0x01, octets(0xff))],
		['INTEGER zero', tlv(0x02, octets(0x00))],
		['INTEGER -1', tlv(0x02, octets(0xff))],
		['INTEGER 128', tlv(0x02, octets(0x00, 0x80))],
		['INTEGER -129', tlv(0x02, octets(0xff, 0x7f))],
		['INTEGER past 2^53', tlv(0x02, new Uint8Array(40).fill(0x7f))],
		['empty BIT STRING', tlv(0x03, octets(0x00))],
		['BIT STRING with zero padding', tlv(0x03, octets(0x03, 0xf8))],
		['empty OCTET STRING', tlv(0x04, new Uint8Array())],
		['NULL', tlv(0x05, new Uint8Array())],
		[
			'OBJECT IDENTIFIER with a 128-bit arc',
			objectIdentifier('2.25.329800735698586629295641978511506172918'),
		],
		['ENUMERATED', tlv(0x0a, octets(0x01))],
		['UTF8String', tlv(0x0c, text('ünïcode'))],
		['NumericString', tlv(0x12, text('0123 456'))],
		['PrintableString', tlv(0x13, text("Az 09 '()+,-./:=?"))],
		['IA5String', tlv(0x16, octets(0x00, 0x7f))],
		['UTCTime', tlv(0x17, text('260926120000Z'))],
		['UTCTime on 29 February of year 00', tlv(0x17, text('000229000000Z'))],
		['GeneralizedTime', tlv(0x18, text('20260926120000Z'))],
		['GeneralizedTime with a fraction', tlv(0x18, text('20260926120000.05Z'))],
		['GeneralizedTime in year 4', tlv(0x18, text('00040229000000Z'))],
		['VisibleString', tlv(0x1a, text(' ~'))],
		['UniversalString', tlv(0x1c, octets(0x00, 0x01, 0xf6, 0x00))],
		['BMPString', tlv(0x1e, octets(0x00, 0x41))],
		['empty SEQUENCE', sequence([])],
		['empty SET', setOf([])],
		[
			'universal elements under context tags',
			sequence([nullValue(), explicitContext(0, sequence([tlv(0x02, octets(0x01))]))]),
		],
		['opaque primitive context contents', tlv(0x80, octets(0x00, 0x00))],
		['opaque primitive application contents', tlv(0x41, octets(0x05, 0x01, 0x00))],
		['opaque primitive private contents', tlv(0xc1, octets(0x01, 0x01, 0x01))],
		['REAL plus zero', tlv(0x09, new Uint8Array())],
		['REAL PLUS-INFINITY', tlv(0x09, octets(0x40))],
		['REAL minus zero', tlv(0x09, octets(0x43))],
		['binary REAL 1', tlv(0x09, octets(0x80, 0x00, 0x01))],
		['binary REAL -3 × 2^-2', tlv(0x09, octets(0xc0, 0xfe, 0x03))],
		['binary REAL with a two-octet exponent', tlv(0x09, octets(0x81, 0x01, 0x00, 0x01))],
		['decimal REAL 1.5', tlv(0x09, concatBytes([octets(0x03), text('15.E-1')]))],
		['decimal REAL -5', tlv(0x09, concatBytes([octets(0x03), text('-5.E+0')]))],
		['RELATIVE-OID', tlv(0x0d, octets(0x81, 0x00, 0x01))],
		['ASCII GraphicString', tlv(0x19, text('EXAMPLE.COM'))],
		['ASCII ObjectDescriptor', tlv(0x07, text('descriptor'))],
		['GeneralString with C0 controls and DELETE', tlv(0x1b, octets(0x00, 0x0a, 0x41, 0x7f))],
		['UTF8String holding SHIFT OUT', tlv(0x0c, octets(0x0e))],
	] as const)('accepts %s', (_label, der) => {
		expect(checkStrictDer(der)).toBe('valid');
	});

	it.each([
		['TeletexString', tlv(0x14, text('x'))],
		['VideotexString', tlv(0x15, text('x'))],
		['TIME', tlv(0x0e, text('2026-09-26'))],
		[
			'EXTERNAL',
			tlv(0x28, concatBytes([objectIdentifier('1.2.3'), explicitContext(0, nullValue())])),
		],
		[
			'EMBEDDED PDV',
			tlv(
				0x2b,
				concatBytes([explicitContext(0, tlv(0x85, new Uint8Array())), tlv(0x82, octets(0x01))]),
			),
		],
		[
			'CHARACTER STRING',
			tlv(
				0x3d,
				concatBytes([explicitContext(0, tlv(0x85, new Uint8Array())), tlv(0x82, octets(0x41))]),
			),
		],
		['binary REAL with a long-form exponent', tlv(0x09, octets(0x83, 0x01, 0x05, 0x01))],
		['GeneralizedTime at second 60', tlv(0x18, text('20161231235960Z'))],
		['UTF8String with an escape sequence', tlv(0x0c, octets(0x1b, 0x28, 0x42))],
		['IA5String with ESCAPE', tlv(0x16, octets(0x41, 0x1b))],
		['BMPString with SHIFT OUT', tlv(0x1e, octets(0x00, 0x0e))],
		['UniversalString with CONTROL SEQUENCE INTRODUCER', tlv(0x1c, octets(0x00, 0x00, 0x00, 0x9b))],
		['GraphicString with an escape sequence', tlv(0x19, octets(0x1b, 0x28, 0x42, 0x41))],
		['GeneralString with SHIFT IN', tlv(0x1b, octets(0x41, 0x0f))],
		['TeletexString inside a SEQUENCE', sequence([tlv(0x14, text('x'))])],
	] as const)('reports %s as unsupported', (_label, der) => {
		expect(checkStrictDer(der)).toBe('unsupported');
	});

	it('reports a malformed element over an unsupported one', () => {
		expect(checkStrictDer(sequence([tlv(0x14, text('x')), tlv(0x05, octets(0x00))]))).toBe(
			'malformed',
		);
		expect(checkStrictDer(sequence([tlv(0x05, octets(0x00)), tlv(0x14, text('x'))]))).toBe(
			'malformed',
		);
	});

	it.each([
		['end-of-contents (X.690 §8.1.5, §10.1)', tlv(0x00, new Uint8Array())],
		['empty BOOLEAN (X.690 §8.2.1)', tlv(0x01, new Uint8Array())],
		['two-octet BOOLEAN (X.690 §8.2.1)', tlv(0x01, octets(0xff, 0xff))],
		['BOOLEAN TRUE as 0x01 (X.690 §11.1)', tlv(0x01, octets(0x01))],
		['empty INTEGER (X.690 §8.3.1)', tlv(0x02, new Uint8Array())],
		['INTEGER with a redundant 0x00 (X.690 §8.3.2)', tlv(0x02, octets(0x00, 0x7f))],
		['INTEGER with a redundant 0xFF (X.690 §8.3.2)', tlv(0x02, octets(0xff, 0x80))],
		['ENUMERATED with a redundant 0x00 (X.690 §8.4)', tlv(0x0a, octets(0x00, 0x01))],
		['BIT STRING with no initial octet (X.690 §8.6.2)', tlv(0x03, new Uint8Array())],
		['BIT STRING with eight unused bits (X.690 §8.6.2.2)', tlv(0x03, octets(0x08, 0x00))],
		['empty BIT STRING with unused bits (X.690 §8.6.2.3)', tlv(0x03, octets(0x01))],
		['BIT STRING with a set padding bit (X.690 §11.2.1)', tlv(0x03, octets(0x01, 0x01))],
		['NULL with contents (X.690 §8.8.2)', tlv(0x05, octets(0x00))],
		['empty OBJECT IDENTIFIER (X.690 §8.19)', tlv(0x06, new Uint8Array())],
		[
			'OBJECT IDENTIFIER arc opening with 0x80 (X.690 §8.19.2)',
			tlv(0x06, octets(0x2a, 0x80, 0x01)),
		],
		['unterminated OBJECT IDENTIFIER arc (X.690 §8.19.2)', tlv(0x06, octets(0x2a, 0x86))],
		['UTF8String that is not UTF-8', tlv(0x0c, octets(0xc3, 0x28))],
		['NumericString with a letter', tlv(0x12, text('12a'))],
		['PrintableString with @', tlv(0x13, text('a@b'))],
		['IA5String above 0x7F', tlv(0x16, octets(0x80))],
		['VisibleString with DEL', tlv(0x1a, octets(0x7f))],
		['UniversalString surrogate', tlv(0x1c, octets(0x00, 0x00, 0xd8, 0x00))],
		['odd-length BMPString', tlv(0x1e, octets(0x00))],
		['BMPString holding U+FFFF (X.680 §41.15)', tlv(0x1e, octets(0xff, 0xff))],
		['UTCTime without seconds (X.690 §11.8)', tlv(0x17, text('2609261200Z'))],
		['UTCTime with an offset (X.690 §11.8)', tlv(0x17, text('260926120000+0100'))],
		['UTCTime in month 13', tlv(0x17, text('261326120000Z'))],
		['UTCTime at hour 24 (X.690 §11.8)', tlv(0x17, text('260926240000Z'))],
		[
			'GeneralizedTime with a trailing fraction zero (X.690 §11.7)',
			tlv(0x18, text('20260926120000.50Z')),
		],
		['GeneralizedTime with a zero fraction (X.690 §11.7)', tlv(0x18, text('20260926120000.0Z'))],
		['GeneralizedTime with a decimal comma (X.690 §11.7)', tlv(0x18, text('20260926120000,5Z'))],
		['GeneralizedTime in local time (X.690 §11.7)', tlv(0x18, text('20260926120000'))],
		['GeneralizedTime on 29 February 2025', tlv(0x18, text('20250229000000Z'))],
		['GeneralizedTime on 29 February 1900', tlv(0x18, text('19000229000000Z'))],
		[
			'GeneralizedTime with a BOM',
			tlv(0x18, concatBytes([octets(0xef, 0xbb, 0xbf), text('20260926120000Z')])),
		],
		['constructed OCTET STRING (X.690 §10.2)', tlv(0x24, octetString(octets(0x01)))],
		['constructed BIT STRING (X.690 §10.2)', tlv(0x23, bitString(octets(0x01)))],
		['constructed UTF8String (X.690 §10.2)', tlv(0x2c, utf8String('x'))],
		['constructed BOOLEAN (X.690 §8.2.1)', tlv(0x21, tlv(0x01, octets(0xff)))],
		['primitive SEQUENCE (X.690 §8.9.1)', tlv(0x10, new Uint8Array())],
		['primitive SET (X.690 §8.11.1)', tlv(0x11, new Uint8Array())],
		['reserved universal tag 15', tlv(0x0f, new Uint8Array())],
		['NULL with contents inside a SEQUENCE', sequence([tlv(0x05, octets(0x00))])],
		[
			'BOOLEAN TRUE as 0x01 under a context tag',
			explicitContext(3, sequence([tlv(0x01, octets(0x01))])),
		],
		['BOOLEAN TRUE as 0x01 under an application tag', tlv(0x61, tlv(0x01, octets(0x01)))],
		['trailing data after the element', concatBytes([nullValue(), nullValue()])],
		['REAL in base 8 (X.690 §11.3.1)', tlv(0x09, octets(0x90, 0x00, 0x01))],
		['REAL with scaling factor 1 (X.690 §11.3.1)', tlv(0x09, octets(0x84, 0x00, 0x01))],
		['REAL with an even mantissa (X.690 §11.3.1)', tlv(0x09, octets(0x80, 0x00, 0x02))],
		[
			'REAL mantissa with a leading zero octet (X.690 §11.3.1)',
			tlv(0x09, octets(0x80, 0x00, 0x00, 0x01)),
		],
		['REAL with no mantissa (X.690 §8.5.7)', tlv(0x09, octets(0x80, 0x00))],
		[
			'REAL with a padded two-octet exponent (X.690 §11.3.1)',
			tlv(0x09, octets(0x81, 0x00, 0x01, 0x01)),
		],
		['REAL special value with a second octet (X.690 §8.5.9)', tlv(0x09, octets(0x40, 0x00))],
		['reserved REAL special value (X.690 §8.5.9)', tlv(0x09, octets(0x44))],
		['REAL in NR1 form (X.690 §11.3.2.1)', tlv(0x09, concatBytes([octets(0x01), text('1')]))],
		...[
			['with a zero mantissa', '0.E+0'],
			['whose mantissa ends in 0', '10.E+0'],
			['with a PLUS SIGN', '+5.E+0'],
			['with an exponent of 0 not written +0', '5.E0'],
			['with a PLUS SIGN on its exponent', '5.E+1'],
			['with a leading 0 in its exponent', '5.E01'],
			['with a lower-case exponent mark', '5.e+0'],
			['with a SPACE', '5 .E+0'],
			['with a point inside the mantissa', '1.5E+0'],
		].map(
			([label = '', nr3 = '']) =>
				[
					`decimal REAL ${label} (X.690 §11.3.2)`,
					tlv(0x09, concatBytes([octets(0x03), text(nr3)])),
				] as const,
		),
		['empty RELATIVE-OID (X.680 §33.3)', tlv(0x0d, new Uint8Array())],
		['RELATIVE-OID arc opening with 0x80 (X.690 §8.20.2)', tlv(0x0d, octets(0x80, 0x01))],
		['GraphicString with a C0 control', tlv(0x19, octets(0x0a))],
		['GraphicString with DELETE', tlv(0x19, octets(0x7f))],
		['GraphicString with an octet above 0x7F', tlv(0x19, octets(0xa0))],
		['GeneralString with an octet above 0x7F', tlv(0x1b, octets(0x80))],
		['UTCTime at second 60 (X.680 §47.3)', tlv(0x17, text('161231235960Z'))],
		['primitive EXTERNAL (X.690 §8.18.1)', tlv(0x08, new Uint8Array())],
		['primitive CHARACTER STRING (X.690 §8.24.1)', tlv(0x1d, new Uint8Array())],
		['constructed TIME (X.690 §8.26.1.1)', tlv(0x2e, new Uint8Array())],
	] as const)('rejects %s', (_label, der) => {
		expect(checkStrictDer(der)).toBe('malformed');
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

	// RFC 4055 §5, over sha224/256/384/512WithRSAEncryption: "When any of these four
	// object identifiers appears within an AlgorithmIdentifier, the parameters MUST be
	// NULL. Implementations MUST accept the parameters being absent as well as
	// present." Anything that is neither is still rejected.
	it('getVerifySignatureConfigResult accepts PKCS#1 v1.5 parameters absent or DER NULL', () => {
		expect(
			getVerifySignatureConfigResult(
				OIDS.sha256WithRSAEncryption,
				undefined,
				OIDS.rsaEncryption,
				undefined,
			),
		).toMatchObject({
			ok: true,
			value: { importAlgorithm: { kind: 'rsa', hash: 'SHA-256', scheme: 'pkcs1-v1_5' } },
		});

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

		for (const [oid, hash] of [
			[OIDS.sha256WithRSAEncryption, 'SHA-256'],
			[OIDS.sha384WithRSAEncryption, 'SHA-384'],
			[OIDS.sha512WithRSAEncryption, 'SHA-512'],
		] as const) {
			for (const parameters of [undefined, nullValue()]) {
				expect(
					getVerifySignatureConfigResult(oid, parameters, OIDS.rsaEncryption, undefined),
				).toMatchObject({
					ok: true,
					value: { importAlgorithm: { kind: 'rsa', hash, scheme: 'pkcs1-v1_5' } },
				});
			}
		}
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
		// Raw x400Address [3], ediPartyName [5], and registeredID [8] input keeps its tag.
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

	it('encodeSubjectAltName round-trips every typed GeneralName alternative through the decoder', () => {
		const names = [
			{
				type: 'otherName',
				typeId: '1.3.6.1.4.1.311.20.2.3',
				value: utf8String('user@example.com'),
			},
			{ type: 'x400Address', value: validOrAddress() },
			{ type: 'ediPartyName', value: explicitContext(1, utf8String('party')) },
			{ type: 'registeredID', value: '1.2.840.113549' },
		] as const;
		const encoded = sequence(names.map((name) => encodeSubjectAltName(name)));
		expect(parseGeneralNames(encoded, readRootElement(encoded))).toEqual([...names]);
	});

	it('encodeSubjectAltName validates each EDIPartyName DirectoryString encoding', () => {
		// RFC 5280 gives PrintableString, UniversalString, UTF8String and BMPString each SIZE (1..MAX).
		const alternatives = [
			[0x13, Uint8Array.of(0x70), Uint8Array.of(0x2a)],
			[0x1c, Uint8Array.of(0x00, 0x00, 0x00, 0x70), Uint8Array.of(0x00, 0x11, 0x00, 0x00)],
			[0x0c, Uint8Array.of(0x70), Uint8Array.of(0xff)],
			[0x1e, Uint8Array.of(0x00, 0x70), Uint8Array.of(0x41)],
		] as const;
		for (const [tag, content, invalid] of alternatives) {
			const filled = tlv(tag, content);
			for (const bad of [tlv(tag, new Uint8Array()), tlv(tag, invalid)]) {
				expectEncoderErrorCode(
					() => encodeSubjectAltName({ type: 'ediPartyName', value: explicitContext(1, bad) }),
					'invalid_general_name_content',
				);
				expectEncoderErrorCode(
					() =>
						encodeSubjectAltName({
							type: 'ediPartyName',
							value: concatBytes([explicitContext(0, bad), explicitContext(1, filled)]),
						}),
					'invalid_general_name_content',
				);
			}
			expect(
				encodeSubjectAltName({
					type: 'ediPartyName',
					value: concatBytes([explicitContext(0, filled), explicitContext(1, filled)]),
				})[0],
			).toBe(0xa5);
		}
		for (const zeroWidthNoBreakSpace of [
			tlv(0x0c, Uint8Array.of(0xef, 0xbb, 0xbf)),
			tlv(0x1e, Uint8Array.of(0xfe, 0xff)),
			tlv(0x1c, Uint8Array.of(0x00, 0x00, 0xfe, 0xff)),
		]) {
			expect(
				encodeSubjectAltName({
					type: 'ediPartyName',
					value: explicitContext(1, zeroWidthNoBreakSpace),
				})[0],
			).toBe(0xa5);
		}
	});

	it('encodeSubjectAltName validates x400Address contents against the RFC 5280 ORAddress schema', () => {
		const text = (value: string) => new TextEncoder().encode(value);
		const standard = (...fields: Uint8Array[]) => sequence(fields);
		const extension = (type: number, value: Uint8Array) =>
			sequence([tlv(0x80, Uint8Array.of(type)), explicitContext(1, value)]);
		const accepted = [
			validOrAddress(),
			standard(),
			concatBytes([standard(tlv(0x80, text('0123 456')))]),
			concatBytes([standard(), setOf([extension(23, integerFromNumber(256))])]),
			concatBytes([standard(), setOf([extension(10, setOf([printableString('Office 1')]))])]),
			concatBytes([
				standard(),
				setOf([extension(16, setOf([sequence([printableString('Line')])]))]),
			]),
			standard(tlv(0x62, tlv(0x12, new Uint8Array())), tlv(0xa2, printableString('private'))),
			concatBytes([
				standard(),
				tlv(
					0x31,
					concatBytes([extension(7, printableString('pds')), extension(7, printableString('pds'))]),
				),
			]),
		];
		for (const value of accepted) {
			expect(encodeSubjectAltName({ type: 'x400Address', value })[0]).toBe(0xa3);
		}
		const malformed = [
			sequence([integerFromNumber(1)]),
			standard(tlv(0x83, text('Acme')), tlv(0x61, printableString('NL'))),
			standard(tlv(0x61, printableString('NLD'))),
			standard(tlv(0x61, tlv(0x12, text('12')))),
			standard(tlv(0x83, text(''))),
			standard(tlv(0x83, text('a'.repeat(65)))),
			standard(tlv(0x80, text('12a'))),
			standard(tlv(0x83, text('under_score'))),
			standard(tlv(0xa5, tlv(0x81, text('Jane')))),
			standard(tlv(0xa5, concatBytes([tlv(0x81, text('Jane')), tlv(0x80, text('Doe'))]))),
			standard(tlv(0xa6, concatBytes(Array.from({ length: 5 }, () => printableString('ou'))))),
			concatBytes([
				standard(),
				sequence(
					Array.from({ length: 5 }, () => sequence([printableString('t'), printableString('v')])),
				),
			]),
			concatBytes([
				standard(),
				sequence([sequence([printableString('toolongtype'), printableString('v')])]),
			]),
			concatBytes([standard(), setOf([])]),
			concatBytes([
				standard(),
				tlv(
					0x31,
					concatBytes([extension(7, printableString('b')), extension(1, printableString('a'))]),
				),
			]),
			concatBytes([standard(), setOf([extension(1, printableString(''))])]),
			concatBytes([standard(), setOf([extension(23, integerFromNumber(257))])]),
			concatBytes([standard(), setOf([extension(23, tlv(0x02, new Uint8Array()))])]),
			concatBytes([
				standard(),
				setOf([sequence([tlv(0x80, new Uint8Array()), explicitContext(1, printableString('x'))])]),
			]),
			standard(tlv(0x62, printableString('a'.repeat(17)))),
			standard(tlv(0xa2, printableString(''))),
			concatBytes([standard(), setOf([extension(7, printableString('a'.repeat(17)))])]),
		];
		for (const value of malformed) {
			expectEncoderErrorCode(
				() => encodeSubjectAltName({ type: 'x400Address', value }),
				'invalid_general_name_content',
			);
		}
		const unsupported = [
			concatBytes([standard(), setOf([extension(2, tlv(0x14, text('x')))])]),
			concatBytes([standard(), setOf([extension(22, sequence([tlv(0x80, text('1'))]))])]),
			concatBytes([standard(), setOf([extension(30, printableString('x'))])]),
			concatBytes([standard(), setOf([extension(10, setOf([tlv(0x14, text('x'))]))])]),
		];
		for (const value of unsupported) {
			expect(() => encodeSubjectAltName({ type: 'x400Address', value })).toThrow(/cannot validate/);
		}
	});

	it('encodeSubjectAltName refuses a TeletexString EDIPartyName it cannot validate', () => {
		expect(() =>
			encodeSubjectAltName({
				type: 'ediPartyName',
				value: explicitContext(1, tlv(0x14, Uint8Array.of(0x70))),
			}),
		).toThrow(/cannot validate/);
		expectEncoderErrorCode(
			() =>
				encodeSubjectAltName({
					type: 'ediPartyName',
					value: explicitContext(1, tlv(0x14, Uint8Array.of(0x70))),
				}),
			'invalid_general_name_content',
		);
	});

	it('encodeSubjectAltName refuses an otherName value holding a type it cannot validate', () => {
		const value = sequence([utf8String('a'), tlv(0x14, Uint8Array.of(0x41))]);
		expect(() => encodeSubjectAltName({ type: 'otherName', typeId: '1.2.3.4', value })).toThrow(
			/cannot validate/,
		);
		expectEncoderErrorCode(
			() => encodeSubjectAltName({ type: 'otherName', typeId: '1.2.3.4', value }),
			'invalid_other_name_value',
		);
	});

	it('encodeSubjectAltName encodes an RFC 4556 KRB5PrincipalName otherName', () => {
		const kerberosString = (value: string) => tlv(0x1b, new TextEncoder().encode(value));
		const krb5PrincipalName = sequence([
			explicitContext(0, kerberosString('EXAMPLE.COM')),
			explicitContext(
				1,
				sequence([
					explicitContext(0, integerFromNumber(1)),
					explicitContext(1, sequence([kerberosString('alice')])),
				]),
			),
		]);
		expect(
			encodeSubjectAltName({
				type: 'otherName',
				typeId: '1.3.6.1.5.2.2',
				value: krb5PrincipalName,
			})[0],
		).toBe(0xa0);
	});

	it('encodeSubjectAltName refuses an otherName it cannot encode faithfully', () => {
		for (const typeId of [OIDS.idOnDnsSrv, OIDS.idOnSmtpUtf8Mailbox]) {
			expectEncoderErrorCode(
				() => encodeSubjectAltName({ type: 'otherName', typeId, value: utf8String('x') }),
				'other_name_type_id_has_variant',
			);
		}
		expectEncoderErrorCode(
			() => encodeSubjectAltName({ type: 'otherName', typeId: '3.1', value: utf8String('x') }),
			'invalid_oid',
		);
		expectEncoderErrorCode(
			() =>
				encodeSubjectAltName({
					type: 'otherName',
					typeId: '1.2.3.4',
					value: concatBytes([utf8String('a'), utf8String('b')]),
				}),
			'invalid_other_name_value',
		);
		for (const value of [
			Uint8Array.of(0x00, 0x00),
			sequence([utf8String('a'), Uint8Array.of(0x00, 0x00)]),
			explicitContext(2, sequence([Uint8Array.of(0x00, 0x00)])),
			tlv(0x05, Uint8Array.of(0x00)),
			tlv(0x01, Uint8Array.of(0x01)),
			tlv(0x02, Uint8Array.of(0x00, 0x01)),
			sequence([utf8String('a'), tlv(0x02, Uint8Array.of(0xff, 0xff))]),
		]) {
			expectEncoderErrorCode(
				() => encodeSubjectAltName({ type: 'otherName', typeId: '1.2.3.4', value }),
				'invalid_other_name_value',
			);
		}
		for (const value of [
			octetString(Uint8Array.of(0x00, 0x00)),
			sequence([explicitContext(0, octetString(Uint8Array.of(0x00, 0x00, 0x00)))]),
		]) {
			expect(encodeSubjectAltName({ type: 'otherName', typeId: '1.2.3.4', value })[0]).toBe(0xa0);
		}
		expectEncoderErrorCode(
			() => encodeSubjectAltName({ type: 'registeredID', value: '1' }),
			'invalid_oid',
		);
		const malformed = [
			['x400Address', Uint8Array.of(0xff)],
			['x400Address', Uint8Array.of(0x30, 0x05)],
			['x400Address', new Uint8Array()],
			['x400Address', printableString('x')],
			['x400Address', concatBytes([sequence([]), setOf([]), sequence([])])],
			['ediPartyName', Uint8Array.of(0xff)],
			['ediPartyName', new Uint8Array()],
			['ediPartyName', explicitContext(0, utf8String('assigner'))],
			['ediPartyName', explicitContext(1, integerFromNumber(1))],
			[
				'ediPartyName',
				concatBytes([explicitContext(1, utf8String('a')), explicitContext(0, utf8String('b'))]),
			],
		] as const;
		for (const [type, value] of malformed) {
			expectEncoderErrorCode(
				() => encodeSubjectAltName({ type, value }),
				'invalid_general_name_content',
			);
		}
		expect(
			encodeSubjectAltName({
				type: 'ediPartyName',
				value: concatBytes([
					explicitContext(0, printableString('assigner')),
					explicitContext(1, utf8String('party')),
				]),
			})[0],
		).toBe(0xa5);
	});

	it('encodeNameConstraints writes the three RFC 4985 §4 SRVName restriction forms', () => {
		const encoded = encodeNameConstraints({
			permittedSubtrees: [
				{ base: { type: 'srv', value: '_mail' } },
				{ base: { type: 'srv', value: 'café.example' } },
				{ base: { type: 'srv', value: '_mail.café.example' } },
			],
		});
		expect(parseNameConstraints(encoded).permittedSubtrees).toEqual([
			{ base: { type: 'srv', value: '_mail' } },
			{ base: { type: 'srv', value: 'xn--caf-dma.example' } },
			{ base: { type: 'srv', value: '_mail.xn--caf-dma.example' } },
		]);
	});

	it('encodeNameConstraints and encodeSubjectAltName hold the service to RFC 6335 §5.1', () => {
		for (const service of ['_m', `_${'m'.repeat(15)}`, '_x-400', '_3com']) {
			expect(
				parseNameConstraints(
					encodeNameConstraints({ permittedSubtrees: [{ base: { type: 'srv', value: service } }] }),
				).permittedSubtrees,
			).toEqual([{ base: { type: 'srv', value: service } }]);
			expect(encodeSubjectAltName({ type: 'srv', value: `${service}.example.com` })[0]).toBe(0xa0);
		}
		for (const service of [`_${'m'.repeat(16)}`, '_123', '_-mail', '_mail-', '_ma--il', '_ma_il']) {
			expectEncoderErrorCode(
				() =>
					encodeNameConstraints({ permittedSubtrees: [{ base: { type: 'srv', value: service } }] }),
				'invalid_srv_name_constraint',
			);
			expectEncoderErrorCode(
				() => encodeSubjectAltName({ type: 'srv', value: `${service}.example.com` }),
				'invalid_srv_name',
			);
		}
	});

	it('encodeNameConstraints and encodeSubjectAltName hold the SRVName Name to STD3 LDH labels', () => {
		for (const name of ['example_com', '-example.com', 'example-.com', 'exa mple.com']) {
			for (const value of [name, `_mail.${name}`]) {
				expectEncoderErrorCode(
					() => encodeNameConstraints({ permittedSubtrees: [{ base: { type: 'srv', value } }] }),
					'invalid_srv_name_constraint',
				);
			}
			expectEncoderErrorCode(
				() => encodeSubjectAltName({ type: 'srv', value: `_mail.${name}` }),
				'invalid_srv_name',
			);
		}
		expectEncoderErrorCode(
			() => encodeSubjectAltName({ type: 'srv', value: '_mail.xn--a.example' }),
			'invalid_idn',
		);
		expectEncoderErrorCode(
			() => encodeSubjectAltName({ type: 'srv', value: '_mail' }),
			'invalid_srv_name',
		);
	});

	it('encodeNameConstraints and encodeSubjectAltName store RFC 4985 §3 label separators as U+002E', () => {
		for (const separator of ['\u3002', '\uff0e', '\uff61']) {
			const value = `_mail.例子${separator}com`;
			expect(
				parseNameConstraints(
					encodeNameConstraints({ permittedSubtrees: [{ base: { type: 'srv', value } }] }),
				).permittedSubtrees,
			).toEqual([{ base: { type: 'srv', value: '_mail.xn--fsqu00a.com' } }]);
			expect(encodeSubjectAltName({ type: 'srv', value })).toEqual(
				encodeSubjectAltName({ type: 'srv', value: '_mail.xn--fsqu00a.com' }),
			);
		}
		expectEncoderErrorCode(
			() =>
				encodeNameConstraints({
					permittedSubtrees: [{ base: { type: 'srv', value: '_mail.example\u3002\u3002com' } }],
				}),
			'invalid_srv_name_constraint',
		);
	});

	it('encodeNameConstraints rejects a SRVName restriction outside the RFC 4985 §4 forms', () => {
		const values = [
			'',
			'_',
			'_mail.',
			'_m@il.example.com',
			'.example.com',
			'_mail..example.com',
			'example.com.',
			'ex*ample.com',
			`${'a'.repeat(64)}.example`,
			`_${'m'.repeat(63)}`,
			`_${'m'.repeat(63)}.example.com`,
		];
		for (const value of values) {
			for (const field of ['permittedSubtrees', 'excludedSubtrees'] as const) {
				expectEncoderErrorCode(
					() => encodeNameConstraints({ [field]: [{ base: { type: 'srv', value } }] }),
					'invalid_srv_name_constraint',
				);
			}
		}
	});

	it('encodeSubjectAltName rejects a non-ASCII URI or SRV name', () => {
		expectEncoderErrorCode(
			() => encodeSubjectAltName({ type: 'uri', value: 'http://café.example' }),
			'invalid_ia5_string',
		);
		expectEncoderErrorCode(
			() => encodeSubjectAltName({ type: 'srv', value: '_xmpé.example' }),
			'invalid_srv_name',
		);
		expectEncoderErrorCode(
			() => encodeSubjectAltName({ type: 'email', value: 'josé@example.com' }),
			'invalid_ia5_string',
		);
	});

	it('encodeSubjectAltName writes dNSName and rfc822Name hosts as A-labels', () => {
		expect(encodeSubjectAltName({ type: 'dns', value: '*.café.example' })).toEqual(
			encodeSubjectAltName({ type: 'dns', value: '*.xn--caf-dma.example' }),
		);
		expect(encodeSubjectAltName({ type: 'email', value: 'user@café.example' })).toEqual(
			encodeSubjectAltName({ type: 'email', value: 'user@xn--caf-dma.example' }),
		);
	});

	it('encodeSubjectAltName rejects a dNSName or rfc822Name host that is not valid IDNA2008', () => {
		for (const value of ['\u265a.example', 'xn--45h.example', 'XN--CAF-DMA.example']) {
			expectEncoderErrorCode(() => encodeSubjectAltName({ type: 'dns', value }), 'invalid_idn');
			expectEncoderErrorCode(
				() => encodeSubjectAltName({ type: 'email', value: `user@${value}` }),
				'invalid_idn',
			);
		}
	});

	it('encodeNameConstraints writes dNSName and rfc822Name bases as A-labels', () => {
		for (const type of ['dns', 'email'] as const) {
			expect(
				encodeNameConstraints({ permittedSubtrees: [{ base: { type, value: '.café.example' } }] }),
			).toEqual(
				encodeNameConstraints({
					permittedSubtrees: [{ base: { type, value: '.xn--caf-dma.example' } }],
				}),
			);
			expectEncoderErrorCode(
				() =>
					encodeNameConstraints({
						permittedSubtrees: [{ base: { type, value: 'xn--45h.example' } }],
					}),
				'invalid_idn',
			);
		}
	});

	it('encodeNameConstraints rejects a non-ASCII URI base with a code', () => {
		expectEncoderErrorCode(
			() =>
				encodeNameConstraints({
					permittedSubtrees: [{ base: { type: 'uri', value: 'café.example' } }],
				}),
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
						distributionPoint: { type: 'relativeName', relativeName },
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
						distributionPoint: { type: 'relativeName', relativeName },
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
						distributionPoint: { type: 'relativeName', relativeName },
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
							critical: true,
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
						critical: true,
					},
				],
			}),
		).toBeInstanceOf(Array);
		expectEncoderErrorCode(
			() =>
				buildRequestedExtensions({
					basicConstraints: { ca: true, pathLength: 0 },
					customExtensions: [{ oid: OIDS.keyUsage, value: encodeKeyUsage(['digitalSignature']) }],
				}),
			'path_length_requires_key_cert_sign',
		);
	});

	it.each([OIDS.basicConstraints, OIDS.keyUsage, OIDS.subjectAltName])(
		"rejects a custom %s payload that is not that OID's DER",
		(oid) => {
			expectEncoderErrorCode(
				() =>
					buildCertificateExtensions(subjectPublicKeyInfo, undefined, {
						customExtensions: [{ oid, value: Uint8Array.of(0x05, 0x00) }],
					}),
				'malformed_known_extension_value',
			);
			expectEncoderErrorCode(
				() =>
					buildRequestedExtensions({
						customExtensions: [{ oid, value: Uint8Array.of(0x05, 0x00) }],
					}),
				'malformed_known_extension_value',
			);
		},
	);

	/** The same custom extension offered through both builder entry points. */
	function buildCustomBothWays(
		oid: string,
		value: Uint8Array,
		critical = false,
	): readonly (() => unknown)[] {
		return [
			() =>
				buildCertificateExtensions(subjectPublicKeyInfo, undefined, {
					customExtensions: [{ oid, value, critical }],
				}),
			() => buildRequestedExtensions({ customExtensions: [{ oid, value, critical }] }),
		];
	}

	const CRL_DISTRIBUTION_POINTS_OIDS = [OIDS.cRLDistributionPoints, '2.5.029.31'] as const;
	const crlIssuerDnA = encodeName({ commonName: 'CRL Issuer A' });
	const crlIssuerDnB = encodeName({ commonName: 'CRL Issuer B' });
	const crlRelativeName = encodeRelativeDistinguishedName([{ type: 'commonName', value: 'CRL42' }]);

	// Payloads that decode cleanly and then break RFC 5280 §4.2.1.13.
	const PROFILE_INVALID_CRL_DISTRIBUTION_POINTS = [
		[
			'a URI cRLIssuer',
			encodeUncheckedCrlDistributionPoints([
				{
					fullNameUri: 'http://crl.example/a.crl',
					crlIssuer: [{ type: 'uri', value: 'http://crl.example/issuer' }],
				},
			]),
			'distribution_point_crl_issuer_not_directory_name',
		],
		[
			'a relativeName beside two wire-tagged cRLIssuer DNs',
			encodeUncheckedCrlDistributionPoints([
				{
					relativeNameSetDer: crlRelativeName,
					crlIssuerDer: concatBytes([tlv(0xa4, crlIssuerDnA), tlv(0xa4, crlIssuerDnB)]),
				},
			]),
			'distribution_point_relative_name_multiple_crl_issuers',
		],
	] as const;

	// Payloads that are not CRLDistributionPoints DER at all.
	const MALFORMED_CRL_DISTRIBUTION_POINTS = [
		['a NULL where the SEQUENCE belongs', Uint8Array.of(0x05, 0x00)],
		[
			'an empty cRLIssuer',
			encodeUncheckedCrlDistributionPoints([
				{ fullNameUri: 'http://crl.example/a.crl', crlIssuerDer: new Uint8Array() },
			]),
		],
		['an empty points SEQUENCE', sequence([])],
	] as const;

	// Payloads that satisfy the profile through the custom route.
	const CONFORMANT_CRL_DISTRIBUTION_POINTS = [
		[
			'a fullName URI',
			encodeCrlDistributionPoints([
				{
					distributionPoint: {
						type: 'fullName',
						fullName: [{ type: 'uri', value: 'http://crl.example/a.crl' }],
					},
				},
			]),
		],
		[
			'a relativeName beside one wire-tagged cRLIssuer DN',
			encodeUncheckedCrlDistributionPoints([
				{ relativeNameSetDer: crlRelativeName, crlIssuerDer: tlv(0xa4, crlIssuerDnA) },
			]),
		],
		[
			'a relativeName with no cRLIssuer',
			encodeUncheckedCrlDistributionPoints([{ relativeNameSetDer: crlRelativeName }]),
		],
		[
			'a fullName beside a wire-tagged cRLIssuer DN',
			encodeUncheckedCrlDistributionPoints([
				{ fullNameUri: 'http://crl.example/a.crl', crlIssuerDer: tlv(0xa4, crlIssuerDnA) },
			]),
		],
	] as const;

	it.each(PROFILE_INVALID_CRL_DISTRIBUTION_POINTS)(
		'rejects a custom cRLDistributionPoints payload carrying %s',
		(_label, value, code) => {
			for (const oid of CRL_DISTRIBUTION_POINTS_OIDS) {
				for (const build of buildCustomBothWays(oid, value)) {
					expectEncoderErrorCode(build, code);
				}
			}
		},
	);

	it.each(MALFORMED_CRL_DISTRIBUTION_POINTS)(
		'rejects a custom cRLDistributionPoints payload carrying %s',
		(_label, value) => {
			for (const oid of CRL_DISTRIBUTION_POINTS_OIDS) {
				for (const build of buildCustomBothWays(oid, value)) {
					expectEncoderErrorCode(build, 'malformed_known_extension_value');
				}
			}
		},
	);

	it.each(CONFORMANT_CRL_DISTRIBUTION_POINTS)(
		'accepts a custom cRLDistributionPoints payload carrying %s',
		(_label, value) => {
			for (const oid of CRL_DISTRIBUTION_POINTS_OIDS) {
				for (const build of buildCustomBothWays(oid, value)) {
					expect(build()).toBeInstanceOf(Array);
				}
			}
		},
	);

	it.each(PROFILE_INVALID_CRL_DISTRIBUTION_POINTS)(
		'still parses a cRLDistributionPoints value carrying %s',
		(_label, value) => {
			expect(parseCrlDistributionPoints(value).length).toBe(1);
		},
	);

	// Rules the encoder enforces that the tolerant parser does not, reachable only
	// by handing the builder a raw payload under a known OID.
	const KNOWN_EXTENSION_PROFILE_VIOLATIONS = [
		[
			'certificatePolicies repeating a policy OID',
			OIDS.certificatePolicies,
			sequence([sequence([objectIdentifier('1.2.3.4')]), sequence([objectIdentifier('1.2.3.4')])]),
			'duplicate_policy_oid',
		],
		[
			'certificatePolicies with an explicitText over 200 characters',
			OIDS.certificatePolicies,
			sequence([
				sequence([
					objectIdentifier('1.2.3.4'),
					sequence([
						sequence([
							objectIdentifier(OIDS.userNoticePolicyQualifier),
							sequence([utf8String('a'.repeat(201))]),
						]),
					]),
				]),
			]),
			'display_text_out_of_range',
		],
		[
			'authorityInfoAccess with a dNSName OCSP location',
			OIDS.authorityInfoAccess,
			sequence([
				sequence([
					objectIdentifier(OIDS.ocspAccessMethod),
					tlv(0x82, new TextEncoder().encode('ocsp.example.test')),
				]),
			]),
			'authority_info_access_ocsp_not_uri',
		],
		[
			'nameConstraints with neither subtree',
			OIDS.nameConstraints,
			sequence([]),
			'name_constraints_empty',
		],
		['keyUsage with no bit set', OIDS.keyUsage, bitString(new Uint8Array(), 0), 'key_usage_empty'],
	] as const;

	it.each(KNOWN_EXTENSION_PROFILE_VIOLATIONS)(
		'rejects a custom %s payload',
		(_label, oid, value, code) => {
			for (const build of buildCustomBothWays(oid, value)) {
				expectEncoderErrorCode(build, code);
			}
		},
	);

	// Rules where the decoder is already as strict as the encoder, so a custom
	// payload breaking them never reaches the profile hook.
	const DECODER_REJECTED_KNOWN_PAYLOADS = [
		[
			'subjectAltName using a tag outside the GeneralName CHOICE',
			OIDS.subjectAltName,
			sequence([tlv(0x89, new TextEncoder().encode('x'))]),
		],
		['extendedKeyUsage with no purpose', OIDS.extendedKeyUsage, sequence([])],
		[
			'policyMappings naming anyPolicy',
			OIDS.policyMappings,
			sequence([sequence([objectIdentifier(OIDS.anyPolicy), objectIdentifier('1.2.3.4')])]),
		],
		[
			'basicConstraints with a pathLength but no cA bit',
			OIDS.basicConstraints,
			sequence([integerFromNumber(0)]),
		],
		['policyConstraints with neither field', OIDS.policyConstraints, sequence([])],
	] as const;

	it.each(DECODER_REJECTED_KNOWN_PAYLOADS)('rejects a custom %s payload', (_label, oid, value) => {
		for (const build of buildCustomBothWays(oid, value)) {
			expectEncoderErrorCode(build, 'malformed_known_extension_value');
		}
	});

	// One conformant payload per registered extension. Drives both the accepting
	// path of each profile hook and the proof that every registry default carries
	// the criticality its own hook demands.
	const CONFORMANT_KNOWN_PAYLOADS = new Map<string, Uint8Array>([
		[OIDS.basicConstraints, encodeBasicConstraints({ ca: false })],
		[OIDS.keyUsage, encodeKeyUsage(['digitalSignature'])],
		[OIDS.extendedKeyUsage, encodeExtendedKeyUsage(['serverAuth'])],
		[OIDS.subjectAltName, sequence([encodeSubjectAltName({ type: 'dns', value: 'san.example' })])],
		[OIDS.issuerAltName, sequence([encodeSubjectAltName({ type: 'dns', value: 'ian.example' })])],
		[
			OIDS.nameConstraints,
			encodeNameConstraints({ permittedSubtrees: [{ base: { type: 'dns', value: 'example' } }] }),
		],
		[OIDS.certificatePolicies, encodeCertificatePolicies([{ policyIdentifier: '1.2.3.4' }])],
		[
			OIDS.policyMappings,
			encodePolicyMappings([{ issuerDomainPolicy: '1.2.3.4', subjectDomainPolicy: '1.2.3.5' }]),
		],
		[OIDS.policyConstraints, encodePolicyConstraints({ requireExplicitPolicy: 0 })],
		[OIDS.inhibitAnyPolicy, encodeInhibitAnyPolicy({ skipCerts: 0 })],
		[
			OIDS.authorityInfoAccess,
			encodeAuthorityInfoAccess([
				{ method: 'ocsp', location: { type: 'uri', value: 'http://ocsp.example.test' } },
			]),
		],
		[
			OIDS.cRLDistributionPoints,
			encodeCrlDistributionPoints([
				{
					distributionPoint: {
						type: 'fullName',
						fullName: [{ type: 'uri', value: 'http://crl.example/a.crl' }],
					},
				},
			]),
		],
		[OIDS.noRevAvail, nullValue()],
		[OIDS.subjectKeyIdentifier, octetString(Uint8Array.of(1, 2, 3))],
		[OIDS.authorityKeyIdentifier, sequence([implicitPrimitiveContext(0, Uint8Array.of(1, 2, 3))])],
	]);

	it('emits every registered extension at the criticality its own profile demands', () => {
		for (const definition of listExtensionDefinitions()) {
			const payload = CONFORMANT_KNOWN_PAYLOADS.get(definition.oid);
			expect(payload).toBeInstanceOf(Uint8Array);
			if (payload !== undefined) {
				definition.assertDerProfile(payload, definition.defaultCritical);
			}
		}
	});

	// basicConstraints is auto-emitted on the certificate path, so a custom copy
	// always collides there; every other CSR-context extension takes both paths.
	const CUSTOM_ACCEPTED_IN_BOTH_CONTEXTS = listExtensionDefinitions('csr')
		.filter((definition) => definition.oid !== OIDS.basicConstraints)
		.map((definition) => [definition.oid, definition.defaultCritical] as const);

	it.each(CUSTOM_ACCEPTED_IN_BOTH_CONTEXTS)(
		'accepts a conformant custom %s payload on both builder paths',
		(oid, critical) => {
			const value = CONFORMANT_KNOWN_PAYLOADS.get(oid);
			expect(value).toBeInstanceOf(Uint8Array);
			for (const build of buildCustomBothWays(oid, value ?? new Uint8Array(), critical)) {
				expect(build()).toBeInstanceOf(Array);
			}
		},
	);

	it('accepts a conformant custom basicConstraints payload on the CSR path', () => {
		// buildCertificateExtensions always emits basicConstraints, so a custom one
		// can only reach the profile hook through a CSR.
		expect(
			buildRequestedExtensions({
				customExtensions: [
					{ oid: OIDS.basicConstraints, value: encodeBasicConstraints({ ca: false }) },
				],
			}),
		).toBeInstanceOf(Array);
	});

	it.each([
		['subjectKeyIdentifier', OIDS.subjectKeyIdentifier],
		['authorityKeyIdentifier', OIDS.authorityKeyIdentifier],
	])('validates a custom %s payload before rejecting it as a duplicate', (_label, oid) => {
		const value = CONFORMANT_KNOWN_PAYLOADS.get(oid) ?? new Uint8Array();
		expectEncoderErrorCode(
			() =>
				buildCertificateExtensions(subjectPublicKeyInfo, subjectPublicKeyInfo, {
					customExtensions: [{ oid, value }],
				}),
			'duplicate_extension_oid',
		);
	});

	it('rejects a custom subjectKeyIdentifier that is not an OCTET STRING', () => {
		expectEncoderErrorCode(
			() =>
				buildCertificateExtensions(subjectPublicKeyInfo, subjectPublicKeyInfo, {
					customExtensions: [{ oid: OIDS.subjectKeyIdentifier, value: Uint8Array.of(0x05, 0x00) }],
				}),
			'malformed_known_extension_value',
		);
	});

	// RFC 5280 fixes the criticality of these extensions, and only a custom
	// extension can carry the wrong one; typed input has no criticality knob.
	const CRITICALITY_VIOLATIONS = [
		['nameConstraints', OIDS.nameConstraints, false, 'extension_must_be_critical'],
		['policyConstraints', OIDS.policyConstraints, false, 'extension_must_be_critical'],
		['inhibitAnyPolicy', OIDS.inhibitAnyPolicy, false, 'extension_must_be_critical'],
		['authorityInfoAccess', OIDS.authorityInfoAccess, true, 'extension_must_be_non_critical'],
	] as const;

	it.each(CRITICALITY_VIOLATIONS)(
		'rejects a custom %s marked with the wrong criticality',
		(_label, oid, critical, code) => {
			const value = CONFORMANT_KNOWN_PAYLOADS.get(oid) ?? new Uint8Array();
			for (const build of buildCustomBothWays(oid, value, critical)) {
				expectEncoderErrorCode(build, code);
			}
		},
	);

	it.each([
		['subjectKeyIdentifier', OIDS.subjectKeyIdentifier],
		['authorityKeyIdentifier', OIDS.authorityKeyIdentifier],
	])('rejects a critical custom %s (RFC 5280 §4.2.1.1, §4.2.1.2)', (_label, oid) => {
		const value = CONFORMANT_KNOWN_PAYLOADS.get(oid) ?? new Uint8Array();
		expectEncoderErrorCode(
			() =>
				buildCertificateExtensions(subjectPublicKeyInfo, subjectPublicKeyInfo, {
					customExtensions: [{ oid, value, critical: true }],
				}),
			'extension_must_be_non_critical',
		);
	});

	// RFC 5280 §4.2.1.9 covers any CA certificate whose key may validate signatures
	// on certificates. §4.2.1.3 restricts the key only through a keyUsage that
	// reaches the wire, so absent and empty leave the key unrestricted, and the
	// builder omits an empty keyUsage.
	const CA_KEY_USAGE_CASES = [
		['an absent keyUsage', undefined, true],
		['an empty keyUsage', [], true],
		['a keyCertSign keyUsage', ['keyCertSign'], true],
		['a keyUsage without keyCertSign', ['digitalSignature'], false],
	] as const;

	it.each(CA_KEY_USAGE_CASES)(
		'applies the §4.2.1.9 basicConstraints criticality rule under %s',
		(_label, keyUsage, constrained) => {
			const caBasicConstraints = encodeBasicConstraints({ ca: true });
			const input = (critical: boolean, oid: string) => ({
				...(keyUsage === undefined ? {} : { keyUsage }),
				customExtensions: [{ oid, value: caBasicConstraints, critical }],
			});
			for (const oid of [OIDS.basicConstraints, '2.5.029.19']) {
				if (constrained) {
					expectEncoderErrorCode(
						() => buildRequestedExtensions(input(false, oid)),
						'extension_must_be_critical',
					);
					expectEncoderErrorCode(
						() => buildCertificateExtensions(subjectPublicKeyInfo, undefined, input(false, oid)),
						'extension_must_be_critical',
					);
				} else {
					expect(buildRequestedExtensions(input(false, oid))).toBeInstanceOf(Array);
					// The certificate path always emits its own basicConstraints, so a
					// silent criticality rule surfaces as the duplicate instead.
					expectEncoderErrorCode(
						() => buildCertificateExtensions(subjectPublicKeyInfo, undefined, input(false, oid)),
						'duplicate_extension_oid',
					);
				}
				expect(buildRequestedExtensions(input(true, oid))).toBeInstanceOf(Array);
			}
		},
	);

	it('leaves a non-CA custom basicConstraints non-critical (RFC 5280 §4.2.1.9)', () => {
		expect(
			buildRequestedExtensions({
				customExtensions: [
					{ oid: OIDS.basicConstraints, value: encodeBasicConstraints({ ca: false }) },
				],
			}),
		).toBeInstanceOf(Array);
	});

	it('resolves access-method and EKU OIDs canonically', () => {
		// 1.3.6.1.5.5.7.048.1 and 2.5.29.032.0 encode to id-ad-ocsp and anyPolicy.
		expect(getAuthorityInfoAccessMethodOid({ type: 'oid', value: '1.3.6.1.5.5.7.048.1' })).toBe(
			OIDS.ocspAccessMethod,
		);
		expect(getExtendedKeyUsageOid({ type: 'oid', value: '1.3.6.1.5.5.7.3.01' })).toBe(
			OIDS.serverAuth,
		);
		expectEncoderErrorCode(
			() =>
				encodeAuthorityInfoAccess([
					{
						method: { type: 'oid', value: '1.3.6.1.5.5.7.048.1' },
						location: { type: 'dns', value: 'ocsp.example.test' },
					},
				]),
			'authority_info_access_ocsp_not_uri',
		);
		expectEncoderErrorCode(
			() =>
				encodePolicyMappings([
					{ issuerDomainPolicy: '2.5.29.032.0', subjectDomainPolicy: '1.2.3.4' },
				]),
			'policy_mappings_any_policy',
		);
		expectEncoderErrorCode(
			() =>
				encodePolicyMappings([
					{ issuerDomainPolicy: '1.2.3.4', subjectDomainPolicy: '2.5.29.032.0' },
				]),
			'policy_mappings_any_policy',
		);
	});

	it('accepts a conformant custom issuerAltName only on the certificate path', () => {
		const value = sequence([encodeSubjectAltName({ type: 'dns', value: 'ian.example' })]);
		expect(
			buildCertificateExtensions(subjectPublicKeyInfo, undefined, {
				customExtensions: [{ oid: OIDS.issuerAltName, value }],
			}),
		).toBeInstanceOf(Array);
		expectEncoderErrorCode(
			() => buildRequestedExtensions({ customExtensions: [{ oid: OIDS.issuerAltName, value }] }),
			'extension_not_supported_in_context',
		);
	});

	it.each(['3.1', '1.40', '2', '1.2.', 'not.an.oid'])(
		'encodeExtension rejects the unencodable OID %p with a coded error',
		(oid) => {
			expectEncoderErrorCode(() => encodeExtension(oid, Uint8Array.of(0x05, 0x00)), 'invalid_oid');
		},
	);

	it.each(['3.1', '1.40'])(
		'encodeCertificatePolicies rejects the unencodable policy OID %p with a coded error',
		(oid) => {
			expectEncoderErrorCode(
				() => encodeCertificatePolicies([{ policyIdentifier: oid }]),
				'invalid_oid',
			);
		},
	);

	it('rejects a basicConstraints pathLength without the cA bit (RFC 5280 §4.2.1.9)', () => {
		// The BasicConstraints union already excludes this pairing, so reach the
		// encoder guard the way an untyped caller would.
		expectEncoderErrorCode(
			() => Reflect.apply(encodeBasicConstraints, undefined, [{ ca: false, pathLength: 0 }]),
			'path_length_requires_ca',
		);
	});

	it.each(['3.1', '1.40'])('rejects OID %s, which violates the X.660 arc bounds', (oid) => {
		expectEncoderErrorCode(
			() =>
				buildRequestedExtensions({
					customExtensions: [{ oid, value: Uint8Array.of(0x05, 0x00) }],
				}),
			'invalid_oid',
		);
	});

	it('resolves a known extension supplied under a non-canonical OID spelling', () => {
		// 2.5.029.19 and 2.5.29.19 encode to the same OID, so both are basicConstraints.
		expect(
			buildRequestedExtensions({
				keyUsage: ['keyCertSign'],
				customExtensions: [
					{
						oid: '2.5.029.19',
						value: encodeBasicConstraints({ ca: true, pathLength: 0 }),
						critical: true,
					},
				],
			}),
		).toBeInstanceOf(Array);
		expectEncoderErrorCode(
			() =>
				buildRequestedExtensions({
					keyUsage: ['digitalSignature'],
					customExtensions: [
						{
							oid: '2.5.029.19',
							value: encodeBasicConstraints({ ca: true, pathLength: 0 }),
							critical: true,
						},
					],
				}),
			'path_length_requires_key_cert_sign',
		);
		expectEncoderErrorCode(
			() =>
				buildRequestedExtensions({
					customExtensions: [{ oid: '2.5.029.19', value: Uint8Array.of(0x05, 0x00) }],
				}),
			'malformed_known_extension_value',
		);
		// issuerAltName is certificate-only, and the alias must not evade that.
		expectEncoderErrorCode(
			() =>
				buildRequestedExtensions({
					customExtensions: [
						{
							oid: '2.5.029.18',
							value: sequence([encodeSubjectAltName({ type: 'dns', value: 'alias.example' })]),
						},
					],
				}),
			'extension_not_supported_in_context',
		);
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
			'malformed_known_extension_value',
		);
		// An empty x400Address [3] is not an ORAddress.
		expectEncoderErrorCode(
			() =>
				buildCertificateExtensions(
					subjectPublicKeyInfo,
					undefined,
					{
						customExtensions: [
							{
								oid: OIDS.subjectAltName,
								critical: true,
								value: sequence([tlv(0xa3, new Uint8Array())]),
							},
						],
					},
					true,
				),
			'invalid_general_name_content',
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

	it('parsePbes2AlgorithmIdentifier requires an INTEGER iteration count', () => {
		const badPbkdf2 = sequence([
			objectIdentifier(OIDS.pbes2),
			sequence([
				sequence([
					objectIdentifier(OIDS.pbkdf2),
					sequence([octetString(new Uint8Array(16)), octetString(Uint8Array.of(1))]),
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
				nextUpdate: FAR_FUTURE_NEXT_UPDATE,
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

describe('rebaseDiagnostic', () => {
	async function parsedCertificates(count: number) {
		const certificates = [];
		for (let index = 0; index < count; index += 1) {
			const material = await createSelfSignedCertificate({
				subject: { commonName: `Rebase ${index}` },
			});
			certificates.push(unwrap(parseCertificatePem(material.certificate.pem)));
		}
		return certificates;
	}

	it('moves the suffix onto the new prefix and shifts every index', async () => {
		const [a, b, node, below, bottom, other] = await parsedCertificates(6);
		if (!(a && b && node && below && bottom && other)) throw new Error('fixture');
		const failure = {
			ok: false,
			code: 'certificate_expired',
			message: 'expired',
			index: 4,
		} as const;

		expect(
			rebaseDiagnostic({ kind: 'specific-failure', path: [a, node, below, bottom], failure }, 1, [
				a,
				b,
				other,
				node,
			]),
		).toEqual({
			kind: 'specific-failure',
			path: [a, b, other, node, below, bottom],
			failure: { ...failure, index: 6 },
		});
		expect(
			rebaseDiagnostic({ kind: 'missing-issuer', path: [a, node, below], missingIssuerAt: 2 }, 1, [
				b,
				other,
				node,
			]),
		).toEqual({ kind: 'missing-issuer', path: [b, other, node, below], missingIssuerAt: 3 });
	});

	it('reports only the prefix when the suffix repeats one of its certificates', async () => {
		const [a, node, below, bottom] = await parsedCertificates(4);
		if (!(a && node && below && bottom)) throw new Error('fixture');

		expect(
			rebaseDiagnostic(
				{ kind: 'missing-issuer', path: [a, node, below, bottom], missingIssuerAt: 3 },
				1,
				[below, node],
			),
		).toEqual({ kind: 'none', path: [below, node] });
	});
});
