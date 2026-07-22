import { describe, expect, it } from 'bun:test';
import { createSelfSignedCertificate, parseCertificatePem, unwrap } from '#micro509';
import {
	assertDerMaxDepth,
	decodeDerBitString,
	decodeDerBoolean,
	decodeDerInteger,
	decodeDerOctetString,
	decodeDerOid,
	decodeDerString,
	decodeDerTime,
	derBitString,
	derBmpString,
	derBoolean,
	derChildren,
	derExplicitContext,
	derGeneralizedTime,
	derIa5String,
	derInteger,
	derIntegerFromNumber,
	derNull,
	derOctetString,
	derOid,
	derPrintableString,
	derSequence,
	derSet,
	derTime,
	derUniversalString,
	derUtcTime,
	derUtf8String,
	readDerElement,
	readDerRoot,
	readDerSequence,
	toHex,
} from '#micro509/der';

describe('der domain', () => {
	describe('round-trips', () => {
		it('BOOLEAN', () => {
			expect(decodeDerBoolean(readDerElement(derBoolean(true)))).toBe(true);
			expect(decodeDerBoolean(readDerElement(derBoolean(false)))).toBe(false);
		});

		it('INTEGER up to MAX_SAFE_INTEGER', () => {
			for (const value of [
				0,
				1,
				127,
				128,
				255,
				2 ** 47 - 1,
				2 ** 48 - 1,
				Number.MAX_SAFE_INTEGER,
			]) {
				expect(decodeDerInteger(readDerElement(derIntegerFromNumber(value)))).toBe(value);
			}
		});

		it('OBJECT IDENTIFIER', () => {
			const oid = '1.2.840.113549.1.1.11';
			expect(decodeDerOid(readDerElement(derOid(oid)))).toBe(oid);
		});

		it('OCTET STRING', () => {
			const bytes = Uint8Array.of(0xde, 0xad, 0xbe, 0xef);
			expect(toHex(decodeDerOctetString(readDerElement(derOctetString(bytes))))).toBe('deadbeef');
		});

		it('every supported string type', () => {
			expect(decodeDerString(readDerElement(derUtf8String('héllo')))).toBe('héllo');
			expect(decodeDerString(readDerElement(derPrintableString('Acme Ltd')))).toBe('Acme Ltd');
			expect(decodeDerString(readDerElement(derIa5String('a@b.example')))).toBe('a@b.example');
			expect(decodeDerString(readDerElement(derBmpString('filé')))).toBe('filé');
			expect(decodeDerString(readDerElement(derUniversalString('A\u{1F600}')))).toBe('A\u{1F600}');
		});

		it('UTCTime and GeneralizedTime', () => {
			const near = new Date('2026-07-22T10:11:12Z');
			const far = new Date('2200-01-02T03:04:05Z');
			expect(decodeDerTime(readDerElement(derUtcTime(near))).toISOString()).toBe(
				near.toISOString(),
			);
			expect(decodeDerTime(readDerElement(derGeneralizedTime(far))).toISOString()).toBe(
				far.toISOString(),
			);
			expect(decodeDerTime(readDerElement(derTime(far))).toISOString()).toBe(far.toISOString());
		});

		it('BIT STRING with unused bits', () => {
			for (const unusedBits of [0, 1, 4, 7]) {
				const encoded = derBitString(Uint8Array.of(0x80), unusedBits);
				const decoded = decodeDerBitString(readDerElement(encoded));
				expect(decoded.unusedBits).toBe(unusedBits);
				expect(toHex(decoded.bytes)).toBe('80');
			}
		});

		it('empty BIT STRING', () => {
			const decoded = decodeDerBitString(readDerElement(derBitString(new Uint8Array())));
			expect(decoded.bytes.length).toBe(0);
			expect(decoded.unusedBits).toBe(0);
		});
	});

	describe('structure', () => {
		it('reads SEQUENCE children in order', () => {
			const encoded = derSequence([derIntegerFromNumber(1), derUtf8String('two'), derNull()]);
			const children = readDerSequence(encoded);
			expect(children.length).toBe(3);
			expect(decodeDerInteger(children[0] as never)).toBe(1);
			expect(decodeDerString(children[1] as never)).toBe('two');
			expect(children[2]?.tag).toBe(0x05);
		});

		it('walks a nested constructed element with derChildren', () => {
			const inner = derSequence([derBoolean(true), derIntegerFromNumber(7)]);
			const outer = derExplicitContext(0, inner);
			const root = readDerRoot(outer);
			const wrapped = derChildren(outer, root);
			expect(wrapped.length).toBe(1);
			const fields = derChildren(outer, wrapped[0] as never);
			expect(decodeDerBoolean(fields[0] as never)).toBe(true);
			expect(decodeDerInteger(fields[1] as never)).toBe(7);
		});

		it('DER-sorts SET members', () => {
			const encoded = derSet([
				derOctetString(Uint8Array.of(0x02)),
				derOctetString(Uint8Array.of(0x01)),
			]);
			const first = derChildren(encoded, readDerRoot(encoded))[0];
			expect(toHex(decodeDerOctetString(first as never))).toBe('01');
		});
	});

	describe('strictness', () => {
		it('rejects a mis-tagged element by name', () => {
			expect(() => decodeDerInteger(readDerElement(derBoolean(true)))).toThrow('Expected INTEGER');
			expect(() => decodeDerOid(readDerElement(derIntegerFromNumber(1)))).toThrow(
				'Expected OBJECT IDENTIFIER',
			);
			expect(() => decodeDerBitString(readDerElement(derNull()))).toThrow('Expected BIT STRING');
		});

		it('rejects BER-only and non-minimal encodings', () => {
			expect(() => readDerElement(Uint8Array.of(0x30, 0x80, 0x00, 0x00))).toThrow(
				'Indefinite lengths are not supported',
			);
			expect(() => readDerElement(Uint8Array.of(0x1f, 0x01, 0x41))).toThrow(
				'High-tag-number DER form is not supported',
			);
			expect(() => readDerElement(Uint8Array.of(0x04, 0x81, 0x01, 0x41))).toThrow(
				'Non-minimal DER length encoding',
			);
		});

		it('rejects an integer above MAX_SAFE_INTEGER', () => {
			const tooLarge = Uint8Array.of(0x02, 0x08, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
			expect(() => decodeDerInteger(readDerElement(tooLarge))).toThrow(
				'Integer too large for safe number',
			);
		});

		it('rejects a negative integer', () => {
			const negative = Uint8Array.of(0x02, 0x01, 0xff);
			expect(() => decodeDerInteger(readDerElement(negative))).toThrow(
				'INTEGER must be non-negative',
			);
		});

		it('encodes magnitudes as unsigned, never negative', () => {
			expect(decodeDerInteger(readDerElement(derInteger(Uint8Array.of(0xff))))).toBe(255);
		});

		it('rejects unencodable string content', () => {
			expect(() => derBmpString('a\u{1F600}')).toThrow(
				'code point above the Basic Multilingual Plane',
			);
			expect(() => derPrintableString('a_b')).toThrow('Invalid PrintableString');
			expect(() => derIa5String('héllo')).toThrow('Invalid IA5String');
		});

		it('rejects an unsupported string tag', () => {
			const teletex = Uint8Array.of(0x14, 0x01, 0x41);
			expect(() => decodeDerString(readDerElement(teletex))).toThrow('TeletexString');
		});

		it('rejects trailing data and over-deep nesting', () => {
			const trailing = Uint8Array.of(0x05, 0x00, 0x00);
			expect(() => readDerRoot(trailing)).toThrow('Trailing data after DER element');

			let nested = derNull();
			for (let depth = 0; depth < 8; depth += 1) nested = derSequence([nested]);
			expect(() => assertDerMaxDepth(nested, 4)).toThrow('DER exceeds max depth of 4');
		});
	});

	describe('interoperates with the typed API', () => {
		it('encodes bytes a CustomExtension can carry, and reads them back', async () => {
			const oid = '1.3.6.1.4.1.99999.1';
			const payload = derSequence([derUtf8String('team-alpha'), derIntegerFromNumber(3)]);

			const { certificate } = await createSelfSignedCertificate({
				subject: { commonName: 'der.example' },
				extensions: { customExtensions: [{ oid, critical: false, value: payload }] },
			});

			const parsed = unwrap(parseCertificatePem(certificate.pem));
			const extension = parsed.extensions.find((candidate) => candidate.oid === oid);
			expect(extension).toBeDefined();

			const fields = readDerSequence(extension?.valueDer as Uint8Array);
			expect(decodeDerString(fields[0] as never)).toBe('team-alpha');
			expect(decodeDerInteger(fields[1] as never)).toBe(3);
		});
	});
});
