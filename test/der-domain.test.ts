import { describe, expect, it } from 'bun:test';
import { createSelfSignedCertificate, parseCertificatePem, unwrap } from '#micro509';
import {
	assertDerMaxDepth,
	decodeDerBitString,
	decodeDerBitStringOrThrow,
	decodeDerBoolean,
	decodeDerBooleanOrThrow,
	decodeDerInteger,
	decodeDerIntegerOrThrow,
	decodeDerOctetString,
	decodeDerOctetStringOrThrow,
	decodeDerOid,
	decodeDerOidOrThrow,
	decodeDerString,
	decodeDerStringOrThrow,
	decodeDerTime,
	decodeDerTimeOrThrow,
	derBitString,
	derBmpString,
	derBoolean,
	derChildren,
	derChildrenOrThrow,
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
	readDerElementOrThrow,
	readDerRoot,
	readDerRootOrThrow,
	readDerSequence,
	readDerSequenceOrThrow,
	toHex,
} from '#micro509/der';

describe('der domain', () => {
	describe('round-trips', () => {
		it('BOOLEAN', () => {
			expect(decodeDerBooleanOrThrow(readDerElementOrThrow(derBoolean(true)))).toBe(true);
			expect(decodeDerBooleanOrThrow(readDerElementOrThrow(derBoolean(false)))).toBe(false);
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
				expect(decodeDerIntegerOrThrow(readDerElementOrThrow(derIntegerFromNumber(value)))).toBe(
					value,
				);
			}
		});

		it('OBJECT IDENTIFIER', () => {
			const oid = '1.2.840.113549.1.1.11';
			expect(decodeDerOidOrThrow(readDerElementOrThrow(derOid(oid)))).toBe(oid);
		});

		it('OCTET STRING', () => {
			const bytes = Uint8Array.of(0xde, 0xad, 0xbe, 0xef);
			expect(toHex(decodeDerOctetStringOrThrow(readDerElementOrThrow(derOctetString(bytes))))).toBe(
				'deadbeef',
			);
		});

		it('every supported string type', () => {
			expect(decodeDerStringOrThrow(readDerElementOrThrow(derUtf8String('héllo')))).toBe('héllo');
			expect(decodeDerStringOrThrow(readDerElementOrThrow(derPrintableString('Acme Ltd')))).toBe(
				'Acme Ltd',
			);
			expect(decodeDerStringOrThrow(readDerElementOrThrow(derIa5String('a@b.example')))).toBe(
				'a@b.example',
			);
			expect(decodeDerStringOrThrow(readDerElementOrThrow(derBmpString('filé')))).toBe('filé');
			expect(decodeDerStringOrThrow(readDerElementOrThrow(derUniversalString('A\u{1F600}')))).toBe(
				'A\u{1F600}',
			);
		});

		it('UTCTime and GeneralizedTime', () => {
			const near = new Date('2026-07-22T10:11:12Z');
			const far = new Date('2200-01-02T03:04:05Z');
			expect(decodeDerTimeOrThrow(readDerElementOrThrow(derUtcTime(near))).toISOString()).toBe(
				near.toISOString(),
			);
			expect(
				decodeDerTimeOrThrow(readDerElementOrThrow(derGeneralizedTime(far))).toISOString(),
			).toBe(far.toISOString());
			expect(decodeDerTimeOrThrow(readDerElementOrThrow(derTime(far))).toISOString()).toBe(
				far.toISOString(),
			);
		});

		it('BIT STRING with unused bits', () => {
			for (const unusedBits of [0, 1, 4, 7]) {
				const encoded = derBitString(Uint8Array.of(0x80), unusedBits);
				const decoded = decodeDerBitStringOrThrow(readDerElementOrThrow(encoded));
				expect(decoded.unusedBits).toBe(unusedBits);
				expect(toHex(decoded.bytes)).toBe('80');
			}
		});

		it('empty BIT STRING', () => {
			const decoded = decodeDerBitStringOrThrow(
				readDerElementOrThrow(derBitString(new Uint8Array())),
			);
			expect(decoded.bytes.length).toBe(0);
			expect(decoded.unusedBits).toBe(0);
		});
	});

	describe('structure', () => {
		it('reads SEQUENCE children in order', () => {
			const encoded = derSequence([derIntegerFromNumber(1), derUtf8String('two'), derNull()]);
			const children = readDerSequenceOrThrow(encoded);
			expect(children.length).toBe(3);
			expect(decodeDerIntegerOrThrow(children[0] as never)).toBe(1);
			expect(decodeDerStringOrThrow(children[1] as never)).toBe('two');
			expect(children[2]?.tag).toBe(0x05);
		});

		it('walks a nested constructed element', () => {
			const inner = derSequence([derBoolean(true), derIntegerFromNumber(7)]);
			const outer = derExplicitContext(0, inner);
			const wrapped = derChildrenOrThrow(outer, readDerRootOrThrow(outer));
			expect(wrapped.length).toBe(1);
			const fields = derChildrenOrThrow(outer, wrapped[0] as never);
			expect(decodeDerBooleanOrThrow(fields[0] as never)).toBe(true);
			expect(decodeDerIntegerOrThrow(fields[1] as never)).toBe(7);
		});

		it('DER-sorts SET members', () => {
			const encoded = derSet([
				derOctetString(Uint8Array.of(0x02)),
				derOctetString(Uint8Array.of(0x01)),
			]);
			const first = derChildrenOrThrow(encoded, readDerRootOrThrow(encoded))[0];
			expect(toHex(decodeDerOctetStringOrThrow(first as never))).toBe('01');
		});
	});

	describe('result contract', () => {
		it('returns a value on success', () => {
			const result = decodeDerInteger(readDerElementOrThrow(derIntegerFromNumber(42)));
			expect(result.ok).toBe(true);
			expect(unwrap(result)).toBe(42);
		});

		it('returns a malformed failure instead of throwing', () => {
			const result = decodeDerInteger(readDerElementOrThrow(derBoolean(true)));
			expect(result.ok).toBe(false);
			if (result.ok) throw new Error('expected failure');
			expect(result.code).toBe('malformed');
			expect(result.message).toBe('Expected INTEGER');
		});

		it('reports malformed bytes from the readers', () => {
			const indefinite = readDerElement(Uint8Array.of(0x30, 0x80, 0x00, 0x00));
			expect(indefinite.ok).toBe(false);

			const trailing = readDerSequence(Uint8Array.of(0x05, 0x00, 0x00));
			expect(trailing.ok).toBe(false);
		});

		it('every decoder has a working result variant', () => {
			const outer = derExplicitContext(0, derSequence([derBoolean(true)]));
			expect(unwrap(readDerRoot(outer)).tag).toBe(0xa0);
			expect(unwrap(derChildren(outer, readDerRootOrThrow(outer))).length).toBe(1);
			expect(unwrap(readDerSequence(derSequence([derNull()])))?.length).toBe(1);
			expect(unwrap(decodeDerBoolean(readDerElementOrThrow(derBoolean(true))))).toBe(true);
			expect(
				toHex(
					unwrap(decodeDerOctetString(readDerElementOrThrow(derOctetString(Uint8Array.of(0x01))))),
				),
			).toBe('01');
			expect(unwrap(decodeDerOid(readDerElementOrThrow(derOid('1.2.3'))))).toBe('1.2.3');
			expect(unwrap(decodeDerString(readDerElementOrThrow(derUtf8String('x'))))).toBe('x');
			expect(
				unwrap(decodeDerTime(readDerElementOrThrow(derUtcTime(new Date('2026-01-01T00:00:00Z'))))),
			).toBeInstanceOf(Date);
			expect(
				unwrap(decodeDerBitString(readDerElementOrThrow(derBitString(Uint8Array.of(0x80), 1))))
					.unusedBits,
			).toBe(1);
		});

		it('propagates an unsupported string tag as a failure', () => {
			const teletex = readDerElementOrThrow(Uint8Array.of(0x14, 0x01, 0x41));
			const result = decodeDerString(teletex);
			expect(result.ok).toBe(false);
			if (result.ok) throw new Error('expected failure');
			expect(result.message).toContain('TeletexString');
		});
	});

	describe('strictness', () => {
		it('rejects a mis-tagged element by name', () => {
			expect(() => decodeDerIntegerOrThrow(readDerElementOrThrow(derBoolean(true)))).toThrow(
				'Expected INTEGER',
			);
			expect(() => decodeDerOidOrThrow(readDerElementOrThrow(derIntegerFromNumber(1)))).toThrow(
				'Expected OBJECT IDENTIFIER',
			);
			expect(() => decodeDerBitStringOrThrow(readDerElementOrThrow(derNull()))).toThrow(
				'Expected BIT STRING',
			);
		});

		it('rejects BER-only and non-minimal encodings', () => {
			expect(() => readDerElementOrThrow(Uint8Array.of(0x30, 0x80, 0x00, 0x00))).toThrow(
				'Indefinite lengths are not supported',
			);
			expect(() => readDerElementOrThrow(Uint8Array.of(0x1f, 0x01, 0x41))).toThrow(
				'High-tag-number DER form is not supported',
			);
			expect(() => readDerElementOrThrow(Uint8Array.of(0x04, 0x81, 0x01, 0x41))).toThrow(
				'Non-minimal DER length encoding',
			);
		});

		it('rejects a BIT STRING claiming more than seven unused bits', () => {
			const tooMany = Uint8Array.of(0x03, 0x02, 0x08, 0x80);
			expect(() => decodeDerBitStringOrThrow(readDerElementOrThrow(tooMany))).toThrow(
				'Invalid BIT STRING',
			);
			expect(decodeDerBitString(readDerElementOrThrow(tooMany)).ok).toBe(false);
		});

		it('rejects an empty BIT STRING claiming unused bits', () => {
			const empty = Uint8Array.of(0x03, 0x01, 0x04);
			expect(() => decodeDerBitStringOrThrow(readDerElementOrThrow(empty))).toThrow(
				'Invalid BIT STRING',
			);
		});

		it('returns non-zero padding bits as encoded', () => {
			const nonZeroPadding = Uint8Array.of(0x03, 0x02, 0x04, 0x8f);
			const decoded = decodeDerBitStringOrThrow(readDerElementOrThrow(nonZeroPadding));
			expect(decoded.unusedBits).toBe(4);
			expect(toHex(decoded.bytes)).toBe('8f');
		});

		it('rejects an integer above MAX_SAFE_INTEGER', () => {
			const tooLarge = Uint8Array.of(0x02, 0x08, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
			expect(() => decodeDerIntegerOrThrow(readDerElementOrThrow(tooLarge))).toThrow(
				'Integer too large for safe number',
			);
		});

		it('rejects a negative integer', () => {
			const negative = Uint8Array.of(0x02, 0x01, 0xff);
			expect(() => decodeDerIntegerOrThrow(readDerElementOrThrow(negative))).toThrow(
				'INTEGER must be non-negative',
			);
		});

		it('encodes magnitudes as unsigned, never negative', () => {
			expect(decodeDerIntegerOrThrow(readDerElementOrThrow(derInteger(Uint8Array.of(0xff))))).toBe(
				255,
			);
		});

		it('rejects unencodable string content', () => {
			expect(() => derBmpString('a\u{1F600}')).toThrow(
				'code point above the Basic Multilingual Plane',
			);
			expect(() => derPrintableString('a_b')).toThrow('Invalid PrintableString');
			expect(() => derIa5String('héllo')).toThrow('Invalid IA5String');
		});

		it('rejects trailing data and over-deep nesting', () => {
			expect(() => readDerRootOrThrow(Uint8Array.of(0x05, 0x00, 0x00))).toThrow(
				'Trailing data after DER element',
			);

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

			const fields = readDerSequenceOrThrow(extension?.valueDer as Uint8Array);
			expect(decodeDerStringOrThrow(fields[0] as never)).toBe('team-alpha');
			expect(decodeDerIntegerOrThrow(fields[1] as never)).toBe(3);
		});
	});
});
