import { describe, expect, it } from 'bun:test';
import { OIDS } from '#micro509/internal/asn1/oids';
import { compareNameAttributeValue, prepareNameCompareString } from '#micro509/internal/shared/dn';

const SOFT_HYPHEN = String.fromCodePoint(0x00ad);
const ZWSP = String.fromCodePoint(0x200b);
const VARIATION_SELECTOR = String.fromCodePoint(0xfe00);
const CONTROL_SOH = String.fromCodePoint(0x0001);
const REPLACEMENT = String.fromCodePoint(0xfffd);
const PRIVATE_USE = String.fromCodePoint(0xe000);
const COMBINING_ACUTE = String.fromCodePoint(0x0301);

const cn = (valueTag: number, value: string) => ({ oid: OIDS.commonName, valueTag, value });

describe('RFC 4518 string preparation', () => {
	it('maps ignorable code points to nothing', () => {
		expect(prepareNameCompareString(`Ac${SOFT_HYPHEN}me`)).toBe(prepareNameCompareString('Acme'));
		expect(prepareNameCompareString(`a${ZWSP}b`)).toBe(prepareNameCompareString('ab'));
		expect(prepareNameCompareString(`a${VARIATION_SELECTOR}b`)).toBe(
			prepareNameCompareString('ab'),
		);
	});

	it('case-folds per B.2 rather than plain lowercase', () => {
		expect(prepareNameCompareString('Straße')).toBe(prepareNameCompareString('STRASSE'));
		expect(prepareNameCompareString('ΟΔΟΣ')).toBe(prepareNameCompareString('οδος'));
	});

	it('maps control characters instead of rejecting them', () => {
		const prepared = prepareNameCompareString(`a${CONTROL_SOH}b`);
		expect(prepared).toBeDefined();
		expect(prepared).toBe(prepareNameCompareString('ab'));
	});

	it('prohibits the replacement character', () => {
		expect(prepareNameCompareString(`a${REPLACEMENT}b`)).toBeUndefined();
	});

	it('prohibits private-use code points', () => {
		expect(prepareNameCompareString(`a${PRIVATE_USE}b`)).toBeUndefined();
	});

	it('collapses insignificant spaces but keeps a space bound to a combining mark', () => {
		expect(prepareNameCompareString('a  b')).toBe(prepareNameCompareString('a b'));
		expect(prepareNameCompareString('  x  ')).toBe(prepareNameCompareString('x'));
		expect(prepareNameCompareString(` ${COMBINING_ACUTE}x`)).not.toBe(
			prepareNameCompareString(`${COMBINING_ACUTE}x`),
		);
	});

	it('applies B.2 folds that toLowerCase misses', () => {
		// U+1F80 GREEK SMALL LETTER ALPHA WITH PSILI AND YPOGEGRAMMENI folds to
		// its base plus iota (RFC 3454 B.2); toLowerCase leaves it unchanged.
		const polytonic = String.fromCodePoint(0x1f80);
		const folded = String.fromCodePoint(0x1f00, 0x03b9);
		expect(prepareNameCompareString(polytonic)).toBe(prepareNameCompareString(folded));
	});

	it('prohibits code points unassigned in Unicode 3.2', () => {
		// U+1D2C MODIFIER LETTER CAPITAL A is unassigned in Unicode 3.2 (RFC 3454
		// Table A.1), so preparation fails rather than folding it to `a` via a
		// post-3.2 NFKC mapping.
		expect(prepareNameCompareString(String.fromCodePoint(0x1d2c))).toBeUndefined();
		expect(compareNameAttributeValue(cn(0x0c, String.fromCodePoint(0x1d2c)), cn(0x0c, 'a'))).toBe(
			false,
		);
		// U+1F600 is assigned only after Unicode 3.2.
		expect(prepareNameCompareString(String.fromCodePoint(0x1f600))).toBeUndefined();
	});

	it('freezes normalization to Unicode 3.2', () => {
		// Unicode 4.0 changed NFKC(U+2F868) from U+2136A to U+36FC; RFC 4518 keeps
		// the 3.2 mapping.
		expect(prepareNameCompareString(String.fromCodePoint(0x2f868))).toBe(
			prepareNameCompareString(String.fromCodePoint(0x2136a)),
		);
		expect(prepareNameCompareString(String.fromCodePoint(0x2f868))).not.toBe(
			prepareNameCompareString(String.fromCodePoint(0x36fc)),
		);
	});

	it('does not apply post-3.2 case folds that RFC 3454 B.2 omits', () => {
		// U+10A0 GEORGIAN CAPITAL LETTER AN has no B.2 fold, so it stays itself; a
		// modern toLowerCase would fold it to U+2D00, which is itself 3.2-unassigned.
		expect(prepareNameCompareString(String.fromCodePoint(0x10a0))).toBe(
			String.fromCodePoint(0x10a0),
		);
		expect(prepareNameCompareString(String.fromCodePoint(0x2d00))).toBeUndefined();
	});
});

describe('DirectoryString encoding comparison', () => {
	const attr = (valueTag: number, value: string) => ({ oid: OIDS.commonName, valueTag, value });

	it('compares BMPString, UniversalString, UTF8String, and PrintableString equally', () => {
		expect(compareNameAttributeValue(attr(0x1e, 'Example'), attr(0x0c, 'Example'))).toBe(true);
		expect(compareNameAttributeValue(attr(0x1c, 'Example'), attr(0x13, 'Example'))).toBe(true);
		expect(compareNameAttributeValue(attr(0x1e, 'Example'), attr(0x0c, 'example'))).toBe(true);
	});
});

describe('domainComponent comparison', () => {
	const dc = (value: string) => ({ oid: OIDS.domainComponent, valueTag: 0x16, value });

	it('compares case-insensitively across the whole value', () => {
		expect(compareNameAttributeValue(dc('Example'), dc('example'))).toBe(true);
		expect(compareNameAttributeValue(dc('COM'), dc('com'))).toBe(true);
	});

	it('still distinguishes different domain components', () => {
		expect(compareNameAttributeValue(dc('example'), dc('other'))).toBe(false);
	});

	it('rejects a domainComponent carried under a non-IA5 tag', () => {
		const ia5 = { oid: OIDS.domainComponent, valueTag: 0x16, value: 'example' };
		const utf8 = { oid: OIDS.domainComponent, valueTag: 0x0c, value: 'example' };
		expect(compareNameAttributeValue(utf8, ia5)).toBe(false);
	});

	it('collapses insignificant spaces in domainComponent values', () => {
		expect(compareNameAttributeValue(dc('a  b'), dc('a b'))).toBe(true);
		expect(compareNameAttributeValue(dc('  Example  '), dc('example'))).toBe(true);
	});

	it('rejects a non-ASCII domainComponent value', () => {
		// U+212A KELVIN SIGN lowercases to `k` under a modern engine, but a valid
		// IA5String DC is ASCII, so a UTF8String Kelvin sign must not match `k`.
		const kelvin = {
			oid: OIDS.domainComponent,
			valueTag: 0x0c,
			value: String.fromCodePoint(0x212a),
		};
		const k = { oid: OIDS.domainComponent, valueTag: 0x16, value: 'k' };
		expect(compareNameAttributeValue(kelvin, k)).toBe(false);
	});
});
