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

	it('case-folds compatibility characters to lowercase', () => {
		// U+1D2C MODIFIER LETTER CAPITAL A: NFKC decomposes it to "A", which must
		// then lowercase to "a" rather than survive as an uppercase letter.
		const modifierCapitalA = String.fromCodePoint(0x1d2c);
		expect(prepareNameCompareString(modifierCapitalA)).toBe(prepareNameCompareString('a'));
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
});
