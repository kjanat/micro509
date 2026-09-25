import { describe, expect, it } from 'bun:test';
import type { IdnaFailure } from '#micro509/internal/shared/idna';
import {
	checkALabel,
	checkULabel,
	domainToAscii,
	referenceDomainToAscii,
} from '#micro509/internal/shared/idna';
import { punycodeDecode, punycodeEncode } from '#micro509/internal/shared/punycode';

describe('RFC 3492 Punycode', () => {
	it.each([
		['bücher', 'bcher-kva'],
		['münchen', 'mnchen-3ya'],
		['♚', '45h'],
		['abc', 'abc-'],
		['他们为什么不说中文', 'ihqwcrb4cv8a8dqg056pqjye'],
	])('encodes %s as %s and decodes it back', (unicode, encoded) => {
		expect(punycodeEncode(unicode)).toBe(encoded);
		expect(punycodeDecode(encoded)).toBe(unicode);
	});

	it('decodes uppercase digits', () => {
		expect(punycodeDecode('bcher-KVA')).toBe('bücher');
	});

	it.each([
		['non-ASCII input', 'bü-kva'],
		['a bad digit', 'abc-!'],
		['input that ends mid-number', 'bcher-kv'],
		['an overflow', 'zzzzzzzzzzzzzzzzzzzzz'],
	])('rejects %s', (_name, input) => {
		expect(() => punycodeDecode(input)).toThrow(RangeError);
	});
});

describe('RFC 5891 §4.2 registration tests on a U-label', () => {
	it('accepts a PVALID label', () => {
		expect(checkULabel('bücher', 'registration')).toBeUndefined();
	});

	it('requires NFC', () => {
		expect(checkULabel('á', 'registration')).toBe('not_nfc');
	});

	it('rejects "--" in the third and fourth positions and a leading or trailing hyphen', () => {
		expect(checkULabel('ün--c', 'registration')).toBe('hyphen');
		expect(checkULabel('-ü', 'registration')).toBe('hyphen');
		expect(checkULabel('ü-', 'registration')).toBe('hyphen');
	});

	it('counts the third and fourth positions in code points', () => {
		expect(checkULabel('\u{20000}a--b', 'registration')).toBe('hyphen');
		expect(checkULabel('\u{20000}a--b', 'lookup')).toBe('hyphen');
		expect(checkULabel('a\u{20000}-b', 'registration')).toBeUndefined();
	});

	it('rejects a leading combining mark', () => {
		expect(checkULabel('́a', 'registration')).toBe('leading_combining_mark');
	});

	it('rejects DISALLOWED code points, including symbols and uppercase letters', () => {
		expect(checkULabel('♚', 'registration')).toBe('disallowed_code_point');
		expect(checkULabel('Bücher', 'registration')).toBe('disallowed_code_point');
	});

	it('rejects UNASSIGNED code points', () => {
		expect(checkULabel('a͸', 'registration')).toBe('disallowed_code_point');
	});
});

describe('RFC 5891 §5.4 lookup tests on a U-label', () => {
	it('allows a leading or trailing hyphen', () => {
		expect(checkULabel('-ü', 'lookup')).toBeUndefined();
	});

	it('still rejects "--" in the third and fourth positions', () => {
		expect(checkULabel('ün--c', 'lookup')).toBe('hyphen');
	});
});

describe('RFC 5892 Appendix A contextual rules, evaluated at every occurrence (RFC 8753 §6)', () => {
	const cases: readonly (readonly [string, string, IdnaFailure | undefined])[] = [
		['C1 ZWNJ after a virama', 'क्‌ष', undefined],
		['C1 ZWNJ between joining letters', 'ب‌ب', undefined],
		['C1 ZWNJ between Latin letters', 'a‌b', 'context_rule'],
		['C2 ZWJ after a virama', 'क्‍', undefined],
		['C2 ZWJ without a virama', 'a‍b', 'context_rule'],
		['C3 MIDDLE DOT between two l', 'l·l', undefined],
		['C3 MIDDLE DOT elsewhere', 'a·b', 'context_rule'],
		['C3 at one good and one bad occurrence', 'l·la·b', 'context_rule'],
		['C4 KERAIA before Greek', '͵α', undefined],
		['C4 KERAIA before Latin', '͵a', 'context_rule'],
		['C5 GERESH after Hebrew', 'א׳', undefined],
		['C6 GERSHAYIM after Latin', 'a״', 'context_rule'],
		['C7 KATAKANA MIDDLE DOT with Katakana', '・ア', undefined],
		['C7 KATAKANA MIDDLE DOT without Japanese script', '・a', 'context_rule'],
		['C8 and C9 mixed Arabic-Indic digits', 'ا١۱', 'context_rule'],
		['C8 Arabic-Indic digits alone', 'ا١', undefined],
	];

	it.each(cases)('%s', (_name, label, expected) => {
		expect(checkULabel(label, 'registration')).toBe(expected);
	});
});

describe('RFC 5893 §2 Bidi rule across a Bidi domain name', () => {
	it('accepts an RTL label ending in a digit', () => {
		expect(domainToAscii('א1.example', 'registration')).toEqual({
			ok: true,
			value: 'xn--1-zhc.example',
		});
	});

	it('rejects an RTL label that starts with a digit', () => {
		expect(domainToAscii('1א.example', 'registration')).toEqual({
			ok: false,
			reason: 'bidi_rule',
		});
	});

	it('tests the ASCII labels of a Bidi domain name too', () => {
		expect(domainToAscii('אב.1example', 'registration')).toEqual({
			ok: false,
			reason: 'bidi_rule',
		});
	});
});

describe('RFC 5891 §4.2.1 and §5.3 A-labels', () => {
	it('decodes a valid A-label to its U-label', () => {
		expect(checkALabel('xn--mnchen-3ya', 'registration')).toEqual({ ok: true, uLabel: 'münchen' });
	});

	it('requires lowercase for registration and lowercases for lookup', () => {
		expect(checkALabel('XN--MNCHEN-3YA', 'registration')).toEqual({
			ok: false,
			reason: 'invalid_a_label',
		});
		expect(checkALabel('XN--MNCHEN-3YA', 'lookup')).toEqual({ ok: true, uLabel: 'münchen' });
	});

	it.each([
		['a U-label that is not IDNA2008 valid', 'xn--45h'],
		['Punycode that does not decode', 'xn--abc'],
		['Punycode of ASCII only', 'xn--abc-'],
		['a trailing hyphen', 'xn--45h-'],
	])('rejects %s', (_name, label) => {
		expect(checkALabel(label, 'lookup')).toEqual({ ok: false, reason: 'invalid_a_label' });
	});
});

describe('domainToAscii', () => {
	it('converts U-labels to A-labels', () => {
		expect(domainToAscii('bücher.example', 'registration')).toEqual({
			ok: true,
			value: 'xn--bcher-kva.example',
		});
	});

	it('returns an ASCII name without IDN labels as given', () => {
		expect(domainToAscii('Example.COM', 'registration')).toEqual({
			ok: true,
			value: 'Example.COM',
		});
	});

	it('rejects a U-label whose A-label exceeds 63 octets', () => {
		expect(domainToAscii(`${'ü'.repeat(60)}.example`, 'registration')).toEqual({
			ok: false,
			reason: 'label_too_long',
		});
	});
});

describe('referenceDomainToAscii', () => {
	it('maps case, width and ideographic full stops per RFC 5895 before conversion', () => {
		expect(referenceDomainToAscii('Bücher.Example')).toBe('xn--bcher-kva.example');
		expect(referenceDomainToAscii('ＢÜＣＨＥＲ．example')).toBe('xn--bcher-kva.example');
		expect(referenceDomainToAscii('ü。example')).toBe('xn--tda.example');
	});

	it('lowercases ASCII labels and keeps SRV underscores', () => {
		expect(referenceDomainToAscii('Example.COM')).toBe('example.com');
		expect(referenceDomainToAscii('_imap.example.com')).toBe('_imap.example.com');
	});

	it('returns undefined for a name that is not IDNA2008 valid', () => {
		expect(referenceDomainToAscii('♚.example')).toBeUndefined();
		expect(referenceDomainToAscii('xn--45h.example')).toBeUndefined();
	});
});
