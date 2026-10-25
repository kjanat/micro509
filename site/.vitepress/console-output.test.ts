import { expect, test } from 'bun:test';
import { formatConsoleArgs } from './console-output.ts';

test('multiline PEM begins on a new line and subsequent arguments follow the block', () => {
	const pem = '-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----\n';
	expect(formatConsoleArgs(['Private key:', pem, 'Done'])).toBe(`Private key:\n${pem}Done`);
});

test('pretty-printed objects and JSON strings start below their labels', () => {
	const claims = { sub: 'demo-user', aud: 'api://orders' };
	const json = JSON.stringify(claims, null, 2);
	expect(formatConsoleArgs(['Claims:', claims])).toBe(`Claims:\n${json}`);
	expect(formatConsoleArgs(['Claims:', json, 'Next:', { ok: true }])).toBe(
		`Claims:\n${json}\nNext:\n{\n  "ok": true\n}`,
	);
});

test('single-line values use spaces and explicit line breaks are respected', () => {
	expect(formatConsoleArgs(['Key type:', 'ECDSA', 256, true, undefined, null])).toBe(
		'Key type: ECDSA 256 true undefined null',
	);
	expect(formatConsoleArgs(['Label:\n', 'line one\nline two'])).toBe('Label:\nline one\nline two');
	expect(formatConsoleArgs(['Label:', '\nline one\nline two'])).toBe('Label:\nline one\nline two');
	expect(formatConsoleArgs([])).toBe('');
});
