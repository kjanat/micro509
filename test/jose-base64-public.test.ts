import { expect, it } from 'bun:test';
import { base64url } from 'jose-v5';
import { base64UrlDecode, base64UrlEncode } from '#micro509/jose';

it('decodes jose 5 base64url output through the public API for empty input and every remainder', () => {
	for (let length = 0; length <= 32; length++) {
		const bytes = Uint8Array.from({ length }, (_, index) => (index * 37 + 251) & 255);
		const independent = base64url.encode(bytes);
		expect(base64UrlDecode(independent)).toEqual(bytes);
		expect(base64UrlEncode(bytes)).toBe(independent);
	}
});

it('preserves strict canonical decoding at the public boundary', () => {
	for (const value of ['Zg==', 'Zh', '+/8', 'A', 'Zm 9v', 'Zm9vé']) {
		expect(base64UrlDecode(value)).toBeUndefined();
	}
});
