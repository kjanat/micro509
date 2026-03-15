import { describe, expect, it } from 'bun:test';
import type { ParsedPkcs12MacData, PfxMaterial } from '#micro509/pkcs/index.ts';
import * as pkcs from '#micro509/pkcs/index.ts';

function assertPkcsDomainTypes(_input: {
	readonly pfx?: PfxMaterial;
	readonly mac?: ParsedPkcs12MacData;
}): void {}

describe('pkcs domain', () => {
	it('exposes the consolidated PKCS surface', () => {
		assertPkcsDomainTypes({});

		expect(typeof pkcs.createPfx).toBe('function');
		expect(typeof pkcs.parsePfxPem).toBe('function');
		expect(typeof pkcs.parsePkcs7SignedDataPem).toBe('function');
		expect(typeof pkcs.verifyPkcs7SignedData).toBe('function');
		expect(typeof pkcs.createPkcs12MacData).toBe('function');
		expect(typeof pkcs.parsePkcs12MacData).toBe('function');
	});
});
