import { describe, expect, it } from 'bun:test';
import type { EcKeyAlgorithmInput } from '#micro509/keys/index.ts';
import * as keys from '#micro509/keys/index.ts';
import type { PemBlock } from '#micro509/pem/index.ts';
import * as pem from '#micro509/pem/index.ts';
import * as result from '#micro509/result/index.ts';

describe('utility domains', () => {
	it('exposes the canonical keys domain surface', () => {
		const algorithm: EcKeyAlgorithmInput = { kind: 'ecdsa', namedCurve: 'P-256' };

		expect(algorithm.namedCurve).toBe('P-256');
		expect(typeof keys.generateKeyPair).toBe('function');
		expect(typeof keys.importSpkiPem).toBe('function');
		expect(typeof keys.exportEncryptedPkcs8Pem).toBe('function');
		expect('getCrypto' in keys).toBe(false);
		expect('wrapKeyPair' in keys).toBe(false);
	});

	it('keeps pem focused on PEM boundaries', () => {
		const block: PemBlock = {
			label: 'CERTIFICATE',
			bytes: Uint8Array.of(1, 2, 3),
			pem: '-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----',
		};

		expect(block.label).toBe('CERTIFICATE');
		expect(typeof pem.pemEncode).toBe('function');
		expect(typeof pem.pemDecode).toBe('function');
		expect(typeof pem.splitPemBlocks).toBe('function');
		expect(typeof pem.categorizePemBlocks).toBe('function');
		expect('base64Encode' in pem).toBe(false);
		expect('base64Decode' in pem).toBe(false);
	});

	it('keeps result helpers owned by the result domain', () => {
		expect(typeof result.successResult).toBe('function');
		expect(typeof result.errorResult).toBe('function');
		expect(typeof result.micro509Error).toBe('function');
		expect(typeof result.indexedMicro509Error).toBe('function');
	});
});
