import { describe, expect, it } from 'bun:test';
import type { ImportEcPublicKeyInput } from '#micro509/keys/index.ts';
import * as keys from '#micro509/keys/index.ts';
import * as pem from '#micro509/pem/index.ts';
import * as result from '#micro509/result/index.ts';

const ecAlgorithm = {
	kind: 'ecdsa',
	curve: 'P-256',
} as const satisfies ImportEcPublicKeyInput;

describe('utility domains', () => {
	describe('keys domain', () => {
		it('round-trips a private key through PKCS#8 PEM', async () => {
			const pair = await keys.generateKeyPair(ecAlgorithm);
			const exported = await keys.exportPkcs8Pem(pair.privateKey);
			const imported = result.unwrap(await keys.importPkcs8Pem(exported, ecAlgorithm));
			const reExported = await keys.exportPkcs8Pem(imported);
			expect(reExported).toBe(exported);
		});

		it('round-trips a public key through SPKI PEM', async () => {
			const pair = await keys.generateKeyPair(ecAlgorithm);
			const exported = await keys.exportSpkiPem(pair.publicKey);
			const imported = result.unwrap(await keys.importSpkiPem(exported, ecAlgorithm));
			const reExported = await keys.exportSpkiPem(imported);
			expect(reExported).toBe(exported);
		});

		it('round-trips a private key through encrypted PKCS#8 PEM', async () => {
			const pair = await keys.generateKeyPair(ecAlgorithm);
			const password = 'test-passphrase';
			const encrypted = await keys.exportEncryptedPkcs8Pem(pair.privateKey, { password });
			const imported = result.unwrap(
				await keys.importEncryptedPkcs8Pem(encrypted, password, ecAlgorithm),
			);
			const plainPem = await keys.exportPkcs8Pem(imported);
			const originalPem = await keys.exportPkcs8Pem(pair.privateKey);
			expect(plainPem).toBe(originalPem);
		});

		it('excludes internal helpers from the domain surface', () => {
			expect('getCrypto' in keys).toBe(false);
			expect('wrapKeyPair' in keys).toBe(false);
		});
	});

	describe('pem domain', () => {
		it('round-trips bytes through pemEncode / pemDecode', () => {
			const original = Uint8Array.of(0x30, 0x82, 0x01, 0x22, 0x00, 0xff);
			const encoded = pem.pemEncode('CERTIFICATE', original);
			const decoded = pem.pemDecode('CERTIFICATE', encoded);
			expect(decoded).toEqual(original);
		});

		it('splits a multi-block PEM string into individual blocks', () => {
			const cert1Bytes = Uint8Array.of(1, 2, 3);
			const cert2Bytes = Uint8Array.of(4, 5, 6);
			const multiPem = [
				pem.pemEncode('CERTIFICATE', cert1Bytes),
				pem.pemEncode('CERTIFICATE', cert2Bytes),
			].join('\n');

			const blocks = pem.splitPemBlocks(multiPem);
			expect(blocks).toHaveLength(2);
			expect(blocks[0]?.label).toBe('CERTIFICATE');
			expect(blocks[1]?.label).toBe('CERTIFICATE');
			expect(blocks[0]?.bytes).toEqual(cert1Bytes);
			expect(blocks[1]?.bytes).toEqual(cert2Bytes);
		});

		it('categorizes mixed PEM blocks by label', () => {
			const mixedPem = [
				pem.pemEncode('CERTIFICATE', Uint8Array.of(1)),
				pem.pemEncode('PRIVATE KEY', Uint8Array.of(2)),
			].join('\n');

			const categorized = pem.categorizePemBlocks(mixedPem);
			expect(categorized.certificates).toHaveLength(1);
			expect(categorized.privateKeys).toHaveLength(1);
			expect(categorized.publicKeys).toHaveLength(0);
			expect(categorized.certificateRequests).toHaveLength(0);
			expect(categorized.others).toHaveLength(0);
			expect(categorized.certificates[0]?.label).toBe('CERTIFICATE');
			expect(categorized.privateKeys[0]?.label).toBe('PRIVATE KEY');
		});

		it('excludes base64 internals from the domain surface', () => {
			expect('base64Encode' in pem).toBe(false);
			expect('base64Decode' in pem).toBe(false);
		});
	});

	describe('result domain', () => {
		it('wraps a value in a success result', () => {
			const r = result.successResult(42);
			expect(r.ok).toBe(true);
			expect(r.value).toBe(42);
		});

		it('wraps a micro509Error in an error result with flattened fields', () => {
			const err = result.micro509Error('test_code', 'something went wrong');
			const r = result.errorResult(err);
			expect(r.ok).toBe(false);
			expect(r.code).toBe('test_code');
			expect(r.message).toBe('something went wrong');
			expect(r.error).toEqual(err);
		});

		it('constructs an indexed error with position metadata', () => {
			const err = result.indexedMicro509Error('parse_fail', 'bad cert', 3);
			expect(err.code).toBe('parse_fail');
			expect(err.message).toBe('bad cert');
			expect(err.index).toBe(3);
		});
	});
});
