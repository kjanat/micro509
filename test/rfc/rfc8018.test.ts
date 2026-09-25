import { describe, expect, it } from 'bun:test';
import path from 'node:path';
import { importEncryptedPkcs8Der, inspectEncryptedPkcs8Der } from '#micro509';
import {
	integerFromNumber,
	nullValue,
	objectIdentifier,
	octetString,
	sequence,
	tlv,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import {
	createKdfBudget,
	decryptPbes2,
	encodePbes2AlgorithmIdentifier,
	encryptPbes2,
	parsePbes2AlgorithmIdentifier,
} from '#micro509/internal/crypto/pbes2';
import { flattenedText, projectRoot, rfcDir } from '#test/helpers';

const readLines = async (file: string): Promise<readonly string[]> =>
	(await Bun.file(file).text()).split('\n');

const rfc8018Lines = await readLines(`${rfcDir}/rfc8018.txt`);
const webCryptoText = await flattenedText(
	path.join(projectRoot, 'docs', 'w3c', 'WebCryptoAPI', 'w3c-webcrypto-editors-draft.txt'),
);
const webIdlText = await flattenedText(
	path.join(projectRoot, 'docs', 'w3c', 'WebIDL', 'webidl.txt'),
);

const printed = (lines: readonly string[], from: number, to: number): string =>
	lines
		.slice(from - 1, to)
		.join(' ')
		.replace(/\s+/g, ' ')
		.trim();

const WEBCRYPTO_MAX = 4_294_967_295;

function pbes2WithIterationCount(iterationCount: Uint8Array): Uint8Array {
	return sequence([
		objectIdentifier(OIDS.pbes2),
		sequence([
			sequence([
				objectIdentifier(OIDS.pbkdf2),
				sequence([
					octetString(new Uint8Array(16).fill(0x11)),
					iterationCount,
					integerFromNumber(32),
					sequence([objectIdentifier(OIDS.hmacWithSHA256), nullValue()]),
				]),
			]),
			sequence([objectIdentifier(OIDS.aes256Cbc), octetString(new Uint8Array(16).fill(0x22))]),
		]),
	]);
}

const encryptedPrivateKeyInfo = (algorithmIdentifier: Uint8Array): Uint8Array =>
	sequence([algorithmIdentifier, octetString(new Uint8Array(32))]);

const parameters = (iterations: number) =>
	({
		iterations,
		salt: new Uint8Array(16),
		iv: new Uint8Array(16),
		cipher: 'AES-256-CBC',
		prf: 'HMAC-SHA-256',
	}) as const;

describe('RFC 8018', () => {
	describe('Appendix A.2 PBKDF2: "iterationCount INTEGER (1..MAX)" (L1277)', () => {
		it('prints the PBKDF2-params bounds this suite encodes', () => {
			expect(printed(rfc8018Lines, 1277, 1277)).toBe('iterationCount INTEGER (1..MAX),');
			expect(printed(rfc8018Lines, 1278, 1278)).toBe('keyLength INTEGER (1..MAX) OPTIONAL,');
		});

		it('accepts the lower bound 1', () => {
			expect(
				parsePbes2AlgorithmIdentifier(pbes2WithIterationCount(integerFromNumber(1))).iterations,
			).toBe(1);
		});

		it('rejects iterationCount 0, which lies outside (1..MAX)', () => {
			expect(() =>
				parsePbes2AlgorithmIdentifier(pbes2WithIterationCount(integerFromNumber(0))),
			).toThrow('Invalid PBES2 iterations: must be >= 1, got 0');
		});

		it('rejects a negative iterationCount', () => {
			expect(() =>
				parsePbes2AlgorithmIdentifier(pbes2WithIterationCount(tlv(0x02, Uint8Array.of(0xff)))),
			).toThrow('INTEGER must be non-negative');
		});

		it('requires the INTEGER tag, refusing a constructed 0x22 encoding', () => {
			const constructed = tlv(0x22, integerFromNumber(2048));
			expect(() => parsePbes2AlgorithmIdentifier(pbes2WithIterationCount(constructed))).toThrow(
				'Malformed PBKDF2 params',
			);
		});

		it('rejects an empty INTEGER', () => {
			expect(() =>
				parsePbes2AlgorithmIdentifier(pbes2WithIterationCount(tlv(0x02, new Uint8Array()))),
			).toThrow('INTEGER is empty');
		});

		it('rejects a non-minimal INTEGER', () => {
			expect(() =>
				parsePbes2AlgorithmIdentifier(
					pbes2WithIterationCount(tlv(0x02, Uint8Array.of(0x00, 0x01))),
				),
			).toThrow('INTEGER must use minimal encoding');
		});

		it('rejects a 9-octet iterationCount before building a number from it', () => {
			const oversized = tlv(0x02, Uint8Array.of(0x01, 0, 0, 0, 0, 0, 0, 0, 0));
			expect(() => parsePbes2AlgorithmIdentifier(pbes2WithIterationCount(oversized))).toThrow(
				'Integer too large for safe number (9 bytes)',
			);
		});
	});

	describe('Appendix A.2: "The maximum iteration count allowed depends on the implementation" (L1318-1321)', () => {
		it('prints the implementation-defined maximum', () => {
			expect(printed(rfc8018Lines, 1318, 1321)).toContain(
				'The maximum iteration count allowed depends on the implementation. It is expected that implementation profiles may further constrain the bounds.',
			);
		});

		describe('WebCrypto "required [EnforceRange] unsigned long iterations;" (editor draft) sets that maximum', () => {
			it('prints the WebCrypto and Web IDL bounds', () => {
				expect(webCryptoText).toContain('required [EnforceRange] unsigned long iterations;');
				expect(webIdlText).toContain('[0, 4294967295]');
				expect(webIdlText).toContain(
					'If x < lowerBound or x > upperBound, then throw a TypeError.',
				);
			});

			it('accepts 4294967295 at parse and leaves it to the KDF budget', async () => {
				const algorithmIdentifier = pbes2WithIterationCount(integerFromNumber(WEBCRYPTO_MAX));
				expect(parsePbes2AlgorithmIdentifier(algorithmIdentifier).iterations).toBe(WEBCRYPTO_MAX);
				expect(
					inspectEncryptedPkcs8Der(encryptedPrivateKeyInfo(algorithmIdentifier)).iterations,
				).toBe(WEBCRYPTO_MAX);
				const imported = await importEncryptedPkcs8Der(
					encryptedPrivateKeyInfo(algorithmIdentifier),
					'password',
				);
				expect(imported.ok).toBe(false);
				if (!imported.ok) {
					expect(imported.code).toBe('kdf_iterations_exceeded');
				}
			});

			it('rejects 4294967296 at parse', () => {
				const algorithmIdentifier = pbes2WithIterationCount(integerFromNumber(WEBCRYPTO_MAX + 1));
				expect(() => parsePbes2AlgorithmIdentifier(algorithmIdentifier)).toThrow(
					'Invalid PBES2 iterations: must be <= 4294967295, got 4294967296',
				);
				expect(() =>
					inspectEncryptedPkcs8Der(encryptedPrivateKeyInfo(algorithmIdentifier)),
				).toThrow('Invalid PBES2 iterations: must be <= 4294967295, got 4294967296');
			});

			it('returns malformed for 4294967296 even when maxKdfIterations allows it', async () => {
				const imported = await importEncryptedPkcs8Der(
					encryptedPrivateKeyInfo(pbes2WithIterationCount(integerFromNumber(WEBCRYPTO_MAX + 1))),
					'password',
					undefined,
					{ maxKdfIterations: 2 ** 33 },
				);
				expect(imported.ok).toBe(false);
				if (!imported.ok) {
					expect(imported.code).toBe('malformed');
				}
			});

			it('fails decryptPbes2 with a plain Error before WebCrypto raises its TypeError', async () => {
				const failure = await decryptPbes2(
					pbes2WithIterationCount(integerFromNumber(WEBCRYPTO_MAX + 1)),
					new Uint8Array(32),
					'password',
					createKdfBudget({ maxKdfIterations: 2 ** 33 }),
				).then(
					() => undefined,
					(error: unknown) => error,
				);
				expect(failure).toBeInstanceOf(Error);
				expect(failure instanceof TypeError).toBe(false);
				expect(failure instanceof Error ? failure.message : '').toBe(
					'Invalid PBES2 iterations: must be <= 4294967295, got 4294967296',
				);
			});

			it('refuses to encrypt or encode an iterationCount outside 1 to 4294967295', async () => {
				for (const iterations of [0, -1, 1.5, WEBCRYPTO_MAX + 1]) {
					const failure = await encryptPbes2(new Uint8Array(16), {
						password: 'password',
						iterations,
					}).then(
						() => undefined,
						(error: unknown) => error,
					);
					expect({ iterations, rangeError: failure instanceof RangeError }).toEqual({
						iterations,
						rangeError: true,
					});
					expect(() => encodePbes2AlgorithmIdentifier(parameters(iterations))).toThrow(RangeError);
				}
			});
		});
	});
});
