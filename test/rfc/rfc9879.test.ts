import { describe, expect, it } from 'bun:test';
import path from 'node:path';
import {
	integerFromNumber,
	nullValue,
	objectIdentifier,
	octetString,
	readElement,
	readSequenceChildren,
	sequence,
	tlv,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import { createPfx, parsePfxDer } from '#micro509/pkcs/pfx';
import {
	createPkcs12MacData,
	type ParsedPkcs12MacData,
	parsePkcs12MacData,
} from '#micro509/pkcs/pkcs12-mac';
import { isResultError } from '#micro509/result';
import { flattenedText, projectRoot, rfcDir } from '#test/helpers';

const readLines = async (file: string): Promise<readonly string[]> =>
	(await Bun.file(file).text()).split('\n');

const rfc9879Lines = await readLines(`${rfcDir}/rfc9879.txt`);
const rfc8018Lines = await readLines(`${rfcDir}/rfc8018.txt`);
const webCryptoText = await flattenedText(
	path.join(projectRoot, 'docs', 'w3c', 'WebCryptoAPI', 'w3c-webcrypto-editors-draft.txt'),
);
const webIdlText = await flattenedText(
	path.join(projectRoot, 'docs', 'w3c', 'WebIDL', 'webidl.txt'),
);

const printedIn = (lines: readonly string[], from: number, to: number): string =>
	lines
		.slice(from - 1, to)
		.join(' ')
		.replace(/\s+/g, ' ')
		.trim();

const printed = (from: number, to: number): string =>
	rfc9879Lines
		.slice(from - 1, to)
		.map((line) => line.replace(/^\s*\|/, ''))
		.join(' ')
		.replace(/\s+/g, ' ')
		.trim();

const vectorDer = (from: number, to: number): Uint8Array =>
	new Uint8Array(
		Buffer.from(
			rfc9879Lines
				.slice(from - 1, to)
				.join('')
				.replace(/\s+/g, ''),
			'base64',
		),
	);

const sha256Hex = async (bytes: Uint8Array): Promise<string> =>
	new Bun.CryptoHasher('sha256').update(bytes).digest('hex');

const toHex = (bytes: Uint8Array): string =>
	Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const PASSWORD = '1234';

function splitPfx(der: Uint8Array): {
	readonly authenticatedSafe: Uint8Array;
	readonly macData: Uint8Array;
} {
	const [, authSafe, macData] = readSequenceChildren(der);
	if (authSafe === undefined || macData === undefined) {
		throw new Error('vector is not a PFX with MacData');
	}
	const contentInfo = der.slice(authSafe.start - authSafe.headerLength, authSafe.end);
	const [, content] = readSequenceChildren(contentInfo);
	if (content === undefined) {
		throw new Error('authSafe ContentInfo has no content');
	}
	return {
		authenticatedSafe: readElement(content.value).value,
		macData: der.slice(macData.start - macData.headerLength, macData.end),
	};
}

function rejection(promise: Promise<unknown>): Promise<unknown> {
	return promise.then(
		() => undefined,
		(error: unknown) => error,
	);
}

const hmacAlgorithm = (oid: string): Uint8Array => sequence([objectIdentifier(oid), nullValue()]);

interface Pbmac1Shape {
	readonly kdfOid?: string;
	readonly salt?: Uint8Array;
	readonly iterationCount?: Uint8Array;
	readonly keyLength?: Uint8Array | null;
	readonly prf?: Uint8Array | null;
	readonly messageAuthScheme?: Uint8Array;
	readonly digest?: Uint8Array;
	readonly outerIterations?: Uint8Array;
}

function pbmac1MacData(shape: Pbmac1Shape = {}): Uint8Array {
	const keyLength = shape.keyLength === undefined ? integerFromNumber(32) : shape.keyLength;
	const prf = shape.prf === undefined ? hmacAlgorithm(OIDS.hmacWithSHA256) : shape.prf;
	const pbkdf2Params = sequence([
		shape.salt ?? octetString(new Uint8Array(8).fill(0x11)),
		shape.iterationCount ?? integerFromNumber(2048),
		...(keyLength === null ? [] : [keyLength]),
		...(prf === null ? [] : [prf]),
	]);
	const algorithm = sequence([
		objectIdentifier(OIDS.pbmac1),
		sequence([
			sequence([objectIdentifier(shape.kdfOid ?? OIDS.pbkdf2), pbkdf2Params]),
			shape.messageAuthScheme ?? hmacAlgorithm(OIDS.hmacWithSHA256),
		]),
	]);
	return sequence([
		sequence([algorithm, octetString(shape.digest ?? new Uint8Array(32))]),
		octetString(new TextEncoder().encode('NOT USED')),
		...(shape.outerIterations === undefined ? [] : [shape.outerIterations]),
	]);
}

async function parseCode(
	der: Uint8Array,
	password: string | null = PASSWORD,
	maxKdfIterations?: number,
): Promise<string> {
	const result = await parsePkcs12MacData(
		der,
		Uint8Array.of(1, 2, 3),
		password ?? undefined,
		maxKdfIterations === undefined ? undefined : { maxKdfIterations },
	);
	return result.ok ? result.value.verification : result.code;
}

function pbmac1Fields(parsed: ParsedPkcs12MacData): readonly unknown[] {
	return parsed.type === 'pbmac1'
		? [parsed.iterations, parsed.keyLength, parsed.prf, parsed.messageAuthScheme]
		: [parsed.type];
}

interface Vector {
	readonly name: string;
	readonly from: number;
	readonly to: number;
	readonly sha256: string;
}

const A1: Vector = {
	name: 'A.1',
	from: 327,
	to: 383,
	sha256: 'a5aa952ca788f945834c9edb40f0b94b2d845b86d0c80856adc9578d05e9de43',
};
const A2: Vector = {
	name: 'A.2',
	from: 390,
	to: 446,
	sha256: 'da385cc443abb3bb1872fda6c02a74c1f619c2e6f6abb9dce7793d56388e61d0',
};
const A3: Vector = {
	name: 'A.3',
	from: 453,
	to: 509,
	sha256: 'c3e2845fcb7f78ea188286448669875474009dd29d299ab234bf6f14f1065a53',
};
const A4: Vector = {
	name: 'A.4',
	from: 517,
	to: 573,
	sha256: 'cc6c9709db9a96e5e04dfd740d5a739decb4a9b6605694cda1c4958179d58b0f',
};
const A5: Vector = {
	name: 'A.5',
	from: 581,
	to: 637,
	sha256: 'b03af0abd2075652ed4f17fb014a1b2f7d4f61f3071931dba45e43b13c9a7ffd',
};
const A6: Vector = {
	name: 'A.6',
	from: 645,
	to: 701,
	sha256: 'd2925861db528cbb14d99d8b0073b203ae1577912430058516b70033c0edc9d0',
};

async function verifyVectorMac(vector: Vector): Promise<ParsedPkcs12MacData | string> {
	const { authenticatedSafe, macData } = splitPfx(vectorDer(vector.from, vector.to));
	const result = await parsePkcs12MacData(macData, authenticatedSafe, PASSWORD);
	return result.ok ? result.value : result.code;
}

describe('RFC 9879', () => {
	describe('Appendix A (L319-320): "All test vectors use "1234" as the password for both encryption and integrity protection."', () => {
		it('prints the password line this suite relies on', () => {
			expect(printed(319, 320)).toContain('use "1234" as the password');
		});

		for (const vector of [A1, A2, A3, A4, A5, A6]) {
			it(`${vector.name} base64 at L${vector.from}-${vector.to} decodes to the expected PFX`, async () => {
				expect(await sha256Hex(vectorDer(vector.from, vector.to))).toBe(vector.sha256);
			});
		}
	});

	describe('§5 (L157-160): "all implementations of this specification MUST support the PBKDF2 key derivation function paired with SHA-256 HMAC"', () => {
		it('prints the §5 requirement', () => {
			expect(printed(157, 160)).toContain('MUST support the PBKDF2 key derivation function');
		});

		it('A.1 (L324-325 "MUST be readable"): the PBMAC1 MAC verifies with password "1234"', async () => {
			expect(printed(324, 325)).toContain('MUST be readable');
			const parsed = await verifyVectorMac(A1);
			expect(
				typeof parsed === 'string' ? parsed : [parsed.verification, ...pbmac1Fields(parsed)],
			).toEqual(['valid', 2048, 32, 'HMAC-SHA-256', 'HMAC-SHA-256']);
		});

		it('A.1 parses as a PFX and reports the verified PBMAC1 MacData', async () => {
			const result = await parsePfxDer(vectorDer(A1.from, A1.to), { password: PASSWORD });
			expect(
				result.ok ? [result.value.macData?.type, result.value.macData?.verification] : result.code,
			).toEqual(['pbmac1', 'valid']);
		});

		it('A.2 (L387-388 "SHOULD be readable"): SHA-512 PRF with SHA-256 HMAC verifies', async () => {
			expect(printed(387, 388)).toContain('SHOULD be readable');
			const parsed = await verifyVectorMac(A2);
			expect(
				typeof parsed === 'string' ? parsed : [parsed.verification, ...pbmac1Fields(parsed)],
			).toEqual(['valid', 2048, 32, 'HMAC-SHA-512', 'HMAC-SHA-256']);
		});

		it('A.3 (L450-451 "SHOULD be readable"): SHA-512 PRF with SHA-512 HMAC verifies', async () => {
			expect(printed(450, 451)).toContain('SHOULD be readable');
			const parsed = await verifyVectorMac(A3);
			expect(
				typeof parsed === 'string' ? parsed : [parsed.verification, ...pbmac1Fields(parsed)],
			).toEqual(['valid', 2048, 64, 'HMAC-SHA-512', 'HMAC-SHA-512']);
		});

		it('A.1 without a password parses the PBMAC1 parameters as unchecked', async () => {
			const { authenticatedSafe, macData } = splitPfx(vectorDer(A1.from, A1.to));
			const result = await parsePkcs12MacData(macData, authenticatedSafe);
			expect(result.ok ? [result.value.type, result.value.verification] : result.code).toEqual([
				'pbmac1',
				'unchecked',
			]);
		});
	});

	describe('§4 item d (L151-153): "If the PBMAC1 algorithm is used, the iterations value MUST be ignored."', () => {
		it('prints §4 item d', () => {
			expect(printed(151, 153)).toContain('the iterations value MUST be ignored');
		});

		it('A.4 (L513-515 "MUST NOT be readable"): PBKDF2 iterationCount 2049 fails the MAC although MacData iterations is 2048', async () => {
			expect(printed(513, 515)).toContain('MUST NOT be readable');
			const parsed = await verifyVectorMac(A4);
			expect(typeof parsed === 'string' ? parsed : parsed.verification).toBe('invalid');
		});

		it('A.4 fails PFX parsing with invalid_password', async () => {
			const result = await parsePfxDer(vectorDer(A4.from, A4.to), { password: PASSWORD });
			expect(result.ok ? 'ok' : result.code).toBe('invalid_password');
		});

		it('a negative MacData iterations does not affect a PBMAC1 MAC', async () => {
			const authenticatedSafe = Uint8Array.of(1, 2, 3);
			const { der } = await createPkcs12MacData(authenticatedSafe, {
				type: 'pbmac1',
				password: PASSWORD,
				iterations: 2048,
			});
			const [digestInfo, salt] = readSequenceChildren(der);
			if (digestInfo === undefined || salt === undefined) {
				throw new Error('MacData lost its fields');
			}
			const withNegativeIterations = sequence([
				der.slice(digestInfo.start - digestInfo.headerLength, digestInfo.end),
				der.slice(salt.start - salt.headerLength, salt.end),
				Uint8Array.of(0x02, 0x01, 0xff),
			]);
			const result = await parsePkcs12MacData(withNegativeIterations, authenticatedSafe, PASSWORD);
			expect(
				result.ok ? [result.value.iterations, result.value.verification] : result.code,
			).toEqual([2048, 'valid']);
		});
	});

	describe('§4 item c (L148-149): "If the PBMAC1 algorithm is used, the macSalt value MUST be ignored."', () => {
		it('prints §4 item c', () => {
			expect(printed(148, 149)).toContain('the macSalt value MUST be ignored');
		});

		it('A.5 (L577-579 "MUST NOT be readable"): swapped salts fail the MAC', async () => {
			expect(printed(577, 579)).toContain('MUST NOT be readable');
			const parsed = await verifyVectorMac(A5);
			expect(typeof parsed === 'string' ? parsed : parsed.verification).toBe('invalid');
		});

		it('A.5 fails PFX parsing with invalid_password', async () => {
			const result = await parsePfxDer(vectorDer(A5.from, A5.to), { password: PASSWORD });
			expect(result.ok ? 'ok' : result.code).toBe('invalid_password');
		});
	});

	describe('§5 (L172-173): "Implementations MUST NOT accept PBKDF2 KDF with PBKDF2-params that omit the keyLength field."', () => {
		it('prints the keyLength requirement', () => {
			expect(printed(172, 173)).toContain(
				'MUST NOT accept PBKDF2 KDF with PBKDF2-params that omit the keyLength field',
			);
		});

		it('A.6 (L641-643 "MUST NOT be readable"): PBKDF2-params without keyLength is malformed', async () => {
			expect(printed(641, 643)).toContain('MUST NOT be readable');
			expect(await verifyVectorMac(A6)).toBe('malformed');
		});

		it('A.6 fails PFX parsing with malformed', async () => {
			const result = await parsePfxDer(vectorDer(A6.from, A6.to), { password: PASSWORD });
			expect(result.ok ? 'ok' : result.code).toBe('malformed');
		});

		it('rejects a missing keyLength without a password too', async () => {
			expect(await parseCode(pbmac1MacData({ keyLength: null }), null)).toBe('malformed');
		});
	});

	describe('§4 item a (L137-142): "the parameters field MUST be present and have a value consistent with PBMAC1-params parameters"', () => {
		it('prints §4 item a', () => {
			expect(printed(137, 142)).toContain('the parameters field MUST be present');
		});

		it('rejects id-PBMAC1 without parameters as malformed', async () => {
			const der = sequence([
				sequence([sequence([objectIdentifier(OIDS.pbmac1)]), octetString(new Uint8Array(32))]),
				octetString(new Uint8Array(8)),
			]);
			expect(await parseCode(der)).toBe('malformed');
		});

		it('rejects an HMAC AlgorithmIdentifier whose parameters are not NULL as malformed', async () => {
			expect(
				await parseCode(
					pbmac1MacData({
						prf: sequence([objectIdentifier(OIDS.hmacWithSHA256), integerFromNumber(0)]),
					}),
				),
			).toBe('malformed');
		});

		it('rejects PBKDF2 iterationCount 0, outside INTEGER (1..MAX), as malformed', async () => {
			expect(await parseCode(pbmac1MacData({ iterationCount: integerFromNumber(0) }))).toBe(
				'malformed',
			);
		});
	});

	describe('§6 (L177-183): PBMAC1 passwords "MUST be created from UTF-8 encoding [RFC3629] without a NULL terminator or Byte Order Mark (BOM)"', () => {
		it('prints §6', () => {
			expect(printed(177, 183)).toContain(
				'UTF-8 encoding [RFC3629] without a NULL terminator or Byte Order Mark (BOM)',
			);
		});

		it('keys PBKDF2 with the UTF-8 bytes of a non-ASCII password longer than the 64-octet HMAC block', async () => {
			const password = 'pässwörd€'.repeat(8);
			const salt = new Uint8Array(16).fill(0x42);
			const authenticatedSafe = Uint8Array.of(1, 2, 3);
			const { parsed } = await createPkcs12MacData(authenticatedSafe, {
				type: 'pbmac1',
				password,
				iterations: 1000,
				salt,
			});
			const passwordKey = await crypto.subtle.importKey(
				'raw',
				new TextEncoder().encode(password),
				'PBKDF2',
				false,
				['deriveBits'],
			);
			const keyBytes = await crypto.subtle.deriveBits(
				{ name: 'PBKDF2', salt, iterations: 1000, hash: 'SHA-256' },
				passwordKey,
				256,
			);
			const macKey = await crypto.subtle.importKey(
				'raw',
				keyBytes,
				{ name: 'HMAC', hash: 'SHA-256' },
				false,
				['sign'],
			);
			const expected = new Uint8Array(await crypto.subtle.sign('HMAC', macKey, authenticatedSafe));
			expect(parsed.digestHex).toBe(toHex(expected));
		});

		it('createPkcs12MacData throws password_not_utf8 for an unpaired surrogate', async () => {
			const error = await rejection(
				createPkcs12MacData(Uint8Array.of(1, 2, 3), { type: 'pbmac1', password: 'a\ud800b' }),
			);
			expect(isResultError(error) ? error.code : error).toBe('password_not_utf8');
		});

		it('parsePkcs12MacData returns password_not_utf8 for an unpaired surrogate', async () => {
			expect(await parseCode(pbmac1MacData(), '\udc00')).toBe('password_not_utf8');
		});

		it('accepts a surrogate pair, which has a UTF-8 encoding', async () => {
			const authenticatedSafe = Uint8Array.of(1, 2, 3);
			const { der } = await createPkcs12MacData(authenticatedSafe, {
				type: 'pbmac1',
				password: '\u{1f511}',
				iterations: 1000,
			});
			const result = await parsePkcs12MacData(der, authenticatedSafe, '\u{1f511}');
			expect(result.ok ? result.value.verification : result.code).toBe('valid');
		});
	});

	describe('§9 (L220-227): "It\'s RECOMMENDED to reject any KDF parameters that specify key lengths less than 20 octets."', () => {
		it('prints the §9 recommendation', () => {
			expect(printed(220, 227)).toContain(
				'RECOMMENDED to reject any KDF parameters that specify key lengths less than 20 octets',
			);
		});

		it('returns weak_mac_key_length for keyLength 19', async () => {
			expect(await parseCode(pbmac1MacData({ keyLength: integerFromNumber(19) }))).toBe(
				'weak_mac_key_length',
			);
		});

		it('accepts keyLength 20', async () => {
			expect(await parseCode(pbmac1MacData({ keyLength: integerFromNumber(20) }))).toBe('invalid');
		});
	});

	describe('PBMAC1 variants micro509 does not implement return unsupported_mac_algorithm; RFC 9879 does not say how to report them', () => {
		it('§5 (L157-160) makes only PBKDF2 with HMAC-SHA-256 mandatory', () => {
			expect(printed(157, 160)).toContain('paired with SHA-256 HMAC');
		});

		it('a key derivation function other than PBKDF2', async () => {
			expect(await parseCode(pbmac1MacData({ kdfOid: OIDS.pbes2 }))).toBe(
				'unsupported_mac_algorithm',
			);
		});

		it('an explicit HMAC-SHA-1 PRF, which §7 says SHOULD NOT be used', async () => {
			expect(await parseCode(pbmac1MacData({ prf: hmacAlgorithm(OIDS.hmacWithSHA1) }))).toBe(
				'unsupported_mac_algorithm',
			);
		});

		it('an absent PRF, which defaults to HMAC-SHA-1', async () => {
			expect(await parseCode(pbmac1MacData({ prf: null }))).toBe('unsupported_mac_algorithm');
		});

		it('an HMAC-SHA-1 message authentication scheme', async () => {
			expect(
				await parseCode(pbmac1MacData({ messageAuthScheme: hmacAlgorithm(OIDS.hmacWithSHA1) })),
			).toBe('unsupported_mac_algorithm');
		});

		it('a PBKDF2 otherSource salt', async () => {
			expect(
				await parseCode(pbmac1MacData({ salt: sequence([objectIdentifier(OIDS.sha256)]) })),
			).toBe('unsupported_mac_algorithm');
		});

		it('a keyLength above 64 octets', async () => {
			expect(await parseCode(pbmac1MacData({ keyLength: integerFromNumber(65) }))).toBe(
				'unsupported_mac_algorithm',
			);
		});

		it('an RFC 7292 MAC with a digest other than SHA-256', async () => {
			const der = sequence([
				sequence([
					sequence([objectIdentifier(OIDS.sha1), nullValue()]),
					octetString(new Uint8Array(20)),
				]),
				octetString(new Uint8Array(8)),
				integerFromNumber(2048),
			]);
			expect(await parseCode(der)).toBe('unsupported_mac_algorithm');
			expect(await parseCode(der, null)).toBe('unsupported_mac_algorithm');
		});

		it('a PFX with an unsupported PBMAC1 variant fails with unsupported_mac_algorithm', async () => {
			const pfx = vectorDer(A1.from, A1.to);
			const [version, authSafe] = readSequenceChildren(pfx);
			if (version === undefined || authSafe === undefined) {
				throw new Error('vector lost its fields');
			}
			const unsupported = sequence([
				pfx.slice(version.start - version.headerLength, version.end),
				pfx.slice(authSafe.start - authSafe.headerLength, authSafe.end),
				pbmac1MacData({ prf: null }),
			]);
			const result = await parsePfxDer(unsupported, { password: PASSWORD });
			expect(result.ok ? 'ok' : result.code).toBe('unsupported_mac_algorithm');
		});
	});

	describe('RFC 8018 Appendix A.2: "The maximum iteration count allowed depends on the implementation." (L1318-1321)', () => {
		it('prints the implementation-defined maximum', () => {
			expect(printedIn(rfc8018Lines, 1318, 1321)).toContain(
				'The maximum iteration count allowed depends on the implementation.',
			);
		});

		it('rejects A.1 before deriving when maxKdfIterations is below its 2048 rounds', async () => {
			const { authenticatedSafe, macData } = splitPfx(vectorDer(A1.from, A1.to));
			const result = await parsePkcs12MacData(macData, authenticatedSafe, PASSWORD, {
				maxKdfIterations: 2047,
			});
			expect(result.ok ? result.value.verification : result.code).toBe('kdf_iterations_exceeded');
		});

		it('uses the PBKDF2 default of 2_000_000 rounds, not the PKCS#12 KDF default of 100_000', async () => {
			expect(await parseCode(pbmac1MacData({ iterationCount: integerFromNumber(150_000) }))).toBe(
				'invalid',
			);
			expect(await parseCode(pbmac1MacData({ iterationCount: integerFromNumber(2_000_001) }))).toBe(
				'kdf_iterations_exceeded',
			);
		});

		describe('WebCrypto "required [EnforceRange] unsigned long iterations;" (editor draft) and Web IDL unsigned long "[0, 4294967295]" cap PBMAC1 iterations', () => {
			it('prints the WebCrypto and Web IDL bounds', () => {
				expect(webCryptoText).toContain('required [EnforceRange] unsigned long iterations;');
				expect(webIdlText).toContain('[0, 4294967295]');
				expect(webIdlText).toContain(
					'If x < lowerBound or x > upperBound, then throw a TypeError.',
				);
			});

			it('returns malformed at 4294967296 even when maxKdfIterations allows it, as PBES2 does', async () => {
				expect(
					await parseCode(
						pbmac1MacData({ iterationCount: integerFromNumber(2 ** 32) }),
						PASSWORD,
						Number.MAX_SAFE_INTEGER,
					),
				).toBe('malformed');
			});

			it('returns malformed at 4294967296 without a password', async () => {
				expect(
					await parseCode(pbmac1MacData({ iterationCount: integerFromNumber(2 ** 32) }), null),
				).toBe('malformed');
			});

			it('returns malformed at 2^53 with a password', async () => {
				expect(
					await parseCode(
						pbmac1MacData({
							iterationCount: tlv(0x02, Uint8Array.of(0x20, 0, 0, 0, 0, 0, 0)),
						}),
						PASSWORD,
						Number.MAX_SAFE_INTEGER,
					),
				).toBe('malformed');
			});

			it('createPkcs12MacData throws invalid_iterations for 4294967296 PBMAC1 rounds', async () => {
				const error = await rejection(
					createPkcs12MacData(Uint8Array.of(1, 2, 3), {
						type: 'pbmac1',
						password: PASSWORD,
						iterations: 2 ** 32,
					}),
				);
				expect(isResultError(error) ? error.code : error).toBe('invalid_iterations');
			});
		});

		it('does not charge the budget without a password', async () => {
			expect(
				await parseCode(pbmac1MacData({ iterationCount: integerFromNumber(2 ** 32 - 1) }), null, 1),
			).toBe('unchecked');
		});
	});

	describe('creation with mac.type "pbmac1"', () => {
		it('createPfx writes a PBMAC1 MacData with keyLength 32 and HMAC-SHA-256 that parsePfxDer verifies', async () => {
			const created = await createPfx({
				certificates: [],
				mac: { type: 'pbmac1', password: PASSWORD, iterations: 2048 },
			});
			if (!created.ok) {
				throw new Error(created.message);
			}
			const { macData } = splitPfx(created.value.der);
			const unchecked = await parsePkcs12MacData(macData, new Uint8Array());
			expect(
				unchecked.ok ? [unchecked.value.type, ...pbmac1Fields(unchecked.value)] : unchecked.code,
			).toEqual(['pbmac1', 2048, 32, 'HMAC-SHA-256', 'HMAC-SHA-256']);
			const parsed = await parsePfxDer(created.value.der, { password: PASSWORD });
			expect(
				parsed.ok ? [parsed.value.macData?.type, parsed.value.macData?.verification] : parsed.code,
			).toEqual(['pbmac1', 'valid']);
		});

		it('keeps the RFC 7292 MAC as the default', async () => {
			const { parsed } = await createPkcs12MacData(Uint8Array.of(1, 2, 3), {
				password: PASSWORD,
				iterations: 1,
			});
			expect(parsed.type).toBe('pkcs12-kdf');
		});
	});
});
