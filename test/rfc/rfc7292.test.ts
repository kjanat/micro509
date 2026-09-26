import { describe, expect, it } from 'bun:test';
import type { ParsePfxResult } from '#micro509';
import {
	createSelfSignedCertificate,
	exportPkcs8Der,
	generateKeyPair,
	parsePfxDer,
} from '#micro509';
import {
	concatBytes,
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
import { encryptPbes2 } from '#micro509/internal/crypto/pbes2';
import {
	createPkcs12MacData,
	derivePkcs12Key,
	parsePkcs12MacData,
	parsePkcs12MacDataOrThrow,
} from '#micro509/pkcs/pkcs12-mac';
import { isResultError } from '#micro509/result';
import { rfcDir } from '#test/helpers';

const rfc7292Lines = (await Bun.file(`${rfcDir}/rfc7292.txt`).text()).split('\n');

const printed = (from: number, to: number): string =>
	rfc7292Lines
		.slice(from - 1, to)
		.join(' ')
		.replace(/\s+/g, ' ')
		.trim();

const fromHex = (hex: string): Uint8Array =>
	Uint8Array.from(hex.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));

const toHex = (bytes: Uint8Array): string =>
	Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const bmpStringWithNull = (password: string): string =>
	`${Array.from(password, (character) => character.charCodeAt(0).toString(16).padStart(4, '0')).join('')}0000`;

const opensslCommand = (vector: KdfVector): string =>
	`openssl kdf -keylen ${vector.length} -kdfopt digest:SHA256 -kdfopt hexpass:${bmpStringWithNull(vector.password)} -kdfopt hexsalt:${vector.saltHex} -kdfopt iter:${vector.iterations} -kdfopt id:${vector.id} PKCS12KDF`;

interface KdfVector {
	readonly label: string;
	readonly password: string;
	readonly saltHex: string;
	readonly iterations: number;
	readonly id: 1 | 2 | 3;
	readonly length: number;
	readonly expectedHex: string;
}

const SALT_8 = '0001020304050607';
const SALT_70 =
	'030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6';

const VECTORS: readonly KdfVector[] = [
	{
		label: 'r=1',
		password: 'pw',
		saltHex: SALT_8,
		iterations: 1,
		id: 3,
		length: 32,
		expectedHex: '7e45d73b6c20a8eb4230c23cd562735ee815d44c4f1ffd1898c3a723ebdd5aa4',
	},
	{
		label: 'r=2',
		password: 'pw',
		saltHex: SALT_8,
		iterations: 2,
		id: 3,
		length: 32,
		expectedHex: 'add3847667d1efa249f2f6c47a61663d2e260254fa8fb96e4efb267b06ef861a',
	},
	{
		label: 'r=1000',
		password: 'pw',
		saltHex: SALT_8,
		iterations: 1000,
		id: 3,
		length: 32,
		expectedHex: '0e94dd69a426ddf0db6ff56fa481dd58e6570f0fe9ab7a41695b837170027bda',
	},
	{
		label: 'n=100 spans four SHA-256 blocks',
		password: 'pw',
		saltHex: SALT_8,
		iterations: 3,
		id: 1,
		length: 100,
		expectedHex:
			'5ff0a2e9fd0ae15695526248b67fc7b55c2b2e0ece9c5446b909d451acb18aed98596e848e76895d408220fc754636aadfd8d906ed7a816f21bedf9100e92d7bb6d6aa12f46946b56abb8fc910acf472dfe4d27d7734a1897e3f664bf271297113553fb7',
	},
	{
		label: 'an 84-byte password and a 70-byte salt each span two 64-byte blocks',
		password: 'correct horse battery staple, forty chars',
		saltHex: SALT_70,
		iterations: 2,
		id: 2,
		length: 64,
		expectedHex:
			'446a7855b213771e4fcf544d4bb3d2b56a9c20fed55224ea11bdb1d15b2096982bbb095b8dc32f08537a42582397a416bef747e254f2909465c5b2d9c222a0a6',
	},
	{
		label: 'non-ASCII BMP characters',
		password: 'pässwörd€',
		saltHex: SALT_8,
		iterations: 1,
		id: 3,
		length: 32,
		expectedHex: '7ac307e25a5af782d66d12968f8065254ddaffd9338350dc1532e06fb83a2422',
	},
];

const NON_BMP_PASSWORDS = [
	{ label: 'a surrogate pair (U+1F600)', password: 'pw\u{1F600}' },
	{ label: 'a lone high surrogate', password: 'pw\ud800' },
	{ label: 'a lone low surrogate', password: '\udfffpw' },
] as const;

function rejection(promise: Promise<unknown>): Promise<unknown> {
	return promise.then(
		() => undefined,
		(error: unknown) => error,
	);
}

function expectPasswordNotBmpString(error: unknown): void {
	expect(isResultError(error)).toBe(true);
	expect(isResultError(error) ? error.code : undefined).toBe('password_not_bmp_string');
}

const macDataWithIterations = (iterationsElement?: Uint8Array): Uint8Array =>
	sequence([
		sequence([
			sequence([objectIdentifier(OIDS.sha256), nullValue()]),
			octetString(new Uint8Array(32)),
		]),
		octetString(fromHex(SALT_8)),
		...(iterationsElement === undefined ? [] : [iterationsElement]),
	]);

async function parseCode(der: Uint8Array, password?: string): Promise<string> {
	const result = await parsePkcs12MacData(der, Uint8Array.of(1, 2, 3), password);
	return result.ok ? result.value.verification : result.code;
}

describe('RFC 7292', () => {
	describe('§4 (L589-590): "iterations INTEGER DEFAULT 1"', () => {
		it('prints the MacData iterations field this suite checks', () => {
			expect(printed(589, 590)).toContain('iterations INTEGER DEFAULT 1');
		});

		it('accepts an explicitly encoded iterations 1, which is valid BER', async () => {
			const authenticatedSafe = Uint8Array.of(1, 2, 3);
			const { der } = await createPkcs12MacData(authenticatedSafe, {
				password: 'pw',
				iterations: 1,
				salt: fromHex(SALT_8),
			});
			const [digestInfo, salt] = readSequenceChildren(der);
			expect(digestInfo === undefined || salt === undefined).toBe(false);
			const explicit = sequence([
				der.slice((digestInfo?.start ?? 0) - (digestInfo?.headerLength ?? 0), digestInfo?.end ?? 0),
				der.slice((salt?.start ?? 0) - (salt?.headerLength ?? 0), salt?.end ?? 0),
				integerFromNumber(1),
			]);
			const parsed = await parsePkcs12MacData(explicit, authenticatedSafe, 'pw');
			expect(
				parsed.ok ? [parsed.value.iterations, parsed.value.verification] : parsed.code,
			).toEqual([1, 'valid']);
		});

		it('omits iterations when it equals the DEFAULT 1 and parses the omission back as 1', async () => {
			const authenticatedSafe = Uint8Array.of(1, 2, 3);
			const { der } = await createPkcs12MacData(authenticatedSafe, {
				password: 'pw',
				iterations: 1,
			});
			expect(readSequenceChildren(der)).toHaveLength(2);
			const parsed = await parsePkcs12MacData(der, authenticatedSafe, 'pw');
			expect(
				parsed.ok ? [parsed.value.iterations, parsed.value.verification] : parsed.code,
			).toEqual([1, 'valid']);
		});

		it('rejects an iterations element that is an OCTET STRING (0x04)', async () => {
			expect(await parseCode(macDataWithIterations(Uint8Array.of(0x04, 0x02, 0x08, 0x00)))).toBe(
				'malformed',
			);
		});

		it('rejects an iterations element that is a constructed OCTET STRING (0x22)', async () => {
			expect(
				await parseCode(macDataWithIterations(Uint8Array.of(0x22, 0x03, 0x02, 0x01, 0x05))),
			).toBe('malformed');
		});

		it('rejects a non-minimal INTEGER encoding of iterations', async () => {
			expect(await parseCode(macDataWithIterations(Uint8Array.of(0x02, 0x02, 0x00, 0x01)))).toBe(
				'malformed',
			);
		});

		describe('RFC 7292 gives no range for iterations; rejecting counts below 1 is micro509 policy', () => {
			it('micro509 policy: parsePkcs12MacData rejects iterations 0 as malformed', async () => {
				expect(await parseCode(macDataWithIterations(integerFromNumber(0)))).toBe('malformed');
				expect(await parseCode(macDataWithIterations(integerFromNumber(0)), 'pw')).toBe(
					'malformed',
				);
			});

			it('micro509 policy: parsePkcs12MacData rejects negative iterations as malformed', async () => {
				expect(await parseCode(macDataWithIterations(Uint8Array.of(0x02, 0x01, 0xff)))).toBe(
					'malformed',
				);
			});

			for (const iterations of [0, -1, 1.5, Number.NaN]) {
				it(`micro509 policy: createPkcs12MacData throws invalid_iterations for ${iterations}`, async () => {
					const error = await rejection(
						createPkcs12MacData(Uint8Array.of(1, 2, 3), { password: 'pw', iterations }),
					);
					expect(isResultError(error) ? error.code : error).toBe('invalid_iterations');
				});
			}
		});

		describe('iteration counts and the KDF budget', () => {
			const maxSafe = Uint8Array.of(0x02, 0x07, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
			const twoTo53 = Uint8Array.of(0x02, 0x07, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

			it('without a password, parses any positive safe-integer count as unchecked and ignores maxKdfIterations', async () => {
				const result = await parsePkcs12MacData(
					macDataWithIterations(maxSafe),
					Uint8Array.of(1, 2, 3),
					undefined,
					{ maxKdfIterations: 1 },
				);
				expect(
					result.ok ? [result.value.iterations, result.value.verification] : result.code,
				).toEqual([Number.MAX_SAFE_INTEGER, 'unchecked']);
			});

			it('with a password, reports a count of 2^53 as kdf_iterations_exceeded', async () => {
				expect(await parseCode(macDataWithIterations(twoTo53), 'pw')).toBe(
					'kdf_iterations_exceeded',
				);
			});

			it('without a password, reports a count of 2^53 as malformed', async () => {
				expect(await parseCode(macDataWithIterations(twoTo53))).toBe('malformed');
			});
		});
	});

	describe('Appendix B.2 step 6A as corrected by erratum 4356 (Verified): "A. Set A_i=H^r(D||I). (i.e., the r-th hash of D||I, H(H(H(... H(D||I))))", one hash per round', () => {
		it('prints the original step 6A (L1158-1161) that erratum 4356 corrects', () => {
			expect(printed(1158, 1158)).toContain('6. For i=1, 2, ..., c, do the following:');
			expect(printed(1160, 1161)).toContain(
				'A. Set A2=H^r(D||I). (i.e., the r-th hash of D||1, H(H(H(... H(D||I))))',
			);
		});

		for (const vector of VECTORS) {
			it(`matches OpenSSL PKCS12KDF, ${vector.label}: ${opensslCommand(vector)}`, async () => {
				const key = await derivePkcs12Key(
					vector.password,
					fromHex(vector.saltHex),
					vector.iterations,
					vector.id,
					vector.length,
				);
				expect(toHex(key)).toBe(vector.expectedHex);
			});
		}
	});

	describe('Appendix B.1 (L1081-1086): "each character in the original BMPString is encoded in 2 bytes in big-endian format"', () => {
		it('prints the password encoding this suite checks', () => {
			expect(printed(1081, 1086)).toContain('BMPStrings with a NULL terminator');
			expect(printed(1081, 1086)).toContain(
				'each character in the original BMPString is encoded in 2 bytes in big-endian format',
			);
		});

		describe('X.680 41.15 excludes the surrogate cells from BMPString; micro509 rejects such passwords', () => {
			for (const { label, password } of NON_BMP_PASSWORDS) {
				it(`derivePkcs12Key throws password_not_bmp_string for ${label}`, async () => {
					expectPasswordNotBmpString(
						await rejection(derivePkcs12Key(password, fromHex(SALT_8), 1, 3, 32)),
					);
				});

				it(`createPkcs12MacData throws password_not_bmp_string for ${label}`, async () => {
					expectPasswordNotBmpString(
						await rejection(
							createPkcs12MacData(Uint8Array.of(1, 2, 3), { password, iterations: 1 }),
						),
					);
				});

				it(`parsePkcs12MacData returns password_not_bmp_string for ${label}`, async () => {
					const authenticatedSafe = Uint8Array.of(1, 2, 3);
					const { der } = await createPkcs12MacData(authenticatedSafe, {
						password: 'pw',
						iterations: 1,
					});
					const result = await parsePkcs12MacData(der, authenticatedSafe, password);
					expect(result.ok).toBe(false);
					if (!result.ok) {
						expect(result.code).toBe('password_not_bmp_string');
					}
					expectPasswordNotBmpString(
						await rejection(parsePkcs12MacDataOrThrow(der, authenticatedSafe, password)),
					);
				});
			}

			it('verifies a MAC made with a BMP password that is not ASCII', async () => {
				const authenticatedSafe = Uint8Array.of(1, 2, 3);
				const password = 'pässwörd€';
				const { der } = await createPkcs12MacData(authenticatedSafe, { password, iterations: 2 });
				const result = await parsePkcs12MacData(der, authenticatedSafe, password);
				expect(result.ok ? result.value.verification : result.code).toBe('valid');
			});
		});
	});

	describe('§4 (L546-547): "ASN.1 and BER-encoding ensure platform independence."', () => {
		it('prints the encoding rule this suite checks', () => {
			expect(printed(546, 547).replace('BER- ', 'BER-')).toContain(
				'ASN.1 and BER-encoding ensure platform independence.',
			);
			expect(printed(1037, 1037)).toContain('BER-encoding of the contents');
		});

		it('parses a PFX with indefinite lengths, non-minimal lengths and constructed OCTET STRINGs', async () => {
			const fixture = await berPfxFixture();
			expect(summary(await parsePfxDer(fixture.pfx, { password: 'pw' }))).toEqual({
				certificates: [toHex(fixture.certificateDer)],
				privateKeys: [toHex(fixture.pkcs8Der)],
				friendlyName: 'ber-leaf',
				mac: 'valid',
			});
		});

		it('Appendix A (L1037): verifies the MAC over the BER AuthenticatedSafe octets as received', async () => {
			const { pfx } = await berPfxFixture();
			const valid = await parsePfxDer(pfx, { password: 'pw' });
			expect(valid.ok ? valid.value.macData?.verification : valid.code).toBe('valid');
			expect(await pfxCode(pfx, 'wrong')).toBe('invalid_password');
		});

		it('rejects a PFX whose outer end-of-contents octets are missing', async () => {
			const { pfx } = await berPfxFixture();
			expect(await pfxCode(pfx.subarray(0, pfx.length - 2))).toBe('malformed');
		});

		it('rejects end-of-contents octets whose length octet is not zero', async () => {
			const { pfx } = await berPfxFixture();
			const altered = pfx.slice();
			altered[altered.length - 1] = 0x01;
			expect(await pfxCode(altered)).toBe('malformed');
		});

		it('rejects a truncated BER PFX', async () => {
			const { pfx } = await berPfxFixture();
			for (const length of [3, pfx.length >> 1, pfx.length - 3]) {
				expect(await pfxCode(pfx.subarray(0, length))).toBe('malformed');
			}
		});

		it('rejects a primitive OCTET STRING with an indefinite length', async () => {
			const { certificate } = await createSelfSignedCertificate({
				subject: { commonName: 'ber-pfx.example' },
			});
			const primitiveIndefinite = indefinite(0x04, [certificate.der]);
			expect(
				await pfxCode(await berPfxAround(certBagSafeContents(segmented(0x24, certificate.der, 2)))),
			).toBe('ok');
			expect(await pfxCode(await berPfxAround(certBagSafeContents(primitiveIndefinite)))).toBe(
				'malformed',
			);
		});

		it('rejects an element whose length overruns its definite-length parent', async () => {
			const bag = (bagValue: Uint8Array): Uint8Array =>
				indefinite(0x30, [objectIdentifier(OIDS.pkcs7Data), bagValue, tlv(0x31, new Uint8Array())]);
			const contained = Uint8Array.of(0xa0, 0x04, 0x04, 0x02, 0x31, 0x00);
			const overrun = Uint8Array.of(0xa0, 0x02, 0x04, 0x02);
			expect(await pfxCode(await berPfxAround(indefinite(0x30, [bag(contained)])))).toBe('ok');
			expect(await pfxCode(await berPfxAround(indefinite(0x30, [bag(overrun)])))).toBe('malformed');
		});

		it('re-encodes an unknown bag value with definite lengths, joining constructed BIT STRING segments', async () => {
			const unknownBag = (value: Uint8Array): Uint8Array =>
				indefinite(0x30, [
					indefinite(0x30, [objectIdentifier(OIDS.pkcs7Data), indefinite(0xa0, [value])]),
				]);
			const segments = (first: number): Uint8Array =>
				indefinite(0x23, [
					tlv(0x03, Uint8Array.of(first, 0xaa)),
					indefinite(0x23, [tlv(0x03, Uint8Array.of(0x04, 0xb0))]),
				]);
			const result = await parsePfxDer(await berPfxAround(unknownBag(segments(0))), {
				password: 'pw',
			});
			const bag = result.ok ? result.value.bags[0] : undefined;
			expect(bag?.kind === 'unknown' ? toHex(bag.valueDer) : bag).toBe('030304aab0');
			expect(await pfxCode(await berPfxAround(unknownBag(segments(1))))).toBe('malformed');
		});

		it('micro509 policy: bounds BER nesting depth inside SafeContents', async () => {
			let nested = nullValue();
			for (let depth = 0; depth < 100; depth += 1) {
				nested = indefinite(0x30, [nested]);
			}
			const bag = indefinite(0x30, [objectIdentifier(OIDS.pkcs7Data), indefinite(0xa0, [nested])]);
			expect(await pfxCode(await berPfxAround(indefinite(0x30, [bag])))).toBe('malformed');
		});

		it('keeps the keyBag PrivateKeyInfo DER: an indefinite-length PrivateKeyInfo is malformed', async () => {
			const keyPair = await generateKeyPair();
			const pkcs8 = readElement(await exportPkcs8Der(keyPair.privateKey));
			const bag = indefinite(0x30, [
				objectIdentifier(OIDS.pkcs12KeyBag),
				indefinite(0xa0, [indefinite(0x30, [pkcs8.value])]),
			]);
			expect(await pfxCode(await berPfxAround(indefinite(0x30, [bag])))).toBe('malformed');
		});
	});
});

function indefinite(tag: number, parts: readonly Uint8Array[]): Uint8Array {
	return concatBytes([Uint8Array.of(tag, 0x80), ...parts, Uint8Array.of(0, 0)]);
}

function nonMinimal(tag: number, content: Uint8Array): Uint8Array {
	const length = content.length;
	return concatBytes([
		Uint8Array.of(
			tag,
			0x84,
			length >>> 24,
			(length >>> 16) & 0xff,
			(length >>> 8) & 0xff,
			length & 0xff,
		),
		content,
	]);
}

function segmented(tag: number, content: Uint8Array, pieces: number): Uint8Array {
	const size = Math.ceil(content.length / pieces);
	const segments: Uint8Array[] = [];
	for (let offset = 0; offset < content.length; offset += size) {
		segments.push(octetString(content.subarray(offset, offset + size)));
	}
	return indefinite(tag, segments);
}

function bmp(value: string): Uint8Array {
	return tlv(
		0x1e,
		Uint8Array.from(
			Array.from(value).flatMap((character) => {
				const code = character.charCodeAt(0);
				return [code >> 8, code & 0xff];
			}),
		),
	);
}

function certBagSafeContents(certValue: Uint8Array): Uint8Array {
	return indefinite(0x30, [
		indefinite(0x30, [
			objectIdentifier(OIDS.pkcs12CertBag),
			indefinite(0xa0, [
				indefinite(0x30, [
					objectIdentifier(OIDS.x509CertificateBagType),
					indefinite(0xa0, [certValue]),
				]),
			]),
		]),
	]);
}

async function berPfxAround(safeContents: Uint8Array): Promise<Uint8Array> {
	return await assemblePfx(
		indefinite(0x30, [
			indefinite(0x30, [
				objectIdentifier(OIDS.pkcs7Data),
				indefinite(0xa0, [segmented(0x24, safeContents, 2)]),
			]),
		]),
	);
}

async function assemblePfx(authenticatedSafe: Uint8Array): Promise<Uint8Array> {
	const macData = await createPkcs12MacData(authenticatedSafe, { password: 'pw', iterations: 1 });
	return indefinite(0x30, [
		integerFromNumber(3),
		indefinite(0x30, [
			objectIdentifier(OIDS.pkcs7Data),
			indefinite(0xa0, [segmented(0x24, authenticatedSafe, 3)]),
		]),
		nonMinimal(0x30, readElement(macData.der).value),
	]);
}

async function berPfxFixture(): Promise<{
	readonly pfx: Uint8Array;
	readonly certificateDer: Uint8Array;
	readonly pkcs8Der: Uint8Array;
}> {
	const keyPair = await generateKeyPair();
	const { certificate } = await createSelfSignedCertificate({
		subject: { commonName: 'ber-pfx.example' },
		keyPair,
	});
	const pkcs8Der = await exportPkcs8Der(keyPair.privateKey);
	const certBag = indefinite(0x30, [
		objectIdentifier(OIDS.pkcs12CertBag),
		indefinite(0xa0, [
			indefinite(0x30, [
				objectIdentifier(OIDS.x509CertificateBagType),
				indefinite(0xa0, [segmented(0x24, certificate.der, 3)]),
			]),
		]),
		indefinite(0x31, [
			indefinite(0x30, [
				objectIdentifier(OIDS.friendlyName),
				indefinite(0x31, [indefinite(0x3e, [bmp('ber'), bmp('-leaf')])]),
			]),
		]),
	]);
	const keyBag = nonMinimal(
		0x30,
		concatBytes([objectIdentifier(OIDS.pkcs12KeyBag), nonMinimal(0xa0, pkcs8Der)]),
	);
	const encryption = await encryptPbes2(indefinite(0x30, [keyBag]), {
		password: 'pw',
		iterations: 1,
	});
	const encryptedData = indefinite(0x30, [
		integerFromNumber(0),
		indefinite(0x30, [
			objectIdentifier(OIDS.pkcs7Data),
			nonMinimal(0x30, readElement(encryption.algorithmIdentifierDer).value),
			segmented(0xa0, encryption.encryptedData, 2),
		]),
	]);
	const authenticatedSafe = indefinite(0x30, [
		indefinite(0x30, [
			objectIdentifier(OIDS.pkcs7Data),
			indefinite(0xa0, [segmented(0x24, indefinite(0x30, [certBag]), 2)]),
		]),
		indefinite(0x30, [
			objectIdentifier(OIDS.pkcs7EncryptedData),
			indefinite(0xa0, [encryptedData]),
		]),
	]);
	return { pfx: await assemblePfx(authenticatedSafe), certificateDer: certificate.der, pkcs8Der };
}

function summary(result: ParsePfxResult): unknown {
	if (!result.ok) {
		return result.code;
	}
	return {
		certificates: result.value.certificates.map((certificate) => toHex(certificate.der)),
		privateKeys: result.value.privateKeys.map((key) => toHex(key)),
		friendlyName: result.value.bags[0]?.attributes.friendlyName,
		mac: result.value.macData?.verification,
	};
}

async function pfxCode(pfx: Uint8Array, password = 'pw'): Promise<string> {
	const result = await parsePfxDer(pfx, { password });
	return result.ok ? 'ok' : result.code;
}
