import { describe, expect, it } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { concatBytes } from '#micro509/internal/asn1/der';
import { base64Decode, base64Encode } from '#micro509/internal/shared/base64';
import type { KeyAlgorithmInput } from '#micro509/keys';
import {
	exportPkcs8Pem,
	exportPrivateJwk,
	exportPublicJwk,
	exportSpkiPem,
	generateKeyPair,
	importPkcs8PemOrThrow,
	importSpkiPemOrThrow,
} from '#micro509/keys';
import { pemDecodeOrThrow, pemEncode } from '#micro509/pem';
import { isResultError } from '#micro509/result';
import type { SshErrorCode, SshResult } from '#micro509/ssh';
import {
	exportOpenSshPrivateKey,
	exportSshPublicKey,
	importOpenSshPrivateKey,
	importOpenSshPrivateKeyOrThrow,
	importSshPublicKey,
	importSshPublicKeyOrThrow,
	sshFingerprintSha256,
} from '#micro509/ssh';
import { bigintToBytes, createSshReader, sshMpint } from '#micro509/ssh/wire';

const KEYGEN = Bun.which('ssh-keygen');
const keygenAvailable = KEYGEN !== null;

interface KeygenKind {
	readonly name: string;
	readonly algorithm: KeyAlgorithmInput;
	readonly args: readonly string[];
}

const KEYGEN_KINDS: readonly KeygenKind[] = [
	{
		name: 'rsa-2048',
		algorithm: { kind: 'rsa', modulusLength: 2048 },
		args: ['-t', 'rsa', '-b', '2048'],
	},
	{
		name: 'rsa-4096',
		algorithm: { kind: 'rsa', modulusLength: 4096 },
		args: ['-t', 'rsa', '-b', '4096'],
	},
	{ name: 'ed25519', algorithm: { kind: 'ed25519' }, args: ['-t', 'ed25519'] },
	{
		name: 'ecdsa-p256',
		algorithm: { kind: 'ecdsa', curve: 'P-256' },
		args: ['-t', 'ecdsa', '-b', '256'],
	},
	{
		name: 'ecdsa-p384',
		algorithm: { kind: 'ecdsa', curve: 'P-384' },
		args: ['-t', 'ecdsa', '-b', '384'],
	},
	{
		name: 'ecdsa-p521',
		algorithm: { kind: 'ecdsa', curve: 'P-521' },
		args: ['-t', 'ecdsa', '-b', '521'],
	},
];

function keygen(args: readonly string[]): string {
	if (KEYGEN === null) {
		throw new Error('ssh-keygen is not installed');
	}
	const run = Bun.spawnSync([KEYGEN, ...args], { stdout: 'pipe', stderr: 'pipe' });
	if (run.exitCode !== 0) {
		throw new Error(`ssh-keygen ${args[0] ?? ''} exited ${run.exitCode}: ${run.stderr.toString()}`);
	}
	return run.stdout.toString();
}

function withTempDir<T>(run: (dir: string) => T | Promise<T>): Promise<T> {
	const dir = mkdtempSync(join(tmpdir(), 'micro509-ssh-'));
	return Promise.resolve(run(dir)).finally(() => rmSync(dir, { recursive: true, force: true }));
}

function generateWithKeygen(
	dir: string,
	kind: KeygenKind,
	extra: readonly string[] = ['-N', ''],
): { readonly privatePath: string; readonly publicPath: string } {
	const privatePath = join(dir, `id_${kind.name}`);
	keygen([...kind.args, ...extra, '-C', 'fixture@host', '-q', '-f', privatePath]);
	return { privatePath, publicPath: `${privatePath}.pub` };
}

function listingField(output: string, index: number): string {
	const field = output.trim().split(/\s+/)[index];
	if (field === undefined) {
		throw new Error(`ssh-keygen -l output lacks field ${index}`);
	}
	return field;
}

function ok<T>(result: SshResult<T>): T {
	if (!result.ok) {
		throw new Error(`expected success, got ${result.code}: ${result.message}`);
	}
	return result.value;
}

function codeOf<T>(result: SshResult<T>): SshErrorCode | 'ok' {
	return result.ok ? 'ok' : result.code;
}

const u32 = (value: number): Uint8Array => {
	const bytes = new Uint8Array(4);
	new DataView(bytes.buffer).setUint32(0, value, false);
	return bytes;
};
const text = (value: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(value);
const str = (bytes: Uint8Array): Uint8Array => concatBytes([u32(bytes.length), bytes]);
const strText = (value: string): Uint8Array => str(text(value));

function mpintOf(
	magnitude: Uint8Array,
	mode: 'canonical' | 'redundantZero' | 'negative',
): Uint8Array {
	const start = magnitude.findIndex((byte) => byte !== 0);
	const significant = start === -1 ? new Uint8Array() : magnitude.subarray(start);
	const top = significant[0] ?? 0;
	if (mode === 'negative') {
		return str(
			significant.length === 0
				? Uint8Array.of(0x80)
				: significant.map((b, i) => (i === 0 ? b | 0x80 : b)),
		);
	}
	const canonical = top >= 0x80 ? concatBytes([Uint8Array.of(0), significant]) : significant;
	return str(mode === 'redundantZero' ? concatBytes([Uint8Array.of(0), canonical]) : canonical);
}

const b64u = (value: string | undefined): Uint8Array => {
	if (value === undefined) {
		throw new Error('missing JWK member');
	}
	const padded = value.replace(/-/g, '+').replace(/_/g, '/');
	return base64Decode(padded.padEnd(Math.ceil(padded.length / 4) * 4, '='));
};

interface KeyFields {
	readonly typeName: string;
	readonly publicBlob: Uint8Array;
	readonly privateFields: Uint8Array;
}

type FieldMutation = {
	readonly point?: 'compressed';
	readonly mpint?: 'canonical' | 'redundantZero' | 'negative';
	readonly curveIdentifier?: string;
};

async function fieldsFor(
	kind: 'rsa' | 'ed25519' | 'p256' | 'p384' | 'p521',
	mutation: FieldMutation = {},
): Promise<KeyFields> {
	const algorithm =
		kind === 'rsa'
			? ({ kind: 'rsa', modulusLength: 2048 } as const)
			: kind === 'ed25519'
				? ({ kind: 'ed25519' } as const)
				: ({
						kind: 'ecdsa',
						curve: kind === 'p256' ? 'P-256' : kind === 'p384' ? 'P-384' : 'P-521',
					} as const);
	const pair = await generateKeyPair(algorithm);
	const jwk = await exportPrivateJwk(pair.privateKey);
	const mode = mutation.mpint ?? 'canonical';
	if (kind === 'rsa') {
		const n = b64u(jwk.n);
		const e = b64u(jwk.e);
		return {
			typeName: 'ssh-rsa',
			publicBlob: concatBytes([strText('ssh-rsa'), mpintOf(e, 'canonical'), mpintOf(n, mode)]),
			privateFields: concatBytes([
				mpintOf(n, mode),
				mpintOf(e, 'canonical'),
				mpintOf(b64u(jwk.d), 'canonical'),
				mpintOf(b64u(jwk.qi), 'canonical'),
				mpintOf(b64u(jwk.p), 'canonical'),
				mpintOf(b64u(jwk.q), 'canonical'),
			]),
		};
	}
	if (kind === 'ed25519') {
		const x = b64u(jwk.x);
		return {
			typeName: 'ssh-ed25519',
			publicBlob: concatBytes([strText('ssh-ed25519'), str(x)]),
			privateFields: concatBytes([str(x), str(concatBytes([b64u(jwk.d), x]))]),
		};
	}
	const typeName = `ecdsa-sha2-nistp${kind.slice(1)}`;
	const identifier = mutation.curveIdentifier ?? `nistp${kind.slice(1)}`;
	const x = b64u(jwk.x);
	const y = b64u(jwk.y);
	const point =
		mutation.point === 'compressed'
			? concatBytes([Uint8Array.of((y[y.length - 1] ?? 0) % 2 === 0 ? 2 : 3), x])
			: concatBytes([Uint8Array.of(4), x, y]);
	return {
		typeName,
		publicBlob: concatBytes([strText(typeName), strText(identifier), str(point)]),
		privateFields: concatBytes([strText(identifier), str(point), mpintOf(b64u(jwk.d), mode)]),
	};
}

interface FileParts {
	readonly magic?: Uint8Array;
	readonly cipher?: string;
	readonly kdf?: string;
	readonly kdfOptions?: Uint8Array;
	readonly count?: number;
	readonly publicBlob: Uint8Array;
	readonly checkA?: number;
	readonly checkB?: number;
	readonly typeName?: string;
	readonly privateFields: Uint8Array;
	readonly comment?: string;
	readonly padding?: (needed: number) => Uint8Array;
	readonly trailing?: Uint8Array;
	readonly sectionOverride?: Uint8Array;
}

function buildFile(parts: FileParts): string {
	const typeName = parts.typeName ?? '';
	const unpadded = concatBytes([
		u32(parts.checkA ?? 0x01020304),
		u32(parts.checkB ?? parts.checkA ?? 0x01020304),
		strText(typeName),
		parts.privateFields,
		strText(parts.comment ?? 'c'),
	]);
	const padLength = (8 - (unpadded.length % 8)) % 8;
	const padding =
		parts.padding?.(padLength) ?? Uint8Array.from({ length: padLength }, (_, i) => i + 1);
	const section = parts.sectionOverride ?? concatBytes([unpadded, padding]);
	const file = concatBytes([
		parts.magic ?? concatBytes([text('openssh-key-v1'), Uint8Array.of(0)]),
		strText(parts.cipher ?? 'none'),
		strText(parts.kdf ?? 'none'),
		str(parts.kdfOptions ?? new Uint8Array()),
		u32(parts.count ?? 1),
		str(parts.publicBlob),
		str(section),
		parts.trailing ?? new Uint8Array(),
	]);
	return pemEncode('OPENSSH PRIVATE KEY', file);
}

async function validFile(
	kind: 'rsa' | 'ed25519' | 'p256' | 'p384' | 'p521',
	overrides: Partial<FileParts> = {},
	mutation: FieldMutation = {},
): Promise<string> {
	const fields = await fieldsFor(kind, mutation);
	return buildFile({
		publicBlob: fields.publicBlob,
		typeName: fields.typeName,
		privateFields: fields.privateFields,
		...overrides,
	});
}

describe('OpenSSH key files against ssh-keygen', () => {
	for (const kind of KEYGEN_KINDS) {
		it.skipIf(!keygenAvailable)(`reads a ${kind.name} key written by ssh-keygen`, async () => {
			await withTempDir(async (dir) => {
				const { privatePath, publicPath } = generateWithKeygen(dir, kind);
				const publicLine = readFileSync(publicPath, 'utf8');
				const imported = ok(await importOpenSshPrivateKey(readFileSync(privatePath, 'utf8')));
				expect(imported.comment).toBe('fixture@host');

				const derived = keygen(['-y', '-f', privatePath]).trim();
				expect(await exportSshPublicKey(imported.publicKey, { comment: imported.comment })).toBe(
					derived,
				);
				expect(derived).toBe(publicLine.trim());

				const listing = keygen(['-l', '-E', 'sha256', '-f', publicPath]);
				expect(imported.fingerprint).toBe(listingField(listing, 1));
				expect(await sshFingerprintSha256(imported.publicKey)).toBe(listingField(listing, 1));
				expect(await sshFingerprintSha256(imported.privateKey)).toBe(listingField(listing, 1));

				const fromLine = ok(await importSshPublicKey(publicLine));
				expect(fromLine.keyType).toBe(imported.keyType);
				expect(fromLine.comment).toBe('fixture@host');
				expect(fromLine.fingerprint).toBe(listingField(listing, 1));
				expect(await exportPublicJwk(fromLine.publicKey)).toEqual(
					await exportPublicJwk(imported.publicKey),
				);
			});
		});

		it.skipIf(!keygenAvailable)(
			`ssh-keygen reads a ${kind.name} key exported by micro509`,
			async () => {
				const pair = await generateKeyPair(kind.algorithm);
				const pem = await exportOpenSshPrivateKey(pair.privateKey, { comment: 'made@micro509' });
				const line = await exportSshPublicKey(pair.publicKey, { comment: 'made@micro509' });
				await withTempDir(async (dir) => {
					const path = join(dir, 'id');
					writeFileSync(path, pem, { mode: 0o600 });
					writeFileSync(`${path}.pub`, `${line}\n`);

					expect(keygen(['-y', '-f', path]).trim()).toBe(line);
					const listing = keygen(['-l', '-E', 'sha256', '-f', path]);
					expect(listingField(listing, 1)).toBe(await sshFingerprintSha256(pair.publicKey));
					expect(listingField(listing, 2)).toBe('made@micro509');
					const pubListing = keygen(['-l', '-E', 'sha256', '-f', `${path}.pub`]);
					expect(listingField(pubListing, 1)).toBe(listingField(listing, 1));

					const back = ok(await importOpenSshPrivateKey(pem));
					expect(await exportPrivateJwk(back.privateKey)).toEqual(
						await exportPrivateJwk(pair.privateKey),
					);
					expect(await exportPublicJwk(back.publicKey)).toEqual(
						await exportPublicJwk(pair.publicKey),
					);
					expect(back.comment).toBe('made@micro509');
				});
			},
		);
	}

	it.skipIf(!keygenAvailable)('reports encrypted ssh-keygen files as unsupported', async () => {
		await withTempDir(async (dir) => {
			const { privatePath } = generateWithKeygen(dir, KEYGEN_KINDS[2] as KeygenKind, [
				'-N',
				'correct horse',
			]);
			const result = await importOpenSshPrivateKey(readFileSync(privatePath, 'utf8'));
			expect(codeOf(result)).toBe('unsupported');
		});
	});

	it.skipIf(!keygenAvailable)('reads a 1024-bit ssh-keygen RSA key only when allowed', async () => {
		await withTempDir(async (dir) => {
			const { privatePath, publicPath } = generateWithKeygen(dir, {
				name: 'rsa-1024',
				algorithm: { kind: 'rsa', modulusLength: 2048 },
				args: ['-t', 'rsa', '-b', '1024'],
			});
			const pem = readFileSync(privatePath, 'utf8');
			const line = readFileSync(publicPath, 'utf8');
			expect(codeOf(await importOpenSshPrivateKey(pem))).toBe('unsupported');
			expect(codeOf(await importSshPublicKey(line))).toBe('unsupported');
			const imported = ok(await importOpenSshPrivateKey(pem, { minRsaModulusBits: 1024 }));
			expect(imported.algorithm).toEqual({ kind: 'rsa', modulusBits: 1024 });
			expect(codeOf(await importSshPublicKey(line, { minRsaModulusBits: 1024 }))).toBe('ok');
		});
	});
});

describe('conversion through the existing key APIs', () => {
	it('moves an imported key through PKCS#8, SPKI and JWK', async () => {
		const pair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-384' });
		const imported = ok(
			await importOpenSshPrivateKey(await exportOpenSshPrivateKey(pair.privateKey)),
		);
		const pkcs8 = await exportPkcs8Pem(imported.privateKey);
		expect(pkcs8).toBe(await pair.exportPkcs8Pem());
		const reimported = await importPkcs8PemOrThrow(pkcs8, { kind: 'ecdsa', curve: 'P-384' });
		expect(await exportOpenSshPrivateKey(reimported, { comment: 'x' })).toMatch(
			/^-----BEGIN OPENSSH PRIVATE KEY-----\n/,
		);
		const spki = await exportSpkiPem(imported.publicKey);
		const fromSpki = await importSpkiPemOrThrow(spki, { kind: 'ecdsa', curve: 'P-384' });
		expect(await exportSshPublicKey(fromSpki)).toBe(await exportSshPublicKey(imported.publicKey));
		expect(await exportPublicJwk(imported.publicKey)).toEqual(await pair.exportPublicJwk());
	});

	it('returns usable signing and verifying keys', async () => {
		const pair = await generateKeyPair({ kind: 'ed25519' });
		const imported = ok(
			await importOpenSshPrivateKey(await exportOpenSshPrivateKey(pair.privateKey)),
		);
		const message = text('payload');
		const signature = await crypto.subtle.sign('Ed25519', imported.privateKey, message);
		expect(await crypto.subtle.verify('Ed25519', pair.publicKey, signature, message)).toBe(true);
		expect(imported.privateKey.usages).toEqual(['sign']);
		expect(imported.publicKey.usages).toEqual(['verify']);
		expect(imported.privateKey.extractable).toBe(true);
	});

	it('applies the RSA scheme option to the WebCrypto key only', async () => {
		const pair = await generateKeyPair({ kind: 'rsa' });
		const pem = await exportOpenSshPrivateKey(pair.privateKey);
		const imported = ok(
			await importOpenSshPrivateKey(pem, { rsa: { scheme: 'pss', hash: 'SHA-384' } }),
		);
		expect(imported.privateKey.algorithm).toMatchObject({
			name: 'RSA-PSS',
			hash: { name: 'SHA-384' },
		});
		expect(imported.keyType).toBe('ssh-rsa');
		expect(imported.fingerprint).toBe(await sshFingerprintSha256(pair.publicKey));
	});

	it('fingerprints a raw public-key blob like the key itself', async () => {
		const pair = await generateKeyPair({ kind: 'ed25519' });
		const line = await exportSshPublicKey(pair.publicKey);
		const blob = base64Decode(line.split(' ')[1] ?? '');
		expect(await sshFingerprintSha256(blob)).toBe(await sshFingerprintSha256(pair.publicKey));
		expect(await sshFingerprintSha256(blob)).toMatch(/^SHA256:[A-Za-z0-9+/]{43}$/);
	});
});

describe('exports', () => {
	it('writes a public-key line without comment or line break', async () => {
		const pair = await generateKeyPair({ kind: 'ed25519' });
		const line = await exportSshPublicKey(pair.publicKey);
		expect(line).toMatch(/^ssh-ed25519 [A-Za-z0-9+/]{68}$/);
	});

	it('writes an OpenSSH PEM with the check integers random per export', async () => {
		const pair = await generateKeyPair({ kind: 'ed25519' });
		const first = await exportOpenSshPrivateKey(pair.privateKey);
		const second = await exportOpenSshPrivateKey(pair.privateKey);
		expect(first).toMatch(/^-----BEGIN OPENSSH PRIVATE KEY-----\n/);
		expect(first).toMatch(/\n-----END OPENSSH PRIVATE KEY-----\n$/);
		const body = pemDecodeOrThrow('OPENSSH PRIVATE KEY', first);
		expect(new TextDecoder().decode(body.subarray(0, 14))).toBe('openssh-key-v1');
		expect(await exportPrivateJwk(ok(await importOpenSshPrivateKey(second)).privateKey)).toEqual(
			await exportPrivateJwk(ok(await importOpenSshPrivateKey(first)).privateKey),
		);
	});

	it('rejects comments that would break the line', async () => {
		const pair = await generateKeyPair({ kind: 'ed25519' });
		for (const comment of ['a\nb', 'a\rb', 'a\0b']) {
			let thrown: unknown;
			try {
				await exportSshPublicKey(pair.publicKey, { comment });
			} catch (error) {
				thrown = error;
			}
			expect(isResultError(thrown) && thrown.code).toBe('invalid_comment');
		}
	});

	it('refuses wrong key types, non-extractable keys and unsupported algorithms', async () => {
		const pair = await generateKeyPair({ kind: 'ed25519' });
		const exportCode = async (run: () => Promise<unknown>): Promise<string> => {
			try {
				await run();
			} catch (error) {
				return isResultError(error) ? String(error.code) : 'unexpected';
			}
			return 'none';
		};
		expect(await exportCode(() => exportSshPublicKey(pair.privateKey))).toBe('invalid_key');
		expect(await exportCode(() => exportOpenSshPrivateKey(pair.publicKey))).toBe('invalid_key');
		const hidden = await crypto.subtle.importKey(
			'jwk',
			await exportPrivateJwk(pair.privateKey),
			{ name: 'Ed25519' },
			false,
			['sign'],
		);
		expect(await exportCode(() => exportOpenSshPrivateKey(hidden))).toBe('not_extractable');
		expect(await exportCode(() => sshFingerprintSha256(hidden))).toBe('not_extractable');
		const ecdh = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
			'deriveBits',
		]);
		expect(await exportCode(() => exportSshPublicKey(ecdh.publicKey))).toBe(
			'unsupported_algorithm',
		);
		const aes = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, true, [
			'encrypt',
		]);
		expect(await exportCode(() => sshFingerprintSha256(aes))).toBe('invalid_key');
	});
});

describe('public key lines', () => {
	it('splits fields on spaces and tabs and keeps the comment verbatim', async () => {
		const pair = await generateKeyPair({ kind: 'ed25519' });
		const [type, encoded] = (await exportSshPublicKey(pair.publicKey)).split(' ');
		const imported = ok(await importSshPublicKey(`${type}\t${encoded} \t my comment  here\r\n`));
		expect(imported.comment).toBe('my comment  here');
		expect(ok(await importSshPublicKey(`${type} ${encoded}`)).comment).toBe('');
		expect(ok(await importSshPublicKey(text(`${type} ${encoded}\n`))).keyType).toBe('ssh-ed25519');
	});

	it('rejects malformed lines', async () => {
		const pair = await generateKeyPair({ kind: 'ed25519' });
		const line = await exportSshPublicKey(pair.publicKey);
		const [type, encoded = ''] = line.split(' ');
		const blob = base64Decode(encoded);
		const cases: readonly (readonly [string, string | Uint8Array])[] = [
			['empty', ''],
			['type only', 'ssh-ed25519'],
			['two lines', `${line}\n${line}`],
			['unpadded base64', `${type} ${encoded.replace(/=+$/, '').slice(0, -1)}`],
			['bad base64 alphabet', `${type} ${encoded.slice(0, -2)}!!`],
			['truncated blob', `${type} ${base64Encode(blob.subarray(0, blob.length - 1))}`],
			['trailing blob data', `${type} ${base64Encode(concatBytes([blob, Uint8Array.of(0)]))}`],
			[
				'short ed25519 key',
				`${type} ${base64Encode(concatBytes([strText('ssh-ed25519'), str(blob.subarray(0, 8))]))}`,
			],
			['invalid utf-8', Uint8Array.of(0xff, 0xfe)],
			['options prefix', `no-pty ${line}`],
		];
		for (const [name, input] of cases) {
			expect([name, codeOf(await importSshPublicKey(input))]).toEqual([name, 'malformed']);
		}
	});

	it('flags a line type that disagrees with its blob', async () => {
		const pair = await generateKeyPair({ kind: 'ed25519' });
		const encoded = (await exportSshPublicKey(pair.publicKey)).split(' ')[1] ?? '';
		expect(codeOf(await importSshPublicKey(`ssh-rsa ${encoded}`))).toBe('key_mismatch');
		const rsa = await generateKeyPair({ kind: 'rsa' });
		const rsaEncoded = (await exportSshPublicKey(rsa.publicKey)).split(' ')[1] ?? '';
		expect(codeOf(await importSshPublicKey(`ssh-ed25519 ${rsaEncoded}`))).toBe('key_mismatch');
	});

	it('refuses key types it does not read', async () => {
		const pair = await generateKeyPair({ kind: 'ed25519' });
		const encoded = (await exportSshPublicKey(pair.publicKey)).split(' ')[1] ?? '';
		for (const type of [
			'ssh-dss',
			'sk-ssh-ed25519@openssh.com',
			'ssh-ed25519-cert-v01@openssh.com',
		]) {
			expect([type, codeOf(await importSshPublicKey(`${type} ${encoded}`))]).toEqual([
				type,
				'unsupported',
			]);
		}
		const blob = concatBytes([
			strText('ecdsa-sha2-nistp192'),
			strText('nistp192'),
			str(new Uint8Array(49)),
		]);
		expect(codeOf(await importSshPublicKey(`ecdsa-sha2-nistp192 ${base64Encode(blob)}`))).toBe(
			'unsupported',
		);
		const unknownBlob = concatBytes([strText('ssh-unknown'), str(new Uint8Array(32))]);
		expect(codeOf(await importSshPublicKey(`ssh-ed25519 ${base64Encode(unknownBlob)}`))).toBe(
			'unsupported',
		);
	});

	it('rejects ECDSA curve identifiers that disagree with the key type', async () => {
		const fields = await fieldsFor('p256', { curveIdentifier: 'nistp384' });
		expect(
			codeOf(await importSshPublicKey(`ecdsa-sha2-nistp256 ${base64Encode(fields.publicBlob)}`)),
		).toBe('key_mismatch');
	});

	it('rejects ECDSA points off the curve', async () => {
		const fields = await fieldsFor('p256');
		const blob = fields.publicBlob.slice();
		blob[blob.length - 1] = (blob[blob.length - 1] ?? 0) ^ 1;
		expect(codeOf(await importSshPublicKey(`ecdsa-sha2-nistp256 ${base64Encode(blob)}`))).toBe(
			'malformed',
		);
	});

	it('bounds the input size', async () => {
		expect(codeOf(await importSshPublicKey(`ssh-ed25519 ${'A'.repeat(20_000)}`))).toBe(
			'limit_exceeded',
		);
		expect(codeOf(await importSshPublicKey(new Uint8Array(20_000)))).toBe('limit_exceeded');
	});

	it('does not modify caller buffers', async () => {
		const pair = await generateKeyPair({ kind: 'ed25519' });
		const input = text(`${await exportSshPublicKey(pair.publicKey)} c\n`);
		const copy = input.slice();
		ok(await importSshPublicKey(input));
		expect(input).toEqual(copy);
		const pem = text(await exportOpenSshPrivateKey(pair.privateKey));
		const pemCopy = pem.slice();
		ok(await importOpenSshPrivateKey(pem));
		expect(pem).toEqual(pemCopy);
	});

	for (const [kind, curve] of [
		['p256', 'P-256'],
		['p384', 'P-384'],
		['p521', 'P-521'],
	] as const) {
		it(`reads compressed ${curve} points only when accepted`, async () => {
			const compressed = await fieldsFor(kind, { point: 'compressed' });
			const line = `${compressed.typeName} ${base64Encode(compressed.publicBlob)}`;
			expect(codeOf(await importSshPublicKey(line))).toBe('unsupported');
			const imported = ok(await importSshPublicKey(line, { acceptCompressedEcPoints: true }));
			expect(imported.algorithm).toEqual({ kind: 'ecdsa', curve });
			const uncompressedLine = await exportSshPublicKey(imported.publicKey);
			expect(imported.fingerprint).toBe(
				await sshFingerprintSha256(base64Decode(uncompressedLine.split(' ')[1] ?? '')),
			);
			expect(uncompressedLine.split(' ')[1]).not.toBe(base64Encode(compressed.publicBlob));
		});
	}

	it('rejects a compressed x that is not on the curve', async () => {
		const compressed = await fieldsFor('p256', { point: 'compressed' });
		const blob = compressed.publicBlob.slice();
		const xStart = blob.length - 32;
		for (let candidate = 0; candidate < 256; candidate++) {
			blob[xStart + 31] = candidate;
			const result = await importSshPublicKey(`${compressed.typeName} ${base64Encode(blob)}`, {
				acceptCompressedEcPoints: true,
			});
			if (!result.ok) {
				expect(result.code).toBe('malformed');
				return;
			}
		}
		throw new Error('every x was on the curve');
	});

	it('has a throwing variant carrying the same code', async () => {
		let thrown: unknown;
		try {
			await importSshPublicKeyOrThrow('nonsense');
		} catch (error) {
			thrown = error;
		}
		expect(isResultError(thrown) && thrown.code).toBe('malformed');
		const pair = await generateKeyPair({ kind: 'ed25519' });
		const value = await importSshPublicKeyOrThrow(await exportSshPublicKey(pair.publicKey));
		expect(value.keyType).toBe('ssh-ed25519');
	});
});

describe('private key files', () => {
	it('accepts hand-built files for every key type', async () => {
		for (const kind of ['rsa', 'ed25519', 'p256', 'p384', 'p521'] as const) {
			const imported = ok(await importOpenSshPrivateKey(await validFile(kind)));
			expect(imported.comment).toBe('c');
			expect(imported.fingerprint).toMatch(/^SHA256:/);
		}
	});

	it('accepts a file read as bytes and CRLF line endings', async () => {
		const pem = await validFile('ed25519');
		expect(codeOf(await importOpenSshPrivateKey(text(pem)))).toBe('ok');
		expect(codeOf(await importOpenSshPrivateKey(pem.replace(/\n/g, '\r\n')))).toBe('ok');
	});

	it('rejects a wrong PEM label and non-PEM input', async () => {
		const pem = await validFile('ed25519');
		expect(
			codeOf(await importOpenSshPrivateKey(pem.replaceAll('OPENSSH PRIVATE KEY', 'PRIVATE KEY'))),
		).toBe('malformed');
		expect(codeOf(await importOpenSshPrivateKey('not a key'))).toBe('malformed');
		expect(codeOf(await importOpenSshPrivateKey(''))).toBe('malformed');
	});

	it('rejects a wrong magic header', async () => {
		const wrong = concatBytes([text('openssh-key-v2'), Uint8Array.of(0)]);
		const missingNul = text('openssh-key-v1X');
		expect(
			codeOf(await importOpenSshPrivateKey(await validFile('ed25519', { magic: wrong }))),
		).toBe('malformed');
		expect(
			codeOf(await importOpenSshPrivateKey(await validFile('ed25519', { magic: missingNul }))),
		).toBe('malformed');
	});

	it('reports encrypted and unknown cipher and KDF names as unsupported', async () => {
		const cases: readonly Partial<FileParts>[] = [
			{ cipher: 'aes256-ctr', kdf: 'bcrypt' },
			{ cipher: 'aes256-ctr', kdf: 'none' },
			{ cipher: 'none', kdf: 'bcrypt' },
			{ cipher: 'chacha20-poly1305@openssh.com', kdf: 'bcrypt' },
			{ cipher: 'rot13', kdf: 'none' },
		];
		for (const overrides of cases) {
			expect(codeOf(await importOpenSshPrivateKey(await validFile('ed25519', overrides)))).toBe(
				'unsupported',
			);
		}
	});

	it('rejects KDF options on an unencrypted file', async () => {
		expect(
			codeOf(
				await importOpenSshPrivateKey(await validFile('ed25519', { kdfOptions: Uint8Array.of(1) })),
			),
		).toBe('malformed');
	});

	it('refuses files whose key count is not one', async () => {
		expect(codeOf(await importOpenSshPrivateKey(await validFile('ed25519', { count: 2 })))).toBe(
			'unsupported',
		);
		expect(codeOf(await importOpenSshPrivateKey(await validFile('ed25519', { count: 0 })))).toBe(
			'malformed',
		);
		expect(
			codeOf(await importOpenSshPrivateKey(await validFile('ed25519', { count: 0xffffffff }))),
		).toBe('unsupported');
	});

	it('rejects truncation at every length of a small file', async () => {
		const pem = await validFile('ed25519');
		const bytes = pemDecodeOrThrow('OPENSSH PRIVATE KEY', pem);
		for (let length = 0; length < bytes.length; length++) {
			const result = await importOpenSshPrivateKey(
				pemEncode('OPENSSH PRIVATE KEY', bytes.subarray(0, length)),
			);
			expect([length, codeOf(result)]).toEqual([length, 'malformed']);
		}
	});

	it('rejects trailing bytes after the private section', async () => {
		expect(
			codeOf(
				await importOpenSshPrivateKey(await validFile('ed25519', { trailing: Uint8Array.of(0) })),
			),
		).toBe('malformed');
	});

	it('rejects differing check integers', async () => {
		expect(
			codeOf(await importOpenSshPrivateKey(await validFile('ed25519', { checkA: 1, checkB: 2 }))),
		).toBe('malformed');
	});

	it('rejects invalid padding', async () => {
		const sequence = (length: number, offset = 1): Uint8Array =>
			Uint8Array.from({ length }, (_, i) => i + offset);
		const cases: Record<string, (needed: number) => Uint8Array> = {
			zeros: (needed) => new Uint8Array(needed),
			'starts at 2': (needed) => sequence(needed, 2),
			'wrong last byte': (needed) => sequence(needed).map((b, i) => (i === needed - 1 ? 0xff : b)),
			'full block of padding': (needed) => sequence(needed + 8),
			'one byte too many': (needed) => sequence(needed + 1),
			'one byte missing': (needed) => sequence(needed - 1),
		};
		for (const [name, padding] of Object.entries(cases)) {
			const pem = await validFile('ed25519', { comment: 'cc', padding });
			expect([name, codeOf(await importOpenSshPrivateKey(pem))]).toEqual([name, 'malformed']);
		}
		const valid = await validFile('ed25519', { comment: 'cc' });
		expect(codeOf(await importOpenSshPrivateKey(valid))).toBe('ok');
	});

	it('accepts a section that needs no padding', async () => {
		for (let commentLength = 0; commentLength < 8; commentLength++) {
			const comment = 'a'.repeat(commentLength);
			const pem = await validFile('ed25519', { comment });
			expect([commentLength, codeOf(await importOpenSshPrivateKey(pem))]).toEqual([
				commentLength,
				'ok',
			]);
		}
	});

	it('rejects comments that are not UTF-8 text without NUL', async () => {
		const fields = await fieldsFor('ed25519');
		const comments = {
			'invalid UTF-8': Uint8Array.of(0xff, 0xfe, 0xfd),
			'embedded NUL': Uint8Array.of(0x61, 0x00, 0x62),
		};
		for (const [name, comment] of Object.entries(comments)) {
			const section = concatBytes([
				u32(1),
				u32(1),
				strText('ssh-ed25519'),
				fields.privateFields,
				str(comment),
			]);
			const padLength = (8 - (section.length % 8)) % 8;
			const padded = concatBytes([
				section,
				Uint8Array.from({ length: padLength }, (_, i) => i + 1),
			]);
			const pem = buildFile({
				publicBlob: fields.publicBlob,
				privateFields: fields.privateFields,
				sectionOverride: padded,
			});
			expect([name, codeOf(await importOpenSshPrivateKey(pem))]).toEqual([name, 'malformed']);
		}
	});

	it('rejects non-canonical RSA integers', async () => {
		expect(
			codeOf(await importOpenSshPrivateKey(await validFile('rsa', {}, { mpint: 'redundantZero' }))),
		).toBe('malformed');
		expect(
			codeOf(await importOpenSshPrivateKey(await validFile('rsa', {}, { mpint: 'negative' }))),
		).toBe('malformed');
	});

	it('bounds declared lengths before reading them', async () => {
		const fields = await fieldsFor('ed25519');
		const hugeString = concatBytes([u32(0xffffffff), new Uint8Array(4)]);
		const bytes = pemDecodeOrThrow('OPENSSH PRIVATE KEY', await validFile('ed25519'));
		const oversize = pemEncode(
			'OPENSSH PRIVATE KEY',
			concatBytes([bytes.subarray(0, 15), strText('none'), strText('none'), hugeString]),
		);
		expect(codeOf(await importOpenSshPrivateKey(oversize))).toBe('limit_exceeded');
		expect(codeOf(await importOpenSshPrivateKey(`${'A'.repeat(40_000)}`))).toBe('limit_exceeded');
		const longName = pemEncode(
			'OPENSSH PRIVATE KEY',
			concatBytes([bytes.subarray(0, 15), str(new Uint8Array(65).fill(0x61))]),
		);
		expect(codeOf(await importOpenSshPrivateKey(longName))).toBe('limit_exceeded');
		expect(fields.typeName).toBe('ssh-ed25519');
	});

	it('rejects a private section whose key type differs from the file public key', async () => {
		const ed = await fieldsFor('ed25519');
		const ec = await fieldsFor('p256');
		const pem = buildFile({
			publicBlob: ed.publicBlob,
			typeName: ec.typeName,
			privateFields: ec.privateFields,
		});
		expect(codeOf(await importOpenSshPrivateKey(pem))).toBe('key_mismatch');
		const rsa = await fieldsFor('rsa');
		const swapped = buildFile({
			publicBlob: rsa.publicBlob,
			typeName: ed.typeName,
			privateFields: ed.privateFields,
		});
		expect(codeOf(await importOpenSshPrivateKey(swapped))).toBe('key_mismatch');
	});

	it('rejects a public key that belongs to a different private key', async () => {
		for (const kind of ['rsa', 'ed25519', 'p256', 'p384', 'p521'] as const) {
			const real = await fieldsFor(kind);
			const other = await fieldsFor(kind);
			const pem = buildFile({
				publicBlob: other.publicBlob,
				typeName: real.typeName,
				privateFields: real.privateFields,
			});
			expect([kind, codeOf(await importOpenSshPrivateKey(pem))]).toEqual([kind, 'key_mismatch']);
		}
	});

	it('rejects an Ed25519 private field whose public suffix differs', async () => {
		const fields = await fieldsFor('ed25519');
		const other = await fieldsFor('ed25519');
		const wrongSuffix = concatBytes([
			fields.privateFields.subarray(0, 4 + 32),
			str(
				concatBytes([
					fields.privateFields.subarray(4 + 32 + 4, 4 + 32 + 4 + 32),
					other.publicBlob.subarray(-32),
				]),
			),
		]);
		const pem = buildFile({
			publicBlob: fields.publicBlob,
			typeName: fields.typeName,
			privateFields: wrongSuffix,
		});
		expect(codeOf(await importOpenSshPrivateKey(pem))).toBe('key_mismatch');
	});

	it('rejects an Ed25519 seed that does not derive the embedded public key', async () => {
		const fields = await fieldsFor('ed25519');
		const other = await fieldsFor('ed25519');
		const x = fields.privateFields.subarray(4, 4 + 32);
		const foreignSeed = other.privateFields.subarray(4 + 32 + 4, 4 + 32 + 4 + 32);
		const privateFields = concatBytes([str(x), str(concatBytes([foreignSeed, x]))]);
		const pem = buildFile({
			publicBlob: fields.publicBlob,
			typeName: fields.typeName,
			privateFields,
		});
		expect(codeOf(await importOpenSshPrivateKey(pem))).toBe('key_mismatch');
	});

	it('rejects an Ed25519 private field of the wrong length', async () => {
		const fields = await fieldsFor('ed25519');
		const x = fields.privateFields.subarray(4, 4 + 32);
		const privateFields = concatBytes([str(x), str(x)]);
		const pem = buildFile({
			publicBlob: fields.publicBlob,
			typeName: fields.typeName,
			privateFields,
		});
		expect(codeOf(await importOpenSshPrivateKey(pem))).toBe('malformed');
	});

	it('rejects an ECDSA private scalar that does not belong to the point', async () => {
		const fields = await fieldsFor('p256');
		const other = await fieldsFor('p256');
		const pointEnd = 4 + 8 + 4 + 65;
		const mixed = concatBytes([
			fields.privateFields.subarray(0, pointEnd),
			other.privateFields.subarray(pointEnd),
		]);
		const pem = buildFile({
			publicBlob: fields.publicBlob,
			typeName: fields.typeName,
			privateFields: mixed,
		});
		expect(codeOf(await importOpenSshPrivateKey(pem))).toBe('key_mismatch');
	});

	it('rejects RSA factors that do not multiply to the modulus', async () => {
		const pair = await generateKeyPair({ kind: 'rsa' });
		const jwk = await exportPrivateJwk(pair.privateKey);
		const other = await exportPrivateJwk((await generateKeyPair({ kind: 'rsa' })).privateKey);
		const build = (overrides: Record<string, Uint8Array>): string => {
			const n = b64u(jwk.n);
			const e = b64u(jwk.e);
			const field = (name: 'd' | 'qi' | 'p' | 'q'): Uint8Array =>
				mpintOf(overrides[name] ?? b64u(jwk[name]), 'canonical');
			return buildFile({
				publicBlob: concatBytes([
					strText('ssh-rsa'),
					mpintOf(e, 'canonical'),
					mpintOf(n, 'canonical'),
				]),
				typeName: 'ssh-rsa',
				privateFields: concatBytes([
					mpintOf(n, 'canonical'),
					mpintOf(e, 'canonical'),
					field('d'),
					field('qi'),
					field('p'),
					field('q'),
				]),
			});
		};
		expect(codeOf(await importOpenSshPrivateKey(build({})))).toBe('ok');
		expect(codeOf(await importOpenSshPrivateKey(build({ p: b64u(other.p) })))).toBe('key_mismatch');
		expect(codeOf(await importOpenSshPrivateKey(build({ d: b64u(other.d) })))).toBe('key_mismatch');
		expect(codeOf(await importOpenSshPrivateKey(build({ qi: b64u(other.qi) })))).toBe(
			'key_mismatch',
		);
		expect(codeOf(await importOpenSshPrivateKey(build({ q: b64u(jwk.p), p: b64u(jwk.q) })))).toBe(
			'key_mismatch',
		);
	});

	it('rejects ECDSA curve identifier mismatches inside the private section', async () => {
		const pem = await validFile('p256', {}, { curveIdentifier: 'nistp384' });
		expect(codeOf(await importOpenSshPrivateKey(pem))).toBe('key_mismatch');
	});

	it('honours the compressed-point option in private files', async () => {
		const pem = await validFile('p384', {}, { point: 'compressed' });
		expect(codeOf(await importOpenSshPrivateKey(pem))).toBe('unsupported');
		expect(codeOf(await importOpenSshPrivateKey(pem, { acceptCompressedEcPoints: true }))).toBe(
			'ok',
		);
	});

	it('does not leak private material into failure messages', async () => {
		const fields = await fieldsFor('ed25519');
		const other = await fieldsFor('ed25519');
		const seed = fields.privateFields.subarray(4 + 32 + 4, 4 + 32 + 4 + 32);
		const pem = buildFile({
			publicBlob: other.publicBlob,
			typeName: fields.typeName,
			privateFields: fields.privateFields,
		});
		const result = await importOpenSshPrivateKey(pem);
		expect(result.ok).toBe(false);
		const serialized = JSON.stringify(result);
		expect(serialized).not.toContain(base64Encode(seed));
		expect(serialized).not.toContain(Buffer.from(seed).toString('hex'));
	});

	it('has a throwing variant carrying the same code', async () => {
		let thrown: unknown;
		try {
			await importOpenSshPrivateKeyOrThrow(
				await validFile('ed25519', { cipher: 'aes256-ctr', kdf: 'bcrypt' }),
			);
		} catch (error) {
			thrown = error;
		}
		expect(isResultError(thrown) && thrown.code).toBe('unsupported');
		const value = await importOpenSshPrivateKeyOrThrow(await validFile('ed25519'));
		expect(value.keyType).toBe('ssh-ed25519');
	});
});

describe('public key blob edge cases', () => {
	const rsaLine = (e: Uint8Array, n: Uint8Array): string =>
		`ssh-rsa ${base64Encode(concatBytes([strText('ssh-rsa'), mpintOf(e, 'canonical'), mpintOf(n, 'canonical')]))}`;
	const modulus = (bytes: number): Uint8Array =>
		Uint8Array.from({ length: bytes }, (_, i) => (i === 0 ? 0xc0 : 1));
	const exponent = Uint8Array.of(1, 0, 1);

	it('accepts a synthetic well-formed RSA blob', async () => {
		expect(codeOf(await importSshPublicKey(rsaLine(exponent, modulus(256))))).toBe('ok');
	});

	it('rejects RSA exponents that are even, below 3, or not below the modulus', async () => {
		for (const e of [Uint8Array.of(2), Uint8Array.of(1), Uint8Array.of(1, 0, 0), modulus(256)]) {
			expect(codeOf(await importSshPublicKey(rsaLine(e, modulus(256))))).toBe('malformed');
		}
	});

	it('bounds the RSA modulus size', async () => {
		const huge = Uint8Array.from({ length: 2049 }, (_, i) => (i === 0 ? 1 : 0xff));
		expect(codeOf(await importSshPublicKey(rsaLine(exponent, huge)))).toBe('limit_exceeded');
		const tooLong = Uint8Array.from({ length: 2050 }, (_, i) => (i === 0 ? 1 : 0xff));
		expect(codeOf(await importSshPublicKey(rsaLine(exponent, tooLong)))).toBe('limit_exceeded');
	});

	it('rejects a zero RSA integer', async () => {
		const blob = concatBytes([strText('ssh-rsa'), u32(0), mpintOf(modulus(256), 'canonical')]);
		expect(codeOf(await importSshPublicKey(`ssh-rsa ${base64Encode(blob)}`))).toBe('malformed');
	});

	it('rejects key type names that are not printable ASCII', async () => {
		for (const name of ['', 'ssh ed25519', 'ssh-\u00e9d25519']) {
			const blob = concatBytes([strText(name), str(new Uint8Array(32))]);
			expect([name, codeOf(await importSshPublicKey(`ssh-ed25519 ${base64Encode(blob)}`))]).toEqual(
				[name, 'malformed'],
			);
		}
	});

	it('rejects ECDSA point encodings that are neither compressed nor uncompressed', async () => {
		const x = new Uint8Array(32).fill(7);
		const points = {
			'hybrid prefix': concatBytes([Uint8Array.of(6), x, x]),
			'uncompressed too short': concatBytes([Uint8Array.of(4), x]),
			'compressed too long': concatBytes([Uint8Array.of(2), x, x]),
			empty: new Uint8Array(),
		};
		for (const [name, point] of Object.entries(points)) {
			const blob = concatBytes([strText('ecdsa-sha2-nistp256'), strText('nistp256'), str(point)]);
			const line = `ecdsa-sha2-nistp256 ${base64Encode(blob)}`;
			expect([
				name,
				codeOf(await importSshPublicKey(line, { acceptCompressedEcPoints: true })),
			]).toEqual([name, 'malformed']);
		}
	});

	it('rejects a compressed x coordinate at or above the field prime', async () => {
		const point = concatBytes([Uint8Array.of(2), new Uint8Array(32).fill(0xff)]);
		const blob = concatBytes([strText('ecdsa-sha2-nistp256'), strText('nistp256'), str(point)]);
		const line = `ecdsa-sha2-nistp256 ${base64Encode(blob)}`;
		expect(codeOf(await importSshPublicKey(line, { acceptCompressedEcPoints: true }))).toBe(
			'malformed',
		);
	});

	it('counts input bytes, not characters, against the size limit', async () => {
		expect(codeOf(await importSshPublicKey(`ssh-ed25519 AAAA ${'\u20ac'.repeat(6000)}`))).toBe(
			'limit_exceeded',
		);
	});

	it('rejects an ECDSA private scalar longer than the curve size', async () => {
		const fields = await fieldsFor('p256');
		const pointEnd = 4 + 8 + 4 + 65;
		const privateFields = concatBytes([
			fields.privateFields.subarray(0, pointEnd),
			mpintOf(new Uint8Array(40).fill(1), 'canonical'),
		]);
		const pem = buildFile({
			publicBlob: fields.publicBlob,
			typeName: fields.typeName,
			privateFields,
		});
		expect(codeOf(await importOpenSshPrivateKey(pem))).toBe('malformed');
	});
});

describe('keys outside the SSH algorithm set', () => {
	const exportCode = async (run: () => Promise<unknown>): Promise<string> => {
		try {
			await run();
		} catch (error) {
			return isResultError(error) ? String(error.code) : 'unexpected';
		}
		return 'none';
	};

	it('refuses ECDH and X25519 keys on export and fingerprinting', async () => {
		const ecdh = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
			'deriveBits',
		]);
		expect(await exportCode(() => exportOpenSshPrivateKey(ecdh.privateKey))).toBe(
			'unsupported_algorithm',
		);
		expect(await exportCode(() => sshFingerprintSha256(ecdh.privateKey))).toBe(
			'unsupported_algorithm',
		);
		const x25519 = await crypto.subtle.generateKey('X25519', true, ['deriveBits']);
		expect(await exportCode(() => exportSshPublicKey(x25519.publicKey))).toBe(
			'unsupported_algorithm',
		);
	});
});

describe('SSH wire encoding', () => {
	it('encodes the RFC 4251 section 5 mpint examples', () => {
		const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
		expect(hex(sshMpint(new Uint8Array()))).toBe('00000000');
		expect(hex(sshMpint(Uint8Array.of(0, 0)))).toBe('00000000');
		expect(hex(sshMpint(bigintToBytes(0x09a378f9b2e332a7n)))).toBe('0000000809a378f9b2e332a7');
		expect(hex(sshMpint(Uint8Array.of(0x80)))).toBe('000000020080');
		expect(hex(sshMpint(Uint8Array.of(0, 0, 0x7f)))).toBe('000000017f');
	});

	it('rejects an integer that does not fit its field', () => {
		let thrown: unknown;
		try {
			bigintToBytes(256n, 1);
		} catch (error) {
			thrown = error;
		}
		expect(isResultError(thrown) && thrown.code).toBe('malformed');
		expect(bigintToBytes(5n, 3)).toEqual(Uint8Array.of(0, 0, 5));
	});

	it('reads canonical mpints and refuses reads past the end', () => {
		const reader = createSshReader(concatBytes([sshMpint(Uint8Array.of(0x80)), u32(7)]));
		expect(reader.mpint(8)).toEqual(Uint8Array.of(0x80));
		expect(reader.uint32()).toBe(7);
		expect(reader.remaining()).toBe(0);
		let thrown: unknown;
		try {
			reader.uint32();
		} catch (error) {
			thrown = error;
		}
		expect(isResultError(thrown) && thrown.code).toBe('malformed');
	});
});

describe('runtime options and comment boundaries', () => {
	it('rejects invalid policy values before importing either format', async () => {
		const pair = await generateKeyPair({ kind: 'ed25519' });
		const line = await exportSshPublicKey(pair.publicKey);
		const file = await exportOpenSshPrivateKey(pair.privateKey);
		const invalidOptions: readonly unknown[] = [
			null,
			false,
			[],
			...[NaN, Infinity, -Infinity, 0, -1, 1.5, 16385, null, '2048'].map((minRsaModulusBits) => ({
				minRsaModulusBits,
			})),
			...[null, 0, 'false'].map((acceptCompressedEcPoints) => ({ acceptCompressedEcPoints })),
			...[null, false, []].map((rsa) => ({ rsa })),
			...[null, 'oaep', ''].map((scheme) => ({ rsa: { scheme } })),
			...[null, 'SHA-1', 'sha256', ''].map((hash) => ({ rsa: { hash } })),
		];
		for (const options of invalidOptions) {
			const publicResult: unknown = await Reflect.apply(importSshPublicKey, undefined, [
				line,
				options,
			]);
			const privateResult: unknown = await Reflect.apply(importOpenSshPrivateKey, undefined, [
				file,
				options,
			]);
			expect(publicResult).toMatchObject({ ok: false, error: { code: 'invalid_options' } });
			expect(privateResult).toMatchObject({ ok: false, error: { code: 'invalid_options' } });
		}
	});

	it('round-trips a leading BOM and the 8192-byte UTF-8 boundary', async () => {
		const pair = await generateKeyPair({ kind: 'ed25519' });
		for (const comment of [
			'\ufeffme@host',
			'a\u2028b',
			'a\u2029b',
			'\u2028trailing\u2029',
			'a'.repeat(8192),
			'é'.repeat(4096),
		]) {
			const line = await exportSshPublicKey(pair.publicKey, { comment });
			const file = await exportOpenSshPrivateKey(pair.privateKey, { comment });
			expect(ok(await importSshPublicKey(line)).comment).toBe(comment);
			expect(ok(await importSshPublicKey(text(line))).comment).toBe(comment);
			expect(ok(await importOpenSshPrivateKey(file)).comment).toBe(comment);
		}
	});

	it('refuses comments that cannot round-trip through the bounded UTF-8 format', async () => {
		const pair = await generateKeyPair({ kind: 'ed25519' });
		const line = await exportSshPublicKey(pair.publicKey);
		for (const comment of ['a'.repeat(8193), 'é'.repeat(4097), '\ud800', '\udfff', 'a\0b']) {
			for (const operation of [
				() => exportSshPublicKey(pair.publicKey, { comment }),
				() => exportOpenSshPrivateKey(pair.privateKey, { comment }),
			]) {
				let thrown: unknown;
				try {
					await operation();
				} catch (error) {
					thrown = error;
				}
				expect(isResultError(thrown) && thrown.code).toBe('invalid_comment');
			}
			expect(codeOf(await importSshPublicKey(`${line} ${comment}`))).toBe(
				comment.length > 8192 || text(comment).length > 8192 ? 'limit_exceeded' : 'malformed',
			);
		}
	});
});
