import { describe, expect, it } from 'bun:test';
import { X509Certificate } from 'node:crypto';
import {
	createCertificate,
	decryptRsaOaep,
	decryptRsaOaepOrThrow,
	derivePublicKey,
	encryptRsaOaep,
	encryptRsaOaepOrThrow,
	exportBinaryBase64,
	exportEncryptedPkcs1Pem,
	exportEncryptedPkcs8Der,
	exportEncryptedPkcs8Pem,
	exportEncryptedSec1Pem,
	exportPkcs1Der,
	exportPkcs1Pem,
	exportPkcs8Der,
	exportPkcs8Pem,
	exportPrivateJwk,
	exportPublicJwk,
	exportSec1Der,
	exportSec1Pem,
	exportSpkiDer,
	exportSpkiPem,
	generateKeyPair,
	importEncryptedPkcs1Pem,
	importEncryptedPkcs8Der,
	importEncryptedPkcs8Pem,
	importEncryptedSec1Pem,
	importPkcs1Der,
	importPkcs1Pem,
	importPkcs8Base64,
	importPkcs8Der,
	importPkcs8Pem,
	importPrivateJwk,
	importPrivateJwkOrThrow,
	importPublicJwk,
	importSec1Der,
	importSec1DerOrThrow,
	importSec1Pem,
	importSpkiBase64,
	importSpkiDer,
	importSpkiPem,
	pemEncode,
	unwrap,
} from '#micro509';
import type { KeyPairMaterial } from '#micro509';

/** Minimal shape every `import*` Result satisfies, success or failure. */
type FailableImport =
	| { readonly ok: true; readonly value: CryptoKey }
	| { readonly ok: false; readonly error: { readonly code: string; readonly message: string } };

/** Assert an import Result failed with the given code and a message substring. */
async function expectImportFailure(
	pending: Promise<FailableImport>,
	code: string,
	messagePart: string,
): Promise<void> {
	const result = await pending;
	expect(result.ok).toBe(false);
	if (result.ok) {
		return;
	}
	expect(result.error.code).toBe(code);
	expect(result.error.message).toContain(messagePart);
}

describe('keys', () => {
	it('roundtrips RSA PKCS#1 and EC SEC1 private keys', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const pkcs1Pem = await exportPkcs1Pem(rsa.privateKey);
		const pkcs1Der = await exportPkcs1Der(rsa.privateKey);
		const rsaFromPem = unwrap(await importPkcs1Pem(pkcs1Pem, { kind: 'rsa' }));
		const rsaFromDer = unwrap(await importPkcs1Der(pkcs1Der, { kind: 'rsa' }));
		expect(await exportPkcs8Der(rsaFromPem)).toEqual(await exportPkcs8Der(rsa.privateKey));
		expect(await exportPkcs8Der(rsaFromDer)).toEqual(await exportPkcs8Der(rsa.privateKey));

		const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const sec1Pem = await exportSec1Pem(ec.privateKey);
		const sec1Der = await exportSec1Der(ec.privateKey);
		const ecFromPem = unwrap(
			await importSec1Pem(sec1Pem, {
				kind: 'ecdsa',
				curve: 'P-256',
			}),
		);
		const ecFromDer = unwrap(
			await importSec1Der(sec1Der, {
				kind: 'ecdsa',
				curve: 'P-256',
			}),
		);
		expect(await exportPkcs8Der(ecFromPem)).toEqual(await exportPkcs8Der(ec.privateKey));
		expect(await exportPkcs8Der(ecFromDer)).toEqual(await exportPkcs8Der(ec.privateKey));
	});

	it('roundtrips encrypted PKCS#8 helpers', async () => {
		const keyPair = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const cases = [
			{ cipher: 'AES-128-CBC', prf: 'HMAC-SHA-1' },
			{ cipher: 'AES-128-CBC', prf: 'HMAC-SHA-256' },
			{ cipher: 'AES-192-CBC', prf: 'HMAC-SHA-1' },
			{ cipher: 'AES-192-CBC', prf: 'HMAC-SHA-256' },
			{ cipher: 'AES-256-CBC', prf: 'HMAC-SHA-1' },
			{ cipher: 'AES-256-CBC', prf: 'HMAC-SHA-256' },
		] as const;
		for (const testCase of cases) {
			const pem = await exportEncryptedPkcs8Pem(keyPair.privateKey, {
				password: 'secret123',
				...testCase,
			});
			const der = await exportEncryptedPkcs8Der(keyPair.privateKey, {
				password: 'secret123',
				...testCase,
			});
			const importedPem = unwrap(
				await importEncryptedPkcs8Pem(pem, 'secret123', {
					kind: 'rsa',
				}),
			);
			const importedDer = unwrap(
				await importEncryptedPkcs8Der(der, 'secret123', {
					kind: 'rsa',
				}),
			);
			expect(await exportPkcs8Der(importedPem)).toEqual(await exportPkcs8Der(keyPair.privateKey));
			expect(await exportPkcs8Der(importedDer)).toEqual(await exportPkcs8Der(keyPair.privateKey));
		}

		const pem = await exportEncryptedPkcs8Pem(keyPair.privateKey, {
			password: 'secret123',
		});
		await expectImportFailure(
			importEncryptedPkcs8Pem(pem, 'wrong', { kind: 'rsa' }),
			'invalid_password',
			'Invalid password or encrypted content',
		);
	});

	it('returns invalid_password when decrypting PKCS#8 DER with the wrong password', async () => {
		const keyPair = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const der = await exportEncryptedPkcs8Der(keyPair.privateKey, { password: 'right' });
		const result = await importEncryptedPkcs8Der(der, 'wrong', {
			kind: 'ecdsa',
			curve: 'P-256',
		});
		expect(result.ok).toBe(false);
		if (!result.ok) {
			expect(result.error.code).toBe('invalid_password');
		}
	});

	it('roundtrips encrypted traditional RSA and EC PEM helpers', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const encryptedRsaPem = await exportEncryptedPkcs1Pem(rsa.privateKey, {
			password: 'secret123',
		});
		const importedRsa = unwrap(
			await importEncryptedPkcs1Pem(encryptedRsaPem, 'secret123', {
				kind: 'rsa',
			}),
		);
		expect(await exportPkcs8Der(importedRsa)).toEqual(await exportPkcs8Der(rsa.privateKey));
		await expectImportFailure(
			importEncryptedPkcs1Pem(encryptedRsaPem, 'wrong', { kind: 'rsa' }),
			'invalid_password',
			'Invalid password or encrypted PEM content',
		);

		const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const encryptedEcPem = await exportEncryptedSec1Pem(ec.privateKey, {
			password: 'secret123',
		});
		const importedEc = unwrap(
			await importEncryptedSec1Pem(encryptedEcPem, 'secret123', {
				kind: 'ecdsa',
				curve: 'P-256',
			}),
		);
		expect(await exportPkcs8Der(importedEc)).toEqual(await exportPkcs8Der(ec.privateKey));
	});

	it('roundtrips keys through PEM, base64, and JWK imports', async () => {
		const original = await generateKeyPair({
			kind: 'rsa',
			modulusLength: 2048,
		});
		const importedPublic = unwrap(
			await importSpkiPem(await original.exportSpkiPem(), {
				kind: 'rsa',
			}),
		);
		const importedPrivate = unwrap(
			await importPkcs8Pem(await original.exportPkcs8Pem(), { kind: 'rsa' }),
		);
		const base64Public = unwrap(
			await importSpkiBase64(await exportBinaryBase64(original.publicKey), {
				kind: 'rsa',
			}),
		);
		const base64Private = unwrap(
			await importPkcs8Base64(await exportBinaryBase64(original.privateKey), {
				kind: 'rsa',
			}),
		);
		const jwkPublic = unwrap(
			await importPublicJwk(await original.exportPublicJwk(), {
				kind: 'rsa',
			}),
		);
		const jwkPrivate = unwrap(
			await importPrivateJwk(await original.exportPrivateJwk(), { kind: 'rsa' }),
		);

		const certificate = await createCertificate({
			issuer: { commonName: 'imported-ca' },
			subject: { commonName: 'imported-leaf' },
			publicKey: importedPublic,
			signerPrivateKey: importedPrivate,
			issuerPublicKey: importedPublic,
		});
		const certificateFromBase64 = await createCertificate({
			issuer: { commonName: 'imported-ca-2' },
			subject: { commonName: 'imported-leaf-2' },
			publicKey: base64Public,
			signerPrivateKey: base64Private,
			issuerPublicKey: base64Public,
		});
		const certificateFromJwk = await createCertificate({
			issuer: { commonName: 'imported-ca-3' },
			subject: { commonName: 'imported-leaf-3' },
			publicKey: jwkPublic,
			signerPrivateKey: jwkPrivate,
			issuerPublicKey: jwkPublic,
		});

		expect(new X509Certificate(certificate.pem).subject).toContain('CN=imported-leaf');
		expect(new X509Certificate(certificateFromBase64.pem).subject).toContain('CN=imported-leaf-2');
		expect(new X509Certificate(certificateFromJwk.pem).subject).toContain('CN=imported-leaf-3');
		expect(await exportSpkiDer(importedPublic)).toEqual(await original.exportSpkiDer());
		expect(await exportPkcs8Der(importedPrivate)).toEqual(await original.exportPkcs8Der());
		expect(await exportSpkiDer(base64Public)).toEqual(await original.exportSpkiDer());
		expect(await exportPkcs8Der(base64Private)).toEqual(await original.exportPkcs8Der());
		expect(await exportSpkiDer(jwkPublic)).toEqual(await original.exportSpkiDer());
		expect(await exportPkcs8Der(jwkPrivate)).toEqual(await original.exportPkcs8Der());
	});

	it('importPublicJwk rejects private-key material and algorithm mismatches', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const publicJwk = await exportPublicJwk(rsa.publicKey);
		const privateJwk = await exportPrivateJwk(rsa.privateKey);
		await expectImportFailure(
			importPublicJwk(privateJwk, { kind: 'rsa' }),
			'malformed',
			'Public JWK must not contain private key material',
		);
		await expectImportFailure(
			importPublicJwk(publicJwk, { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'Public JWK algorithm does not match requested import algorithm',
		);
	});

	it('importPrivateJwk rejects public-only JWKs and algorithm mismatches', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const rsaPublicJwk = await exportPublicJwk(rsa.publicKey);
		const rsaPrivateJwk = await exportPrivateJwk(rsa.privateKey);
		const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const ecPrivateJwk = await exportPrivateJwk(ec.privateKey);
		await expectImportFailure(
			importPrivateJwk(rsaPublicJwk, { kind: 'rsa' }),
			'malformed',
			'Private JWK must contain private key material',
		);
		await expectImportFailure(
			importPrivateJwk(ecPrivateJwk, { kind: 'ecdsa', curve: 'P-384' }),
			'malformed',
			'Private JWK algorithm does not match requested import algorithm',
		);
		await expectImportFailure(
			importPrivateJwk(rsaPrivateJwk, { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'Private JWK algorithm does not match requested import algorithm',
		);
		expect(importPrivateJwkOrThrow(rsaPublicJwk, { kind: 'rsa' })).rejects.toThrow(
			'Private JWK must contain private key material',
		);
		expect(
			importPrivateJwkOrThrow(ecPrivateJwk, { kind: 'ecdsa', curve: 'P-384' }),
		).rejects.toThrow('Private JWK algorithm does not match requested import algorithm');
	});

	it('roundtrips EC and Ed25519 private keys through JWK', async () => {
		const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		const ecFromJwk = unwrap(
			await importPrivateJwk(await ec.exportPrivateJwk(), { kind: 'ecdsa', curve: 'P-256' }),
		);
		expect(await exportPkcs8Der(ecFromJwk)).toEqual(await ec.exportPkcs8Der());

		const ed = await generateKeyPair({ kind: 'ed25519' });
		const edFromJwk = unwrap(
			await importPrivateJwk(await ed.exportPrivateJwk(), { kind: 'ed25519' }),
		);
		expect(await exportPkcs8Der(edFromJwk)).toEqual(await ed.exportPkcs8Der());
	});

	it('imports and exports keys via ecdsa and ed25519', async () => {
		const ecP384 = await generateKeyPair({
			kind: 'ecdsa',
			curve: 'P-384',
		});
		const ecPub = unwrap(
			await importSpkiBase64(await exportBinaryBase64(ecP384.publicKey), {
				kind: 'ecdsa',
				curve: 'P-384',
			}),
		);
		const ecPriv = unwrap(
			await importPkcs8Base64(await exportBinaryBase64(ecP384.privateKey), {
				kind: 'ecdsa',
				curve: 'P-384',
			}),
		);
		expect(await exportSpkiDer(ecPub)).toEqual(await ecP384.exportSpkiDer());
		expect(await exportPkcs8Der(ecPriv)).toEqual(await ecP384.exportPkcs8Der());

		const ed = await generateKeyPair({ kind: 'ed25519' });
		const edPub = unwrap(
			await importSpkiPem(await ed.exportSpkiPem(), {
				kind: 'ed25519',
			}),
		);
		const edPriv = unwrap(
			await importPkcs8Pem(await ed.exportPkcs8Pem(), {
				kind: 'ed25519',
			}),
		);
		expect(await exportSpkiDer(edPub)).toEqual(await ed.exportSpkiDer());
		expect(await exportPkcs8Der(edPriv)).toEqual(await ed.exportPkcs8Der());
	});

	it('derivePublicKey reconstructs the SPKI from an imported private key', async () => {
		const cases = [
			{ kind: 'rsa', modulusLength: 2048 } as const,
			{ kind: 'ecdsa', curve: 'P-256' } as const,
			{ kind: 'ecdsa', curve: 'P-521' } as const,
			{ kind: 'ed25519' } as const,
		];
		for (const algorithm of cases) {
			const original = await generateKeyPair(algorithm);
			// Round-trip through PKCS#8 so we start from a bare sign-only private key.
			const importAlgorithm =
				algorithm.kind === 'ecdsa'
					? { kind: 'ecdsa' as const, curve: algorithm.curve }
					: algorithm.kind === 'rsa'
						? { kind: 'rsa' as const }
						: { kind: 'ed25519' as const };
			const privateKey = unwrap(
				await importPkcs8Pem(await original.exportPkcs8Pem(), importAlgorithm),
			);
			expect(privateKey.type).toBe('private');

			const publicKey = await derivePublicKey(privateKey);
			expect(publicKey.type).toBe('public');
			expect(publicKey.usages).toEqual(['verify']);
			expect(publicKey.algorithm.name).toBe(original.publicKey.algorithm.name);
			expect(await exportSpkiDer(publicKey)).toEqual(await original.exportSpkiDer());
		}
	});

	it('derivePublicKey rejects public and non-extractable keys', async () => {
		const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		expect(derivePublicKey(ec.publicKey)).rejects.toThrow(
			'derivePublicKey requires a private CryptoKey',
		);

		const nonExtractable = await crypto.subtle.generateKey(
			{ name: 'ECDSA', namedCurve: 'P-256' },
			false,
			['sign', 'verify'],
		);
		if (!('privateKey' in nonExtractable)) {
			throw new Error('expected an asymmetric key pair');
		}
		expect(derivePublicKey(nonExtractable.privateKey)).rejects.toThrow(
			'Cannot derive public key from a non-extractable private key',
		);
	});

	it('accepts RSA-PSS and ECDSA P-521 key inputs', async () => {
		const rsaPss = await generateKeyPair({
			kind: 'rsa',
			scheme: 'pss',
			hash: 'SHA-256',
		});
		expect(rsaPss.privateKey.algorithm.name).toBe('RSA-PSS');

		const rsaPssPublic = unwrap(
			await importSpkiPem(await rsaPss.exportSpkiPem(), {
				kind: 'rsa',
				scheme: 'pss',
				hash: 'SHA-256',
			}),
		);
		expect(rsaPssPublic.algorithm.name).toBe('RSA-PSS');

		const ecP521 = await generateKeyPair({
			kind: 'ecdsa',
			curve: 'P-521',
		});
		const ecP521Public = unwrap(
			await importSpkiBase64(await exportBinaryBase64(ecP521.publicKey), {
				kind: 'ecdsa',
				curve: 'P-521',
			}),
		);
		const ecP521Private = unwrap(
			await importPkcs8Base64(await exportBinaryBase64(ecP521.privateKey), {
				kind: 'ecdsa',
				curve: 'P-521',
			}),
		);
		expect(await exportSpkiDer(ecP521Public)).toEqual(await ecP521.exportSpkiDer());
		expect(await exportPkcs8Der(ecP521Private)).toEqual(await ecP521.exportPkcs8Der());
	});

	it('exports keys with standalone PEM and JWK helpers', async () => {
		const keyPair = await generateKeyPair({ kind: 'ed25519' });
		expect(await exportSpkiPem(keyPair.publicKey)).toContain('BEGIN PUBLIC KEY');
		expect(await exportPkcs8Pem(keyPair.privateKey)).toContain('BEGIN PRIVATE KEY');
		expect(await exportPublicJwk(keyPair.publicKey)).toHaveProperty('kty');
		expect(await exportPrivateJwk(keyPair.privateKey)).toHaveProperty('kty');
	});

	it('exportPkcs1Der throws for non-RSA key', async () => {
		const ecKeys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-256' });
		expect(exportPkcs1Der(ecKeys.privateKey)).rejects.toThrow(
			'PKCS#1 export requires an RSA private key',
		);
	});

	it('exportSec1Der throws for non-EC key', async () => {
		const rsaKeys = await generateKeyPair({
			kind: 'rsa',
			modulusLength: 2048,
		});
		expect(exportSec1Der(rsaKeys.privateKey)).rejects.toThrow(
			'SEC1 export requires an EC private key',
		);
	});

	it('round-trips RSA SHA-512 keys through PKCS#1', async () => {
		const keys = await generateKeyPair({
			kind: 'rsa',
			modulusLength: 2048,
			hash: 'SHA-512',
		});
		const pkcs1Der = await exportPkcs1Der(keys.privateKey);
		expect(pkcs1Der.length).toBeGreaterThan(100);
		const pkcs1Pem = await exportPkcs1Pem(keys.privateKey);
		expect(pkcs1Pem).toContain('BEGIN RSA PRIVATE KEY');
		const reimported = unwrap(
			await importPkcs1Der(pkcs1Der, {
				kind: 'rsa',
				hash: 'SHA-512',
			}),
		);
		expect(reimported.type).toBe('private');
	});

	it('round-trips EC P-384 keys through SEC1', async () => {
		const keys = await generateKeyPair({
			kind: 'ecdsa',
			curve: 'P-384',
		});
		const sec1Der = await exportSec1Der(keys.privateKey);
		expect(sec1Der.length).toBeGreaterThan(40);
		const sec1Pem = await exportSec1Pem(keys.privateKey);
		expect(sec1Pem).toContain('BEGIN EC PRIVATE KEY');
		const reimported = unwrap(
			await importSec1Der(sec1Der, {
				kind: 'ecdsa',
				curve: 'P-384',
			}),
		);
		expect(reimported.type).toBe('private');
	});

	it('round-trips EC P-521 keys through SEC1', async () => {
		const keys = await generateKeyPair({
			kind: 'ecdsa',
			curve: 'P-521',
		});
		const sec1Der = await exportSec1Der(keys.privateKey);
		expect(sec1Der.length).toBeGreaterThan(60);
		const sec1Pem = await exportSec1Pem(keys.privateKey);
		expect(sec1Pem).toContain('BEGIN EC PRIVATE KEY');
		const reimported = unwrap(
			await importSec1Pem(sec1Pem, {
				kind: 'ecdsa',
				curve: 'P-521',
			}),
		);
		expect(await exportPkcs8Der(reimported)).toEqual(await exportPkcs8Der(keys.privateKey));
	});

	it('round-trips encrypted PKCS#1 PEM for RSA keys', async () => {
		const keys = await generateKeyPair({
			kind: 'rsa',
			modulusLength: 2048,
		});
		for (const cipher of ['AES-128-CBC', 'AES-192-CBC', 'AES-256-CBC'] as const) {
			const encrypted = await exportEncryptedPkcs1Pem(keys.privateKey, {
				password: 'testpass',
				cipher,
			});
			expect(encrypted).toContain('Proc-Type: 4,ENCRYPTED');
			expect(encrypted).toContain(`DEK-Info: ${cipher}`);
			const reimported = unwrap(
				await importEncryptedPkcs1Pem(encrypted, 'testpass', {
					kind: 'rsa',
				}),
			);
			expect(reimported.type).toBe('private');
		}
	});

	it('round-trips encrypted SEC1 PEM for EC keys', async () => {
		const keys = await generateKeyPair({
			kind: 'ecdsa',
			curve: 'P-256',
		});
		for (const cipher of ['AES-128-CBC', 'AES-192-CBC', 'AES-256-CBC'] as const) {
			const encrypted = await exportEncryptedSec1Pem(keys.privateKey, {
				password: 'ecpass',
				cipher,
			});
			expect(encrypted).toContain('Proc-Type: 4,ENCRYPTED');
			expect(encrypted).toContain(`DEK-Info: ${cipher}`);
			const reimported = unwrap(
				await importEncryptedSec1Pem(encrypted, 'ecpass', {
					kind: 'ecdsa',
					curve: 'P-256',
				}),
			);
			expect(reimported.type).toBe('private');
		}
	});

	it('PKCS#8 base64 import works for Ed25519 keys', async () => {
		const keys = await generateKeyPair({ kind: 'ed25519' });
		const base64 = await exportBinaryBase64(keys.privateKey);
		const reimported = unwrap(await importPkcs8Base64(base64, { kind: 'ed25519' }));
		expect(reimported.type).toBe('private');
	});
});

describe('keys: coverage — malformed inputs', () => {
	it('importEncryptedPkcs8Der throws on malformed EncryptedPrivateKeyInfo (missing OCTET STRING)', async () => {
		// SEQUENCE with only one child (algorithmIdentifier) and no encryptedData
		const { sequence, objectIdentifier, nullValue } = await import('#micro509/internal/asn1/der');
		const malformed = sequence([
			sequence([objectIdentifier('1.2.840.113549.1.5.13'), nullValue()]),
		]);
		await expectImportFailure(
			importEncryptedPkcs8Der(malformed, 'pass', { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'Malformed EncryptedPrivateKeyInfo',
		);
	});

	it('importEncryptedPkcs8Der throws when second child is not OCTET STRING', async () => {
		const { sequence, objectIdentifier, nullValue, integerFromNumber } = await import(
			'#micro509/internal/asn1/der'
		);
		// second child is INTEGER (tag 0x02), not OCTET STRING (tag 0x04)
		const malformed = sequence([
			sequence([objectIdentifier('1.2.840.113549.1.5.13'), nullValue()]),
			integerFromNumber(42),
		]);
		await expectImportFailure(
			importEncryptedPkcs8Der(malformed, 'pass', { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'Malformed EncryptedPrivateKeyInfo',
		);
	});

	it('importEncryptedPkcs8Der throws when EncryptedPrivateKeyInfo has trailing children', async () => {
		const { sequence, objectIdentifier, nullValue, octetString, integerFromNumber } = await import(
			'#micro509/internal/asn1/der'
		);
		const malformed = sequence([
			sequence([objectIdentifier('1.2.840.113549.1.5.13'), nullValue()]),
			octetString(Uint8Array.of(0x01, 0x02)),
			integerFromNumber(7),
		]);
		await expectImportFailure(
			importEncryptedPkcs8Der(malformed, 'pass', { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'Malformed EncryptedPrivateKeyInfo',
		);
	});

	it('importSpkiBase64 throws on malformed SubjectPublicKeyInfo', async () => {
		await expectImportFailure(
			importSpkiBase64('MAI=', { kind: 'rsa' }),
			'malformed',
			'Malformed SubjectPublicKeyInfo',
		);
	});

	it('importSpkiBase64 throws on SubjectPublicKeyInfo with trailing fields', async () => {
		const { bitString, integerFromNumber, sequence, objectIdentifier } = await import(
			'#micro509/internal/asn1/der'
		);
		const malformed = sequence([
			sequence([objectIdentifier('1.2.840.113549.1.1.1')]),
			bitString(Uint8Array.of(0x00), 0),
			integerFromNumber(1),
		]);
		await expectImportFailure(
			importSpkiBase64(Buffer.from(malformed).toString('base64'), { kind: 'rsa' }),
			'malformed',
			'Malformed SubjectPublicKeyInfo',
		);
	});

	it('importSpkiBase64 throws on algorithm identifiers missing an OID', async () => {
		const { bitString, integerFromNumber, sequence } = await import('#micro509/internal/asn1/der');
		const malformed = sequence([
			sequence([integerFromNumber(1)]),
			bitString(Uint8Array.of(0x00), 0),
		]);
		await expectImportFailure(
			importSpkiBase64(Buffer.from(malformed).toString('base64'), { kind: 'rsa' }),
			'malformed',
			'Malformed SubjectPublicKeyInfo',
		);
	});

	it('importSpkiBase64 throws on invalid subjectPublicKey BIT STRING content', async () => {
		const { sequence, objectIdentifier } = await import('#micro509/internal/asn1/der');
		const malformed = sequence([
			sequence([objectIdentifier('1.2.840.113549.1.1.1')]),
			Uint8Array.of(0x03, 0x02, 0x01, 0x01),
		]);
		await expectImportFailure(
			importSpkiBase64(Buffer.from(malformed).toString('base64'), { kind: 'rsa' }),
			'malformed',
			'Malformed SubjectPublicKeyInfo',
		);
	});

	it('importSpki base64 and PEM preserve algorithm mismatch errors', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const base64 = await exportBinaryBase64(rsa.publicKey);
		const pem = await exportSpkiPem(rsa.publicKey);
		await expectImportFailure(
			importSpkiBase64(base64, { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'SubjectPublicKeyInfo algorithm does not match requested import algorithm',
		);
		await expectImportFailure(
			importSpkiPem(pem, { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'SubjectPublicKeyInfo algorithm does not match requested import algorithm',
		);
	});

	it('importPkcs8Base64 throws on malformed PKCS#8 private key', async () => {
		await expectImportFailure(
			importPkcs8Base64('MAI=', { kind: 'rsa' }),
			'malformed',
			'Malformed PKCS#8 private key',
		);
	});

	it('importPkcs8Der and base64 throw on PKCS#8 with wrong privateKey tag', async () => {
		const { integerFromNumber, nullValue, objectIdentifier, sequence } = await import(
			'#micro509/internal/asn1/der'
		);
		const malformed = sequence([
			integerFromNumber(0),
			sequence([objectIdentifier('1.2.840.113549.1.1.1'), nullValue()]),
			integerFromNumber(1),
		]);
		await expectImportFailure(
			importPkcs8Der(malformed, { kind: 'rsa' }),
			'malformed',
			'Malformed PKCS#8 private key',
		);
		await expectImportFailure(
			importPkcs8Base64(Buffer.from(malformed).toString('base64'), { kind: 'rsa' }),
			'malformed',
			'Malformed PKCS#8 private key',
		);
	});

	it('importPkcs8Der throws on algorithm identifiers missing an OID', async () => {
		const { integerFromNumber, octetString, sequence } = await import(
			'#micro509/internal/asn1/der'
		);
		const malformed = sequence([
			integerFromNumber(0),
			sequence([integerFromNumber(1)]),
			octetString(Uint8Array.of(0x01)),
		]);
		await expectImportFailure(
			importPkcs8Der(malformed, { kind: 'rsa' }),
			'malformed',
			'Malformed PKCS#8 private key',
		);
	});

	it('importPkcs8 base64 and PEM preserve algorithm mismatch errors', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const base64 = await exportBinaryBase64(rsa.privateKey);
		const pem = await exportPkcs8Pem(rsa.privateKey);
		await expectImportFailure(
			importPkcs8Base64(base64, { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'PKCS#8 private key algorithm does not match requested import algorithm',
		);
		await expectImportFailure(
			importPkcs8Pem(pem, { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'PKCS#8 private key algorithm does not match requested import algorithm',
		);
	});

	it('importSec1Der cross-checks the embedded RFC 5915 parameters curve', async () => {
		const { explicitContext, objectIdentifier, readSequenceChildren, sequence } = await import(
			'#micro509/internal/asn1/der'
		);
		const { OIDS } = await import('#micro509/internal/asn1/oids');
		const keys = await generateKeyPair({ kind: 'ecdsa', curve: 'P-384' });
		const sec1Der = await exportSec1Der(keys.privateKey);
		// Re-encode with the `parameters [0]` named-curve field OpenSSL always writes.
		const children = readSequenceChildren(sec1Der);
		const raw = (child: (typeof children)[number]): Uint8Array =>
			sec1Der.slice(child.start - child.headerLength, child.end);
		const withParameters = sequence([
			...children.slice(0, 2).map(raw),
			explicitContext(0, objectIdentifier(OIDS.secp384r1)),
			...children
				.slice(2)
				.filter((child) => child.tag !== 0xa0)
				.map(raw),
		]);
		// Matching curve with parameters present still imports.
		const reimported = unwrap(
			await importSec1Der(withParameters, { kind: 'ecdsa', curve: 'P-384' }),
		);
		expect(reimported.type).toBe('private');
		// Claiming P-256 fails in the library, not with a WebCrypto internal error.
		await expectImportFailure(
			importSec1Der(withParameters, { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'SEC 1 private key curve does not match requested import algorithm',
		);
		await expectImportFailure(
			importSec1Pem(pemEncode('EC PRIVATE KEY', withParameters), {
				kind: 'ecdsa',
				curve: 'P-256',
			}),
			'malformed',
			'SEC 1 private key curve does not match requested import algorithm',
		);
		expect(importSec1DerOrThrow(withParameters, { kind: 'ecdsa', curve: 'P-256' })).rejects.toThrow(
			'SEC 1 private key curve does not match requested import algorithm',
		);
	});

	it('importSec1Der reports malformed for bytes that are not an ECPrivateKey', async () => {
		const { integerFromNumber, sequence } = await import('#micro509/internal/asn1/der');
		await expectImportFailure(
			importSec1Der(Uint8Array.of(0x01, 0x02, 0x03), { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'Malformed SEC 1 private key',
		);
		// Valid DER SEQUENCE, but not an ECPrivateKey shape.
		const notEcPrivateKey = sequence([integerFromNumber(1), integerFromNumber(2)]);
		await expectImportFailure(
			importSec1Der(notEcPrivateKey, { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'Malformed SEC 1 private key',
		);
		expect(
			importSec1DerOrThrow(notEcPrivateKey, { kind: 'ecdsa', curve: 'P-256' }),
		).rejects.toThrow('Malformed SEC 1 private key');
	});

	it('encryptTraditionalPem throws on non-16-byte IV', async () => {
		const keys = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		expect(
			exportEncryptedPkcs1Pem(keys.privateKey, {
				password: 'test',
				iv: new Uint8Array(8), // too short — must be 16
			}),
		).rejects.toThrow('16-byte IV');
	});

	it('decryptTraditionalPem throws on wrong PEM label', async () => {
		// Encrypt as RSA, try to import as EC — label mismatch
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const encrypted = await exportEncryptedPkcs1Pem(rsa.privateKey, { password: 'test' });
		await expectImportFailure(
			importEncryptedSec1Pem(encrypted, 'test', { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'Expected EC PRIVATE KEY PEM block',
		);
	});

	it('decryptTraditionalPem throws when Proc-Type/DEK-Info headers are missing', async () => {
		// A plain (unencrypted) RSA PEM has no encryption headers
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const plainPem = await exportPkcs1Pem(rsa.privateKey);
		await expectImportFailure(
			importEncryptedPkcs1Pem(plainPem, 'test', { kind: 'rsa' }),
			'malformed',
			'encryption headers missing',
		);
	});

	it('decryptTraditionalPem throws on unsupported cipher', async () => {
		// Build a PEM with a non-AES-256-CBC cipher header
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const encrypted = await exportEncryptedPkcs1Pem(rsa.privateKey, { password: 'test' });
		// Replace AES-256-CBC with DES-EDE3-CBC in the header
		const tampered = encrypted.replace('AES-256-CBC', 'DES-EDE3-CBC');
		await expectImportFailure(
			importEncryptedPkcs1Pem(tampered, 'test', { kind: 'rsa' }),
			'malformed',
			'Only AES-128-CBC, AES-192-CBC, and AES-256-CBC',
		);
	});

	it('decryptTraditionalPem throws on malformed DEK-Info IV hex', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const encrypted = await exportEncryptedPkcs1Pem(rsa.privateKey, { password: 'test' });
		const tampered = encrypted.replace(/DEK-Info: [^,]+,.+/, 'DEK-Info: AES-256-CBC,XYZ');
		await expectImportFailure(
			importEncryptedPkcs1Pem(tampered, 'test', { kind: 'rsa' }),
			'malformed',
			'16-byte IV encoded as 32 hex characters',
		);
	});

	it('decryptTraditionalPem rejects duplicate encryption headers', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const encrypted = await exportEncryptedPkcs1Pem(rsa.privateKey, { password: 'test' });
		const withDuplicateProcType = encrypted.replace(
			'Proc-Type: 4,ENCRYPTED',
			'Proc-Type: 4,ENCRYPTED\nProc-Type: 4,ENCRYPTED',
		);
		await expectImportFailure(
			importEncryptedPkcs1Pem(withDuplicateProcType, 'test', { kind: 'rsa' }),
			'malformed',
			'Duplicate PEM header: Proc-Type',
		);
		const withDuplicateDekInfo = encrypted.replace(
			/DEK-Info: .+/,
			(match) => `${match}\nDEK-Info: AES-128-CBC,00000000000000000000000000000000`,
		);
		await expectImportFailure(
			importEncryptedPkcs1Pem(withDuplicateDekInfo, 'test', { kind: 'rsa' }),
			'malformed',
			'Duplicate PEM header: DEK-Info',
		);
	});

	it('parseTraditionalPem throws on non-PEM input', async () => {
		await expectImportFailure(
			importEncryptedPkcs1Pem('not a pem block', 'test', { kind: 'rsa' }),
			'malformed',
			'Invalid PEM block',
		);
	});

	it('parseTraditionalPem throws when BEGIN/END labels mismatch', async () => {
		const badPem = '-----BEGIN RSA PRIVATE KEY-----\nYWJj\n-----END EC PRIVATE KEY-----';
		await expectImportFailure(
			importEncryptedPkcs1Pem(badPem, 'test', { kind: 'rsa' }),
			'malformed',
			'PEM boundaries do not match',
		);
	});

	/** Read `namedCurve` off a CryptoKey algorithm without a type assertion. */
	function namedCurveOf(algorithm: KeyAlgorithm): string {
		if ('namedCurve' in algorithm && typeof algorithm.namedCurve === 'string') {
			return algorithm.namedCurve;
		}
		throw new Error('expected an EC key algorithm with a namedCurve');
	}

	it('importSpkiDer infers the algorithm and curve from the DER when none is given', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const rsaDer = await rsa.exportSpkiDer();
		const rsaPublic = unwrap(await importSpkiDer(rsaDer));
		expect(rsaPublic.algorithm.name).toBe('RSASSA-PKCS1-v1_5');
		expect(await exportSpkiDer(rsaPublic)).toEqual(rsaDer);

		for (const curve of ['P-256', 'P-384', 'P-521'] as const) {
			const ec = await generateKeyPair({ kind: 'ecdsa', curve });
			const ecDer = await ec.exportSpkiDer();
			const ecPublic = unwrap(await importSpkiDer(ecDer));
			expect(ecPublic.algorithm.name).toBe('ECDSA');
			expect(namedCurveOf(ecPublic.algorithm)).toBe(curve);
			expect(await exportSpkiDer(ecPublic)).toEqual(ecDer);
		}

		const ed = await generateKeyPair({ kind: 'ed25519' });
		const edDer = await ed.exportSpkiDer();
		const edPublic = unwrap(await importSpkiDer(edDer));
		expect(edPublic.algorithm.name).toBe('Ed25519');
		expect(await exportSpkiDer(edPublic)).toEqual(edDer);
	});

	it('importSpkiPem/Base64 infer the algorithm from the encoded key', async () => {
		const ec = await generateKeyPair({ kind: 'ecdsa', curve: 'P-384' });
		const fromPem = unwrap(await importSpkiPem(await ec.exportSpkiPem()));
		const fromBase64 = unwrap(await importSpkiBase64(await exportBinaryBase64(ec.publicKey)));
		expect(namedCurveOf(fromPem.algorithm)).toBe('P-384');
		expect(namedCurveOf(fromBase64.algorithm)).toBe('P-384');
	});

	it('importSpkiDer still asserts against an explicitly requested algorithm', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		await expectImportFailure(
			importSpkiDer(await rsa.exportSpkiDer(), { kind: 'ecdsa', curve: 'P-256' }),
			'malformed',
			'SubjectPublicKeyInfo algorithm does not match requested import algorithm',
		);
	});

	it('importSpkiDer without a hint rejects an unsupported algorithm OID', async () => {
		const { bitString, sequence, objectIdentifier } = await import('#micro509/internal/asn1/der');
		// A well-formed SPKI whose AlgorithmIdentifier OID the library does not support (DSA).
		const unsupported = sequence([
			sequence([objectIdentifier('1.2.840.10040.4.1')]),
			bitString(Uint8Array.of(0x00), 0),
		]);
		await expectImportFailure(
			importSpkiDer(unsupported),
			'malformed',
			'Unsupported SubjectPublicKeyInfo algorithm',
		);
	});

	describe('RSA-OAEP', () => {
		/** One shared OAEP pair — RSA keygen is the slow part, every test reuses it. */
		let pairCache: Promise<KeyPairMaterial> | undefined;
		function oaepPair(): Promise<KeyPairMaterial> {
			pairCache ??= generateKeyPair({ kind: 'rsa', scheme: 'oaep', modulusLength: 2048 });
			return pairCache;
		}

		/** Assert an OAEP Result failed with the given code and message substring. */
		function expectOaepFailure(
			result:
				| { readonly ok: true; readonly value: Uint8Array }
				| { readonly ok: false; readonly code: string; readonly message: string },
			code: string,
			messagePart: string,
		): void {
			expect(result.ok).toBe(false);
			if (result.ok) {
				return;
			}
			expect(result.code).toBe(code);
			expect(result.message).toContain(messagePart);
		}

		it('generates encrypt/decrypt pairs and roundtrips a message', async () => {
			const pair = await oaepPair();
			expect(pair.publicKey.algorithm.name).toBe('RSA-OAEP');
			expect(pair.publicKey.usages).toContain('encrypt');
			expect(pair.privateKey.usages).toContain('decrypt');

			const plaintext = new TextEncoder().encode('booga booga session key');
			const ciphertext = unwrap(await encryptRsaOaep(pair.publicKey, plaintext));
			expect(ciphertext.length).toBe(256); // always modulus-sized for RSA-2048
			expect(unwrap(await decryptRsaOaep(pair.privateKey, ciphertext))).toEqual(plaintext);
		});

		it('binds the label: decryption requires the exact same label', async () => {
			const pair = await oaepPair();
			const plaintext = Uint8Array.of(1, 2, 3);
			const label = new TextEncoder().encode('context-v1');
			const ciphertext = unwrap(await encryptRsaOaep(pair.publicKey, plaintext, { label }));

			expect(unwrap(await decryptRsaOaep(pair.privateKey, ciphertext, { label }))).toEqual(
				plaintext,
			);
			expectOaepFailure(
				await decryptRsaOaep(pair.privateKey, ciphertext),
				'decryption_failed',
				'RSA-OAEP decryption failed',
			);
			expectOaepFailure(
				await decryptRsaOaep(pair.privateKey, ciphertext, {
					label: new TextEncoder().encode('context-v2'),
				}),
				'decryption_failed',
				'RSA-OAEP decryption failed',
			);
		});

		it('fails with decryption_failed on tampered ciphertext', async () => {
			const pair = await oaepPair();
			const ciphertext = unwrap(await encryptRsaOaep(pair.publicKey, Uint8Array.of(42)));
			const tampered = Uint8Array.from(ciphertext);
			const first = tampered[0];
			if (first === undefined) {
				throw new Error('empty ciphertext');
			}
			tampered[0] = first ^ 0xff;
			expectOaepFailure(
				await decryptRsaOaep(pair.privateKey, tampered),
				'decryption_failed',
				'RSA-OAEP decryption failed',
			);
		});

		it('rejects non-OAEP and wrong-type keys with invalid_key', async () => {
			const pair = await oaepPair();
			const signingRsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
			const payload = Uint8Array.of(1);

			expectOaepFailure(
				await encryptRsaOaep(signingRsa.publicKey, payload),
				'invalid_key',
				"generate or import the key with scheme: 'oaep'",
			);
			expectOaepFailure(
				await encryptRsaOaep(pair.privateKey, payload),
				'invalid_key',
				'requires a public CryptoKey',
			);
			expectOaepFailure(
				await decryptRsaOaep(pair.publicKey, payload),
				'invalid_key',
				'requires a private CryptoKey',
			);
			expectOaepFailure(
				await decryptRsaOaep(signingRsa.privateKey, payload),
				'invalid_key',
				"generate or import the key with scheme: 'oaep'",
			);
		});

		it('reports message_too_long past the OAEP capacity boundary', async () => {
			const pair = await oaepPair();
			// RSA-2048 + SHA-256: capacity = 256 − 2·32 − 2 = 190 bytes.
			const atCapacity = new Uint8Array(190).fill(7);
			const roundTripped = unwrap(
				await decryptRsaOaep(
					pair.privateKey,
					unwrap(await encryptRsaOaep(pair.publicKey, atCapacity)),
				),
			);
			expect(roundTripped).toEqual(atCapacity);
			expectOaepFailure(
				await encryptRsaOaep(pair.publicKey, new Uint8Array(191)),
				'message_too_long',
				'exceeds the RSA-OAEP capacity',
			);
		});

		it('OrThrow variants throw with the same diagnostics', async () => {
			const pair = await oaepPair();
			const plaintext = Uint8Array.of(9, 9, 9);
			const ciphertext = await encryptRsaOaepOrThrow(pair.publicKey, plaintext);
			expect(await decryptRsaOaepOrThrow(pair.privateKey, ciphertext)).toEqual(plaintext);
			expect(decryptRsaOaepOrThrow(pair.publicKey, ciphertext)).rejects.toThrow(
				'requires a private CryptoKey',
			);
			expect(
				decryptRsaOaepOrThrow(pair.privateKey, ciphertext, { label: Uint8Array.of(1) }),
			).rejects.toThrow('RSA-OAEP decryption failed');
		});

		it('roundtrips OAEP keys through PKCS#8, SPKI, and JWK', async () => {
			const pair = await oaepPair();
			const plaintext = Uint8Array.of(4, 5, 6);

			const privatePem = await pair.exportPkcs8Pem();
			const privateFromPem = unwrap(
				await importPkcs8Pem(privatePem, { kind: 'rsa', scheme: 'oaep' }),
			);
			expect(privateFromPem.algorithm.name).toBe('RSA-OAEP');

			const publicFromDer = unwrap(
				await importSpkiDer(await pair.exportSpkiDer(), { kind: 'rsa', scheme: 'oaep' }),
			);
			const publicFromJwk = unwrap(
				await importPublicJwk(await pair.exportPublicJwk(), { kind: 'rsa', scheme: 'oaep' }),
			);
			const privateFromJwk = unwrap(
				await importPrivateJwk(await pair.exportPrivateJwk(), { kind: 'rsa', scheme: 'oaep' }),
			);

			for (const publicKey of [publicFromDer, publicFromJwk]) {
				const ciphertext = unwrap(await encryptRsaOaep(publicKey, plaintext));
				expect(unwrap(await decryptRsaOaep(privateFromPem, ciphertext))).toEqual(plaintext);
				expect(unwrap(await decryptRsaOaep(privateFromJwk, ciphertext))).toEqual(plaintext);
			}
		});

		it('derivePublicKey yields an encrypting public key from an OAEP private key', async () => {
			const pair = await oaepPair();
			const derived = await derivePublicKey(pair.privateKey);
			expect(derived.algorithm.name).toBe('RSA-OAEP');
			expect(derived.usages).toContain('encrypt');
			const plaintext = Uint8Array.of(7, 8);
			const ciphertext = unwrap(await encryptRsaOaep(derived, plaintext));
			expect(unwrap(await decryptRsaOaep(pair.privateKey, ciphertext))).toEqual(plaintext);
		});
	});
});
