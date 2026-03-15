import { describe, expect, it } from 'bun:test';
import { X509Certificate } from 'node:crypto';
import {
	createCertificate,
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
	importPkcs8Pem,
	importPrivateJwk,
	importPublicJwk,
	importSec1Der,
	importSec1Pem,
	importSpkiBase64,
	importSpkiPem,
} from '#micro509';

describe('keys', () => {
	it('roundtrips RSA PKCS#1 and EC SEC1 private keys', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const pkcs1Pem = await exportPkcs1Pem(rsa.privateKey);
		const pkcs1Der = await exportPkcs1Der(rsa.privateKey);
		const rsaFromPem = await importPkcs1Pem(pkcs1Pem, { kind: 'rsa' });
		const rsaFromDer = await importPkcs1Der(pkcs1Der, { kind: 'rsa' });
		expect(await exportPkcs8Der(rsaFromPem)).toEqual(await exportPkcs8Der(rsa.privateKey));
		expect(await exportPkcs8Der(rsaFromDer)).toEqual(await exportPkcs8Der(rsa.privateKey));

		const ec = await generateKeyPair({ kind: 'ecdsa', namedCurve: 'P-256' });
		const sec1Pem = await exportSec1Pem(ec.privateKey);
		const sec1Der = await exportSec1Der(ec.privateKey);
		const ecFromPem = await importSec1Pem(sec1Pem, {
			kind: 'ecdsa',
			namedCurve: 'P-256',
		});
		const ecFromDer = await importSec1Der(sec1Der, {
			kind: 'ecdsa',
			namedCurve: 'P-256',
		});
		expect(await exportPkcs8Der(ecFromPem)).toEqual(await exportPkcs8Der(ec.privateKey));
		expect(await exportPkcs8Der(ecFromDer)).toEqual(await exportPkcs8Der(ec.privateKey));
	});

	it('roundtrips encrypted PKCS#8 helpers', async () => {
		const keyPair = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const cases = [
			{ encryption: 'aes128-cbc', prf: 'hmac-sha1' },
			{ encryption: 'aes128-cbc', prf: 'hmac-sha256' },
			{ encryption: 'aes192-cbc', prf: 'hmac-sha1' },
			{ encryption: 'aes192-cbc', prf: 'hmac-sha256' },
			{ encryption: 'aes256-cbc', prf: 'hmac-sha1' },
			{ encryption: 'aes256-cbc', prf: 'hmac-sha256' },
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
			const importedPem = await importEncryptedPkcs8Pem(pem, 'secret123', {
				kind: 'rsa',
			});
			const importedDer = await importEncryptedPkcs8Der(der, 'secret123', {
				kind: 'rsa',
			});
			expect(await exportPkcs8Der(importedPem)).toEqual(await exportPkcs8Der(keyPair.privateKey));
			expect(await exportPkcs8Der(importedDer)).toEqual(await exportPkcs8Der(keyPair.privateKey));
		}

		const pem = await exportEncryptedPkcs8Pem(keyPair.privateKey, {
			password: 'secret123',
		});
		expect(importEncryptedPkcs8Pem(pem, 'wrong', { kind: 'rsa' })).rejects.toThrow(
			'Invalid password or encrypted content',
		);
	});

	it('roundtrips encrypted traditional RSA and EC PEM helpers', async () => {
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const encryptedRsaPem = await exportEncryptedPkcs1Pem(rsa.privateKey, {
			password: 'secret123',
		});
		const importedRsa = await importEncryptedPkcs1Pem(encryptedRsaPem, 'secret123', {
			kind: 'rsa',
		});
		expect(await exportPkcs8Der(importedRsa)).toEqual(await exportPkcs8Der(rsa.privateKey));
		expect(importEncryptedPkcs1Pem(encryptedRsaPem, 'wrong', { kind: 'rsa' })).rejects.toThrow(
			'Invalid password or encrypted PEM content',
		);

		const ec = await generateKeyPair({ kind: 'ecdsa', namedCurve: 'P-256' });
		const encryptedEcPem = await exportEncryptedSec1Pem(ec.privateKey, {
			password: 'secret123',
		});
		const importedEc = await importEncryptedSec1Pem(encryptedEcPem, 'secret123', {
			kind: 'ecdsa',
			namedCurve: 'P-256',
		});
		expect(await exportPkcs8Der(importedEc)).toEqual(await exportPkcs8Der(ec.privateKey));
	});

	it('roundtrips keys through PEM, base64, and JWK imports', async () => {
		const original = await generateKeyPair({
			kind: 'rsa',
			modulusLength: 2048,
		});
		const importedPublic = await importSpkiPem(await original.exportSpkiPem(), {
			kind: 'rsa',
		});
		const importedPrivate = await importPkcs8Pem(await original.exportPkcs8Pem(), { kind: 'rsa' });
		const base64Public = await importSpkiBase64(await exportBinaryBase64(original.publicKey), {
			kind: 'rsa',
		});
		const base64Private = await importPkcs8Base64(await exportBinaryBase64(original.privateKey), {
			kind: 'rsa',
		});
		const jwkPublic = await importPublicJwk(await original.exportPublicJwk(), {
			kind: 'rsa',
		});
		const jwkPrivate = await importPrivateJwk(await original.exportPrivateJwk(), { kind: 'rsa' });

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

	it('imports and exports keys via ecdsa and ed25519', async () => {
		const ecP384 = await generateKeyPair({
			kind: 'ecdsa',
			namedCurve: 'P-384',
		});
		const ecPub = await importSpkiBase64(await exportBinaryBase64(ecP384.publicKey), {
			kind: 'ecdsa',
			namedCurve: 'P-384',
		});
		const ecPriv = await importPkcs8Base64(await exportBinaryBase64(ecP384.privateKey), {
			kind: 'ecdsa',
			namedCurve: 'P-384',
		});
		expect(await exportSpkiDer(ecPub)).toEqual(await ecP384.exportSpkiDer());
		expect(await exportPkcs8Der(ecPriv)).toEqual(await ecP384.exportPkcs8Der());

		const ed = await generateKeyPair({ kind: 'ed25519' });
		const edPub = await importSpkiPem(await ed.exportSpkiPem(), {
			kind: 'ed25519',
		});
		const edPriv = await importPkcs8Pem(await ed.exportPkcs8Pem(), {
			kind: 'ed25519',
		});
		expect(await exportSpkiDer(edPub)).toEqual(await ed.exportSpkiDer());
		expect(await exportPkcs8Der(edPriv)).toEqual(await ed.exportPkcs8Der());
	});

	it('accepts RSA-PSS and ECDSA P-521 key inputs', async () => {
		const rsaPss = await generateKeyPair({
			kind: 'rsa',
			scheme: 'pss',
			hash: 'SHA-256',
		});
		expect(rsaPss.privateKey.algorithm.name).toBe('RSA-PSS');

		const rsaPssPublic = await importSpkiPem(await rsaPss.exportSpkiPem(), {
			kind: 'rsa',
			scheme: 'pss',
			hash: 'SHA-256',
		});
		expect(rsaPssPublic.algorithm.name).toBe('RSA-PSS');

		const ecP521 = await generateKeyPair({
			kind: 'ecdsa',
			namedCurve: 'P-521',
		});
		const ecP521Public = await importSpkiBase64(await exportBinaryBase64(ecP521.publicKey), {
			kind: 'ecdsa',
			namedCurve: 'P-521',
		});
		const ecP521Private = await importPkcs8Base64(await exportBinaryBase64(ecP521.privateKey), {
			kind: 'ecdsa',
			namedCurve: 'P-521',
		});
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
		const ecKeys = await generateKeyPair({ kind: 'ecdsa', namedCurve: 'P-256' });
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
		const reimported = await importPkcs1Der(pkcs1Der, {
			kind: 'rsa',
			hash: 'SHA-512',
		});
		expect(reimported.type).toBe('private');
	});

	it('round-trips EC P-384 keys through SEC1', async () => {
		const keys = await generateKeyPair({
			kind: 'ecdsa',
			namedCurve: 'P-384',
		});
		const sec1Der = await exportSec1Der(keys.privateKey);
		expect(sec1Der.length).toBeGreaterThan(40);
		const sec1Pem = await exportSec1Pem(keys.privateKey);
		expect(sec1Pem).toContain('BEGIN EC PRIVATE KEY');
		const reimported = await importSec1Der(sec1Der, {
			kind: 'ecdsa',
			namedCurve: 'P-384',
		});
		expect(reimported.type).toBe('private');
	});

	it('round-trips EC P-521 keys through SEC1', async () => {
		const keys = await generateKeyPair({
			kind: 'ecdsa',
			namedCurve: 'P-521',
		});
		const sec1Der = await exportSec1Der(keys.privateKey);
		expect(sec1Der.length).toBeGreaterThan(60);
		const sec1Pem = await exportSec1Pem(keys.privateKey);
		expect(sec1Pem).toContain('BEGIN EC PRIVATE KEY');
		const reimported = await importSec1Pem(sec1Pem, {
			kind: 'ecdsa',
			namedCurve: 'P-521',
		});
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
			const reimported = await importEncryptedPkcs1Pem(encrypted, 'testpass', {
				kind: 'rsa',
			});
			expect(reimported.type).toBe('private');
		}
	});

	it('round-trips encrypted SEC1 PEM for EC keys', async () => {
		const keys = await generateKeyPair({
			kind: 'ecdsa',
			namedCurve: 'P-256',
		});
		for (const cipher of ['AES-128-CBC', 'AES-192-CBC', 'AES-256-CBC'] as const) {
			const encrypted = await exportEncryptedSec1Pem(keys.privateKey, {
				password: 'ecpass',
				cipher,
			});
			expect(encrypted).toContain('Proc-Type: 4,ENCRYPTED');
			expect(encrypted).toContain(`DEK-Info: ${cipher}`);
			const reimported = await importEncryptedSec1Pem(encrypted, 'ecpass', {
				kind: 'ecdsa',
				namedCurve: 'P-256',
			});
			expect(reimported.type).toBe('private');
		}
	});

	it('PKCS#8 base64 import works for Ed25519 keys', async () => {
		const keys = await generateKeyPair({ kind: 'ed25519' });
		const base64 = await exportBinaryBase64(keys.privateKey);
		const reimported = await importPkcs8Base64(base64, { kind: 'ed25519' });
		expect(reimported.type).toBe('private');
	});
});

describe('keys: coverage — malformed inputs', () => {
	it('importEncryptedPkcs8Der throws on malformed EncryptedPrivateKeyInfo (missing OCTET STRING)', async () => {
		// SEQUENCE with only one child (algorithmIdentifier) and no encryptedData
		const { sequence, objectIdentifier, nullValue } = await import(
			'#micro509/internal/asn1/der.ts'
		);
		const malformed = sequence([
			sequence([objectIdentifier('1.2.840.113549.1.5.13'), nullValue()]),
		]);
		expect(
			importEncryptedPkcs8Der(malformed, 'pass', { kind: 'ecdsa', namedCurve: 'P-256' }),
		).rejects.toThrow('Malformed EncryptedPrivateKeyInfo');
	});

	it('importEncryptedPkcs8Der throws when second child is not OCTET STRING', async () => {
		const { sequence, objectIdentifier, nullValue, integerFromNumber } = await import(
			'#micro509/internal/asn1/der.ts'
		);
		// second child is INTEGER (tag 0x02), not OCTET STRING (tag 0x04)
		const malformed = sequence([
			sequence([objectIdentifier('1.2.840.113549.1.5.13'), nullValue()]),
			integerFromNumber(42),
		]);
		expect(
			importEncryptedPkcs8Der(malformed, 'pass', { kind: 'ecdsa', namedCurve: 'P-256' }),
		).rejects.toThrow('Malformed EncryptedPrivateKeyInfo');
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
		expect(
			importEncryptedSec1Pem(encrypted, 'test', { kind: 'ecdsa', namedCurve: 'P-256' }),
		).rejects.toThrow('Expected EC PRIVATE KEY PEM block');
	});

	it('decryptTraditionalPem throws when Proc-Type/DEK-Info headers are missing', async () => {
		// A plain (unencrypted) RSA PEM has no encryption headers
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const plainPem = await exportPkcs1Pem(rsa.privateKey);
		expect(importEncryptedPkcs1Pem(plainPem, 'test', { kind: 'rsa' })).rejects.toThrow(
			'encryption headers missing',
		);
	});

	it('decryptTraditionalPem throws on unsupported cipher', async () => {
		// Build a PEM with a non-AES-256-CBC cipher header
		const rsa = await generateKeyPair({ kind: 'rsa', modulusLength: 2048 });
		const encrypted = await exportEncryptedPkcs1Pem(rsa.privateKey, { password: 'test' });
		// Replace AES-256-CBC with DES-EDE3-CBC in the header
		const tampered = encrypted.replace('AES-256-CBC', 'DES-EDE3-CBC');
		expect(importEncryptedPkcs1Pem(tampered, 'test', { kind: 'rsa' })).rejects.toThrow(
			'Only AES-128-CBC, AES-192-CBC, and AES-256-CBC',
		);
	});

	it('parseTraditionalPem throws on non-PEM input', async () => {
		expect(importEncryptedPkcs1Pem('not a pem block', 'test', { kind: 'rsa' })).rejects.toThrow(
			'Invalid PEM block',
		);
	});

	it('parseTraditionalPem throws when BEGIN/END labels mismatch', async () => {
		const badPem = '-----BEGIN RSA PRIVATE KEY-----\nYWJj\n-----END EC PRIVATE KEY-----';
		expect(importEncryptedPkcs1Pem(badPem, 'test', { kind: 'rsa' })).rejects.toThrow(
			'PEM boundaries do not match',
		);
	});
});
