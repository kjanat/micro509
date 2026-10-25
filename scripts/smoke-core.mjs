/**
 * Shared smoke assertions, run in every supported runtime (Node, Deno, workerd, browser).
 * @module
 */

import { rfc9106Vectors } from '../test/fixtures/argon2.mjs';
import * as legacyOaep from '../test/fixtures/rsa-oaep-sha1.mjs';

/**
 * @param {typeof import('#micro509')} micro509
 * @param {typeof import('#micro509/crypto')} cryptoApi
 * @param {typeof import('#micro509/kdf')} kdfApi
 */
export async function runSmoke(micro509, cryptoApi, kdfApi) {
	const { signData, verifySignatureWithKey } = cryptoApi;
	const { certificate, keyPair } = await micro509.createSelfSignedCertificate({
		subject: { commonName: 'smoke.example' },
		validity: { days: 1 },
	});

	const parsed = micro509.unwrap(micro509.parseCertificatePem(certificate.pem));
	if (parsed.subject.values.commonName !== 'smoke.example') {
		throw new Error('smoke: parsed commonName mismatch');
	}

	const verified = await micro509.verifyCertificateChain({
		leaf: certificate.pem,
		roots: [certificate.pem],
		allowSelfSignedLeaf: true,
	});
	if (!verified.ok) {
		throw new Error(`smoke: verifyCertificateChain failed: ${verified.error.code}`);
	}

	const data = new TextEncoder().encode('detached smoke payload');
	const signed = await signData(keyPair.privateKey, data);
	const publicKey = await crypto.subtle.importKey(
		'jwk',
		await micro509.exportPublicJwk(keyPair.publicKey),
		{ name: 'ECDSA', namedCurve: 'P-256' },
		false,
		['verify'],
	);
	const input = {
		publicKey,
		signatureAlgorithm: { oid: signed.algorithmOid },
		/** @type {'der'} */
		signatureEncoding: 'der',
		signature: signed.signature,
		data,
	};
	const valid = await verifySignatureWithKey(input);
	const changed = await verifySignatureWithKey({ ...input, data: new Uint8Array([0]) });
	if (publicKey.extractable || !valid.ok || !valid.valid || !changed.ok || changed.valid) {
		throw new Error('smoke: reused non-extractable public key verification failed');
	}

	const legacyKey = await micro509.importPkcs8DerOrThrow(
		Uint8Array.from(atob(legacyOaep.pkcs8), (char) => char.charCodeAt(0)),
		{ kind: 'rsa', scheme: 'oaep', hash: 'SHA-1' },
	);
	const decrypted = await micro509.decryptRsaOaepOrThrow(
		legacyKey,
		Uint8Array.from(atob(legacyOaep.ciphertext), (char) => char.charCodeAt(0)),
	);
	if (new TextDecoder().decode(decrypted) !== legacyOaep.plaintext) {
		throw new Error('smoke: independently generated SHA-1 OAEP ciphertext failed');
	}

	await runArgon2Smoke(kdfApi);
	return 'smoke OK';
}

/** @param {typeof import('#micro509/kdf')} kdfApi */
async function runArgon2Smoke(kdfApi) {
	for (const { input, expected } of rfc9106Vectors) {
		let available = true;
		try {
			await Reflect.apply(crypto.subtle.importKey, crypto.subtle, [
				'raw-secret',
				input.password,
				input.algorithm === 'argon2id' ? 'Argon2id' : 'Argon2d',
				false,
				['deriveBits'],
			]);
		} catch (error) {
			if (!(error instanceof Error) || error.name !== 'NotSupportedError') throw error;
			available = false;
		}
		const derived = await kdfApi.deriveArgon2(input);
		if (available) {
			if (!derived.ok) throw new Error(`smoke: native Argon2 failed: ${derived.error.code}`);
			const actual = Array.from(derived.value, (byte) => byte.toString(16).padStart(2, '0')).join(
				'',
			);
			if (actual !== expected) throw new Error('smoke: Argon2 RFC 9106 vector mismatch');
			derived.value.fill(0);
		} else if (derived.ok || derived.error.code !== 'unsupported') {
			throw new Error('smoke: unavailable native Argon2 must report unsupported');
		}
	}
}
