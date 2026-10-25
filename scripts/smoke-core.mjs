/**
 * Shared smoke assertions, run in every supported runtime (Node, Deno, workerd, browser).
 * @module
 */

import { rfc9106Vectors } from '../test/fixtures/argon2.mjs';
import { forgeExponentOneJwt } from '../test/fixtures/jose-exponent-one.mjs';
import * as legacyOaep from '../test/fixtures/rsa-oaep-sha1.mjs';

/**
 * @param {typeof import('#micro509')} micro509
 * @param {typeof import('#micro509/crypto')} cryptoApi
 * @param {typeof import('#micro509/kdf')} kdfApi
 * @param {typeof import('#micro509/ssh')} sshApi
 * @param {typeof import('#micro509/jose')} joseApi
 */
export async function runSmoke(micro509, cryptoApi, kdfApi, sshApi, joseApi) {
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
	await runSshSmoke(micro509, sshApi);
	await runJoseSmoke(micro509, joseApi);
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

/**
 * @param {typeof import('#micro509')} micro509
 * @param {typeof import('#micro509/ssh')} sshApi
 */
async function runSshSmoke(micro509, sshApi) {
	/** @type {readonly import('#micro509/keys').KeyAlgorithmInput[]} */
	const algorithms = [
		{ kind: 'rsa', modulusLength: 2048 },
		{ kind: 'ed25519' },
		{ kind: 'ecdsa', curve: 'P-256' },
		{ kind: 'ecdsa', curve: 'P-384' },
		{ kind: 'ecdsa', curve: 'P-521' },
	];
	for (const algorithm of algorithms) {
		const pair = await micro509.generateKeyPair(algorithm);
		const comment = '\ufeffsmoke@host';
		const line = await sshApi.exportSshPublicKey(pair.publicKey, { comment });
		const file = await sshApi.exportOpenSshPrivateKey(pair.privateKey, { comment });
		const pub = micro509.unwrap(await sshApi.importSshPublicKey(line));
		const priv = micro509.unwrap(await sshApi.importOpenSshPrivateKey(file));
		if (
			pub.comment !== comment ||
			priv.comment !== comment ||
			pub.fingerprint !== priv.fingerprint ||
			pub.fingerprint !== (await sshApi.sshFingerprintSha256(pair.publicKey))
		) {
			throw new Error(`smoke: SSH ${algorithm.kind} round-trip failed`);
		}
		const invalid = await sshApi.importSshPublicKey(line, { minRsaModulusBits: NaN });
		if (invalid.ok || invalid.error.code !== 'invalid_options') {
			throw new Error('smoke: SSH accepted an invalid policy');
		}
	}
}

/**
 * Signs and verifies a JWT, resolves its key from a local JWK Set, and proves none of it uses the network.
 * @param {typeof import('#micro509')} micro509
 * @param {typeof import('#micro509/jose')} joseApi
 */
async function runJoseSmoke(micro509, joseApi) {
	const originalFetch = globalThis.fetch;
	let requests = 0;
	const guarded = Reflect.set(globalThis, 'fetch', () => {
		requests += 1;
		throw new Error('smoke: JOSE used the network');
	});
	try {
		const keys = await micro509.generateKeyPair({ kind: 'rsa' });
		const now = Math.floor(Date.now() / 1000);
		const token = await joseApi.signJwt({
			privateKey: keys.privateKey,
			algorithm: 'RS256',
			header: { kid: 'smoke-1' },
			claims: { iss: 'https://smoke.example', aud: 'smoke', exp: now + 60 },
		});
		const policy = { issuer: 'https://smoke.example', audience: 'smoke' };
		const direct = await joseApi.verifyJwt(token, {
			algorithms: ['RS256'],
			key: keys.publicKey,
			tokenType: 'JWT',
			claims: policy,
		});
		if (!direct.ok || direct.value.registered.iss !== 'https://smoke.example') {
			throw new Error('smoke: JWT verification failed');
		}

		const jwks = joseApi.parseJwks(
			JSON.stringify({ keys: [{ ...(await keys.exportPublicJwk()), kid: 'smoke-1', use: 'sig' }] }),
		);
		if (!jwks.ok) throw new Error(`smoke: parseJwks failed: ${jwks.code}`);
		const viaJwks = await joseApi.verifyJwt(token, {
			algorithms: ['RS256'],
			key: joseApi.createJwksKeyResolver(jwks.value),
			tokenType: 'JWT',
			claims: policy,
		});
		if (!viaJwks.ok) throw new Error('smoke: JWKS verification failed');
		await runExponentOneSmoke(joseApi, keys.publicKey, now);

		const [header, body, signature] = token.split('.');
		const forged = `${header}.${body}.${signature?.slice(0, -4)}AAAA`;
		const refused = await joseApi.verifyJwt(forged, {
			algorithms: ['RS256'],
			key: keys.publicKey,
			tokenType: 'JWT',
			claims: policy,
		});
		if (refused.ok || refused.code !== 'invalid_signature') {
			throw new Error('smoke: a forged JWT was not refused');
		}

		joseApi.createRemoteJwksKeyResolver({ url: 'https://smoke.example/jwks.json' });
		if (requests !== 0) throw new Error('smoke: JOSE made a request before it was needed');
	} finally {
		if (guarded) Reflect.set(globalThis, 'fetch', originalFetch);
	}
}

/**
 * @param {typeof import('#micro509/jose')} joseApi
 * @param {CryptoKey} publicKey
 * @param {number} now
 */
async function runExponentOneSmoke(joseApi, publicKey, now) {
	const forged = await forgeExponentOneJwt(publicKey, {
		iss: 'https://smoke.example',
		aud: 'smoke',
		exp: now + 60,
	});
	const parsed = joseApi.parseJwks(JSON.stringify({ keys: [forged.jwk] }));
	if (!parsed.ok) throw new Error(`smoke: exponent-one JWKS did not parse: ${parsed.code}`);
	const policy = {
		algorithms: /** @type {const} */ (['RS256']),
		tokenType: 'JWT',
		claims: { issuer: 'https://smoke.example', audience: 'smoke' },
	};
	const resolved = await joseApi.verifyJwt(forged.token, {
		...policy,
		key: joseApi.createJwksKeyResolver(parsed.value),
	});
	if (resolved.ok || resolved.code !== 'key_unsuitable') {
		throw new Error('smoke: local JWKS accepted a public-material-only exponent-one forgery');
	}
	let key;
	try {
		key = await crypto.subtle.importKey(
			'jwk',
			forged.jwk,
			{
				name: 'RSASSA-PKCS1-v1_5',
				hash: 'SHA-256',
			},
			false,
			['verify'],
		);
	} catch (error) {
		// Some runtimes reject the invalid RSA key before JOSE receives a CryptoKey.
		if (
			error instanceof Error &&
			['DataError', 'OperationError', 'NotSupportedError'].includes(error.name)
		)
			return;
		throw error;
	}
	if (key.extractable) throw new Error('smoke: exponent-one key must be non-extractable');
	const direct = await joseApi.verifyJwt(forged.token, { ...policy, key });
	if (direct.ok || direct.code !== 'key_unsuitable') {
		throw new Error('smoke: CryptoKey accepted a public-material-only exponent-one forgery');
	}
}
