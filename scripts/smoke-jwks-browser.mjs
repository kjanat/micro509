/** Real browser HTTP-cache regression for remote key rotation. @module */

/**
 * @param {typeof import('#micro509/jose')} joseApi
 * @param {(jwks: {keys: (JsonWebKey & {kid: string, use: string})[]}) => Promise<void>} publishJwks
 */
export async function runJwksRotationSmoke(joseApi, publishJwks) {
	const first = await crypto.subtle.generateKey(
		{
			name: 'RSASSA-PKCS1-v1_5',
			modulusLength: 2048,
			publicExponent: new Uint8Array([1, 0, 1]),
			hash: 'SHA-256',
		},
		true,
		['sign', 'verify'],
	);
	const rotated = await crypto.subtle.generateKey(
		{
			name: 'RSASSA-PKCS1-v1_5',
			modulusLength: 2048,
			publicExponent: new Uint8Array([1, 0, 1]),
			hash: 'SHA-256',
		},
		true,
		['sign', 'verify'],
	);
	let now = Date.now();
	const resolver = joseApi.createRemoteJwksKeyResolver({
		url: new URL('/rotation-jwks.json', location.href),
		cooldownMs: 30_000,
		now: () => now,
	});
	for (const [kid, pair] of /** @type {const} */ ([
		['initial', first],
		['rotated', rotated],
	])) {
		await publishJwks({
			keys: [{ ...(await crypto.subtle.exportKey('jwk', pair.publicKey)), kid, use: 'sig' }],
		});
		const token = await joseApi.signJwt({
			privateKey: pair.privateKey,
			algorithm: 'RS256',
			header: { kid },
			claims: { iss: 'browser-rotation', aud: 'smoke', exp: Math.floor(Date.now() / 1000) + 3600 },
		});
		const verified = await joseApi.verifyJwt(token, {
			algorithms: ['RS256'],
			key: resolver,
			tokenType: 'JWT',
			claims: { issuer: 'browser-rotation', audience: 'smoke' },
		});
		if (!verified.ok) throw new Error(`browser JWKS ${kid}: ${verified.code}`);
		now += 30_001;
	}
}
