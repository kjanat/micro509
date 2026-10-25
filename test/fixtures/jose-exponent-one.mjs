/** Public-material-only RS256 forgery against the invalid RSA exponent e=1. @module */

/** @param {Uint8Array} bytes */
function base64url(bytes) {
	return btoa(String.fromCharCode(...bytes))
		.replaceAll('+', '-')
		.replaceAll('/', '_')
		.replace(/=+$/, '');
}

/**
 * Builds an EMSA-PKCS1-v1_5 block directly. With exponent one the signature is
 * the encoded digest itself. No private key or signing operation is involved.
 * @param {CryptoKey} publicKey A generated RSA public key supplies a realistic modulus.
 * @param {Readonly<Record<string, unknown>>} claims JWT claims encoded in the forged token.
 */
export async function forgeExponentOneJwt(publicKey, claims) {
	const exported = await crypto.subtle.exportKey('jwk', publicKey);
	if (typeof exported.n !== 'string') throw new Error('Fixture requires an RSA public key');
	const kid = 'forged-exponent-one';
	const header = base64url(
		new TextEncoder().encode(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid })),
	);
	const payload = base64url(new TextEncoder().encode(JSON.stringify(claims)));
	const signingInput = `${header}.${payload}`;
	const digest = new Uint8Array(
		await crypto.subtle.digest('SHA-256', new TextEncoder().encode(signingInput)),
	);
	const digestInfoPrefix = Uint8Array.from([
		0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
		0x00, 0x04, 0x20,
	]);
	const modulusBytes = atob(exported.n.replaceAll('-', '+').replaceAll('_', '/')).length;
	const encoded = new Uint8Array(modulusBytes).fill(0xff);
	encoded[0] = 0;
	encoded[1] = 1;
	const separator = modulusBytes - digestInfoPrefix.length - digest.length - 1;
	if (separator < 10) throw new Error('Fixture RSA modulus is too small');
	encoded[separator] = 0;
	encoded.set(digestInfoPrefix, separator + 1);
	encoded.set(digest, separator + 1 + digestInfoPrefix.length);
	return {
		token: `${signingInput}.${base64url(encoded)}`,
		jwk: { ...exported, e: 'AQ', kid, alg: 'RS256', use: 'sig' },
	};
}
