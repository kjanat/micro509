/** Regenerates public, synthetic JOSE migration fixtures. No production keys or tokens. @module */
import { Buffer } from 'node:buffer';
import { CompactSign, exportJWK, generateKeyPair, SignJWT } from 'jose-v5';
import type { JsonObject, VerifyJwtErrorCode } from '#micro509/jose';
import { signJwt } from '#micro509/jose';

const now = 1_900_000_000;
const issuer = 'https://issuer.example';
const audience = 'api://orders';
const [primary, secondary, unsupported] = await Promise.all([
	generateKeyPair('RS256', { extractable: true }),
	generateKeyPair('RS256', { extractable: true }),
	generateKeyPair('PS256', { extractable: true }),
]);
const primaryJwk = await exportJWK(primary.privateKey);
const nativePrivate = await crypto.subtle.importKey(
	'jwk',
	primaryJwk,
	{ name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
	false,
	['sign'],
);
const claims: JsonObject = {
	iss: issuer,
	aud: audience,
	sub: 'synthetic-user',
	name: 'café 🦊',
	roles: ['reader'],
	iat: now,
	nbf: now,
	exp: now + 300,
};
const encode = (text: string) => Buffer.from(text, 'utf8').toString('base64url');
const signed = (value: JsonObject) =>
	new SignJWT(value)
		.setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'primary' })
		.sign(primary.privateKey);
interface Fixture {
	readonly id: string;
	readonly token: string;
	readonly micro: 'ok' | VerifyJwtErrorCode;
	readonly joseAccepts: boolean;
	readonly difference?: string;
}
const cases: Fixture[] = [];
function add(
	id: string,
	token: string,
	micro: Fixture['micro'],
	joseAccepts: boolean,
	difference?: string,
): void {
	cases.push({
		id,
		token,
		micro,
		joseAccepts,
		...(difference === undefined ? {} : { difference }),
	});
}
const valid = await signed(claims);
add('valid-unicode', valid, 'ok', true);
const parts = valid.split('.');
add(
	'tampered-payload',
	`${parts[0]}.${encode(JSON.stringify({ ...claims, name: 'changed' }))}.${parts[2]}`,
	'invalid_signature',
	false,
);
const signature = Buffer.from(parts[2] ?? '', 'base64url');
signature[0] = (signature[0] ?? 0) ^ 1;
add(
	'tampered-signature',
	`${parts[0]}.${parts[1]}.${signature.toString('base64url')}`,
	'invalid_signature',
	false,
);
add(
	'wrong-key',
	await new SignJWT(claims)
		.setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: 'primary' })
		.sign(secondary.privateKey),
	'invalid_signature',
	false,
);
add(
	'untrusted-issuer',
	await signed({ ...claims, iss: 'https://untrusted.example' }),
	'issuer_mismatch',
	false,
);
add(
	'audience-mismatch',
	await signed({ ...claims, aud: 'api://elsewhere' }),
	'audience_mismatch',
	false,
);
const { exp: _exp, ...withoutExpiry } = claims;
add(
	'missing-exp',
	await signed(withoutExpiry),
	'missing_claim',
	true,
	'micro509 requires exp by default; jose does not unless requiredClaims is set.',
);
add('expired', await signed({ ...claims, exp: now - 1 }), 'expired', false);
add('exp-at-now', await signed({ ...claims, exp: now }), 'expired', false);
add(
	'future-iat',
	await signed({ ...claims, iat: now + 1 }),
	'issued_in_future',
	true,
	'micro509 rejects future iat by default; jose checks it when maxTokenAge is configured.',
);
add('future-nbf', await signed({ ...claims, nbf: now + 1 }), 'not_yet_valid', false);
add('nbf-at-now', await signed({ ...claims, nbf: now }), 'ok', true);
const { roles: _roles, ...withoutRoles } = claims;
add('schema-missing-roles', await signed(withoutRoles), 'ok', true);
add('schema-mistyped-roles', await signed({ ...claims, roles: 'reader' }), 'ok', true);
const ps256 = await new SignJWT(claims)
	.setProtectedHeader({ alg: 'PS256', typ: 'JWT' })
	.sign(unsupported.privateKey);
add('signed-unsupported-PS256', ps256, 'algorithm_not_allowed', false);
add(
	'unsecured-none',
	`${encode('{"alg":"none","typ":"JWT"}')}.${encode(JSON.stringify(claims))}.`,
	'unsigned_token',
	false,
);
add('malformed-segments', 'a.b', 'malformed_token', false);
add('invalid-base64url', `${parts[0]}.A.${parts[2]}`, 'invalid_encoding', false);
const invalidUtf8 = await new CompactSign(Uint8Array.of(0xff))
	.setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
	.sign(primary.privateKey);
add('signed-invalid-utf8', invalidUtf8, 'invalid_utf8', false);
// Sign the exact bytes independently to exercise duplicate and padded encodings without placeholder signatures.
async function raw(header: string, payload: string): Promise<string> {
	const input = `${header}.${payload}`;
	const signature = await crypto.subtle.sign(
		'RSASSA-PKCS1-v1_5',
		nativePrivate,
		new TextEncoder().encode(input),
	);
	return `${input}.${Buffer.from(signature).toString('base64url')}`;
}
add(
	'signed-duplicate-header',
	await raw(encode('{"alg":"RS256","alg":"RS256","typ":"JWT"}'), encode(JSON.stringify(claims))),
	'duplicate_member',
	true,
	'micro509 rejects duplicate members; jose accepts the lexically last member.',
);
let paddedHeader = Buffer.from('{"alg":"RS256","typ":"JWT"} ', 'utf8').toString('base64');
// Keep base64url alphabet while deliberately retaining padding.
paddedHeader = paddedHeader.replaceAll('+', '-').replaceAll('/', '_');
add(
	'signed-padded-header',
	await raw(paddedHeader, encode(JSON.stringify(claims))),
	'invalid_encoding',
	true,
	'micro509 requires canonical unpadded base64url; jose accepts this padded protected segment.',
);
const reverse = await signJwt({
	privateKey: nativePrivate,
	algorithm: 'RS256',
	header: { kid: 'primary' },
	claims,
});
const corpus = {
	provenance: {
		producer:
			'jose 5.10.0 + raw WebCrypto for deliberately noncanonical signed cases; micro509 for reverse token',
		regeneration: 'bun scripts/generate-jose-migration-fixtures.ts',
		synthetic: true,
		providerDiversity: false,
	},
	now,
	issuer,
	audience,
	claims,
	keys: {
		primary: await exportJWK(primary.publicKey),
		secondary: await exportJWK(secondary.publicKey),
		unsupported: await exportJWK(unsupported.publicKey),
	},
	cases,
	reverse: { token: reverse, producer: 'micro509 signJwt' },
};
await Bun.write(
	new URL('../site/assets/fixtures/jose-migration.json', import.meta.url),
	`${JSON.stringify(corpus, null, '\t')}\n`,
);
console.log(`Generated ${cases.length} synthetic migration cases and one reverse token`);
