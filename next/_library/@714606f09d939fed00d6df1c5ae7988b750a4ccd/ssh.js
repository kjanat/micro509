import { a as isResultError, c as rethrowIfInvariant, d as unwrap, l as successResult, n as failureResult, u as throwMicro509Error } from "./result-C9WPk47A.js";
import { a as pemDecodeOrThrow, d as base64Encode, o as pemEncode, u as base64Decode } from "./pem-C5BecCKu.js";
import { v as toArrayBuffer, w as concatBytes } from "./asn1-jyOu_Jva.js";
import { U as importPublicJwkOrThrow, V as importPrivateJwkOrThrow, g as exportPublicJwk, h as exportPrivateJwk, pt as getCrypto } from "./keys-BmJSvvnO.js";
// ../../dist/ssh/wire.js
const n = [
	"invalid_options",
	"malformed",
	"unsupported",
	"limit_exceeded",
	"key_mismatch"
];
/** The {@linkcode SshErrorCode} spelled `code`, if it is one. */
function asSshErrorCode(e) {
	return n.find((t) => t === e);
}
/** Throws a `ResultError` carrying an {@linkcode SshErrorCode}. */
function sshFail(t, n) {
	return throwMicro509Error(t, n);
}
/** Creates an {@linkcode SshReader} over `data`. */
function createSshReader(e) {
	let t = 0, remaining = () => e.length - t, raw = (n) => {
		if (n > remaining()) return sshFail("malformed", "SSH data is truncated");
		let r = e.subarray(t, t + n);
		return t += n, r;
	}, uint32 = () => {
		let e = raw(4);
		return new DataView(e.buffer, e.byteOffset, 4).getUint32(0, !1);
	}, string = (e) => {
		let t = uint32();
		return t > e ? sshFail("limit_exceeded", `SSH string of ${t} bytes exceeds ${e}`) : raw(t);
	};
	return {
		remaining,
		uint32,
		raw,
		string,
		name: () => {
			let e = string(64);
			return e.length === 0 || e.some((e) => e < 33 || e > 126) ? sshFail("malformed", "SSH name is not printable US-ASCII") : String.fromCharCode(...e);
		},
		text: (e) => {
			let t = string(e);
			return t.includes(0) ? sshFail("malformed", "SSH text contains a NUL byte") : decodeUtf8(t);
		},
		mpint: (e) => {
			let t = string(e), n = t[0], r = t[1];
			return n === void 0 ? sshFail("malformed", "SSH key integer is zero") : n >= 128 ? sshFail("malformed", "SSH key integer is negative") : n === 0 ? r === void 0 || r < 128 ? sshFail("malformed", "SSH integer has a redundant leading zero byte") : t.subarray(1) : t;
		}
	};
}
/** Strict UTF-8 decode; invalid sequences are malformed input. */
function decodeUtf8(e) {
	try {
		return new TextDecoder("utf-8", {
			fatal: !0,
			ignoreBOM: !0
		}).decode(e);
	} catch {
		return sshFail("malformed", "SSH text is not valid UTF-8");
	}
}
/** Encodes a `uint32` (RFC 4251 §5). */
function sshUint32(e) {
	let t = /* @__PURE__ */ new Uint8Array(4);
	return new DataView(t.buffer).setUint32(0, e, !1), t;
}
/** Encodes a `string` (RFC 4251 §5). */
function sshString(e) {
	return concatBytes([sshUint32(e.length), e]);
}
/** Encodes a US-ASCII or UTF-8 text `string`. */
function sshTextString(e) {
	return sshString(new TextEncoder().encode(e));
}
/** Encodes a non-negative integer, given as a big-endian magnitude, as an `mpint` (RFC 4251 §5). */
function sshMpint(e) {
	let n = e.findIndex((e) => e !== 0);
	if (n === -1) return sshUint32(0);
	let r = e.subarray(n);
	return sshString((r[0] ?? 0) >= 128 ? concatBytes([Uint8Array.of(0), r]) : r);
}
/** Big-endian magnitude of a non-negative `bigint`. */
function bigintToBytes(e, t) {
	let n = e.toString(16);
	n.length % 2 == 1 && (n = `0${n}`);
	let r = new Uint8Array(n.length / 2);
	for (let e = 0; e < r.length; e++) r[e] = Number.parseInt(n.slice(e * 2, e * 2 + 2), 16);
	if (t === void 0) return r;
	if (r.length > t) return sshFail("malformed", "SSH integer is larger than its field");
	let i = new Uint8Array(t);
	return i.set(r, t - r.length), i;
}
/** The non-negative `bigint` of a big-endian magnitude. */
function bytesToBigint(e) {
	let t = 0n;
	for (let n of e) t = t << 8n | BigInt(n);
	return t;
}
/** Whether two byte strings are equal. */
function bytesEqual(e, t) {
	return e.length === t.length && e.every((e, n) => e === t[n]);
}
// ../../dist/ssh/ssh.js
/**
* OpenSSH public-key lines, unencrypted `openssh-key-v1` private keys, and
* `SHA256:` fingerprints for RSA, Ed25519, and ECDSA on P-256, P-384 and P-521.
*
* Keys move through the existing WebCrypto, JWK and PKCS#8/SPKI APIs of
* `micro509/keys`. Nothing here opens a connection, speaks the SSH transport,
* reads SSH certificates, evaluates `authorized_keys` options, or decrypts a
* private key.
*
* The `ssh-rsa` key type names the RSA public-key encoding (RFC 4253 §6.6). It
* does not select a signature hash: RFC 8332 §3 keeps the `ssh-rsa` key format
* for the `rsa-sha2-256` and `rsa-sha2-512` signature algorithms. Importing an
* `ssh-rsa` key enables no SHA-1 signature.
*
* @example
* ```ts
* import { generateKeyPair, unwrap } from 'micro509';
* import {
* 	exportOpenSshPrivateKey,
* 	exportSshPublicKey,
* 	importOpenSshPrivateKey,
* } from 'micro509/ssh';
*
* const keys = await generateKeyPair({ kind: 'ed25519' });
* const line = await exportSshPublicKey(keys.publicKey, { comment: 'me@host' });
* const pem = await exportOpenSshPrivateKey(keys.privateKey, { comment: 'me@host' });
* const imported = unwrap(await importOpenSshPrivateKey(pem));
* console.log(line, imported.fingerprint);
* ```
*
* @module
*/
const O = 32768;
const k = 2049;
const A = 8192;
const j = 16384;
const M = "OPENSSH PRIVATE KEY";
const N = Uint8Array.from("openssh-key-v1", (e) => e.charCodeAt(0));
const P = [
	"ssh-rsa",
	"ssh-ed25519",
	"ecdsa-sha2-nistp256",
	"ecdsa-sha2-nistp384",
	"ecdsa-sha2-nistp521"
];
function asSshKeyType(e) {
	return P.find((t) => t === e);
}
const F = {
	"P-256": {
		identifier: "nistp256",
		size: 32,
		hash: "SHA-256",
		prime: 2n ** 256n - 2n ** 224n + 2n ** 192n + 2n ** 96n - 1n,
		b: 41058363725152142129326129780047268409114441015993725554835256314039467401291n
	},
	"P-384": {
		identifier: "nistp384",
		size: 48,
		hash: "SHA-384",
		prime: 2n ** 384n - 2n ** 128n - 2n ** 96n + 2n ** 32n - 1n,
		b: 27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575n
	},
	"P-521": {
		identifier: "nistp521",
		size: 66,
		hash: "SHA-512",
		prime: 2n ** 521n - 1n,
		b: 1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984n
	}
};
const I = [
	"P-256",
	"P-384",
	"P-521"
];
const L = {
	"ecdsa-sha2-nistp256": "P-256",
	"ecdsa-sha2-nistp384": "P-384",
	"ecdsa-sha2-nistp521": "P-521"
};
function resolveImportOptions(e) {
	if (typeof e != "object" || !e || Array.isArray(e)) return sshFail("invalid_options", "SSH import options must be an object");
	let t = e.minRsaModulusBits === void 0 ? 2048 : e.minRsaModulusBits;
	if (!Number.isSafeInteger(t) || t < 1 || t > j) return sshFail("invalid_options", "minRsaModulusBits must be an integer from 1 to 16384");
	let n = e.acceptCompressedEcPoints !== void 0 && e.acceptCompressedEcPoints;
	if (typeof n != "boolean") return sshFail("invalid_options", "acceptCompressedEcPoints must be a boolean");
	let r = e.rsa === void 0 ? {} : e.rsa;
	if (typeof r != "object" || !r || Array.isArray(r)) return sshFail("invalid_options", "rsa must be an object");
	let i = r.scheme === void 0 ? "pkcs1-v1_5" : r.scheme, a = r.hash === void 0 ? "SHA-256" : r.hash;
	return i !== "pkcs1-v1_5" && i !== "pss" ? sshFail("invalid_options", "Unsupported RSA signature scheme") : a !== "SHA-256" && a !== "SHA-384" && a !== "SHA-512" ? sshFail("invalid_options", "Unsupported RSA signature hash") : {
		minRsaModulusBits: t,
		acceptCompressedEcPoints: n,
		rsaScheme: i,
		rsaHash: a
	};
}
function unhandledKey(e) {
	throw Error(`Unhandled SSH key: ${String(e)}`);
}
function keyTypeOf(e) {
	switch (e.kind) {
		case "rsa": return "ssh-rsa";
		case "ed25519": return "ssh-ed25519";
		case "ecdsa": return `ecdsa-sha2-${F[e.curve].identifier}`;
		default: return unhandledKey(e);
	}
}
function bitLength(e) {
	return (e.length - 1) * 8 + 32 - Math.clz32(e[0] ?? 0);
}
function algorithmOf(e) {
	switch (e.kind) {
		case "rsa": return {
			kind: "rsa",
			modulusBits: bitLength(e.n)
		};
		case "ecdsa": return {
			kind: "ecdsa",
			curve: e.curve
		};
		case "ed25519": return { kind: "ed25519" };
		default: return unhandledKey(e);
	}
}
function toBase64Url(e) {
	return base64Encode(e).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromBase64Url(e) {
	let t = e.replace(/-/g, "+").replace(/_/g, "/");
	return base64Decode(t.padEnd(Math.ceil(t.length / 4) * 4, "="));
}
function modPow(e, t, n) {
	let r = 1n, i = e % n, a = t;
	for (; a > 0n;) (a & 1n) == 1n && (r = r * i % n), i = i * i % n, a >>= 1n;
	return r;
}
function decompressPoint(e, t, n) {
	let { prime: r, b: i, size: a } = F[e], o = bytesToBigint(n);
	if (o >= r) return sshFail("malformed", "ECDSA point coordinate is out of range");
	let s = (((o * o - 3n) * o + i) % r + r) % r, c = modPow(s, (r + 1n) / 4n, r);
	if (c * c % r !== s) return sshFail("malformed", "ECDSA point is not on the curve");
	let l = t === 3;
	return bigintToBytes((c & 1n) == 1n === l ? c : r - c, a);
}
function readPoint(e, t, n) {
	let { size: r } = F[e], i = t[0];
	if (i === 4 && t.length === 1 + 2 * r) return {
		x: t.subarray(1, 1 + r),
		y: t.subarray(1 + r)
	};
	if ((i === 2 || i === 3) && t.length === 1 + r) {
		if (!n.acceptCompressedEcPoints) return sshFail("unsupported", "Compressed ECDSA points need acceptCompressedEcPoints");
		let r = t.subarray(1);
		return {
			x: r,
			y: decompressPoint(e, i, r)
		};
	}
	return sshFail("malformed", "ECDSA point encoding is invalid");
}
function readRsaPublic(e, t, n) {
	let r = e.mpint(k), i = e.mpint(k), [a, o] = t === "e-n" ? [r, i] : [i, r], s = bitLength(o);
	if (s > j) return sshFail("limit_exceeded", `RSA modulus of ${s} bits exceeds ${j}`);
	if (s < n.minRsaModulusBits) return sshFail("unsupported", `RSA modulus of ${s} bits is below ${n.minRsaModulusBits}`);
	let c = bytesToBigint(a);
	return c < 3n || (c & 1n) == 0n || c >= bytesToBigint(o) ? sshFail("malformed", "RSA public exponent is invalid") : {
		kind: "rsa",
		e: a,
		n: o
	};
}
function readEcdsaPublic(e, t, n) {
	return e.name() === F[t].identifier ? {
		kind: "ecdsa",
		curve: t,
		...readPoint(t, e.string(A), n)
	} : sshFail("key_mismatch", "ECDSA curve identifier disagrees with the key type");
}
function readEd25519Public(e) {
	let t = e.string(A);
	return t.length === 32 ? {
		kind: "ed25519",
		x: t
	} : sshFail("malformed", "Ed25519 public key is not 32 bytes");
}
function decodePublicBlob(e, t) {
	let n = createSshReader(e), r = asSshKeyType(n.name());
	if (r === void 0) return sshFail("unsupported", "Unsupported SSH key type");
	let i;
	switch (r) {
		case "ssh-rsa":
			i = readRsaPublic(n, "e-n", t);
			break;
		case "ssh-ed25519":
			i = readEd25519Public(n);
			break;
		case "ecdsa-sha2-nistp256":
		case "ecdsa-sha2-nistp384":
		case "ecdsa-sha2-nistp521":
			i = readEcdsaPublic(n, L[r], t);
			break;
		default: return unhandledKey(r);
	}
	return n.remaining() === 0 ? i : sshFail("malformed", "SSH public key has trailing data");
}
function ecPoint(e) {
	return concatBytes([
		Uint8Array.of(4),
		e.x,
		e.y
	]);
}
function encodePublicBlob(e) {
	let t = sshTextString(keyTypeOf(e));
	switch (e.kind) {
		case "rsa": return concatBytes([
			t,
			sshMpint(e.e),
			sshMpint(e.n)
		]);
		case "ed25519": return concatBytes([t, sshString(e.x)]);
		case "ecdsa": return concatBytes([
			t,
			sshTextString(F[e.curve].identifier),
			sshString(ecPoint(e))
		]);
		default: return unhandledKey(e);
	}
}
function samePublicMaterial(e, t) {
	return bytesEqual(encodePublicBlob(e), encodePublicBlob(t));
}
function publicJwk(e) {
	switch (e.kind) {
		case "rsa": return {
			kty: "RSA",
			n: toBase64Url(e.n),
			e: toBase64Url(e.e)
		};
		case "ecdsa": return {
			kty: "EC",
			crv: e.curve,
			x: toBase64Url(e.x),
			y: toBase64Url(e.y)
		};
		case "ed25519": return {
			kty: "OKP",
			crv: "Ed25519",
			x: toBase64Url(e.x)
		};
		default: return unhandledKey(e);
	}
}
function privateJwk(e) {
	switch (e.kind) {
		case "rsa": {
			let t = bytesToBigint(e.d), n = bytesToBigint(e.p), r = bytesToBigint(e.q);
			return {
				...publicJwk(e.pub),
				d: toBase64Url(e.d),
				p: toBase64Url(e.p),
				q: toBase64Url(e.q),
				dp: toBase64Url(bigintToBytes(t % (n - 1n))),
				dq: toBase64Url(bigintToBytes(t % (r - 1n))),
				qi: toBase64Url(e.iqmp)
			};
		}
		case "ecdsa": return {
			...publicJwk(e.pub),
			d: toBase64Url(bigintToBytes(bytesToBigint(e.d), F[e.pub.curve].size))
		};
		case "ed25519": return {
			...publicJwk(e.pub),
			d: toBase64Url(e.seed)
		};
		default: return unhandledKey(e);
	}
}
function importInputFor(e, t) {
	switch (e.kind) {
		case "rsa": return {
			kind: "rsa",
			scheme: t.rsaScheme,
			hash: t.rsaHash
		};
		case "ecdsa": return {
			kind: "ecdsa",
			curve: e.curve
		};
		case "ed25519": return { kind: "ed25519" };
		default: return unhandledKey(e);
	}
}
function signParams(e, t) {
	switch (e.kind) {
		case "rsa": return t.rsaScheme === "pss" ? {
			name: "RSA-PSS",
			saltLength: 32
		} : { name: "RSASSA-PKCS1-v1_5" };
		case "ecdsa": return {
			name: "ECDSA",
			hash: F[e.curve].hash
		};
		case "ed25519": return { name: "Ed25519" };
		default: return unhandledKey(e);
	}
}
async function importPublicMaterial(e, t) {
	return await importPublicJwkOrThrow(publicJwk(e), importInputFor(e, t));
}
async function importPrivateMaterial(e, t, r) {
	try {
		return await importPrivateJwkOrThrow(privateJwk(e), importInputFor(t, r));
	} catch (e) {
		return rethrowIfInvariant(e), sshFail("key_mismatch", "Private key material is invalid for the embedded public key");
	}
}
async function assertKeyPairConsistent(e, t, n, r) {
	let { subtle: i } = getCrypto(), a = getCrypto().getRandomValues(/* @__PURE__ */ new Uint8Array(32)), o = signParams(n, r), s = await i.sign(o, e, a);
	await i.verify(o, t, s, a) || sshFail("key_mismatch", "Private key does not match the embedded public key");
}
async function sha256Fingerprint(e) {
	let t = new Uint8Array(await getCrypto().subtle.digest("SHA-256", toArrayBuffer(e)));
	return `SHA256:${base64Encode(t).replace(/=+$/, "")}`;
}
function textOf(e, t) {
	return typeof e == "string" ? e.length > t || new TextEncoder().encode(e).length > t ? sshFail("limit_exceeded", `SSH key input exceeds ${t} bytes`) : e : e.length > t ? sshFail("limit_exceeded", `SSH key input exceeds ${t} bytes`) : decodeUtf8(e);
}
const R = /^([^ \t]+)[ \t]+([A-Za-z0-9+/]+={0,2})(?:[ \t]+(.*))?$/s;
async function decodePublicKeyLine(e, t) {
	let n = textOf(e, 16384).replace(/\r?\n$/, "");
	if (/[\r\n]/.test(n)) return sshFail("malformed", "SSH public key must be a single line");
	let r = R.exec(n);
	if (r === null) return sshFail("malformed", "SSH public key line is not \"<type> <base64> [comment]\"");
	let [, i = "", a = "", o = ""] = r;
	assertImportedComment(o);
	let s = asSshKeyType(i);
	if (s === void 0) return sshFail("unsupported", "Unsupported SSH key type");
	let c = decodePublicBlob(base64Decode(a), t);
	return keyTypeOf(c) === s ? {
		keyType: s,
		algorithm: algorithmOf(c),
		publicKey: await importPublicMaterial(c, t),
		comment: o,
		fingerprint: await sha256Fingerprint(encodePublicBlob(c))
	} : sshFail("key_mismatch", "Line key type disagrees with the key blob");
}
function readPrivateMaterial(e, t, n) {
	if (e.name() !== t) return sshFail("key_mismatch", "Private section key type disagrees with the public key");
	switch (t) {
		case "ssh-rsa": return {
			kind: "rsa",
			pub: readRsaPublic(e, "n-e", n),
			d: e.mpint(k),
			iqmp: e.mpint(k),
			p: e.mpint(k),
			q: e.mpint(k)
		};
		case "ssh-ed25519": {
			let t = readEd25519Public(e), n = e.string(A);
			return n.length === 64 ? bytesEqual(n.subarray(32), t.x) ? {
				kind: "ed25519",
				pub: t,
				seed: n.subarray(0, 32)
			} : sshFail("key_mismatch", "Ed25519 private key suffix differs from the public key") : sshFail("malformed", "Ed25519 private key is not 64 bytes");
		}
		case "ecdsa-sha2-nistp256":
		case "ecdsa-sha2-nistp384":
		case "ecdsa-sha2-nistp521": {
			let r = readEcdsaPublic(e, L[t], n), i = e.mpint(k);
			return i.length > F[r.curve].size ? sshFail("malformed", "ECDSA private scalar is larger than the curve order") : {
				kind: "ecdsa",
				pub: r,
				d: i
			};
		}
		default: return unhandledKey(t);
	}
}
function assertRsaConsistent(e) {
	let t = bytesToBigint(e.pub.n), n = bytesToBigint(e.pub.e), r = bytesToBigint(e.d), i = bytesToBigint(e.p), a = bytesToBigint(e.q), o = bytesToBigint(e.iqmp);
	(i < 3n || a < 3n || i * a !== t) && sshFail("key_mismatch", "RSA primes do not multiply to the modulus"), (r >= t || r * n % (i - 1n) != 1n || r * n % (a - 1n) != 1n) && sshFail("key_mismatch", "RSA private exponent does not match the public exponent"), (o >= i || o * a % i !== 1n) && sshFail("key_mismatch", "RSA coefficient is not the inverse of q modulo p");
}
function assertPadding(e) {
	let t = e.raw(e.remaining());
	t.length >= 8 && sshFail("malformed", "OpenSSH private key padding is too long"), t.forEach((e, t) => {
		e !== t + 1 && sshFail("malformed", "OpenSSH private key padding is invalid");
	});
}
async function decodePrivateKey(e, t) {
	let n = textOf(e, O), r = pemDecodeOrThrow(M, n);
	try {
		return await decodePrivateBinary(r, t);
	} finally {
		r.fill(0);
	}
}
async function decodePrivateBinary(e, t) {
	let n = createSshReader(e), r = n.raw(N.length + 1);
	if (!bytesEqual(r.subarray(0, N.length), N) || r[N.length] !== 0) return sshFail("malformed", "Missing openssh-key-v1 magic");
	let i = n.name(), a = n.name();
	if (i !== "none" || a !== "none") return sshFail("unsupported", "Encrypted OpenSSH private keys are not supported");
	if (n.string(A).length !== 0) return sshFail("malformed", "KDF options must be empty for kdf none");
	let o = n.uint32();
	if (o === 0) return sshFail("malformed", "OpenSSH private key file holds no keys");
	if (o > 1) return sshFail("unsupported", "OpenSSH private key files with several keys are not supported");
	let s = decodePublicBlob(n.string(A), t), c = n.string(O);
	if (n.remaining() !== 0) return sshFail("malformed", "OpenSSH private key file has trailing data");
	if (c.length === 0 || c.length % 8 != 0) return sshFail("malformed", "OpenSSH private section is not a multiple of the block size");
	let l = createSshReader(c);
	if (l.uint32() !== l.uint32()) return sshFail("malformed", "OpenSSH check integers differ");
	let u = readPrivateMaterial(l, keyTypeOf(s), t), d = l.text(A);
	if (assertImportedComment(d), assertPadding(l), !samePublicMaterial(s, u.pub)) return sshFail("key_mismatch", "Private section public key differs from the file public key");
	u.kind === "rsa" && assertRsaConsistent(u);
	let f = await importPublicMaterial(s, t), p = await importPrivateMaterial(u, s, t);
	return await assertKeyPairConsistent(p, f, s, t), {
		keyType: keyTypeOf(s),
		algorithm: algorithmOf(s),
		publicKey: f,
		privateKey: p,
		comment: d,
		fingerprint: await sha256Fingerprint(encodePublicBlob(s))
	};
}
async function toSshResult(i) {
	try {
		return successResult(await i());
	} catch (r) {
		if (isResultError(r)) {
			let t = asSshErrorCode(r.code);
			if (t !== void 0) return failureResult(t, r.error.message);
		}
		return rethrowIfInvariant(r), failureResult("malformed", r instanceof Error ? r.message : "Malformed SSH key");
	}
}
/**
* Import an OpenSSH public-key line (`<type> <base64> [comment]`).
*
* Reads `ssh-rsa`, `ssh-ed25519`, and `ecdsa-sha2-nistp256/384/521` keys as
* written by `ssh-keygen` into `.pub` files. The line key type must equal the
* type inside the blob (RFC 4253 §6.6), an ECDSA curve identifier must equal
* its key type suffix (RFC 5656 §3.1), and trailing data after the blob is
* rejected. Fields are separated by spaces or tabs, one trailing line break
* is allowed, and everything after the base64 field is the comment.
* `authorized_keys` options and SSH certificate types are not read.
*
* Input is capped at 16 KiB and RSA moduli at 16384 bits. `input` is never
* modified.
*
* @param input - The line as text or UTF-8 bytes
* @param options - Policy options; see {@linkcode SshImportOptions}
* @returns The WebCrypto verification key, its comment and its SHA-256 fingerprint
*
* @see {@linkcode importSshPublicKeyOrThrow} for the throwing variant
* @see {@linkcode exportSshPublicKey} for the inverse operation
*/
function importSshPublicKey(e, t = {}) {
	return toSshResult(() => decodePublicKeyLine(e, resolveImportOptions(t)));
}
/**
* Throwing variant of {@linkcode importSshPublicKey}.
*
* @throws {ResultError} Carrying an {@linkcode SshErrorCode} as `code`
*/
async function importSshPublicKeyOrThrow(e, t = {}) {
	return unwrap(await importSshPublicKey(e, t));
}
/**
* Import an unencrypted single-key `openssh-key-v1` private key file.
*
* Accepts the `-----BEGIN OPENSSH PRIVATE KEY-----` PEM that `ssh-keygen`
* writes for RSA, Ed25519 and ECDSA P-256/P-384/P-521 keys. The cipher and
* KDF must both be `none` with empty KDF options; any other value returns
* `unsupported`, as does a file holding several keys. The check integers,
* the `1, 2, 3, ...` padding, the block alignment, and the absence of trailing
* bytes are verified, and RSA integers must be canonical positive `mpint`s.
*
* The public key embedded in the file must equal the public half of the
* private section and its key type, or the result is `key_mismatch`. The
* private material is then checked cryptographically: for RSA, `p·q = n`,
* `d·e ≡ 1` modulo both `p-1` and `q-1`, and `iqmp·q ≡ 1 (mod p)`; for every
* key, a signature made with the private key must verify under the embedded
* public key. For Ed25519 the 32-byte suffix of the private field must equal
* the public key.
*
* Both keys are returned extractable. The decoded binary copy of the file is
* zeroed before returning. JavaScript strings, including the PEM text and the
* JWK members used for the import, cannot be zeroed, and `input` is never
* modified.
*
* @param input - The PEM file as text or UTF-8 bytes, at most 32 KiB
* @param options - Policy options; see {@linkcode SshImportOptions}
*
* @see {@linkcode importOpenSshPrivateKeyOrThrow} for the throwing variant
* @see {@linkcode exportOpenSshPrivateKey} for the inverse operation
*/
function importOpenSshPrivateKey(e, t = {}) {
	return toSshResult(() => decodePrivateKey(e, resolveImportOptions(t)));
}
/**
* Throwing variant of {@linkcode importOpenSshPrivateKey}.
*
* @throws {ResultError} Carrying an {@linkcode SshErrorCode} as `code`
*/
async function importOpenSshPrivateKeyOrThrow(e, t = {}) {
	return unwrap(await importOpenSshPrivateKey(e, t));
}
function exportFail(e, t) {
	return throwMicro509Error(e, t);
}
function validCommentText(e) {
	return typeof e == "string" && e.isWellFormed() && !/[\r\n\0]/.test(e);
}
function oversizedComment(e) {
	return e.length > A || new TextEncoder().encode(e).length > A;
}
function assertImportedComment(e) {
	validCommentText(e) || sshFail("malformed", "Comment must be well-formed Unicode without CR, LF or NUL"), oversizedComment(e) && sshFail("limit_exceeded", "Comment exceeds 8192 UTF-8 bytes");
}
function assertComment(e) {
	(!validCommentText(e) || oversizedComment(e)) && exportFail("invalid_comment", "Comment must be well-formed Unicode without CR, LF or NUL and at most 8192 UTF-8 bytes");
}
function assertExportable(e, t) {
	e.type !== t && exportFail("invalid_key", `Expected a ${t} key`), e.extractable || exportFail("not_extractable", "The key must be extractable");
}
function jwkBytes(e, t) {
	let n = e[t];
	if (typeof n != "string") throw Error(`WebCrypto key export lacks JWK member ${t}`);
	return fromBase64Url(n);
}
function publicMaterialFromJwk(e, t) {
	if (e.kty === "RSA") return {
		kind: "rsa",
		e: jwkBytes(e, "e"),
		n: jwkBytes(e, "n")
	};
	if (e.kty === "OKP" && e.crv === "Ed25519" && t === "Ed25519") return {
		kind: "ed25519",
		x: jwkBytes(e, "x")
	};
	if (e.kty === "EC" && t === "ECDSA") {
		let t = I.find((t) => t === e.crv);
		if (t !== void 0) return {
			kind: "ecdsa",
			curve: t,
			x: jwkBytes(e, "x"),
			y: jwkBytes(e, "y")
		};
	}
	return exportFail("unsupported_algorithm", "Only RSA, ECDSA P-256/384/521 and Ed25519 are supported");
}
/**
* Export a public key as an OpenSSH public-key line.
*
* Writes `<type> <base64> [comment]` with padded base64 and no trailing line
* break, the form `ssh-keygen` puts in `.pub` files. ECDSA points are written
* uncompressed. The key must be an extractable RSA, ECDSA (P-256, P-384,
* P-521) or Ed25519 public `CryptoKey`.
*
* @throws {ResultError} Carrying an {@linkcode SshExportErrorCode} as `code`
*
* @see {@linkcode importSshPublicKey} for the inverse operation
*/
async function exportSshPublicKey(e, t = {}) {
	let n = t.comment === void 0 ? "" : t.comment;
	assertComment(n), assertExportable(e, "public");
	let r = publicMaterialFromJwk(await exportPublicJwk(e), e.algorithm.name), i = `${keyTypeOf(r)} ${base64Encode(encodePublicBlob(r))}`;
	return n === "" ? i : `${i} ${n}`;
}
/**
* Export a private key as an unencrypted `openssh-key-v1` PEM file.
*
* The file holds one key, cipher `none` and KDF `none`, with the check
* integers drawn from the WebCrypto random source and the public key derived
* from the private key. `ssh-keygen` reads it directly. Check integers are
* random, so compare keys, not file bytes, between two exports.
*
* The private `CryptoKey` must be extractable. The binary encoding is zeroed
* after the PEM text is built; the returned string and the JWK used for the
* export cannot be zeroed.
*
* @throws {ResultError} Carrying an {@linkcode SshExportErrorCode} as `code`
*
* @see {@linkcode importOpenSshPrivateKey} for the inverse operation
*/
async function exportOpenSshPrivateKey(e, t = {}) {
	let n = t.comment === void 0 ? "" : t.comment;
	assertComment(n), assertExportable(e, "private");
	let r = await exportPrivateJwk(e), i = publicMaterialFromJwk(r, e.algorithm.name), a = privateFields(i, r), s = getCrypto().getRandomValues(/* @__PURE__ */ new Uint32Array(1))[0] ?? 0, l = concatBytes([
		sshUint32(s),
		sshUint32(s),
		sshTextString(keyTypeOf(i)),
		a,
		sshTextString(n)
	]), u = (8 - l.length % 8) % 8, d = concatBytes([l, Uint8Array.from({ length: u }, (e, t) => t + 1)]), m = concatBytes([
		N,
		Uint8Array.of(0),
		sshTextString("none"),
		sshTextString("none"),
		sshUint32(0),
		sshUint32(1),
		sshString(encodePublicBlob(i)),
		sshString(d)
	]);
	try {
		return pemEncode(M, m);
	} finally {
		l.fill(0), d.fill(0), m.fill(0), a.fill(0);
	}
}
function privateFields(e, t) {
	switch (e.kind) {
		case "rsa": return concatBytes([
			sshMpint(e.n),
			sshMpint(e.e),
			sshMpint(jwkBytes(t, "d")),
			sshMpint(jwkBytes(t, "qi")),
			sshMpint(jwkBytes(t, "p")),
			sshMpint(jwkBytes(t, "q"))
		]);
		case "ecdsa": return concatBytes([
			sshTextString(F[e.curve].identifier),
			sshString(ecPoint(e)),
			sshMpint(jwkBytes(t, "d"))
		]);
		case "ed25519": return concatBytes([sshString(e.x), sshString(concatBytes([jwkBytes(t, "d"), e.x]))]);
		default: return unhandledKey(e);
	}
}
/**
* The `SHA256:` fingerprint `ssh-keygen -l -E sha256` prints for a key.
*
* It is the SHA-256 digest of the SSH public-key blob (RFC 4253 §6.6 layout),
* base64-encoded without padding and prefixed with `SHA256:`. It differs from a
* certificate fingerprint and from a digest of the SPKI encoding. Pass a
* public or private `CryptoKey`, or the raw blob bytes (the decoded base64
* field of a public-key line). A private key must be extractable.
*
* @throws {ResultError} Carrying an {@linkcode SshExportErrorCode} when a `CryptoKey` cannot be encoded
*/
async function sshFingerprintSha256(e) {
	return e instanceof Uint8Array ? await sha256Fingerprint(e) : (e.type === "secret" && exportFail("invalid_key", "Expected a public or private key"), assertExportable(e, e.type), await sha256Fingerprint(encodePublicBlob(publicMaterialFromJwk(e.type === "private" ? await exportPrivateJwk(e) : await exportPublicJwk(e), e.algorithm.name))));
}
export { exportOpenSshPrivateKey, exportSshPublicKey, importOpenSshPrivateKey, importOpenSshPrivateKeyOrThrow, importSshPublicKey, importSshPublicKeyOrThrow, sshFingerprintSha256 };
