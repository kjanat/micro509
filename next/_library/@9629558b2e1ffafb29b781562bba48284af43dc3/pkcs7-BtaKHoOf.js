import { a as isResultError, c as rethrowIfInvariant, l as successResult, n as failureResult, s as n, u as throwMicro509Error } from "./result-C9WPk47A.js";
import { D as explicitContext, F as integerFromNumber, G as sequence, H as readIdentifier, I as nullValue, K as setOf, L as objectIdentifier, P as integer, R as octetString, S as bmpString, T as encodeLength, U as readRootElement, V as readElement, W as readSequenceChildren, Y as tlv, _ as requireElement, d as decodeString, et as decodeFailureResult, it as throwDecodeRefusal, m as hexToBytes, nt as i, o as decodeIntegerMagnitude, r as childrenOf, s as decodeIntegerNumber, tt as decodeRefusalOf, u as decodeObjectIdentifier, v as toArrayBuffer, w as concatBytes, y as toHex } from "./asn1-jyOu_Jva.js";
import { at as decryptPbes2, ct as f, dt as isWrongPasswordError, ft as p, gt as t, it as createKdfBudget, lt as h, mt as getCrypto, ot as derivePbkdf2Bytes, p as exportPkcs8Der, rt as chargeKdfBudget, st as encryptPbes2, ut as isKdfIterationLimitError } from "./keys--ezXXsdp.js";
import { c as splitPemBlocksOrThrow, f as base64Encode, o as pemEncode } from "./pem-DDW-AzkK.js";
import { n as getSignatureAlgorithm, r as signBytes, t as encodeAlgorithmIdentifier } from "./signing-D1WtGOZO.js";
import { Mt as describeHashAlgorithm, Nt as describeSignatureAlgorithm, _ as parseCertificateDerOrThrow, ot as compareDistinguishedNames, ut as nameFieldKeyFromOid } from "./parse-IPfTS_-5.js";
import { n as verifySignedDataDetailed, t as getVerifySignatureConfigResult } from "./sig-verify-BKSwk3FP.js";
// ../../dist/internal/asn1/ber.js
const a = /* @__PURE__ */ new Set([
	4,
	7,
	12,
	18,
	19,
	20,
	21,
	22,
	23,
	24,
	25,
	26,
	27,
	28,
	30
]);
function readBerRoot(e, t = 64) {
	if (!Number.isSafeInteger(t) || t < 1) throw RangeError("BER max depth must be a positive safe integer");
	let n = readBerElement(e, 0, e.length, 1, t);
	if (n.end !== e.length) throw Error("Trailing data after BER element");
	return n;
}
function berEncoding(e, t) {
	return e.slice(t.headerStart, t.end);
}
function berPrimitiveContent(e, t, n) {
	if (t.tag !== n || n & 32) throw Error(`Expected primitive BER tag 0x${n.toString(16)}`);
	return e.slice(t.start, t.contentEnd);
}
function berSequenceChildren(e) {
	if (e.tag !== 48) throw Error("Expected SEQUENCE");
	return e.children;
}
function berStringContent(e, n, r, i = r) {
	if (n.tag === r) return berPrimitiveContent(e, n, r);
	if (n.tag !== (r | 32)) throw Error(`Expected BER string tag 0x${r.toString(16)}`);
	return concatBytes(n.children.map((t) => berStringContent(e, t, i)));
}
function definiteElement(e, r, i) {
	return concatBytes([
		e.subarray(r.headerStart, r.headerStart + r.identifierLength),
		encodeLength(i.length),
		i
	]);
}
function berToDefiniteLength(e, n) {
	if (!(n.tag & 32)) return definiteElement(e, n, e.slice(n.start, n.contentEnd));
	let r = n.tag & -33;
	return r === 3 ? tlv(3, bitStringContent(e, n)) : a.has(r) ? tlv(r, berStringContent(e, n, r)) : definiteElement(e, n, concatBytes(n.children.map((t) => berToDefiniteLength(e, t))));
}
function bitStringContent(e, n) {
	let r = bitStringSegments(e, n), i = r.at(-1);
	if (i === void 0) return Uint8Array.of(0);
	let a = [];
	for (let e of r) {
		let t = e[0];
		if (t === void 0 || t > 7) throw Error("Malformed BER BIT STRING segment");
		if (e !== i && t !== 0) throw Error("Only the last BER BIT STRING segment may have unused bits");
		if (e.length === 1 && t !== 0) throw Error("Empty BER BIT STRING segment must have zero unused bits");
		a.push(e.subarray(1));
	}
	return concatBytes([Uint8Array.of(i[0] ?? 0), ...a]);
}
function bitStringSegments(e, t) {
	if (t.tag === 3) return [e.slice(t.start, t.contentEnd)];
	if (t.tag !== 35) throw Error("Expected BER BIT STRING segment");
	return t.children.flatMap((t) => bitStringSegments(e, t));
}
function readBerElement(t, n, i, a, o) {
	a > o && throwDecodeRefusal("limit_exceeded", `BER exceeds max depth of ${o}`);
	let s = byteAt(t, n);
	if (s === 0) throw Error("Unexpected end-of-contents octets");
	let c = readIdentifier(t, n), l = n + c.length, u = byteAt(t, l), d = !!(s & 32);
	if (u === 128) {
		if (!d) throw Error("Indefinite length requires a constructed encoding");
		return readIndefiniteElement(t, n, c, i, a, o);
	}
	let { lengthOctets: f, length: p } = readDefiniteLength(t, l, u), m = l + f, h = m + p;
	if (h > i) throw Error("BER element exceeds its container");
	return {
		tag: s,
		tagNumber: c.tagNumber,
		headerStart: n,
		identifierLength: c.length,
		start: m,
		contentEnd: h,
		end: h,
		children: d ? readDefiniteChildren(t, m, h, a, o) : []
	};
}
function readIndefiniteElement(e, t, n, r, i, a) {
	let o = t + n.length + 1, s = [], c = o;
	for (; c < r && e[c] !== 0;) {
		let t = readBerElement(e, c, r, i + 1, a);
		s.push(t), c = t.end;
	}
	if (c + 1 >= r || e[c + 1] !== 0) throw Error("Missing end-of-contents octets");
	return {
		tag: n.tag,
		tagNumber: n.tagNumber,
		headerStart: t,
		identifierLength: n.length,
		start: o,
		contentEnd: c,
		end: c + 2,
		children: s
	};
}
function readDefiniteChildren(e, t, n, r, i) {
	let a = [], o = t;
	for (; o < n;) {
		let t = readBerElement(e, o, n, r + 1, i);
		a.push(t), o = t.end;
	}
	return a;
}
function readDefiniteLength(e, t, n) {
	if (!(n & 128)) return {
		lengthOctets: 1,
		length: n
	};
	let r = n & 127;
	if (r === 127) throw Error("Reserved BER length octet");
	let i = 0;
	for (let n = 0; n < r; n += 1) {
		let r = byteAt(e, t + 1 + n);
		if (i > Math.floor((2 ** 53 - 1 - r) / 256)) throw Error("BER length exceeds safe integer range");
		i = i * 256 + r;
	}
	return {
		lengthOctets: 1 + r,
		length: i
	};
}
function byteAt(e, t) {
	let n = e[t];
	if (n === void 0) throw Error("Unexpected end of BER input");
	return n;
}
// ../../dist/pkcs/pkcs12-mac.js
/**
* PKCS#12 MAC data creation and verification.
*
* Computes and verifies the password-based integrity check of a PFX: the
* RFC 7292 HMAC-SHA-256 MAC keyed by the PKCS#12 key-derivation scheme, and
* PBMAC1 (RFC 9879) keyed by PBKDF2.
*
* @module
*/
function throwPkcs12MacError(e, t) {
	throwMicro509Error(e, t);
}
/**
* Computes a PKCS#12 MAC over the AuthenticatedSafe and returns the DER-encoded MacData
* block alongside its parsed representation.
*
* @throws {ResultError} with code `invalid_iterations` when `iterations` is out of range,
* `password_not_bmp_string` when a `'pkcs12-kdf'` password contains a UTF-16 surrogate, U+FFFE
* or U+FFFF, and `password_not_utf8` when a `'pbmac1'` password contains an unpaired UTF-16
* surrogate.
*/
async function createPkcs12MacData(e, t$13) {
	if (t$13.type === "pbmac1") return await createPbmac1MacData(e, t$13);
	let n = t$13.iterations ?? 2048;
	(!Number.isSafeInteger(n) || n <= 0) && throwPkcs12MacError("invalid_iterations", `MacData iterations must be a positive safe integer, got ${n}`);
	let i = t$13.salt ?? getCrypto().getRandomValues(/* @__PURE__ */ new Uint8Array(16)), a = await computePkcs12Mac(e, t$13.password, i, n);
	return {
		der: sequence([
			sequence([sequence([objectIdentifier(t.sha256), nullValue()]), octetString(a)]),
			octetString(i),
			...n === 1 ? [] : [integerFromNumber(n)]
		]),
		parsed: {
			type: "pkcs12-kdf",
			digestAlgorithmOid: t.sha256,
			digestAlgorithmName: describeHashAlgorithm(t.sha256),
			digestHex: toHex(a),
			saltHex: toHex(i),
			iterations: n,
			verification: "valid"
		}
	};
}
async function createPbmac1MacData(e, t$14) {
	let n = t$14.iterations ?? 1e5;
	(!Number.isInteger(n) || n < 1 || n > 4294967295) && throwPkcs12MacError("invalid_iterations", `PBMAC1 iterations must be an integer from 1 to 4294967295, got ${n}`);
	let i = t$14.salt ?? getCrypto().getRandomValues(/* @__PURE__ */ new Uint8Array(16)), a = {
		salt: i,
		iterations: n,
		keyLength: 32,
		prf: "HMAC-SHA-256",
		messageAuthScheme: "HMAC-SHA-256"
	}, o = await computePbmac1(e, t$14.password, a), d = sequence([objectIdentifier(t.hmacWithSHA256), nullValue()]), m = sequence([objectIdentifier(t.pbmac1), sequence([sequence([objectIdentifier(t.pbkdf2), sequence([
		octetString(i),
		integerFromNumber(n),
		integerFromNumber(a.keyLength),
		d
	])]), d])]);
	return {
		der: sequence([sequence([m, octetString(o)]), octetString(i)]),
		parsed: {
			type: "pbmac1",
			digestAlgorithmOid: t.pbmac1,
			digestAlgorithmName: "PBMAC1",
			digestHex: toHex(o),
			saltHex: toHex(i),
			iterations: n,
			keyLength: a.keyLength,
			prf: a.prf,
			messageAuthScheme: a.messageAuthScheme,
			verification: "valid"
		}
	};
}
const O = [
	"password_not_bmp_string",
	"password_not_utf8",
	"unsupported_mac_algorithm",
	"weak_mac_key_length"
];
function throwMacDataError(e, t) {
	throwMicro509Error(e, t);
}
/**
* Throwing core for {@linkcode parsePkcs12MacData}. When `password` is
* provided, verifies the MAC and reports the outcome in `verification`, and
* throws before deriving when the iteration count exceeds
* `options.maxKdfIterations` or {@linkcode Number.MAX_SAFE_INTEGER}. The
* default limit is `100_000` for the PKCS#12 KDF and `2_000_000` for the
* PBKDF2 behind PBMAC1. Without `password` no key is derived, so
* `options.maxKdfIterations` is not applied and `verification` is
* `'unchecked'`. Throws a {@linkcode ResultError} carrying a
* {@linkcode ParsePkcs12MacDataErrorCode} for an unsupported MAC, a PBMAC1 key
* length below 20 octets, or a password the MAC cannot encode.
*/
async function parsePkcs12MacDataOrThrow(e, n, i, a) {
	let o = createKdfBudget(a, p), s = createKdfBudget(a, f), c = readSequenceChildren(e), l = c[0], u = c[1], f$1 = c[2];
	if (c.length !== 2 && c.length !== 3 || l === void 0 || u === void 0 || u.tag !== 4 || f$1 !== void 0 && f$1.tag !== 2) throw Error("Malformed MacData");
	let _ = e.slice(l.start - l.headerLength, l.end), b = readSequenceChildren(_), x = b[0], S = b[1];
	if (b.length !== 2 || x === void 0 || S === void 0 || S.tag !== 4) throw Error("Malformed DigestInfo");
	let C = _.slice(x.start - x.headerLength, x.end), w = readSequenceChildren(C), T = w[0];
	if (T === void 0 || w.length !== 1 && w.length !== 2) throw Error("MacData algorithm missing");
	let E = decodeObjectIdentifier(T.value);
	if (E === t.pbmac1) return await verifyPbmac1MacData(C, w[1], S.value, n, i, s);
	E !== t.sha256 && throwMacDataError("unsupported_mac_algorithm", `Only SHA-256 PKCS#12 MAC and PBMAC1 are supported, got ${describeHashAlgorithm(E)}`);
	let D = f$1 === void 0 ? 1 : decodeMacIterations(f$1.value, o, i, "MacData iterations");
	if (D === 0) throw Error("MacData iterations must be a positive safe integer");
	let O = {
		type: "pkcs12-kdf",
		digestAlgorithmOid: E,
		digestAlgorithmName: describeHashAlgorithm(E),
		digestHex: toHex(S.value),
		saltHex: toHex(u.value),
		iterations: D,
		verification: "unchecked"
	};
	if (i === void 0) return O;
	chargeKdfBudget(o, D);
	let k = await computePkcs12Mac(n, i, u.value, D);
	return {
		...O,
		verification: equalBytes(k, S.value) ? "valid" : "invalid"
	};
}
/**
* Decodes a DER-encoded MacData block. When `password` is provided, verifies
* the MAC and reports the outcome in `verification`.
*
* Returns a typed failure (`code: 'malformed'`) on malformed input, an
* iteration count below 1, or a PBMAC1 iteration count above 4294967295,
* `'unsupported_mac_algorithm'` for a MAC other than
* the RFC 7292 SHA-256 MAC or a PBMAC1 variant this implementation does not
* handle, `'weak_mac_key_length'` for a PBMAC1 key length below 20 octets,
* `'password_not_bmp_string'` when an RFC 7292 password contains a UTF-16
* surrogate, U+FFFE or U+FFFF, and `'password_not_utf8'` when a PBMAC1 password contains an
* unpaired UTF-16 surrogate. With a `password`, returns
* `code: 'kdf_iterations_exceeded'` when the iteration count exceeds
* `options.maxKdfIterations`, or an RFC 7292 MAC count exceeds
* {@linkcode Number.MAX_SAFE_INTEGER}. Without a `password` no key is derived:
* `options.maxKdfIterations` is not applied, an RFC 7292 MAC count above
* {@linkcode Number.MAX_SAFE_INTEGER} is `'malformed'`, and `verification` is
* `'unchecked'`. For the throwing form use {@linkcode parsePkcs12MacDataOrThrow}.
*/
async function parsePkcs12MacData(e, t, n, r) {
	try {
		return successResult(await parsePkcs12MacDataOrThrow(e, t, n, r));
	} catch (e) {
		if (rethrowIfInvariant(e), isKdfIterationLimitError(e)) return failureResult("kdf_iterations_exceeded", e.message);
		if (isResultError(e)) {
			let t = O.find((t) => t === e.code);
			if (t !== void 0) return failureResult(t, e.error.message);
		}
		return decodeFailureResult(e, i, "Malformed MacData");
	}
}
function decodeMacIterations(t, n, r, i) {
	let a = decodeIntegerMagnitude(t, i);
	if (a.type === "safe") return a.value;
	throw r !== void 0 && chargeKdfBudget(n, Infinity), Error(`${i} too large for safe number (${t.length} bytes)`);
}
async function verifyPbmac1MacData(e, t$15, n, i, a, o) {
	if (t$15 === void 0) throw Error("PBMAC1 parameters must be present");
	let s = parsePbmac1Parameters(e, t$15), c = {
		type: "pbmac1",
		digestAlgorithmOid: t.pbmac1,
		digestAlgorithmName: "PBMAC1",
		digestHex: toHex(n),
		saltHex: toHex(s.salt),
		iterations: s.iterations,
		keyLength: s.keyLength,
		prf: s.prf,
		messageAuthScheme: s.messageAuthScheme,
		verification: "unchecked"
	};
	if (a === void 0) return c;
	chargeKdfBudget(o, s.iterations);
	let l = await computePbmac1(i, a, s);
	return {
		...c,
		verification: equalBytes(l, n) ? "valid" : "invalid"
	};
}
function parsePbmac1Parameters(e, t$16) {
	if (t$16.tag !== 48) throw Error("Malformed PBMAC1-params");
	let n = e.slice(t$16.start - t$16.headerLength, t$16.end), r = readSequenceChildren(n), i = r[0], a = r[1];
	if (r.length !== 2 || i === void 0 || a === void 0) throw Error("Malformed PBMAC1-params");
	let o = readAlgorithmIdentifier(n, i, "PBMAC1 keyDerivationFunc");
	o.oid !== t.pbkdf2 && throwMacDataError("unsupported_mac_algorithm", `Unsupported PBMAC1 key derivation function ${o.oid}`);
	let s = parseHmacAlgorithm(readAlgorithmIdentifier(n, a, "PBMAC1 messageAuthScheme"), "PBMAC1 messageAuthScheme");
	return {
		...parsePbkdf2Parameters(o),
		messageAuthScheme: s
	};
}
function parsePbkdf2Parameters(t) {
	if (t.parameters === void 0 || t.parameters.tag !== 48) throw Error("Malformed PBKDF2-params");
	let n = t.der.slice(t.parameters.start - t.parameters.headerLength, t.parameters.end), [r, i, ...a] = readSequenceChildren(n);
	if (r === void 0 || i === void 0 || i.tag !== 2) throw Error("Malformed PBKDF2-params");
	if (r.tag === 48 && throwMacDataError("unsupported_mac_algorithm", "PBKDF2 otherSource salt is not supported"), r.tag !== 4) throw Error("Malformed PBKDF2 salt");
	let o = a[0]?.tag === 2 ? a[0] : void 0, s = o === void 0 ? a : a.slice(1), c = s[0];
	if (s.length > 1 || c !== void 0 && c.tag !== 48) throw Error("Malformed PBKDF2-params");
	if (o === void 0) throw Error("PBKDF2-params in PBMAC1 must include keyLength");
	c === void 0 && throwMacDataError("unsupported_mac_algorithm", "PBKDF2 prf is absent and defaults to HMAC-SHA-1, which PBMAC1 verification does not accept");
	let l = parseHmacAlgorithm(readAlgorithmIdentifier(n, c, "PBKDF2 prf"), "PBKDF2 prf"), u = decodeIntegerMagnitude(i.value, "PBKDF2 iterationCount");
	if (u.type === "unsafe" || u.value > 4294967295) throw Error(`PBKDF2 iterationCount must be at most ${h}`);
	if (u.value === 0) throw Error("PBKDF2 iterationCount must be at least 1");
	return {
		salt: new Uint8Array(r.value),
		iterations: u.value,
		keyLength: decodePbmac1KeyLength(o.value),
		prf: l
	};
}
function decodePbmac1KeyLength(t) {
	let n = decodeIntegerMagnitude(t, "PBKDF2 keyLength");
	if ((n.type === "unsafe" || n.value > 64) && throwMacDataError("unsupported_mac_algorithm", "PBKDF2 keyLength above 64 octets is not supported"), n.value === 0) throw Error("PBKDF2 keyLength must be at least 1");
	return n.value < 20 && throwMacDataError("weak_mac_key_length", `PBKDF2 keyLength ${n.value} is below 20 octets`), n.value;
}
function readAlgorithmIdentifier(e, n, r) {
	if (n.tag !== 48) throw Error(`Malformed ${r}`);
	let i = e.slice(n.start - n.headerLength, n.end), a = readSequenceChildren(i), o = a[0];
	if (o === void 0 || o.tag !== 6 || a.length > 2) throw Error(`Malformed ${r}`);
	return {
		oid: decodeObjectIdentifier(o.value),
		parameters: a[1],
		der: i
	};
}
function parseHmacAlgorithm(e, t$17) {
	if (e.parameters !== void 0 && (e.parameters.tag !== 5 || e.parameters.length !== 0)) throw Error(`${t$17} parameters must be NULL`);
	switch (e.oid) {
		case t.hmacWithSHA256: return "HMAC-SHA-256";
		case t.hmacWithSHA384: return "HMAC-SHA-384";
		case t.hmacWithSHA512: return "HMAC-SHA-512";
	}
	return throwMacDataError("unsupported_mac_algorithm", `Unsupported ${t$17} ${e.oid}`);
}
function hmacHash(e) {
	switch (e) {
		case "HMAC-SHA-256": return "SHA-256";
		case "HMAC-SHA-384": return "SHA-384";
		case "HMAC-SHA-512": return "SHA-512";
		default: throw Error(`Unhandled PBMAC1 HMAC: ${String(e)}`);
	}
}
async function computePbmac1(e, t, n) {
	return await hmac(e, await derivePbkdf2Bytes(encodePbmac1Password(t), n.salt, n.iterations, hmacHash(n.prf), n.keyLength), hmacHash(n.messageAuthScheme));
}
function encodePbmac1Password(e) {
	for (let t = 0; t < e.length; t += 1) {
		let n = e.charCodeAt(t);
		if (n >= 55296 && n <= 56319) {
			let n = e.charCodeAt(t + 1);
			if (n >= 56320 && n <= 57343) {
				t += 1;
				continue;
			}
		}
		n >= 55296 && n <= 57343 && throwPkcs12MacError("password_not_utf8", `PBMAC1 password has no UTF-8 encoding: unpaired UTF-16 surrogate 0x${n.toString(16)} at index ${t}`);
	}
	return new TextEncoder().encode(e);
}
/** Derives an HMAC-SHA-256 key via the PKCS#12 KDF and signs the AuthenticatedSafe. */
async function computePkcs12Mac(e, t, n, r) {
	return await hmac(e, await derivePkcs12Key(t, n, r, 3, 32), "SHA-256");
}
async function hmac(e, t, r) {
	let i = await getCrypto().subtle.importKey("raw", toArrayBuffer(t), {
		name: "HMAC",
		hash: r
	}, !1, ["sign"]);
	return new Uint8Array(await getCrypto().subtle.sign("HMAC", i, toArrayBuffer(e)));
}
/**
* PKCS#12 key derivation with SHA-256 (RFC 7292 Appendix B). `id` selects the purpose:
* 1 for key material, 2 for an IV, 3 for a MAC key.
*
* @throws {ResultError} with code `password_not_bmp_string` when the password contains a
* UTF-16 surrogate, U+FFFE or U+FFFF.
*/
async function derivePkcs12Key(e, t, n, r, i) {
	let a = (/* @__PURE__ */ new Uint8Array(64)).fill(r), s = encodePkcs12Password(e), c = concatBytes([repeatToMultiple(t, 64), repeatToMultiple(s, 64)]), l = Math.ceil(i / 32), u = new Uint8Array(l * 32);
	for (let e = 0; e < l; e += 1) {
		let t = await digestSha256(concatBytes([a, c]));
		for (let e = 1; e < n; e += 1) t = await digestSha256(t);
		if (u.set(t, e * 32), e + 1 === l) break;
		let r = repeatToLength(t, 64);
		for (let e = 0; e < c.length; e += 64) addBlockInPlace(c.subarray(e, e + 64), r);
	}
	return u.slice(0, i);
}
/** SHA-256 hash via WebCrypto. */
async function digestSha256(e) {
	return new Uint8Array(await getCrypto().subtle.digest("SHA-256", toArrayBuffer(e)));
}
/** Encodes a password as a null-terminated BMPString, two big-endian bytes per character (RFC 7292 B.1). */
function encodePkcs12Password(e) {
	let t = new Uint8Array((e.length + 1) * 2);
	for (let n = 0; n < e.length; n += 1) {
		let r = e.charCodeAt(n);
		r >= 55296 && r <= 57343 && throwPkcs12MacError("password_not_bmp_string", `PKCS#12 password is not a BMPString: UTF-16 surrogate 0x${r.toString(16)} at index ${n}`), r >= 65534 && throwPkcs12MacError("password_not_bmp_string", `PKCS#12 password is not a BMPString: U+${r.toString(16).toUpperCase()} at index ${n}`), t[n * 2] = r >> 8, t[n * 2 + 1] = r & 255;
	}
	return t;
}
/** Repeats `bytes` to the nearest multiple of `size`. */
function repeatToMultiple(e, t) {
	return e.length === 0 ? /* @__PURE__ */ new Uint8Array() : repeatToLength(e, t * Math.ceil(e.length / t));
}
/** Cyclically repeats `bytes` to fill exactly `length` bytes. */
function repeatToLength(e, t) {
	let n = new Uint8Array(t);
	for (let r = 0; r < t; r += 1) n[r] = e[r % e.length] ?? 0;
	return n;
}
/** Big-endian add-with-carry of `addend` into `block`, modifying `block` in place. */
function addBlockInPlace(e, t) {
	let n = 1;
	for (let r = e.length - 1; r >= 0; --r) {
		let i = (e[r] ?? 0) + (t[r] ?? 0) + n;
		e[r] = i & 255, n = i >> 8;
	}
}
/** Constant-time byte comparison to avoid timing side-channels in MAC checks. */
function equalBytes(e, t) {
	if (e.length !== t.length) return !1;
	let n = 0;
	for (let r = 0; r < e.length; r += 1) n |= (e[r] ?? 0) ^ (t[r] ?? 0);
	return n === 0;
}
// ../../dist/pkcs/pfx.js
/**
* PKCS#12/PFX container creation and parsing.
*
* Builds and decodes PFX archives containing certificate bags, private-key bags,
* optional PBES2 encryption, and PKCS#12 MAC integrity verification.
*
* @module
*/
/**
* Builds a PKCS#12/PFX archive containing certificates and/or private keys.
*
* When `encryption` is provided, the key-bag ContentInfo is PBES2-encrypted.
* When `mac` is provided, a PKCS#12 MAC integrity block is appended.
*
* Returns a {@linkcode CreatePfxResult}: the container material on success, or a
* typed `invalid_certificate` failure when a certificate source is not a single
* PEM/DER certificate.
*
* When `mac` is provided, `mac.type` selects the RFC 7292 MAC (the default) or
* RFC 9879 PBMAC1.
*
* @throws {ResultError} with a {@linkcode CreatePkcs12MacDataErrorCode} when `mac.iterations`
* is out of range or `mac.password` cannot be encoded for the selected MAC, and with
* {@linkcode PfxEncoderErrorCode} `invalid_friendly_name` when a bag `friendlyName` is not a
* BMPString of 1 to 255 characters.
*
* @example
* ```ts
* import { createPfx, unwrap } from 'micro509';
*
* const result = await createPfx({
*   certificates: [{ certificate: certPem }],
*   privateKeys: [{ privateKey: keyPair.privateKey }],
*   encryption: { password: 's3cret' },
*   mac: { password: 's3cret' },
* });
* if (result.ok) {
*   const pfx = result.value; // pfx.der, pfx.pem, pfx.base64
* }
* // or, when inputs are already validated: const pfx = unwrap(result);
* ```
*/
async function createPfx(e) {
	let t = [], n = [];
	for (let n of e.certificates ?? []) {
		let e;
		try {
			e = normalizeCertificate(n.certificate);
		} catch {
			return pfxCreationFailure("invalid_certificate", "Each PFX certificate source must be a single PEM or DER certificate");
		}
		t.push(createCertificateBag(e, n.attributes));
	}
	for (let t of e.privateKeys ?? []) n.push(createPrivateKeyBag(await normalizePrivateKey(t.privateKey), t.attributes));
	let r = [];
	if (t.length > 0 && r.push(createDataContentInfo(sequence(t))), n.length > 0) {
		let t = sequence(n);
		r.push(e.encryption === void 0 ? createDataContentInfo(t) : await createEncryptedDataContentInfo(t, e.encryption));
	}
	let i = sequence(r), a = e.mac === void 0 ? void 0 : await createPkcs12MacData(i, e.mac), o = sequence([
		integerFromNumber(3),
		createDataContentInfo(i),
		...a === void 0 ? [] : [a.der]
	]);
	return {
		ok: !0,
		value: {
			der: o,
			pem: pemEncode("PKCS12", o),
			base64: base64Encode(o)
		}
	};
}
/** Shorthand for constructing a PFX creation failure result. */
function pfxCreationFailure(e, t) {
	return failureResult(e, t);
}
/**
* Decodes a BER- or DER-encoded PKCS#12/PFX container into its constituent bags.
*
* The PFX, AuthenticatedSafe and SafeContents layers accept BER: indefinite and
* non-minimal lengths and constructed OCTET STRINGs. The MAC is verified over the
* AuthenticatedSafe octets as received. Certificates and private keys inside the
* bags must be DER.
*
* Returns a result union — check `ok` before accessing `value`.
* Encrypted containers require `options.password`. MAC verification uses
* `options.macPassword` (falls back to `options.password`).
*
* @example
* ```ts
* import { parsePfxDer } from 'micro509';
*
* const result = await parsePfxDer(pfxBytes, { password: 's3cret' });
* if (result.ok) {
*   console.log(result.value.certificates.length);
* }
* ```
*/
async function parsePfxDer(e, t) {
	return await parsePfxDerWithBudget(e, t, createKdfBudget(t));
}
async function parsePfxDerWithBudget(t, n$5, r) {
	try {
		let i = berSequenceChildren(readBerRoot(t));
		if (i.length < 2 || i.length > 3) return pfxFailure("malformed", "Malformed PFX structure");
		let s = i[0], u = i[1];
		if (s === void 0 || u === void 0) return pfxFailure("malformed", "Malformed PFX structure");
		if (decodeIntegerNumber(berPrimitiveContent(t, s, 2)) !== 3) return pfxFailure("malformed", "Unsupported PFX version");
		let d = extractContentInfoData(t, u), f = i[2], p;
		if (f !== void 0) {
			let e = await verifyPfxMacData(berToDefiniteLength(t, f), d, n$5);
			if (e.error !== void 0) return e.error;
			p = e.macData;
		}
		let m = [];
		for (let e of berSequenceChildren(readBerRoot(d))) {
			let t = await extractSafeContents(d, e, n$5, r);
			if (t.error !== void 0) return t.error;
			let i = t.data;
			for (let e of berSequenceChildren(t.root)) m.push(parseSafeBag(i, e));
		}
		return {
			ok: !0,
			value: {
				bags: m,
				certificates: m.flatMap((e) => e.kind === "certificate" ? [e.certificate] : []),
				privateKeys: m.flatMap((e) => e.kind === "privateKey" ? [e.pkcs8Der] : []),
				...p === void 0 ? {} : { macData: p }
			}
		};
	} catch (e) {
		rethrowIfInvariant(e);
		let t = decodeRefusalOf(e, n);
		return t === void 0 ? pfxFailure("malformed", "Malformed PFX structure") : pfxFailure(t.code, t.message);
	}
}
/**
* Decodes a PEM-armored PKCS#12/PFX container. Expects exactly one `PKCS12` block.
*
* Delegates to {@linkcode parsePfxDer} after PEM decoding.
*
* @example
* ```ts
* import { parsePfxPem } from 'micro509';
*
* const result = await parsePfxPem(pfxPemString, { password: 's3cret' });
* if (result.ok) {
*   console.log(result.value.privateKeys.length);
* }
* ```
*/
async function parsePfxPem(e, t) {
	let n = createKdfBudget(t), r;
	try {
		let t = splitPemBlocksOrThrow(e).filter((e) => e.label === "PKCS12"), n = t[0];
		if (n === void 0 || t.length !== 1) return pfxFailure("malformed", "Expected exactly one PKCS12 PEM block");
		r = n.bytes;
	} catch {
		return pfxFailure("malformed", "Expected exactly one PKCS12 PEM block");
	}
	return await parsePfxDerWithBudget(r, t, n);
}
/** Shorthand for constructing a PFX parse failure result. */
function pfxFailure(e, t) {
	return failureResult(e, t);
}
/** Unwraps a `data` ContentInfo to its inner OCTET STRING payload. */
function extractContentInfoData(e, t$7) {
	let { oid: n, content: r } = readContentInfo(e, t$7);
	if (n !== t.pkcs7Data) throw Error("Only passwordless data ContentInfo is supported");
	return extractContextOctetString(e, r);
}
function readContentInfo(e, n) {
	let r = berSequenceChildren(n), i = r[0], s = r[1];
	if (i === void 0 || s === void 0 || r.length !== 2) throw Error("Malformed ContentInfo");
	return {
		oid: decodeObjectIdentifier(berPrimitiveContent(e, i, 6)),
		content: s
	};
}
/** Extracts SafeContents bytes from a ContentInfo, decrypting if EncryptedData. */
async function extractSafeContents(e, t$8, n, r) {
	let i$1, a;
	try {
		({oid: i$1, content: a} = readContentInfo(e, t$8));
	} catch (e) {
		rethrowIfInvariant(e);
		let t = decodeRefusalOf(e, i);
		return { error: t === void 0 ? pfxFailure("malformed", "Malformed ContentInfo") : pfxFailure(t.code, t.message) };
	}
	if (i$1 === t.pkcs7Data) {
		let t = extractContextOctetString(e, a);
		return {
			data: t,
			root: readBerRoot(t)
		};
	}
	if (i$1 !== t.pkcs7EncryptedData) return { error: pfxFailure("malformed", "Unsupported PFX ContentInfo type") };
	if (n?.password === void 0) return { error: pfxFailure("password_required", "Password required for encrypted PFX content") };
	let s = extractContextChild(a), c;
	try {
		c = await decryptEncryptedData(e, s, n.password, r);
	} catch (e) {
		if (rethrowIfInvariant(e), isWrongPasswordError(e)) return { error: pfxFailure("invalid_password", "Invalid PFX password or encrypted content") };
		if (isKdfIterationLimitError(e)) return { error: pfxFailure("kdf_iterations_exceeded", e.message) };
		let t = decodeRefusalOf(e, i);
		return { error: t === void 0 ? pfxFailure("malformed", "Malformed PFX encrypted content") : pfxFailure(t.code, t.message) };
	}
	try {
		let e = readBerRoot(c);
		return berSequenceChildren(e), {
			data: c,
			root: e
		};
	} catch (e) {
		rethrowIfInvariant(e);
		let t = decodeRefusalOf(e, i);
		return t === void 0 ? { error: pfxFailure("invalid_password", "Invalid PFX password or encrypted content") } : { error: pfxFailure(t.code, t.message) };
	}
}
/** Encodes a certBag SafeBag wrapping a DER certificate with optional attributes. */
function createCertificateBag(e, t$9) {
	let n = sequence([objectIdentifier(t.x509CertificateBagType), explicitContext(0, octetString(e))]);
	return sequence([
		objectIdentifier(t.pkcs12CertBag),
		explicitContext(0, n),
		...encodeBagAttributes(t$9)
	]);
}
/** Encodes a keyBag SafeBag wrapping PKCS#8 DER with optional attributes. */
function createPrivateKeyBag(e, t$10) {
	return sequence([
		objectIdentifier(t.pkcs12KeyBag),
		explicitContext(0, e),
		...encodeBagAttributes(t$10)
	]);
}
/** Wraps raw bytes in a `pkcs7-data` ContentInfo SEQUENCE. */
function createDataContentInfo(e) {
	return sequence([objectIdentifier(t.pkcs7Data), explicitContext(0, octetString(e))]);
}
/** PBES2-encrypts data and wraps it in a `pkcs7-encryptedData` ContentInfo. */
async function createEncryptedDataContentInfo(e, t$11) {
	let n = await encryptPbes2(e, t$11), r = sequence([integerFromNumber(0), sequence([
		objectIdentifier(t.pkcs7Data),
		n.algorithmIdentifierDer,
		tlv(128, n.encryptedData)
	])]);
	return sequence([objectIdentifier(t.pkcs7EncryptedData), explicitContext(0, r)]);
}
/** DER-encodes optional friendlyName / localKeyId into a SET OF SEQUENCE. */
function encodeBagAttributes(e) {
	if (e === void 0) return [];
	let t$12 = [];
	return e.friendlyName !== void 0 && t$12.push(sequence([objectIdentifier(t.friendlyName), setOf([encodeFriendlyName(e.friendlyName)])])), e.localKeyId !== void 0 && t$12.push(sequence([objectIdentifier(t.localKeyId), setOf([octetString(e.localKeyId)])])), t$12.length === 0 ? [] : [setOf(t$12)];
}
function encodeFriendlyName(e) {
	let refuse = () => throwMicro509Error("invalid_friendly_name", "friendlyName must be a BMPString of 1 to 255 characters, none of them a surrogate, U+FFFE or U+FFFF");
	if (e.length === 0 || e.length > 255) return refuse();
	try {
		return bmpString(e);
	} catch {
		return refuse();
	}
}
/** Decodes a single SafeBag into a {@linkcode ParsedPfxBag} discriminated union. */
function parseSafeBag(e, n) {
	let r = berSequenceChildren(n), s = r[0], l = r[1], u = r[2];
	if (s === void 0 || l === void 0 || r.length > 3) throw Error("Malformed SafeBag");
	let d = decodeObjectIdentifier(berPrimitiveContent(e, s, 6)), f = parseBagAttributes(e, u), p = extractContextChild(l);
	if (d === t.pkcs12CertBag) {
		let n = berSequenceChildren(p), r = n[0], i = n[1];
		if (r === void 0 || i === void 0 || n.length !== 2 || decodeObjectIdentifier(berPrimitiveContent(e, r, 6)) !== t.x509CertificateBagType) throw Error("Malformed certBag");
		return {
			kind: "certificate",
			bagId: d,
			attributes: f,
			certificate: parseCertificateDerOrThrow(extractContextOctetString(e, i))
		};
	}
	if (d === t.pkcs12KeyBag) {
		let t = berEncoding(e, p);
		return readRootElement(t), {
			kind: "privateKey",
			bagId: d,
			attributes: f,
			pkcs8Der: t
		};
	}
	return {
		kind: "unknown",
		bagId: d,
		attributes: f,
		valueDer: berToDefiniteLength(e, p)
	};
}
/** Decodes the SET OF attributes attached to a SafeBag. */
function parseBagAttributes(e, n) {
	if (n === void 0) return { entries: [] };
	if (n.tag !== 49) throw Error("Malformed PFX bag attributes");
	let i = [], s, l;
	for (let u of n.children) {
		let n = berSequenceChildren(u), d = n[0], f = n[1];
		if (d === void 0 || f === void 0 || n.length !== 2 || f.tag !== 49) throw Error("Malformed PFX bag attribute");
		let p = decodeObjectIdentifier(berPrimitiveContent(e, d, 6)), m = f.children.map((t) => berToDefiniteLength(e, t));
		if (i.push({
			oid: p,
			valuesHex: m.map((e) => toHex(e))
		}), p === t.friendlyName) {
			let e = m[0];
			if (s !== void 0 || m.length !== 1 || e === void 0) throw Error("Malformed friendlyName attribute");
			s = decodeFriendlyName(e);
		} else if (p === t.localKeyId) {
			let e = m[0];
			if (l !== void 0 || m.length !== 1 || e === void 0) throw Error("Malformed localKeyId attribute");
			l = decodeLocalKeyId(e);
		}
	}
	return {
		entries: i,
		...s === void 0 ? {} : { friendlyName: s },
		...l === void 0 ? {} : { localKeyId: l }
	};
}
function decodeLocalKeyId(e) {
	let t = readElement(e);
	if (t.tag !== 4) throw Error("localKeyId must use OCTET STRING");
	return toHex(t.value);
}
/** Exports a `CryptoKey` to PKCS#8 DER, or passes raw bytes through. */
function normalizePrivateKey(e) {
	return e instanceof CryptoKey ? exportPkcs8Der(e) : Promise.resolve(new Uint8Array(e));
}
/** Extracts DER bytes from a PEM string, or passes raw DER through. */
function normalizeCertificate(e) {
	if (typeof e == "string") {
		let t = splitPemBlocksOrThrow(e).find((e) => e.label === "CERTIFICATE");
		if (t === void 0) throw Error("Certificate PEM required");
		return new Uint8Array(t.bytes);
	}
	return e instanceof Uint8Array ? new Uint8Array(e) : new Uint8Array(e.der);
}
/** Parses the MacData block and verifies it against the AuthenticatedSafe when a password is given. */
async function verifyPfxMacData(e, t, n) {
	let r = await parsePkcs12MacData(e, t, n?.macPassword ?? n?.password, n);
	return r.ok ? r.value.verification === "invalid" ? { error: pfxFailure("invalid_password", "Invalid PFX MAC password or corrupted content") } : { macData: r.value } : { error: r.code === "malformed" ? pfxFailure("malformed", "Malformed PFX MacData") : pfxFailure(r.code, r.message) };
}
/** Decrypts a PKCS#7 EncryptedData structure using PBES2 with the given password. */
function decryptEncryptedData(t, n, r, i) {
	let l = berSequenceChildren(n), u = l[0], d = l[1];
	if (l.length !== 2 || u === void 0 || d === void 0 || decodeIntegerNumber(berPrimitiveContent(t, u, 2)) !== 0) throw Error("Malformed EncryptedData");
	let f = berSequenceChildren(d), p = f[0], m = f[1], h = f[2];
	if (p === void 0 || m === void 0 || h === void 0 || f.length !== 3) throw Error("Malformed EncryptedContentInfo");
	return berPrimitiveContent(t, p, 6), decryptPbes2(berToDefiniteLength(t, m), berStringContent(t, h, 128, 4), r, i);
}
/** Reads the OCTET STRING inside a `[0] EXPLICIT` wrapper. */
function extractContextOctetString(e, t) {
	return berStringContent(e, extractContextChild(t), 4);
}
/** Reads the single child element inside a `[0] EXPLICIT` wrapper. */
function extractContextChild(e) {
	if (e.tag !== 160) throw Error("Expected [0] EXPLICIT value");
	let t = e.children[0];
	if (e.children.length !== 1 || t === void 0) throw Error("Expected context-specific wrapper with exactly one value");
	return t;
}
/** RFC 2985 §5.5.1: a friendlyName value is a BMPString of SIZE (1..255). */
function decodeFriendlyName(e) {
	let t = readElement(e);
	if (t.tag !== 30) throw Error("friendlyName must be a BMPString");
	let r = decodeString(30, t.value);
	if (r.length < 1 || r.length > 255) throw Error("friendlyName must hold 1 to 255 characters");
	return r;
}
// ../../dist/pkcs/pkcs7.js
/**
* PKCS#7/CMS certificate bags and SignedData.
*
* Creates degenerate (signature-less) certificate bags, parses RFC 5652
* SignedData (and the RFC 2315 form whose contentInfo content is an OCTET
* STRING), and verifies signer signatures including signed-attribute flows.
* A CertificateSet is decoded as RFC 5652 §10.2.2 CertificateChoices, so an
* attribute certificate or other-format entry is preserved rather than dropped.
*
* @module
*/
/** RFC 7468 Section 8 armors an RFC 2315 ContentInfo; Section 9 armors an RFC 5652 one. */
const L = ["PKCS7", "CMS"];
/**
* Creates a degenerate PKCS#7 SignedData structure containing only
* certificates (no signers), returning DER, PEM, and base64 forms, or a
* typed `invalid_certificate` failure when a certificate source is not
* valid PEM/DER.
*/
function createPkcs7CertBag(e) {
	let t$1;
	try {
		t$1 = e.flatMap(normalizeCertificateSource);
		for (let e of t$1) parseCertificateDerOrThrow(e);
	} catch (e) {
		let t = decodeRefusalOf(e, n);
		return t === void 0 ? createCertBagFailure("invalid_certificate", "Each PKCS#7 certificate source must be valid PEM or DER") : createCertBagFailure(t.code, t.message);
	}
	let n$1 = new Uint8Array(setOf(t$1));
	n$1[0] = 160;
	let r = sequence([
		integerFromNumber(1),
		setOf([]),
		sequence([objectIdentifier(t.pkcs7Data)]),
		n$1,
		setOf([])
	]), i = sequence([objectIdentifier(t.pkcs7SignedData), explicitContext(0, r)]);
	return {
		ok: !0,
		value: {
			der: i,
			pem: pemEncode("PKCS7", i),
			base64: base64Encode(i)
		}
	};
}
/**
* Creates a PKCS#7/CMS SignedData with one or more signers over `content`.
*
* Each signer uses the RFC 5652 Section 5.4 signed-attributes flow: the
* signature covers a `SET OF` authenticated attributes carrying `contentType`
* and `messageDigest` (the digest of the encapsulated content). By default the
* content is embedded (attached signature), so the result verifies with
* {@linkcode verifyPkcs7SignedData} without any external data. With
* `detached: true` the `eContent` is omitted (RFC 5652 Section 5.2) and the
* verifier must supply the content externally.
*
* The content digest is derived from each signer's key (P-256/RSA-SHA256 →
* SHA-256, P-384 → SHA-384, P-521 → SHA-512, Ed25519 → SHA-512 per RFC 8419).
*
* Returns a {@linkcode CreatePkcs7SignedDataResult}: DER, PEM, and base64
* forms on success, or a typed failure for caller-correctable input (no
* signers, a signer source that is not exactly one certificate, a signer
* certificate whose public key cannot verify the signer key's algorithm, or an
* unsupported signer key).
*/
async function createPkcs7SignedData(e) {
	if (e.signers.length === 0) return createPkcs7Failure("no_signers", "createPkcs7SignedData requires at least one signer");
	let t$2 = e.encapsulatedContentTypeOid ?? t.pkcs7Data, n$2 = e.content.slice(), r = [], i = /* @__PURE__ */ new Set(), addCertificate = (e) => {
		let t = toHex(e);
		i.has(t) || (i.add(t), r.push(e));
	}, a = /* @__PURE__ */ new Set(), o = [];
	for (let r of e.signers) {
		let e = await buildPkcs7SignerInfo(r, n$2, t$2);
		if (!e.ok) return e;
		addCertificate(e.certificateDer), a.add(e.digestOid), o.push(e.signerInfoDer);
	}
	for (let t of e.additionalCertificates ?? []) try {
		for (let e of normalizeCertificateSource(t)) parseCertificateDerOrThrow(e), addCertificate(e);
	} catch (e) {
		let t = decodeRefusalOf(e, n);
		return t === void 0 ? createPkcs7Failure("invalid_certificate", "Each additional PKCS#7 certificate source must be valid PEM or DER") : createPkcs7Failure(t.code, t.message);
	}
	let u = t$2 === t.pkcs7Data ? 1 : 3, m = new Uint8Array(setOf(r));
	m[0] = 160;
	let h = sequence([
		integerFromNumber(u),
		setOf([...a].map((e) => sequence([objectIdentifier(e)]))),
		e.detached === !0 ? sequence([objectIdentifier(t$2)]) : sequence([objectIdentifier(t$2), explicitContext(0, octetString(n$2))]),
		m,
		setOf(o)
	]), g = sequence([objectIdentifier(t.pkcs7SignedData), explicitContext(0, h)]);
	return {
		ok: !0,
		value: {
			der: g,
			pem: pemEncode(u === 1 ? "PKCS7" : "CMS", g),
			base64: base64Encode(g)
		}
	};
}
/**
* Builds one signer's SignerInfo over `content` (RFC 5652 Section 5.4
* signed-attributes flow). Every throwing step here reacts to
* caller-correctable input — malformed PEM/DER, unsupported key — so each is
* mapped to a typed failure rather than rejecting the public Promise.
*/
async function buildPkcs7SignerInfo(e, t, n$3) {
	let r;
	try {
		r = normalizeCertificateSource(e.certificate);
	} catch {
		return createPkcs7Failure("invalid_signer_certificate", "Each PKCS#7 signer certificate source must be valid PEM or DER");
	}
	let a = r[0];
	if (a === void 0 || r.length !== 1) return createPkcs7Failure("invalid_signer_certificate", "Each PKCS#7 signer must provide exactly one certificate");
	let s;
	try {
		s = parseCertificateDerOrThrow(a);
	} catch (e) {
		let t = decodeRefusalOf(e, n);
		return t === void 0 ? createPkcs7Failure("invalid_signer_certificate", "Each PKCS#7 signer certificate must be a parseable X.509 certificate") : createPkcs7Failure(t.code, t.message);
	}
	let l;
	try {
		l = getSignatureAlgorithm(e.privateKey, e.signature);
	} catch {
		return createPkcs7Failure("unsupported_signer_key", "Unsupported signer key or signature profile");
	}
	if (!getVerifySignatureConfigResult(l.algorithmOid, l.parameters, s.publicKeyAlgorithmOid, s.publicKeyParametersOid, "signer").ok) return createPkcs7Failure("signer_certificate_key_mismatch", "Each PKCS#7 signer certificate must carry a public key that verifies the signer key algorithm");
	let m = contentDigestForPrivateKey(e.privateKey);
	if (m === void 0) return createPkcs7Failure("unsupported_signer_key", "Unsupported signer key algorithm for content digest");
	let { setForSigning: h, implicitForEmit: g } = buildSignedAttributes(n$3, new Uint8Array(await getCrypto().subtle.digest(m.hashName, toArrayBuffer(t)))), v;
	try {
		v = await signBytes(e.privateKey, l, h);
	} catch {
		return createPkcs7Failure("unsupported_signer_key", "Signer key could not produce a PKCS#7 signature");
	}
	return {
		ok: !0,
		signerInfoDer: sequence([
			integerFromNumber(1),
			sequence([hexToBytes(s.issuer.derHex), integer(hexToBytes(s.serialNumberHex))]),
			sequence([objectIdentifier(m.digestOid)]),
			g,
			encodeAlgorithmIdentifier(l),
			octetString(v)
		]),
		digestOid: m.digestOid,
		certificateDer: a
	};
}
/** Parses a DER-encoded PKCS#7 cert bag, returning the contained certificates. */
function parsePkcs7CertBagDer(e) {
	let t = parsePkcs7SignedDataDer(e);
	return t.ok ? {
		ok: !0,
		value: x509CertificatesOf(t.value.certificateChoices)
	} : t;
}
/** The DER of the single `PKCS7` or `CMS` block in `pem`, or a typed failure. */
function contentInfoPemBytes(e) {
	try {
		let t = splitPemBlocksOrThrow(e).filter((e) => L.some((t) => t === e.label)), n = t[0];
		return n === void 0 || t.length !== 1 ? pkcs7Failure("malformed", "Expected exactly one PKCS7 or CMS PEM block") : {
			ok: !0,
			bytes: n.bytes
		};
	} catch {
		return pkcs7Failure("malformed", "Expected exactly one PKCS7 or CMS PEM block");
	}
}
/** Parses a PEM-armored PKCS#7/CMS cert bag. Expects exactly one `PKCS7` or `CMS` PEM block. */
function parsePkcs7CertBagPem(e) {
	let t = contentInfoPemBytes(e);
	return t.ok ? parsePkcs7CertBagDer(t.bytes) : t;
}
/** Decodes a DER-encoded PKCS#7 ContentInfo expecting `signedData` content type. */
function parsePkcs7SignedDataDer(r) {
	try {
		let i = readSequenceChildren(r, { maxDepth: 64 }), a = i[0], o = i[1];
		if (a === void 0 || i.length > 2 || a.tag !== 6 || o !== void 0 && (o.tag !== 160 || childrenOf(r, o).length !== 1)) return pkcs7Failure("malformed", "Malformed PKCS#7 content info");
		let s = decodeObjectIdentifier(a.value);
		if (s !== t.pkcs7SignedData) return pkcs7Failure("not_signed_data", "PKCS#7 content is not signedData");
		if (o === void 0) return pkcs7Failure("malformed", "PKCS#7 signedData content info carries no content");
		let c = childAt(r, o, 0, "signedData"), l = childrenOf(r, c), u = l[0], d = l[1], f = l[2], p = l.slice(3), m = p[p.length - 1], h = parseSignedDataOptionalFields(p.slice(0, -1));
		if (!h.ok) return h;
		if (u === void 0 || d === void 0 || f === void 0 || m === void 0 || m.tag !== 49) return pkcs7Failure("malformed", "Malformed SignedData");
		let _ = r.slice(f.start - f.headerLength, f.end), v = readSequenceChildren(_), x = v[0], S = v[1], C = parseDigestAlgorithms(r, d);
		return x === void 0 || v.length > 2 || x.tag !== 6 ? pkcs7Failure("malformed", "Malformed EncapsulatedContentInfo") : {
			ok: !0,
			value: {
				der: new Uint8Array(r),
				contentTypeOid: s,
				version: decodeIntegerNumber(u.value),
				digestAlgorithmOids: C,
				digestAlgorithmNames: C.map((e) => describeHashAlgorithm(e)),
				encapsulatedContentTypeOid: decodeObjectIdentifier(x.value),
				...S === void 0 ? {} : { encapsulatedContent: extractEncapsulatedContent(_, S) },
				certificateChoices: parseCertificateSet(r, h.value.certificates),
				signerInfos: parseSignerInfos(r, m)
			}
		};
	} catch (e) {
		rethrowIfInvariant(e);
		let t = decodeRefusalOf(e, n);
		return t === void 0 ? pkcs7Failure("malformed", "Malformed PKCS#7 structure") : pkcs7Failure(t.code, t.message);
	}
}
function parseSignedDataOptionalFields(e) {
	let t, n;
	for (let r of e) if (r.tag === 160) {
		if (n !== void 0) return pkcs7Failure("malformed", "SignedData certificates field must precede CRLs field");
		if (t !== void 0) return pkcs7Failure("malformed", "SignedData certificates field must not repeat");
		t = r;
	} else if (r.tag === 161) {
		if (n !== void 0) return pkcs7Failure("malformed", "SignedData CRLs field must not repeat");
		n = r;
	} else return pkcs7Failure("malformed", "Malformed SignedData optional field");
	return {
		ok: !0,
		value: {
			...t === void 0 ? {} : { certificates: t },
			...n === void 0 ? {} : { crls: n }
		}
	};
}
/** Decodes a PEM-armored PKCS#7/CMS SignedData. Expects exactly one `PKCS7` or `CMS` PEM block. */
function parsePkcs7SignedDataPem(e) {
	let t = contentInfoPemBytes(e);
	return t.ok ? parsePkcs7SignedDataDer(t.bytes) : t;
}
/**
* Verifies all signer signatures in a PKCS#7 SignedData structure.
*
* Accepts PEM text, raw DER, or an already-parsed {@linkcode ParsedPkcs7SignedData}.
* For each signer, locates the matching certificate in the embedded set and
* verifies the signature (including signed-attribute digest checks per RFC 5652 Section 5.4).
* Defaults to id-data and requires signed attributes on every signer. Select
* `expectedContentTypeOid` from the application's protocol, not the input envelope.
* Legacy bare id-data signatures require `signedAttributes: 'allowed'` or 'forbidden'.
* Non-id-data always requires attributes (RFC 5652 §5.3).
*
* For a detached SignedData (absent `eContent`), pass the externally-held
* content via `options.content`; without it, verification fails with the
* typed `detached_content_required` code. When the SignedData embeds its own
* content, that embedded content is verified and `options.content` is ignored.
*
* @example
* ```ts
* import { verifyPkcs7SignedData } from 'micro509';
*
* const result = await verifyPkcs7SignedData(pkcs7Pem);
* if (result.ok) {
*   for (const { signerInfo, certificate } of result.signers) {
*     console.log(signerInfo.digestAlgorithmOid, certificate.subject);
*   }
* }
*
* // Detached signature: supply the content externally
* const detached = await verifyPkcs7SignedData(cmsBlob, { content: signedBytes });
* ```
*/
async function verifyPkcs7SignedData(e, t$3 = {}) {
	let r, i = t$3.signedAttributes ?? "required";
	if (![
		"required",
		"allowed",
		"forbidden"
	].includes(i)) return verifyPkcs7Failure("invalid_options", "Unknown signed-attribute policy");
	try {
		r = decodeObjectIdentifier(readElement(objectIdentifier(t$3.expectedContentTypeOid ?? t.pkcs7Data)).value);
	} catch {
		return verifyPkcs7Failure("invalid_options", "Expected content type must be an OID");
	}
	let a = normalizePkcs7SignedDataForVerification(e);
	if (!a.ok) return a;
	let o = a.value, s = o.encapsulatedContent ?? t$3.content?.slice();
	if (s === void 0) return verifyPkcs7Failure("detached_content_required", "SignedData has no encapsulated content; supply the detached content via options.content");
	if (o.signerInfos.length === 0) return verifyPkcs7Failure("no_signers", "SignedData contains no signer information");
	if (o.encapsulatedContentTypeOid !== r) return verifyPkcs7Failure("content_type_mismatch", "Unexpected SignedData content type");
	for (let e of o.signerInfos) {
		if (!e.hasSignedAttrs && (i === "required" || o.encapsulatedContentTypeOid !== t.pkcs7Data)) return verifyPkcs7Failure("signed_attributes_required", "Signed attributes are required");
		if (e.hasSignedAttrs && i === "forbidden") return verifyPkcs7Failure("signed_attributes_forbidden", "Signed attributes are forbidden");
	}
	let c = [];
	for (let e of o.signerInfos) {
		let t = await verifyPkcs7SignerInfo(o, e, s);
		if (!t.ok) return t;
		c.push({
			signerInfo: e,
			certificate: t.certificate
		});
	}
	return {
		ok: !0,
		value: o,
		signers: c
	};
}
/** Normalizes encoded or parsed SignedData into a freshly parsed verification input. */
function normalizePkcs7SignedDataForVerification(e) {
	return typeof e == "string" ? parsePkcs7SignedDataPem(e) : e instanceof Uint8Array ? parsePkcs7SignedDataDer(e) : hasReparseablePkcs7SignedData(e) ? parsePkcs7SignedDataDer(new Uint8Array(e.der)) : verifyPkcs7Failure("malformed", "SignedData parsed input is malformed");
}
/** Resolves and verifies one signer entry in a parsed PKCS#7 SignedData value. */
async function verifyPkcs7SignerInfo(e, t, n) {
	let r = x509CertificatesOf(e.certificateChoices).find((e) => signerIdentifierMatches(e, t));
	if (r === void 0) return verifyPkcs7Failure("signer_not_found", "Signer certificate not found in SignedData certificates");
	let i = t.hasSignedAttrs ? await verifySignedAttrs(t, r, n, e.encapsulatedContentTypeOid) : await verifyPkcs7BareSignerInfo(t, r, n);
	return i.ok ? {
		ok: !0,
		certificate: r
	} : i;
}
async function verifyPkcs7BareSignerInfo(e, t, n) {
	try {
		let r = await verifySignedDataDetailed(e.signatureAlgorithmOid, e.signatureAlgorithmParametersDer, t.publicKeyAlgorithmOid, t.publicKeyParametersOid, t.subjectPublicKeyInfoDer, e.signature, n);
		return r.ok ? r.valid ? { ok: !0 } : verifyPkcs7Failure("signature_invalid", "SignedData signature does not verify") : r.code === "verification_error" ? verifyPkcs7Failure("malformed", "SignedData signature verification failed") : verifyPkcs7Failure("malformed", "Unsupported signature algorithm in SignedData");
	} catch (e) {
		return signatureVerificationThrowFailure(e);
	}
}
/** Shorthand for constructing a PKCS#7 parse failure result. */
function pkcs7Failure(e, t) {
	return failureResult(e, t);
}
/** Shorthand for constructing a PKCS#7 verification failure result. */
/** A signer's signature verification that threw: its decode refusal, else `malformed`. */
function signatureVerificationThrowFailure(e) {
	let t = decodeRefusalOf(e, n);
	return t === void 0 ? verifyPkcs7Failure("malformed", "Unsupported signature algorithm in SignedData") : verifyPkcs7Failure(t.code, t.message);
}
function verifyPkcs7Failure(e, t) {
	return failureResult(e, t);
}
/** Shorthand for constructing a PKCS#7 certificate bag creation failure result. */
function createCertBagFailure(e, t) {
	return failureResult(e, t);
}
/** Shorthand for constructing a PKCS#7 SignedData creation failure result. */
function createPkcs7Failure(e, t) {
	return failureResult(e, t);
}
/** Converts PEM text to an array of DER certificate blobs, or wraps raw DER. */
function normalizeCertificateSource(e) {
	if (typeof e == "string") {
		let t = splitPemBlocksOrThrow(e).filter((e) => e.label === "CERTIFICATE").map((e) => new Uint8Array(e.bytes));
		if (t.length === 0) throw Error("Certificate PEM required");
		return t;
	}
	return e instanceof Uint8Array ? [new Uint8Array(e)] : [new Uint8Array(e.der)];
}
/** Type guard: key algorithm carries an RSA `hash`. */
function signerHasHash(e) {
	return "hash" in e;
}
/** Type guard: key algorithm carries an EC `namedCurve`. */
function signerHasNamedCurve(e) {
	return "namedCurve" in e;
}
/**
* Resolves the content-digest hash and its OID for a signer key.
*
* ECDSA curve pairing follows RFC 5753 §8: P-256 → SHA-256, P-384 → SHA-384,
* P-521 → SHA-512. RSA uses the hash bound to the key.
* Digest OIDs are from RFC 5754 §2.
* Ed25519 uses SHA-512 for the messageDigest attribute, per RFC 8419.
*/
function contentDigestForPrivateKey(e) {
	let t$4 = e.algorithm;
	if (t$4.name === "ECDSA") {
		if (!signerHasNamedCurve(t$4)) return;
		switch (t$4.namedCurve) {
			case "P-256": return {
				hashName: "SHA-256",
				digestOid: t.sha256
			};
			case "P-384": return {
				hashName: "SHA-384",
				digestOid: t.sha384
			};
			case "P-521": return {
				hashName: "SHA-512",
				digestOid: t.sha512
			};
			default: return;
		}
	}
	if (t$4.name === "RSASSA-PKCS1-v1_5" || t$4.name === "RSA-PSS") {
		if (!signerHasHash(t$4)) return;
		switch (t$4.hash.name) {
			case "SHA-256": return {
				hashName: "SHA-256",
				digestOid: t.sha256
			};
			case "SHA-384": return {
				hashName: "SHA-384",
				digestOid: t.sha384
			};
			case "SHA-512": return {
				hashName: "SHA-512",
				digestOid: t.sha512
			};
			default: return;
		}
	}
	if (t$4.name === "Ed25519") return {
		hashName: "SHA-512",
		digestOid: t.sha512
	};
}
/**
* Builds CMS signed attributes (contentType + messageDigest) in two forms:
* `setForSigning` (SET OF, tag 0x31) is what the signature covers per RFC 5652
* Section 5.4; `implicitForEmit` (IMPLICIT [0], tag 0xa0) is what goes in the
* SignerInfo. The two differ only in the leading tag byte.
*/
function buildSignedAttributes(e, t$5) {
	let n = setOf([sequence([objectIdentifier(t.cmsContentType), setOf([objectIdentifier(e)])]), sequence([objectIdentifier(t.cmsMessageDigest), setOf([octetString(t$5)])])]), r = new Uint8Array(n);
	return r[0] = 160, {
		setForSigning: n,
		implicitForEmit: r
	};
}
/** The X.509 subset of a decoded CertificateSet. */
function x509CertificatesOf(e) {
	return e.flatMap((e) => e.type === "certificate" ? [e.certificate] : []);
}
/**
* `otherCertFormat` from an `other [3] IMPLICIT OtherCertificateFormat` entry.
*
* The IMPLICIT tag replaces the SEQUENCE tag, so the OID and the `ANY DEFINED BY`
* value are direct children of the `[3]` element.
*/
function parseOtherCertificateFormatOid(t, r) {
	let i = requireElement(childrenOf(t, r)[0], "otherCertFormat");
	if (i.tag !== 6) throw Error("otherCertFormat must be an OBJECT IDENTIFIER");
	return decodeObjectIdentifier(i.value);
}
/** Decodes one RFC 5652 §10.2.2 CertificateChoices alternative. */
function parseCertificateChoice(e, t, n) {
	switch (t.tag) {
		case 48: return {
			type: "certificate",
			certificate: parseCertificateDerOrThrow(n)
		};
		case 160: return {
			type: "extendedCertificate",
			der: n
		};
		case 161: return {
			type: "attributeCertificateV1",
			der: n
		};
		case 162: return {
			type: "attributeCertificateV2",
			der: n
		};
		case 163: return {
			type: "other",
			formatOid: parseOtherCertificateFormatOid(e, t),
			der: n
		};
		default: throw Error(`Unsupported CertificateChoices tag: ${t.tag}`);
	}
}
/**
* Parses the IMPLICIT [0] certificate set from a SignedData structure as
* RFC 5652 §10.2.3 `CertificateSet ::= SET OF CertificateChoices`.
*/
function parseCertificateSet(t, n) {
	return n === void 0 || n.tag !== 160 ? [] : childrenOf(t, n).map((e) => parseCertificateChoice(t, e, t.slice(e.start - e.headerLength, e.end)));
}
/** Extracts the list of digest algorithm OIDs from the digestAlgorithms SET. */
function parseDigestAlgorithms(t, r) {
	let i = [];
	if (r.tag !== 49) throw Error("digestAlgorithms must use SET");
	for (let a of childrenOf(t, r)) {
		if (a.tag !== 48) throw Error("digestAlgorithm must use AlgorithmIdentifier SEQUENCE");
		let e = t.slice(a.start - a.headerLength, a.end), r = readSequenceChildren(e), o = r[0];
		if (o === void 0 || r.length < 1 || r.length > 2 || o.tag !== 6) throw Error("Malformed digest AlgorithmIdentifier");
		i.push(decodeObjectIdentifier(o.value));
	}
	return i;
}
/** Decodes the signerInfos SET OF from a SignedData structure. */
function parseSignerInfos(t, n) {
	return childrenOf(t, n).map((e) => parseSignerInfo(t, e));
}
function parseSignerInfo(e, r) {
	let i = e.slice(r.start - r.headerLength, r.end), o = readSequenceChildren(i), c = o[0], l = o[1], u = o[2], d = 3, f = o[d]?.tag === 160 ? o[d] : void 0;
	f !== void 0 && (d += 1);
	let p = o[d], m = o[d + 1], h = o[d + 2];
	if (c === void 0 || l === void 0 || u === void 0 || p === void 0 || m === void 0 || m.tag !== 4 || o.length > d + 3 || h !== void 0 && h.tag !== 161) throw Error("Malformed SignerInfo");
	let _ = parsePkcs7AlgorithmOid(i, u, "digest algorithm OID"), v = i.slice(p.start - p.headerLength, p.end), y = readSequenceChildren(v), S = decodeObjectIdentifier(requireElement(y[0], "signature algorithm OID").value), C = y[1];
	return {
		version: decodeIntegerNumber(c.value),
		signerIdentifier: parseSignerIdentifier(i.slice(l.start - l.headerLength, l.end)),
		digestAlgorithmOid: _,
		digestAlgorithmName: describeHashAlgorithm(_),
		signatureAlgorithmOid: S,
		signatureAlgorithmName: describeSignatureAlgorithm(S, C === void 0 ? void 0 : new Uint8Array(v.slice(C.start - C.headerLength, C.end))),
		...C === void 0 ? {} : { signatureAlgorithmParametersDer: new Uint8Array(v.slice(C.start - C.headerLength, C.end)) },
		signatureHex: toHex(m.value),
		signature: new Uint8Array(m.value),
		...f === void 0 ? { hasSignedAttrs: !1 } : {
			hasSignedAttrs: !0,
			signedAttrsDer: new Uint8Array(i.slice(f.start - f.headerLength, f.end))
		}
	};
}
function parsePkcs7AlgorithmOid(e, t, r) {
	let i = e.slice(t.start - t.headerLength, t.end);
	return decodeObjectIdentifier(requireElement(readSequenceChildren(i)[0], r).value);
}
/** Unwraps the OCTET STRING inside the IMPLICIT [0] encapsulated content. */
function extractEncapsulatedContent(e, t) {
	if (t.tag !== 160) throw Error("Unexpected encapsulated content tag");
	let n = readElement(e, t.start);
	if (n.tag !== 4) throw Error("Expected encapsulated OCTET STRING");
	if (n.end !== t.end) throw Error("Encapsulated content must hold exactly one element");
	return n.value;
}
/** Extracts issuer Name and serial number from an issuerAndSerialNumber SEQUENCE, or subjectKeyIdentifier from [0] IMPLICIT. */
function parseSignerIdentifier(e) {
	let t = readRootElement(e, { maxDepth: 64 });
	if (t.tag === 128) {
		if (t.value.length === 0) throw Error("SignerIdentifier subjectKeyIdentifier must not be empty");
		return {
			type: "subjectKeyIdentifier",
			subjectKeyIdentifier: toHex(t.value)
		};
	}
	if (t.tag === 48) {
		let t = readSequenceChildren(e), n = t[0], r = t[1];
		if (n === void 0 || r === void 0 || t.length !== 2) throw Error("SignerIdentifier issuerAndSerialNumber is malformed");
		if (n.tag !== 48) throw Error("SignerIdentifier issuer must use Name SEQUENCE");
		if (r.tag !== 2) throw Error("SignerIdentifier serialNumber must use INTEGER");
		return assertImplicitSerialNumberEncoding(r.value, "SignerIdentifier serialNumber"), {
			type: "issuerAndSerialNumber",
			issuer: parseSignerIssuerName(e, n),
			serialNumberHex: toHex(r.value)
		};
	}
	throw Error(`Unsupported SignerIdentifier tag: ${String(t.tag)}`);
}
/** Parses a Name SEQUENCE element from a PKCS#7 signer identifier into a {@linkcode ParsedName}. */
function parseSignerIssuerName(t, i) {
	let o = toHex(t.slice(i.start - i.headerLength, i.end)), c = [], l = [], u = {};
	for (let o of childrenOf(t, i)) {
		let i = [], d = {};
		for (let s of childrenOf(t, o)) {
			let o = childrenOf(t, s), c = requireElement(o[0], "signer issuer attribute OID"), f = requireElement(o[1], "signer issuer attribute value"), p = decodeObjectIdentifier(c.value), m = decodeString(f.tag, f.value), h = nameFieldKeyFromOid(p), g = h === void 0 ? {
				oid: p,
				valueTag: f.tag,
				value: m
			} : {
				oid: p,
				key: h,
				valueTag: f.tag,
				value: m
			};
			i.push(g), l.push(g), h !== void 0 && (d[h] === void 0 && (d[h] = m), u[h] === void 0 && (u[h] = m));
		}
		c.push({
			derHex: toHex(t.slice(o.start - o.headerLength, o.end)),
			attributes: i,
			values: d
		});
	}
	return {
		derHex: o,
		rdns: c,
		attributes: l,
		values: u
	};
}
/** Returns the nth child element inside a constructed ASN.1 element, or throws. */
function childAt(e, t, n, r) {
	let i = t.start, a = 0;
	for (; i < t.end;) {
		let t = readElement(e, i);
		if (a === n) return t;
		i = t.end, a += 1;
	}
	throw Error(`Missing ${r}`);
}
/** Maps a digest algorithm OID to the WebCrypto hash name. */
function digestAlgorithmHash(e) {
	switch (e) {
		case t.sha256: return "SHA-256";
		case t.sha384: return "SHA-384";
		case t.sha512: return "SHA-512";
		default: throw Error(`Unsupported digest algorithm OID: ${e}`);
	}
}
/** Parses required signed attributes and enforces uniqueness + exact-one-value shape. */
function parseSignedAttributeRequirements(t) {
	let n = readElement(t), r = {};
	for (let i of childrenOf(t, n)) parseSignedAttributeRequirement(t, i, r);
	if (r.messageDigest === void 0) throw Error("Missing messageDigest attribute in signedAttrs");
	if (r.contentTypeOid === void 0) throw Error("Missing contentType attribute in signedAttrs");
	return {
		messageDigest: r.messageDigest,
		contentTypeOid: r.contentTypeOid
	};
}
function parseSignedAttributeRequirement(t$6, r, i) {
	let a = t$6.slice(r.start - r.headerLength, r.end), o = readSequenceChildren(a), s = o[0], c = o[1];
	if (s === void 0 || c === void 0 || o.length !== 2 || c.tag !== 49) throw Error("Malformed signedAttrs attribute");
	let l = decodeObjectIdentifier(s.value), u = childrenOf(a, c);
	l === t.cmsMessageDigest && (i.messageDigest = parseUniqueSignedAttributeOctetString(i.messageDigest, u, "messageDigest")), l === t.cmsContentType && (i.contentTypeOid = parseUniqueSignedAttributeOid(i.contentTypeOid, u, "contentType"));
}
function parseUniqueSignedAttributeOctetString(e, t, n) {
	if (e !== void 0 || t.length !== 1) throw Error(`${n} attribute must appear exactly once with one value`);
	let r = requireElement(t[0], `${n} attribute value`);
	if (r.tag !== 4) throw Error(`${n} attribute value must use OCTET STRING`);
	return r.value;
}
function parseUniqueSignedAttributeOid(e, t, r) {
	if (e !== void 0 || t.length !== 1) throw Error(`${r} attribute must appear exactly once with one value`);
	let i = requireElement(t[0], `${r} attribute value`);
	if (i.tag !== 6) throw Error(`${r} attribute value must use OBJECT IDENTIFIER`);
	return decodeObjectIdentifier(i.value);
}
/** Replaces the IMPLICIT [0] tag (0xa0) with SET OF (0x31) per RFC 5652 Section 5.4. */
function retagSignedAttrsAsSet(e) {
	let t = new Uint8Array(e);
	return t[0] = 49, t;
}
/** Constant-time byte comparison to avoid timing side-channels in digest checks. */
function constantTimeEqual(e, t) {
	if (e.length !== t.length) return !1;
	let n = 0;
	for (let r = 0; r < e.length; r += 1) n |= (e[r] ?? 0) ^ (t[r] ?? 0);
	return n === 0;
}
/** Verifies a signed-attributes flow: digest match + signature over re-tagged attrs. */
async function verifySignedAttrs(e, t, n$4, r) {
	if (!e.hasSignedAttrs) return verifyPkcs7Failure("malformed", "Missing signedAttrs DER");
	let i;
	try {
		assertImplicitSignedAttrsDer(e.signedAttrsDer), i = parseSignedAttributeRequirements(e.signedAttrsDer);
	} catch (e) {
		rethrowIfInvariant(e);
		let t = decodeRefusalOf(e, n);
		return t === void 0 ? verifyPkcs7Failure("malformed", "Malformed signedAttrs in SignedData") : verifyPkcs7Failure(t.code, t.message);
	}
	if (i.contentTypeOid !== r) return verifyPkcs7Failure("malformed", "SignedData contentType attribute does not match");
	let a;
	try {
		let t = digestAlgorithmHash(e.digestAlgorithmOid);
		a = new Uint8Array(await getCrypto().subtle.digest(t, toArrayBuffer(n$4)));
	} catch {
		return verifyPkcs7Failure("malformed", "Unsupported digest algorithm in SignedData");
	}
	if (!constantTimeEqual(a, i.messageDigest)) return verifyPkcs7Failure("message_digest_mismatch", "Content digest does not match messageDigest attribute");
	let s;
	try {
		s = retagSignedAttrsAsSet(e.signedAttrsDer);
	} catch {
		return verifyPkcs7Failure("malformed", "Malformed signedAttrs in SignedData");
	}
	let l;
	try {
		let n = await verifySignedDataDetailed(e.signatureAlgorithmOid, e.signatureAlgorithmParametersDer, t.publicKeyAlgorithmOid, t.publicKeyParametersOid, t.subjectPublicKeyInfoDer, e.signature, s);
		if (!n.ok) return n.code === "verification_error" ? verifyPkcs7Failure("malformed", "SignedData signature verification failed") : verifyPkcs7Failure("malformed", "Unsupported signature algorithm in SignedData");
		l = n.valid;
	} catch (e) {
		return signatureVerificationThrowFailure(e);
	}
	return l ? { ok: !0 } : verifyPkcs7Failure("signature_invalid", "SignedData signature over signedAttrs does not verify");
}
function signerIdentifierMatches(e, t) {
	let n = t.signerIdentifier;
	return n.type === "issuerAndSerialNumber" ? e.serialNumberHex === n.serialNumberHex && compareDistinguishedNames(e.issuer, n.issuer) : e.subjectKeyIdentifier === n.subjectKeyIdentifier;
}
function assertImplicitSignedAttrsDer(e) {
	if (readElement(e).tag !== 160) throw Error("signedAttrs must use IMPLICIT [0] tag");
}
function hasReparseablePkcs7SignedData(e) {
	return "der" in e && e.der instanceof Uint8Array;
}
function assertImplicitSerialNumberEncoding(e, t) {
	let n = e[0];
	if (n === void 0) throw Error(`${t} must not be empty`);
	if (n & 128) throw Error(`${t} must be non-negative`);
	if (e.length > 1 && n === 0 && !((e[1] ?? 0) & 128)) throw Error(`${t} must use minimal encoding`);
}
export { parsePkcs7SignedDataDer as a, createPfx as c, createPkcs12MacData as d, parsePkcs12MacData as f, parsePkcs7CertBagPem as i, parsePfxDer as l, createPkcs7SignedData as n, parsePkcs7SignedDataPem as o, parsePkcs12MacDataOrThrow as p, parsePkcs7CertBagDer as r, verifyPkcs7SignedData as s, createPkcs7CertBag as t, parsePfxPem as u };
