import { W as importPublicJwk, gt as t$2, mt as getCrypto } from "./keys-MB16_ABQ.js";
import { c as rethrowIfInvariant, l as successResult, n as failureResult, u as throwMicro509Error } from "./result-C9WPk47A.js";
import { a as verifySignatureWithKey, r as signData, t as ecdsaSignatureDerToRaw } from "./crypto-CTrhyq34.js";
import { t as isPrimeEcPoint } from "./prime-ec-D_2XyeDl.js";
// ../../dist/internal/jose/base64url.js
const e$2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const t$1 = (() => {
	let t = (/* @__PURE__ */ new Int8Array(128)).fill(-1);
	for (let n = 0; n < 64; n++) t[e$2.charCodeAt(n)] = n;
	return t;
})();
/** Encodes bytes as unpadded base64url (RFC 4648 §5, RFC 7515 §2). */
function base64UrlEncode$1(t) {
	let n = "", r = 0;
	for (; r + 2 < t.length; r += 3) {
		let i = (t[r] ?? 0) * 65536 + (t[r + 1] ?? 0) * 256 + (t[r + 2] ?? 0);
		n += e$2[i >> 18 & 63] ?? "", n += e$2[i >> 12 & 63] ?? "", n += e$2[i >> 6 & 63] ?? "", n += e$2[i & 63] ?? "";
	}
	let i = t.length - r;
	if (i === 1) {
		let i = (t[r] ?? 0) * 65536;
		n += e$2[i >> 18 & 63] ?? "", n += e$2[i >> 12 & 63] ?? "";
	} else if (i === 2) {
		let i = (t[r] ?? 0) * 65536 + (t[r + 1] ?? 0) * 256;
		n += e$2[i >> 18 & 63] ?? "", n += e$2[i >> 12 & 63] ?? "", n += e$2[i >> 6 & 63] ?? "";
	}
	return n;
}
/**
* Decodes canonical unpadded base64url. Returns `undefined` for any character outside the URL-safe
* alphabet, padding, whitespace, an impossible length, or non-zero trailing bits.
*/
function base64UrlDecode$1(e) {
	if (e.length % 4 == 1) return;
	let n = new Uint8Array(Math.floor(e.length * 3 / 4)), r = 0, i = 0, a = 0;
	for (let o = 0; o < e.length; o++) {
		let s = e.charCodeAt(o), c = s < 128 ? t$1[s] ?? -1 : -1;
		if (c < 0) return;
		i = i << 6 | c, a += 6, a >= 8 && (a -= 8, n[r++] = i >> a & 255, i &= (1 << a) - 1);
	}
	if (i === 0) return n;
}
// ../../dist/jose/base64url.js
/** Public byte-oriented JOSE base64url codecs. @module */
/** Encodes bytes as canonical unpadded base64url; does not encode text. */
function base64UrlEncode(e) {
	return base64UrlEncode$1(e);
}
/** Decodes canonical unpadded base64url, or returns `undefined` for invalid/noncanonical input. Empty input yields empty bytes. */
function base64UrlDecode(t) {
	return base64UrlDecode$1(t);
}
// ../../dist/internal/jose/json-data.js
const e$1 = Symbol("JSON data refusal");
function refuse$1(t) {
	throw {
		marker: e$1,
		code: t
	};
}
function isRefusal$1(t) {
	return typeof t == "object" && !!t && "marker" in t && t.marker === e$1;
}
function bytes(e, t) {
	e.bytes += t, e.bytes > e.maxBytes && refuse$1("limit_exceeded");
}
function node(e) {
	++e.nodes > e.maxNodes && refuse$1("limit_exceeded");
}
/** Counts the UTF-8 bytes of the shortest JSON string spelling without allocating it. */
function string(e, t) {
	t.length > e.maxBytes - e.bytes && refuse$1("limit_exceeded"), bytes(e, 2);
	for (let n = 0; n < t.length; n++) {
		let r = t.charCodeAt(n);
		if (r >= 55296 && r <= 56319) {
			let r = t.charCodeAt(++n);
			r >= 56320 && r <= 57343 || refuse$1("invalid_json"), bytes(e, 4);
		} else bytes(e, characterBytes(r));
	}
	return t;
}
function characterBytes(e) {
	return e >= 56320 && e <= 57343 && refuse$1("invalid_json"), e === 34 || e === 92 ? 2 : e < 32 ? [
		8,
		9,
		10,
		12,
		13
	].includes(e) ? 2 : 6 : e < 128 ? 1 : e < 2048 ? 2 : 3;
}
/** Reflection can execute proxy traps or encounter a revoked proxy; that is an input refusal. */
function inspect(e) {
	try {
		return e();
	} catch {
		return refuse$1("invalid_json");
	}
}
function arrayLength(e, t) {
	let n = inspect(() => Object.getOwnPropertyDescriptor(e, "length"))?.value;
	return (typeof n != "number" || !Number.isSafeInteger(n) || n < 0) && refuse$1("invalid_json"), n > t.maxNodes - t.nodes && refuse$1("limit_exceeded"), n;
}
function dataMember(e, t) {
	let n = inspect(() => Object.getOwnPropertyDescriptor(e, t));
	return n !== void 0 && "value" in n && n.enumerable || refuse$1("invalid_json"), n.value;
}
function checkPrototype(e, t) {
	let n = inspect(() => Object.getPrototypeOf(e));
	(t ? n !== Array.prototype : n !== null && n !== Object.prototype) && refuse$1("invalid_json");
}
function copy(e, t, n) {
	if (node(t), e === null || typeof e == "boolean") return bytes(t, e === null || e ? 4 : 5), e;
	if (typeof e == "string") return string(t, e);
	if (typeof e == "number") return Number.isFinite(e) || refuse$1("invalid_json"), bytes(t, String(e).length), e;
	typeof e != "object" && refuse$1("invalid_json"), n >= t.maxDepth && refuse$1("limit_exceeded"), t.active.has(e) && refuse$1("invalid_json");
	let r = inspect(() => Array.isArray(e));
	checkPrototype(e, r), t.active.add(e), r && arrayLength(e, t);
	let i = inspect(() => Reflect.ownKeys(e));
	i.length > t.maxNodes - t.nodes + +!!r && refuse$1("limit_exceeded"), bytes(t, 2);
	let a = r ? copyArray(e, i, t, n) : copyObject(e, i, t, n);
	return t.active.delete(e), a;
}
function copyArray(e, t, n, r) {
	let i = arrayLength(e, n);
	t.length !== i + 1 && refuse$1("invalid_json");
	let a = [];
	for (let t = 0; t < i; t++) t > 0 && bytes(n, 1), a.push(copy(dataMember(e, String(t)), n, r + 1));
	return Object.freeze(a);
}
function copyObject(e, t, n, r) {
	let i = {};
	for (let [a, o] of t.entries()) typeof o != "string" && refuse$1("invalid_json"), node(n), string(n, o), bytes(n, a > 0 ? 2 : 1), Object.defineProperty(i, o, {
		value: copy(dataMember(e, o), n, r + 1),
		enumerable: !0
	});
	return Object.freeze(i);
}
/** Copies plain JSON data without invoking getters, coercion or `toJSON`. */
function snapshotJsonData(e, t) {
	try {
		return {
			ok: !0,
			value: copy(e, {
				...t,
				bytes: 0,
				nodes: 0,
				active: /* @__PURE__ */ new Set()
			}, 0)
		};
	} catch (e) {
		if (isRefusal$1(e)) return {
			ok: !1,
			code: e.code
		};
		throw e;
	}
}
// ../../dist/internal/jose/strict-json.js
const e = Symbol("micro509.jose.strictJsonFailure");
function refuse(t, n) {
	throw {
		[e]: !0,
		code: t,
		message: n
	};
}
function isRefusal(t) {
	return typeof t == "object" && !!t && e in t;
}
/**
* Parses RFC 8259 JSON text, refusing duplicate object member names, lone surrogate escapes,
* non-finite numbers, and documents beyond the given depth and node bounds.
*/
function parseStrictJson(e, t) {
	let n = {
		text: e,
		index: 0,
		nodes: 0,
		limits: t
	};
	try {
		skipWhitespace(n);
		let t = parseValue(n, 0);
		return skipWhitespace(n), n.index !== e.length && refuse("invalid_json", "Trailing characters after JSON value"), {
			ok: !0,
			value: t
		};
	} catch (e) {
		if (isRefusal(e)) return {
			ok: !1,
			code: e.code,
			message: e.message
		};
		throw e;
	}
}
function skipWhitespace(e) {
	for (; e.index < e.text.length;) {
		let t = e.text.charCodeAt(e.index);
		if (t !== 32 && t !== 9 && t !== 10 && t !== 13) return;
		e.index++;
	}
}
function countNode(e) {
	e.nodes++, e.nodes > e.limits.maxNodes && refuse("limit_exceeded", "JSON document exceeds the node limit");
}
function parseValue(e, t) {
	switch (countNode(e), e.text[e.index]) {
		case "{": return parseObject(e, t + 1);
		case "[": return parseArray(e, t + 1);
		case "\"": return parseString(e);
		case "t": return parseLiteral(e, "true", !0);
		case "f": return parseLiteral(e, "false", !1);
		case "n": return parseLiteral(e, "null", null);
		default: return parseNumber(e);
	}
}
function parseLiteral(e, t, n) {
	return e.text.startsWith(t, e.index) || refuse("invalid_json", "Unexpected token in JSON"), e.index += t.length, n;
}
const t = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
function parseNumber(e) {
	t.lastIndex = e.index;
	let n = t.exec(e.text);
	n === null && refuse("invalid_json", "Unexpected token in JSON"), e.index += n[0].length;
	let r = Number(n[0]);
	return Number.isFinite(r) || refuse("invalid_json", "JSON number is not finite"), r;
}
function enter(e, t) {
	t > e.limits.maxDepth && refuse("limit_exceeded", "JSON document exceeds the nesting limit");
}
function parseArray(e, t) {
	enter(e, t), e.index++;
	let n = [];
	if (skipWhitespace(e), e.text[e.index] === "]") return e.index++, n;
	for (;;) {
		skipWhitespace(e), n.push(parseValue(e, t)), skipWhitespace(e);
		let r = e.text[e.index++];
		if (r === "]") return n;
		r !== "," && refuse("invalid_json", "Expected \",\" or \"]\" in JSON array");
	}
}
function parseObject(e, t) {
	enter(e, t), e.index++;
	let n = /* @__PURE__ */ new Map();
	if (skipWhitespace(e), e.text[e.index] === "}") return e.index++, {};
	for (;;) {
		skipWhitespace(e), e.text[e.index] !== "\"" && refuse("invalid_json", "Expected member name in JSON object"), countNode(e);
		let r = parseString(e);
		n.has(r) && refuse("duplicate_member", "JSON object repeats a member name"), skipWhitespace(e), e.text[e.index++] !== ":" && refuse("invalid_json", "Expected \":\" in JSON object"), skipWhitespace(e), n.set(r, parseValue(e, t)), skipWhitespace(e);
		let i = e.text[e.index++];
		if (i === "}") break;
		i !== "," && refuse("invalid_json", "Expected \",\" or \"}\" in JSON object");
	}
	let r = {};
	for (let [e, t] of n) Object.defineProperty(r, e, {
		value: t,
		enumerable: !0,
		writable: !0,
		configurable: !0
	});
	return r;
}
const n = /[0-9a-fA-F]{4}/y;
function readEscapedUnit(e) {
	n.lastIndex = e.index;
	let t = n.exec(e.text);
	return t === null && refuse("invalid_json", "Invalid unicode escape in JSON string"), e.index += 4, Number.parseInt(t[0], 16);
}
function parseString(e) {
	e.index++;
	let t = "", n = e.index;
	for (;;) {
		e.index >= e.text.length && refuse("invalid_json", "Unterminated JSON string");
		let r = e.text.charCodeAt(e.index);
		if (r === 34) return t += e.text.slice(n, e.index), e.index++, t;
		r < 32 && refuse("invalid_json", "Control character in JSON string"), r === 92 ? (t += e.text.slice(n, e.index), e.index++, t += parseEscape(e), n = e.index) : e.index++;
	}
}
const r = {
	"\"": "\"",
	"\\": "\\",
	"/": "/",
	b: "\b",
	f: "\f",
	n: "\n",
	r: "\r",
	t: "	"
};
function parseEscape(e) {
	let t = e.text[e.index++];
	if (t === void 0 && refuse("invalid_json", "Unterminated JSON string"), t !== "u") {
		let e = Object.hasOwn(r, t) ? r[t] : void 0;
		return e === void 0 && refuse("invalid_json", "Invalid escape in JSON string"), e;
	}
	let n = readEscapedUnit(e);
	if (n >= 56320 && n <= 57343 && refuse("invalid_json", "Lone low surrogate escape in JSON string"), n < 55296 || n > 56319) return String.fromCharCode(n);
	e.text.startsWith("\\u", e.index) || refuse("invalid_json", "Lone high surrogate escape in JSON string"), e.index += 2;
	let i = readEscapedUnit(e);
	return (i < 56320 || i > 57343) && refuse("invalid_json", "High surrogate escape without a low surrogate"), String.fromCharCode(n, i);
}
/** Narrows a parsed value to a JSON object. */
function isJsonObject(e) {
	return typeof e == "object" && !!e && !Array.isArray(e);
}
/** Narrows a parsed value to a JSON array. */
function isJsonArray(e) {
	return Array.isArray(e);
}
// ../../dist/jose/errors.js
/** Builds a failed result, truncating any reported `kid`. */
function joseFailure(t, n, r) {
	return failureResult(t, n, r?.kid === void 0 ? r : {
		...r,
		kid: r.kid.slice(0, 64)
	});
}
// ../../dist/jose/jws.js
/**
* Compact JWS (RFC 7515) parsing, signing and verification with an explicit algorithm and token
* type policy. Parsing yields an {@linkcode UnverifiedJws}; only {@linkcode verifyCompactJws}
* yields a {@linkcode VerifiedJws}.
*
* @module
*/
/** Every {@linkcode JwsAlgorithm}. */
const f = [
	"RS256",
	"RS384",
	"RS512",
	"ES256",
	"ES384"
];
const p$1 = 2048;
const m = p$1;
const h$1 = {
	RS256: {
		kind: "rsa",
		hash: "SHA-256",
		oid: t$2.sha256WithRSAEncryption
	},
	RS384: {
		kind: "rsa",
		hash: "SHA-384",
		oid: t$2.sha384WithRSAEncryption
	},
	RS512: {
		kind: "rsa",
		hash: "SHA-512",
		oid: t$2.sha512WithRSAEncryption
	},
	ES256: {
		kind: "ec",
		hash: "SHA-256",
		curve: "P-256",
		coordinateBytes: 32,
		oid: t$2.ecdsaWithSHA256
	},
	ES384: {
		kind: "ec",
		hash: "SHA-384",
		curve: "P-384",
		coordinateBytes: 48,
		oid: t$2.ecdsaWithSHA384
	}
};
/** The exact key and signature profile for an admitted JWS algorithm. */
function jwsAlgorithmProfile(e) {
	return h$1[e];
}
/** The limits applied when a caller supplies none. */
const g = {
	maxTokenLength: 32768,
	maxHeaderBytes: 4096,
	maxPayloadBytes: 16384,
	maxSignatureBytes: 1024,
	maxJsonDepth: 16,
	maxJsonNodes: 2048
};
const _ = [
	"maxTokenLength",
	"maxHeaderBytes",
	"maxPayloadBytes",
	"maxSignatureBytes",
	"maxJsonDepth",
	"maxJsonNodes"
];
/**
* Resolves caller-supplied limit overrides against {@linkcode DEFAULT_JOSE_LIMITS}. An omitted or
* `undefined` field takes its default; any other value must be a positive safe integer, and
* `maxJsonDepth` may not exceed {@linkcode MAX_JSON_DEPTH_LIMIT}.
*/
function resolveJoseLimits(e) {
	if (e !== void 0 && (typeof e != "object" || !e)) return joseFailure("invalid_options", "limits must be an object");
	let t = { ...g };
	for (let n of _) {
		let r = e?.[n];
		if (r === void 0) continue;
		let i = n === "maxJsonDepth" ? 64 : 2 ** 53 - 1;
		if (!Number.isSafeInteger(r) || r < 1 || r > i) return joseFailure("invalid_options", `limits.${n} must be a positive safe integer`);
		t[n] = r;
	}
	return successResult(t);
}
const v = new TextEncoder();
const y = new TextDecoder("utf-8", {
	fatal: !0,
	ignoreBOM: !0
});
function maxEncodedLength(e) {
	return Math.ceil(e * 4 / 3);
}
function parseFailure(e, t) {
	return joseFailure(e, t);
}
function decodeSegment$1(e, t, n) {
	if (e.length > maxEncodedLength(t)) return parseFailure("limit_exceeded", `JWS ${n} exceeds ${t} bytes`);
	let r = base64UrlDecode$1(e);
	return r === void 0 ? parseFailure("invalid_encoding", `JWS ${n} is not canonical base64url`) : successResult(r);
}
/** Decodes UTF-8 strictly and parses it as a JSON object with no duplicate members. */
function decodeJsonObject(e, t, n, r, i = "JWS") {
	let a;
	try {
		a = y.decode(e);
	} catch {
		return parseFailure("invalid_utf8", `${i} ${n} is not valid UTF-8`);
	}
	let o = parseStrictJson(a, {
		maxDepth: t.maxJsonDepth,
		maxNodes: t.maxJsonNodes
	});
	if (!o.ok) return parseFailure(o.code, `${i} ${n}: ${o.message}`);
	let l = o.value;
	return isJsonObject(l) ? successResult(l) : parseFailure(r, `${i} ${n} is not a JSON object`);
}
function optionalString(e, t) {
	if (!Object.hasOwn(e, t)) return successResult(void 0);
	let n = e[t];
	return typeof n == "string" ? successResult(n) : parseFailure("invalid_header", `JWS header "${t}" is not a string`);
}
function criticalNames(e) {
	if (!Object.hasOwn(e, "crit")) return successResult([]);
	let t = e.crit;
	if (!isJsonArray(t) || t.length === 0) return parseFailure("invalid_header", "JWS header \"crit\" is not a non-empty array");
	let n = [];
	for (let e of t) {
		if (typeof e != "string" || n.includes(e)) return parseFailure("invalid_header", "JWS header \"crit\" holds a non-string or repeated name");
		n.push(e);
	}
	return successResult(n);
}
function parseHeader(e, t) {
	let n = decodeJsonObject(e, t, "header", "invalid_header");
	if (!n.ok) return n;
	let r = n.value, i = r.alg;
	if (typeof i != "string" || i.length === 0) return parseFailure("invalid_header", "JWS header \"alg\" is missing or not a string");
	let a = optionalString(r, "typ");
	if (!a.ok) return a;
	let o = optionalString(r, "kid");
	if (!o.ok) return o;
	let s = optionalString(r, "cty");
	if (!s.ok) return s;
	let c = criticalNames(r);
	return c.ok ? r.b64 === !1 || c.value.includes("b64") ? parseFailure("unsupported_unencoded_payload", "Unencoded and detached payloads (RFC 7797) are not supported") : Object.hasOwn(r, "b64") && typeof r.b64 != "boolean" ? parseFailure("invalid_header", "JWS header \"b64\" is not a boolean") : c.value.length > 0 ? joseFailure("unsupported_critical_header", "JWS header lists critical extensions", {
		alg: i,
		crit: c.value
	}) : successResult({
		alg: i,
		...a.value === void 0 ? {} : { typ: a.value },
		...o.value === void 0 ? {} : { kid: o.value },
		...s.value === void 0 ? {} : { cty: s.value },
		members: r
	}) : c;
}
/**
* Parses a compact JWS without checking its signature.
*
* Refuses tokens that are oversized, do not have exactly three segments, carry non-canonical
* base64url, invalid UTF-8, a header that is not a duplicate-free JSON object with a string `alg`,
* a `crit` list, or an unencoded payload (`b64: false`). The result is {@linkcode UnverifiedJws};
* pass the token to {@linkcode verifyCompactJws} before trusting any of it.
*/
function parseCompactJws(e, t) {
	let n = resolveJoseLimits(t);
	return n.ok ? parseWithLimits$1(e, n.value) : n;
}
function parseWithLimits$1(e, t) {
	if (typeof e != "string") return parseFailure("malformed_token", "JWS token is not a string");
	if (e.length > t.maxTokenLength) return parseFailure("token_too_large", `JWS token exceeds ${t.maxTokenLength} characters`);
	let n = e.split("."), [r, i, a] = n;
	if (n.length !== 3 || r === void 0 || i === void 0 || a === void 0 || r.length === 0) return parseFailure("malformed_token", "JWS compact serialization needs three segments");
	let o = decodeSegment$1(r, t.maxHeaderBytes, "header");
	if (!o.ok) return o;
	let s = parseHeader(o.value, t);
	if (!s.ok) return s;
	let c = decodeSegment$1(i, t.maxPayloadBytes, "payload");
	if (!c.ok) return c;
	let l = decodeSegment$1(a, t.maxSignatureBytes, "signature");
	return l.ok ? successResult({
		verified: !1,
		header: s.value,
		payload: c.value,
		signingInput: v.encode(`${r}.${i}`),
		signature: l.value
	}) : l;
}
/**
* Comparison key for a media type per RFC 7515 §4.1.9: type, subtype and parameter names fold to
* lower case, an omitted `application/` is restored, and parameter values stay exact.
*/
function mediaTypeKey(e) {
	let [t = "", ...n] = e.split(";"), r = t.trim().toLowerCase(), i = n.map((e) => {
		let t = e.indexOf("=");
		return t < 0 ? e.trim().toLowerCase() : `${e.slice(0, t).trim().toLowerCase()}=${e.slice(t + 1).trim()}`;
	});
	return [r.includes("/") ? r : `application/${r}`, ...i].join(";");
}
/** Whether `value` is exactly `{ unchecked: true }`. */
function isUncheckedPolicy(e) {
	return soleTrueMember(e) === "unchecked";
}
function soleTrueMember(e) {
	if (typeof e != "object" || !e || Array.isArray(e)) return;
	let t = Object.keys(e), [n] = t;
	if (t.length === 1 && n !== void 0) return Reflect.get(e, n) === !0 ? n : void 0;
}
function normalizeTokenType(e) {
	if (typeof e == "string") return {
		kind: "media",
		key: mediaTypeKey(e)
	};
	let t = soleTrueMember(e);
	if (t === "absent") return { kind: "absent" };
	if (t === "unchecked") return { kind: "unchecked" };
}
function matchesTokenType(e, t) {
	switch (t.kind) {
		case "media": return e.typ !== void 0 && mediaTypeKey(e.typ) === t.key;
		case "unchecked": return !0;
		case "absent": return e.typ === void 0;
		default: return t;
	}
}
function isAlgorithmAdmitted(e, t) {
	return t.includes(e) && f.some((t) => t === e);
}
/** Checks the observable RSA exponent constraints in RFC 8017 section 3.1. */
function validRsaPublicExponent(e, t) {
	let n = e.findIndex((e) => e !== 0), r = e[e.length - 1] ?? 0;
	if (n < 0 || !(r & 1)) return !1;
	let i = e.length - n;
	if (i === 1 && r < 3) return !1;
	if (t === void 0) return !0;
	if (i !== t.length) return i < t.length;
	for (let r = 0; r < i; r++) {
		let i = e[n + r] ?? 0, a = t[r] ?? 0;
		if (i !== a) return i < a;
	}
	return !1;
}
/** Checks the key profile and returns the exact JOSE signature length (RFC 7518 §§3.3–3.4). */
function checkJwsVerificationKey(e, t) {
	return checkJwsKey(e, t, "public");
}
function checkJwsKey(e, t, n) {
	try {
		return inspectJwsKey(e, t, n);
	} catch {
		return joseFailure("key_unsuitable", "The key cannot be inspected");
	}
}
function inspectJwsKey(e, t, n) {
	let r = jwsAlgorithmProfile(t), i = n === "public" ? "verify" : "sign";
	if (e.type !== n || !e.usages.includes(i)) return joseFailure("key_unsuitable", `${t} needs a ${n} key with ${i} usage`);
	let a = e.algorithm;
	return r.kind === "ec" ? a.name !== "ECDSA" || !("namedCurve" in a) || a.namedCurve !== r.curve ? joseFailure("key_unsuitable", `${t} needs an ECDSA ${r.curve} key`) : successResult(r.coordinateBytes * 2) : a.name !== "RSASSA-PKCS1-v1_5" || !("hash" in a) || typeof a.hash != "object" || a.hash === null || !("name" in a.hash) || a.hash.name !== r.hash ? joseFailure("key_unsuitable", `${t} needs an RSASSA-PKCS1-v1_5 ${r.hash} key`) : !("modulusLength" in a) || typeof a.modulusLength != "number" || a.modulusLength < 2048 ? joseFailure("key_unsuitable", `${t} needs an RSA modulus of at least ${m} bits`) : !("publicExponent" in a) || !(a.publicExponent instanceof Uint8Array) || !validRsaPublicExponent(a.publicExponent) ? joseFailure("key_unsuitable", `${t} needs a valid odd RSA public exponent of at least 3`) : successResult(Math.ceil(a.modulusLength / 8));
}
function isCryptoKey(e) {
	return e instanceof CryptoKey;
}
/** Validates and copies verification options. Everything the run reads is captured here. */
function prepareVerify(e) {
	if (typeof e != "object" || !e) return joseFailure("invalid_options", "Verification options are required");
	let { algorithms: t, key: n, tokenType: r, limits: i, signal: a } = e;
	if (!Array.isArray(t) || t.length === 0) return joseFailure("invalid_options", "An explicit, non-empty algorithm list is required");
	let o = [];
	for (let e of t) {
		let t = f.find((t) => t === e);
		if (t === void 0) return joseFailure("invalid_options", "The algorithm list names an unsupported algorithm");
		o.push(t);
	}
	if (typeof n != "function" && !isCryptoKey(n)) return joseFailure("invalid_options", "A key or key resolver is required");
	let s = normalizeTokenType(r);
	if (s === void 0) return joseFailure("invalid_options", "A token type policy is required");
	if (a !== void 0 && !(a instanceof AbortSignal)) return joseFailure("invalid_options", "signal must be an AbortSignal");
	let c = resolveJoseLimits(i);
	return c.ok ? successResult({
		algorithms: o,
		key: n,
		typeRule: s,
		limits: c.value,
		signal: a
	}) : c;
}
async function resolveKey(e, t) {
	let { key: n, signal: r } = e;
	if (typeof n != "function") return successResult(n);
	let i;
	try {
		i = await n({
			header: t,
			algorithm: t.alg,
			...t.kid === void 0 ? {} : { kid: t.kid },
			...r === void 0 ? {} : { signal: r }
		});
	} catch {
		return r?.aborted === !0 ? joseFailure("aborted", "Key resolution was cancelled") : joseFailure("key_resolution_failed", "The key resolver failed");
	}
	if (typeof i != "object" || !i) return joseFailure("key_resolution_failed", "The key resolver returned no result");
	if (Reflect.get(i, "ok") === !0) {
		let e = Reflect.get(i, "value");
		return isCryptoKey(e) ? successResult(e) : joseFailure("key_resolution_failed", "The key resolver returned no key");
	}
	let a = Reflect.get(i, "code");
	switch (a) {
		case "key_not_found":
		case "ambiguous_key":
		case "key_unsuitable":
		case "key_resolution_failed":
		case "jwks_unavailable":
		case "jwks_malformed":
		case "aborted": return joseFailure(a, `Key resolution failed: ${a}`, resolverDetails(i));
		default: return joseFailure("key_resolution_failed", "The key resolver returned an unknown failure");
	}
}
function resolverDetails(e) {
	let t = Reflect.get(e, "details");
	if (typeof t != "object" || !t) return;
	let n = Reflect.get(t, "kid"), r = Reflect.get(t, "status");
	return {
		...typeof n == "string" ? { kid: n } : {},
		...typeof r == "number" && Number.isSafeInteger(r) ? { status: r } : {}
	};
}
/**
* Verifies a compact JWS.
*
* The caller's `algorithms` list decides what is accepted; the token's `alg` only selects among
* them, and `none` is always refused as `unsigned_token`. The `tokenType` policy is applied before
* any key is resolved. The key must match the admitted algorithm's RSA hash (at least 2048 bits)
* or ECDSA curve. ECDSA signatures must be fixed-width raw R || S, with no DER retry.
* Header members such as `jku`, `jwk`, `x5u` and
* `x5c` are never used to find a key. A resolver that throws or returns something other than a
* result is reported as `key_resolution_failed` without its message.
*
* Returns a {@linkcode VerifiedJws} on success. Failures carry a stable code and never echo the
* token.
*/
async function verifyCompactJws(e, t) {
	let n = prepareVerify(t);
	return n.ok ? await verifyPrepared(e, n.value) : n;
}
/** Verifies `token` under options already checked by {@linkcode prepareVerify}. */
async function verifyPrepared(e, t) {
	let r = parseWithLimits$1(e, t.limits);
	if (!r.ok) return r;
	let i = r.value, a = i.header.alg;
	if (a === "none") return joseFailure("unsigned_token", "Unsigned tokens are never accepted", { alg: a });
	if (!isAlgorithmAdmitted(a, t.algorithms)) return joseFailure("algorithm_not_allowed", "The token algorithm is not in the allowed list", { alg: a });
	if (!matchesTokenType(i.header, t.typeRule)) return joseFailure("token_type_mismatch", "The token \"typ\" does not match the expected type", { alg: a });
	let o = {
		...i.header,
		alg: a
	}, s = await resolveKey(t, o);
	if (!s.ok) return s;
	let c = checkJwsVerificationKey(s.value, a);
	if (!c.ok) return c;
	if (i.signature.length !== c.value) return joseFailure("invalid_signature", "The signature length does not match the algorithm and key", { alg: a });
	let d = joseFailure("invalid_signature", "The signature does not verify", {
		alg: a,
		...o.kid === void 0 ? {} : { kid: o.kid }
	}), f = await verifySignatureWithKey({
		publicKey: s.value,
		signatureAlgorithm: { oid: jwsAlgorithmProfile(a).oid },
		signatureEncoding: "raw",
		signature: i.signature,
		data: i.signingInput
	});
	return !f.ok || !f.valid ? d : successResult({
		verified: !0,
		header: o,
		payload: i.payload
	});
}
function assertSigningKey(e) {
	f.includes(e.algorithm) || throwMicro509Error("unsupported_algorithm", "Unsupported JWS algorithm");
	let t = checkJwsKey(e.privateKey, e.algorithm, "private");
	t.ok || throwMicro509Error("incompatible_key", t.message);
}
/**
* Signs a compact JWS with an existing private `CryptoKey`.
*
* The header is `alg` followed by the optional `typ`, `kid` and `cty`. Throws a `ResultError`
* (see `isResultError`) coded {@linkcode SignJoseErrorCode} when the algorithm, key or header
* input is invalid. Intended for issuing tokens and for building synthetic tokens in tests.
*/
async function signCompactJws(n) {
	assertSigningKey(n);
	let r = jwsAlgorithmProfile(n.algorithm), i = { alg: n.algorithm };
	for (let e of [
		"typ",
		"kid",
		"cty"
	]) {
		let t = n.header?.[e];
		t !== void 0 && (typeof t != "string" && throwMicro509Error("invalid_header", `Header "${e}" must be a string`), i[e] = t);
	}
	let o = `${base64UrlEncode$1(v.encode(JSON.stringify(i)))}.${base64UrlEncode$1(n.payload)}`, { signature: s } = await signData(n.privateKey, v.encode(o));
	return `${o}.${base64UrlEncode$1(r.kind === "ec" ? ecdsaSignatureDerToRaw(s, r.curve) : s)}`;
}
// ../../dist/jose/jwe.js
function checkKey(e, t) {
	if (!(e instanceof CryptoKey) || e.type !== t || e.algorithm.name !== "RSA-OAEP" || !e.usages.includes(t === "public" ? "encrypt" : "decrypt")) return joseFailure("key_unsuitable", "JWE requires an RSA-OAEP key with the correct type and usage");
	let n = e.algorithm;
	return !("hash" in n) || typeof n.hash != "object" || n.hash === null || !("name" in n.hash) || n.hash.name !== "SHA-512" ? joseFailure("key_unsuitable", "JWE RSA-OAEP-512 requires SHA-512") : !("modulusLength" in n) || typeof n.modulusLength != "number" || !Number.isSafeInteger(n.modulusLength) || n.modulusLength < 2048 || n.modulusLength > 8192 || !("publicExponent" in n) || !(n.publicExponent instanceof Uint8Array) || !validRsaPublicExponent(n.publicExponent) ? joseFailure("key_unsuitable", "JWE RSA keys require a 2048–8192 bit modulus and a suitable exponent") : successResult(Math.ceil(n.modulusLength / 8));
}
function checkCritical(e) {
	if (!Object.hasOwn(e, "crit")) return successResult(void 0);
	let t = e.crit;
	if (!isJsonArray(t) || t.length === 0) return joseFailure("invalid_header", "JWE crit must be a nonempty array");
	let n = /* @__PURE__ */ new Set();
	for (let r of t) {
		if (typeof r != "string" || r.length === 0 || n.has(r) || !Object.hasOwn(e, r)) return joseFailure("invalid_header", "JWE crit has a repeated, absent or invalid member");
		n.add(r);
	}
	return joseFailure("unsupported_critical_header", "JWE critical extensions are not supported");
}
function headerFromMembers(e) {
	if (typeof e.alg != "string" || e.alg.length === 0 || typeof e.enc != "string" || e.enc.length === 0) return joseFailure("invalid_header", "JWE requires string alg and enc");
	for (let t of [
		"typ",
		"cty",
		"kid"
	]) if (Object.hasOwn(e, t) && typeof e[t] != "string") return joseFailure("invalid_header", `JWE ${t} must be a string`);
	let t = checkCritical(e);
	return t.ok ? Object.hasOwn(e, "zip") ? joseFailure("unsupported_compression", "JWE compression is not supported") : successResult({
		alg: e.alg,
		enc: e.enc,
		members: e
	}) : t;
}
function encryptionHeader(e, t) {
	if (e.algorithm !== "RSA-OAEP-512") return joseFailure("algorithm_not_allowed", "Unsupported JWE key-management algorithm");
	if (e.encryption !== "A256GCM") return joseFailure("encryption_not_allowed", "Unsupported JWE content-encryption algorithm");
	let i = snapshotJsonData(e.header === void 0 ? {} : e.header, {
		maxBytes: t.maxHeaderBytes,
		maxDepth: t.maxJsonDepth,
		maxNodes: t.maxJsonNodes
	});
	if (!i.ok) return joseFailure(i.code, "JWE header must be bounded plain JSON data");
	if (!isJsonObject(i.value)) return joseFailure("invalid_header", "JWE header must be an object");
	let s = i.value;
	if (Object.hasOwn(s, "alg") && s.alg !== e.algorithm || Object.hasOwn(s, "enc") && s.enc !== e.encryption) return joseFailure("invalid_header", "JWE header conflicts with the requested algorithms");
	let c = {
		...s,
		alg: e.algorithm,
		enc: e.encryption
	}, l = snapshotJsonData(c, {
		maxBytes: t.maxHeaderBytes,
		maxDepth: t.maxJsonDepth,
		maxNodes: t.maxJsonNodes
	});
	if (!l.ok) return joseFailure(l.code, "JWE completed header exceeds its JSON bounds");
	let u = headerFromMembers(c);
	if (!u.ok) return u;
	let f = new TextEncoder().encode(JSON.stringify(c));
	return f.length > t.maxHeaderBytes ? joseFailure("limit_exceeded", "JWE header exceeds maxHeaderBytes") : successResult(base64UrlEncode$1(f));
}
function encodedLength(e) {
	return Math.ceil(e * 4 / 3);
}
/**
* Encrypts one compact JWE for the limited RSA-OAEP-512/A256GCM profile (RFC 7516 §5.1).
* Generates a fresh 32-byte CEK and 12-byte IV; no externally supplied IV, compression or external AAD.
* The protected header's ORIGINAL base64url segment is the ASCII AAD (RFC 7516 §5.1 step 14).
*/
async function encryptCompactJwe(t) {
	if (typeof t != "object" || !t || !(t.plaintext instanceof Uint8Array)) return joseFailure("invalid_options", "JWE input requires plaintext bytes");
	let r = resolveJoseLimits(t.limits);
	if (!r.ok) return r;
	if (t.plaintext.length > r.value.maxPayloadBytes) return joseFailure("limit_exceeded", "JWE plaintext exceeds maxPayloadBytes");
	let i = encryptionHeader(t, r.value);
	if (!i.ok) return i;
	let a = checkKey(t.publicKey, "public");
	if (!a.ok) return a;
	if (a.value > r.value.maxSignatureBytes) return joseFailure("limit_exceeded", "JWE encrypted key exceeds maxSignatureBytes");
	if (i.value.length + encodedLength(a.value) + encodedLength(12) + encodedLength(t.plaintext.length) + encodedLength(16) + 4 > r.value.maxTokenLength) return joseFailure("token_too_large", "JWE exceeds maxTokenLength");
	let s = new Uint8Array(t.plaintext), l = getCrypto(), f = l.getRandomValues(/* @__PURE__ */ new Uint8Array(32)), p = l.getRandomValues(/* @__PURE__ */ new Uint8Array(12));
	try {
		let e = new Uint8Array(await l.subtle.encrypt({ name: "RSA-OAEP" }, t.publicKey, f)), r = await l.subtle.importKey("raw", f, { name: "AES-GCM" }, !1, ["encrypt"]), a = new Uint8Array(await l.subtle.encrypt({
			name: "AES-GCM",
			iv: p,
			additionalData: new TextEncoder().encode(i.value),
			tagLength: 128
		}, r, s));
		return successResult([
			i.value,
			base64UrlEncode$1(e),
			base64UrlEncode$1(p),
			base64UrlEncode$1(a.subarray(0, a.length - 16)),
			base64UrlEncode$1(a.subarray(a.length - 16))
		].join("."));
	} catch (e) {
		return rethrowIfInvariant(e), joseFailure("encryption_failed", "JWE encryption failed");
	} finally {
		f.fill(0), s.fill(0);
	}
}
function decodeSegment(e, n) {
	if (e.length > encodedLength(n)) return joseFailure("limit_exceeded", "JWE segment exceeds its byte limit");
	let r = base64UrlDecode$1(e);
	return r === void 0 ? joseFailure("invalid_encoding", "JWE segment is not canonical base64url") : r.length > n ? joseFailure("limit_exceeded", "JWE segment exceeds its byte limit") : successResult(r);
}
function parse(e, t) {
	if (typeof e != "string") return joseFailure("malformed_token", "JWE must be a string");
	if (e.length > t.maxTokenLength) return joseFailure("token_too_large", "JWE exceeds maxTokenLength");
	let n = e.split("."), [r, i, a, c, l] = n;
	if (n.length !== 5 || !r || i === void 0 || !a || c === void 0 || !l) return joseFailure("malformed_token", "JWE requires five compact segments");
	let u = decodeSegment(r, t.maxHeaderBytes);
	if (!u.ok) return u;
	let f = decodeJsonObject(u.value, t, "header", "invalid_header", "JWE");
	if (!f.ok) return f;
	let p = headerFromMembers(f.value);
	if (!p.ok) return p;
	let m = decodeSegment(i, t.maxSignatureBytes);
	if (!m.ok) return m;
	let h = decodeSegment(a, 12);
	if (!h.ok) return h;
	let g = decodeSegment(c, t.maxPayloadBytes);
	if (!g.ok) return g;
	let _ = decodeSegment(l, 16);
	return _.ok ? h.value.length !== 12 || _.value.length !== 16 ? joseFailure("malformed_token", "JWE requires a 12-byte IV and 16-byte tag") : successResult({
		header: p.value,
		aad: new TextEncoder().encode(r),
		encryptedKey: m.value,
		iv: h.value,
		ciphertext: g.value,
		tag: _.value
	}) : _;
}
function decryptionFailure() {
	return joseFailure("decryption_failed", "JWE decryption failed");
}
/** Uniform CEK/tag refusal, with dummy CEK on unwrap failure (RFC 7516 §11.5). */
async function decryptPayload(t, n, r) {
	let i = getCrypto(), a = i.getRandomValues(/* @__PURE__ */ new Uint8Array(32)), o = t.encryptedKey.length !== r;
	try {
		if (!o) try {
			let e = new Uint8Array(await i.subtle.decrypt({ name: "RSA-OAEP" }, n, new Uint8Array(t.encryptedKey)));
			e.length === 32 ? (a.fill(0), a = e) : (e.fill(0), o = !0);
		} catch (e) {
			rethrowIfInvariant(e), o = !0;
		}
		let e = await i.subtle.importKey("raw", a, { name: "AES-GCM" }, !1, ["decrypt"]), r = new Uint8Array(t.ciphertext.length + 16);
		r.set(t.ciphertext), r.set(t.tag, t.ciphertext.length);
		let s = new Uint8Array(await i.subtle.decrypt({
			name: "AES-GCM",
			iv: new Uint8Array(t.iv),
			additionalData: new Uint8Array(t.aad),
			tagLength: 128
		}, e, r));
		return o ? (s.fill(0), decryptionFailure()) : successResult({
			authenticated: !0,
			plaintext: s,
			header: t.header
		});
	} catch (e) {
		return rethrowIfInvariant(e), decryptionFailure();
	} finally {
		a.fill(0);
	}
}
/**
* Decrypts with explicit application allowlists, bounded parsing and the supplied private key.
* RSA unwrap, wrong CEK length, wrong key and GCM authentication failures share `decryption_failed`.
* A wrong RSA ciphertext length skips RSA and follows the dummy-CEK/GCM path. This reduces oracle
* information; JavaScript and provider implementations are not promised to be constant-time.
*/
async function decryptCompactJwe(e, t) {
	if (typeof t != "object" || !t || !Array.isArray(t.keyManagementAlgorithms) || t.keyManagementAlgorithms.length === 0 || t.keyManagementAlgorithms.some((e) => e !== "RSA-OAEP-512") || !Array.isArray(t.contentEncryptionAlgorithms) || t.contentEncryptionAlgorithms.length === 0 || t.contentEncryptionAlgorithms.some((e) => e !== "A256GCM")) return joseFailure("invalid_options", "JWE requires nonempty supported alg and enc allowlists");
	let n = resolveJoseLimits(t.limits);
	if (!n.ok) return n;
	let r = parse(e, n.value);
	if (!r.ok) return r;
	if (!t.keyManagementAlgorithms.some((e) => e === r.value.header.alg)) return joseFailure("algorithm_not_allowed", "JWE key-management algorithm is not allowed");
	if (!t.contentEncryptionAlgorithms.some((e) => e === r.value.header.enc)) return joseFailure("encryption_not_allowed", "JWE content-encryption algorithm is not allowed");
	let i = checkKey(t.privateKey, "private");
	return i.ok ? await decryptPayload(r.value, t.privateKey, i.value) : i;
}
// ../../dist/jose/jwks.js
/**
* JSON Web Key Set (RFC 7517) parsing, key selection and a local key resolver. Nothing here
* performs network access.
*
* @module
*/
/** The limits applied when a caller supplies none. */
const p = {
	maxBytes: 65536,
	maxKeys: 32
};
function malformed(e) {
	return joseFailure("jwks_malformed", e);
}
function memberString(e, t) {
	if (!Object.hasOwn(e, t)) return;
	let n = e[t];
	return typeof n == "string" ? n : null;
}
function memberStrings(e, t) {
	if (!Object.hasOwn(e, t)) return;
	let n = e[t];
	if (!isJsonArray(n)) return null;
	let i = [];
	for (let e of n) {
		if (typeof e != "string" || i.includes(e)) return null;
		i.push(e);
	}
	return i;
}
function parseEntry(e) {
	if (!isJsonObject(e)) return malformed("JWK Set key is not an object");
	let t = memberString(e, "kty"), n = memberString(e, "kid"), r = memberString(e, "use"), a = memberString(e, "alg"), o = memberStrings(e, "key_ops");
	if (typeof t != "string" || n === null || r === null || a === null || o === null) return successResult({
		kind: "unsupported",
		...typeof t == "string" ? { kty: t } : {},
		members: e
	});
	let s = {
		...n === void 0 ? {} : { kid: n },
		...r === void 0 ? {} : { use: r },
		...a === void 0 ? {} : { alg: a },
		...o === void 0 ? {} : { keyOps: o }
	};
	return t === "RSA" && typeof e.n == "string" && typeof e.e == "string" ? successResult({
		kind: "rsa",
		n: e.n,
		e: e.e,
		...s,
		members: e
	}) : t === "EC" && typeof e.crv == "string" && typeof e.x == "string" && typeof e.y == "string" ? successResult({
		kind: "ec",
		crv: e.crv,
		x: e.x,
		y: e.y,
		...s,
		members: e
	}) : successResult({
		kind: "unsupported",
		kty: t,
		...s,
		members: e
	});
}
/**
* Parses a JWK Set document.
*
* The document must be duplicate-free JSON with a `keys` array within `limits`. Keys with a `kty`
* other than `RSA` or `EC`, and keys with missing or wrongly typed members, are kept as `unsupported`
* entries and never selected (RFC 7517 §5). A set that is not a duplicate-free object with a
* `keys` array of objects is `jwks_malformed`.
*/
function parseJwks(e, t) {
	let n = resolveJwksLimits(t);
	return n.ok ? parseWithLimits(e, n.value) : n;
}
/**
* Validates already parsed, plain JSON data and owns a detached deep snapshot of it.
*
* Prefer {@linkcode parseJwks} for untrusted transport text: an object cannot reveal lost duplicate
* member names or invalid original UTF-8. No getters or `toJSON` are called. Cycles, non-JSON values,
* sparse arrays, accessors, symbols and custom prototypes are refused. `maxBytes` bounds the UTF-8
* size of the compact JSON data spelling, not the original transport bytes. Depth and node limits
* match the text parser. A changed source object requires a new validation and resolver instance.
*/
function validateJwks(e, t) {
	let r = resolveJwksLimits(t);
	if (!r.ok) return r;
	let i = snapshotJsonData(e, {
		maxBytes: r.value.maxBytes,
		maxDepth: 8,
		maxNodes: r.value.maxKeys * 64 + 64
	});
	return i.ok ? validateDocument(i.value, r.value) : i.code === "limit_exceeded" ? joseFailure("limit_exceeded", "JWK Set exceeds its JSON data bounds") : malformed("JWK Set is not plain JSON data");
}
const m$1 = 16777216;
const h = 1024;
function resolveJwksLimits(e) {
	if (e !== void 0 && (typeof e != "object" || !e)) return joseFailure("invalid_options", "limits must be an object");
	let t = e?.maxBytes === void 0 ? p.maxBytes : e.maxBytes, n = e?.maxKeys === void 0 ? p.maxKeys : e.maxKeys;
	return !Number.isSafeInteger(t) || t < 1 || t > m$1 ? joseFailure("invalid_options", `limits.maxBytes must be from 1 to ${m$1}`) : !Number.isSafeInteger(n) || n < 1 || n > h ? joseFailure("invalid_options", `limits.maxKeys must be from 1 to ${h}`) : successResult({
		maxBytes: t,
		maxKeys: n
	});
}
function parseWithLimits(e, t) {
	if (typeof e == "string" && e.length > t.maxBytes) return joseFailure("limit_exceeded", `JWK Set exceeds ${t.maxBytes} bytes`);
	if (typeof e != "string" && !(e instanceof Uint8Array)) return malformed("JWK Set input is neither a string nor bytes");
	let n = typeof e == "string" ? new TextEncoder().encode(e) : e;
	if (n.byteLength > t.maxBytes) return joseFailure("limit_exceeded", `JWK Set exceeds ${t.maxBytes} bytes`);
	let r;
	try {
		r = new TextDecoder("utf-8", {
			fatal: !0,
			ignoreBOM: !0
		}).decode(n);
	} catch {
		return malformed("JWK Set is not valid UTF-8");
	}
	let i = parseStrictJson(r, {
		maxDepth: 8,
		maxNodes: t.maxKeys * 64 + 64
	});
	return i.ok ? validateDocument(i.value, t) : i.code === "limit_exceeded" ? joseFailure("limit_exceeded", `JWK Set: ${i.message}`) : malformed(`JWK Set: ${i.message}`);
}
function validateDocument(e, t) {
	if (!isJsonObject(e)) return malformed("JWK Set is not an object");
	let n = e.keys;
	if (!isJsonArray(n)) return malformed("JWK Set \"keys\" is not an array");
	if (n.length > t.maxKeys) return joseFailure("limit_exceeded", `JWK Set holds more than ${t.maxKeys} keys`);
	let a = [];
	for (let e of n) {
		let t = parseEntry(e);
		if (!t.ok) return t;
		a.push(t.value);
	}
	return successResult({
		keys: a,
		members: e
	});
}
/** Why a key entry cannot verify a given algorithm, or `undefined` when it can. */
function unsuitableReason(n, r) {
	if (!f.includes(r)) return "unsupported algorithm";
	let i = jwsAlgorithmProfile(r);
	if (n.kind !== i.kind) return "key type does not match the algorithm";
	if (n.use !== void 0 && n.use !== "sig") return "\"use\" is not \"sig\"";
	if (n.keyOps !== void 0 && !n.keyOps.includes("verify")) return "\"key_ops\" does not include \"verify\"";
	if (n.use === "sig" && n.keyOps?.some((e) => e !== "sign" && e !== "verify")) return "\"use\" and \"key_ops\" are inconsistent";
	if (n.alg !== void 0 && n.alg !== r) return "\"alg\" names another algorithm";
	if (n.kind === "ec" && i.kind === "ec") {
		if (n.crv !== i.curve) return "EC curve does not match the algorithm";
		let r = base64UrlDecode$1(n.x), a = base64UrlDecode$1(n.y);
		return r?.length !== i.coordinateBytes || a?.length !== i.coordinateBytes ? "EC coordinates must be canonical base64url of the required fixed width" : isPrimeEcPoint(i.curve, r, a) ? void 0 : "EC point is not on the curve";
	}
	return n.kind === "rsa" ? unsuitableRsaParameters(n) : "key type does not match the algorithm";
}
function unsuitableRsaParameters(e) {
	let n = base64UrlDecode$1(e.n), r = base64UrlDecode$1(e.e);
	if (n === void 0 || r === void 0 || n.length === 0) return "RSA parameters are not canonical base64url";
	if (n[0] === 0 || r[0] === 0 || r.length === 0) return "RSA parameters have leading zero octets";
	if (n.length > 1024) return "RSA modulus is too large";
	if ((n.length - 1) * 8 + 32 - Math.clz32(n[0] ?? 0) < 2048) return "RSA modulus is too small";
	if (!validRsaPublicExponent(r, n)) return "RSA public exponent is invalid";
}
/**
* Selects the one key of a set that can verify `selector`.
*
* Keys are filtered by `kid` (when the token has one), key type, `use`, `key_ops`, `alg` and RSA/EC
* parameters. No match is `key_not_found`, or `key_unsuitable` when `kid` matched only keys that
* fail the other checks. More than one match is `ambiguous_key`: a token without `kid` therefore
* resolves only against a set with a single usable key.
*/
function selectJwk(e, t) {
	let n = e.keys.filter((e) => t.kid === void 0 || e.kid === t.kid), r = t.kid === void 0 ? {} : { kid: t.kid };
	if (n.length === 0) return joseFailure("key_not_found", "No key matches the token", r);
	let i = [];
	for (let e of n) e.kind !== "unsupported" && unsuitableReason(e, t.algorithm) === void 0 && i.push(e);
	let [a, s] = i;
	return a === void 0 ? joseFailure("key_unsuitable", "No matching key can verify this algorithm", r) : s === void 0 ? successResult(a) : joseFailure("ambiguous_key", "More than one key matches the token", r);
}
/**
* Imports a selected entry as a verify-only key for `algorithm`. The default remains RS256;
* pass the selected algorithm explicitly for every other RSA hash or ECDSA curve.
*/
async function importJwkEntry(e, t = "RS256") {
	let n = unsuitableReason(e, t);
	if (n !== void 0) return joseFailure("key_unsuitable", n, e.kid === void 0 ? void 0 : { kid: e.kid });
	let r = jwsAlgorithmProfile(t), i = e.kind === "rsa" ? {
		kty: "RSA",
		n: e.n,
		e: e.e,
		alg: t,
		key_ops: ["verify"],
		ext: !0
	} : {
		kty: "EC",
		crv: e.crv,
		x: e.x,
		y: e.y,
		alg: t,
		key_ops: ["verify"],
		ext: !0
	}, a = await importPublicJwk(i, r.kind === "rsa" ? {
		kind: "rsa",
		scheme: "pkcs1-v1_5",
		hash: r.hash
	} : {
		kind: "ecdsa",
		curve: r.curve
	});
	if (!a.ok) return joseFailure("key_unsuitable", "The JWK cannot be imported", { ...e.kid === void 0 ? {} : { kid: e.kid } });
	let s = checkJwsVerificationKey(a.value, t);
	return s.ok ? successResult(a.value) : s;
}
/** Cache identity includes the admitted algorithm, which binds the RSA import hash. */
function jwkEntryCacheKey(e, t) {
	return e.kind === "rsa" ? `${t}.rsa.${e.n}.${e.e}` : `${t}.ec.${e.crv}.${e.x}.${e.y}`;
}
/**
* Creates a key resolver over a fixed JWK Set.
*
* The resolver selects with {@linkcode selectJwk} and imports each key once, so repeated
* verifications reuse the same `CryptoKey`. Keep one resolver per trusted source/snapshot and
* replace it when that snapshot changes so removed keys do not survive rotation.
*
* @see https://micro509.kjanat.dev/guide/jose-cache for application-owned raw JWKS caches.
*/
function createJwksKeyResolver(e) {
	let t = /* @__PURE__ */ new Map();
	return async (n) => {
		let r = selectJwk(e, {
			algorithm: n.algorithm,
			...n.kid === void 0 ? {} : { kid: n.kid }
		});
		if (!r.ok) return r;
		let i = jwkEntryCacheKey(r.value, n.algorithm), a = t.get(i);
		if (a !== void 0) return await a;
		let o = importJwkEntry(r.value, n.algorithm);
		return t.set(i, o), await o;
	};
}
// ../../dist/jose/jwt.js
/** Largest clock tolerance {@linkcode JwtClaimsPolicy.clockToleranceSeconds} accepts. */
const f$1 = 600;
function decodeClaims(e, r, a) {
	return e.cty !== void 0 && mediaTypeKey(e.cty) === "application/jwt" ? joseFailure("unsupported_nested_jwt", "Nested JWTs (cty \"JWT\") are not supported") : decodeJsonObject(r, a, "payload", "invalid_payload");
}
/** Decodes a JWT without checking its signature. Every field of the result is unauthenticated. */
function decodeJwtUnverified(e, t) {
	let n = resolveJoseLimits(t);
	if (!n.ok) return n;
	let r = parseCompactJws(e, n.value);
	if (!r.ok) return r;
	let i = decodeClaims(r.value.header, r.value.payload, n.value);
	return i.ok ? successResult({
		verified: !1,
		header: r.value.header,
		claims: i.value
	}) : i;
}
function claimFailure(e, n, r) {
	return joseFailure(e, n, { claim: r });
}
function numericDate(e, t) {
	if (!Object.hasOwn(e, t)) return successResult(void 0);
	let n = e[t];
	return typeof n != "number" || !Number.isFinite(n) ? claimFailure("invalid_claim", `Claim "${t}" is not a NumericDate`, t) : successResult(n);
}
function stringClaim(e, t) {
	if (!Object.hasOwn(e, t)) return successResult(void 0);
	let n = e[t];
	return typeof n == "string" ? successResult(n) : claimFailure("invalid_claim", `Claim "${t}" is not a string`, t);
}
function audienceClaim(t) {
	if (!Object.hasOwn(t, "aud")) return successResult(void 0);
	let n = t.aud;
	if (typeof n == "string") return successResult(n);
	if (!isJsonArray(n)) return claimFailure("invalid_claim", "Claim \"aud\" is neither a string nor an array", "aud");
	let r = [];
	for (let e of n) {
		if (typeof e != "string") return claimFailure("invalid_claim", "Claim \"aud\" holds a non-string", "aud");
		r.push(e);
	}
	return successResult(r);
}
function registeredClaims(e) {
	let t = stringClaim(e, "iss");
	if (!t.ok) return t;
	let n = stringClaim(e, "sub");
	if (!n.ok) return n;
	let r = stringClaim(e, "jti");
	if (!r.ok) return r;
	let i = audienceClaim(e);
	if (!i.ok) return i;
	let a = numericDate(e, "exp");
	if (!a.ok) return a;
	let o = numericDate(e, "nbf");
	if (!o.ok) return o;
	let s = numericDate(e, "iat");
	return s.ok ? successResult({
		...t.value === void 0 ? {} : { iss: t.value },
		...n.value === void 0 ? {} : { sub: n.value },
		...i.value === void 0 ? {} : { aud: i.value },
		...a.value === void 0 ? {} : { exp: a.value },
		...o.value === void 0 ? {} : { nbf: o.value },
		...s.value === void 0 ? {} : { iat: s.value },
		...r.value === void 0 ? {} : { jti: r.value }
	}) : s;
}
function expectedValues(e) {
	return typeof e == "string" ? successResult([e]) : isUncheckedPolicy(e) ? successResult(void 0) : Array.isArray(e) && e.length > 0 && e.every((e) => typeof e == "string") ? successResult([...e]) : joseFailure("invalid_options", "issuer and audience need expected values or { unchecked: true }");
}
function prepareClaims(e) {
	if (typeof e != "object" || !e) return joseFailure("invalid_options", "A claims policy is required");
	let n = e.clockToleranceSeconds ?? 0;
	if (typeof n != "number" || !Number.isFinite(n) || n < 0 || n > 600) return joseFailure("invalid_options", "clockToleranceSeconds must be between 0 and 600");
	let r = e.maxAgeSeconds;
	if (r !== void 0 && (typeof r != "number" || !Number.isFinite(r) || r < 0)) return joseFailure("invalid_options", "maxAgeSeconds must be a non-negative number");
	let i = e.requiredClaims ?? ["exp"];
	if (!Array.isArray(i) || !i.every((e) => typeof e == "string")) return joseFailure("invalid_options", "requiredClaims must be an array of strings");
	if (e.futureIssuedAt !== void 0 && e.futureIssuedAt !== "reject" && e.futureIssuedAt !== "allow") return joseFailure("invalid_options", "futureIssuedAt must be 'reject' or 'allow'");
	if (e.now !== void 0 && typeof e.now != "function") return joseFailure("invalid_options", "now must be a function");
	let a = expectedValues(e.issuer);
	if (!a.ok) return a;
	let o = expectedValues(e.audience);
	return o.ok ? successResult({
		issuers: a.value,
		audiences: o.value,
		required: [...i],
		now: e.now ?? (() => /* @__PURE__ */ new Date()),
		toleranceSeconds: n,
		maxAgeSeconds: r,
		allowFutureIssuedAt: e.futureIssuedAt === "allow"
	}) : o;
}
function checkIdentity(e, t) {
	let { issuers: n, audiences: r } = t;
	if (n !== void 0 && (e.iss === void 0 || !n.includes(e.iss))) return claimFailure("issuer_mismatch", "The token issuer is not accepted", "iss");
	if (r !== void 0 && !(typeof e.aud == "string" ? [e.aud] : e.aud ?? []).some((e) => r.includes(e))) return claimFailure("audience_mismatch", "The token audience is not accepted", "aud");
}
function checkTimes(e, t, n) {
	let r = t.toleranceSeconds, { exp: i, nbf: a, iat: o } = e;
	if (i !== void 0 && n >= i + r) return claimFailure("expired", "The token has expired", "exp");
	if (a !== void 0 && n < a - r) return claimFailure("not_yet_valid", "The token is not valid yet", "nbf");
	if (o !== void 0 && !t.allowFutureIssuedAt && o - r > n) return claimFailure("issued_in_future", "The token was issued in the future", "iat");
	if (t.maxAgeSeconds !== void 0) {
		if (o === void 0) return claimFailure("missing_claim", "Claim \"iat\" is required by maxAgeSeconds", "iat");
		if (n - o > t.maxAgeSeconds + r) return claimFailure("token_too_old", "The token is older than the maximum age", "iat");
	}
}
function clockSeconds(e) {
	let n;
	try {
		n = e.now();
	} catch {
		return joseFailure("invalid_options", "The claims clock threw");
	}
	return !(n instanceof Date) || !Number.isFinite(n.getTime()) ? joseFailure("invalid_options", "The claims clock did not return a valid Date") : successResult(n.getTime() / 1e3);
}
function validateClaims(e, t) {
	for (let n of t.required) if (!Object.hasOwn(e, n)) return claimFailure("missing_claim", `Claim "${n}" is required`, n);
	let n = registeredClaims(e);
	if (!n.ok) return n;
	let r = checkIdentity(n.value, t);
	if (r !== void 0) return r;
	let i = clockSeconds(t);
	if (!i.ok) return i;
	let a = checkTimes(n.value, t, i.value);
	return a === void 0 ? n : a;
}
/**
* Verifies a JWT: the signature and `tokenType` policy as {@linkcode verifyCompactJws} applies
* them, then the payload as a duplicate-free JSON object, then `claims`.
*
* `iss` and `aud` must be stated explicitly. Time claims follow RFC 7519 §4.1.4 and §4.1.5: the
* token is expired when the clock is at or after `exp` and not yet valid when it is before
* `nbf`, each moved by `clockToleranceSeconds`. Time claims must be JSON numbers; strings are never
* coerced. `exp` is required unless `requiredClaims` says otherwise.
*/
async function verifyJwt(e, n) {
	if (typeof n != "object" || !n) return joseFailure("invalid_options", "Verification options are required");
	let r = prepareClaims(n.claims);
	if (!r.ok) return r;
	let i = prepareVerify(n);
	if (!i.ok) return i;
	let a = await verifyPrepared(e, i.value);
	if (!a.ok) return a;
	let s = decodeClaims(a.value.header, a.value.payload, i.value.limits);
	if (!s.ok) return s;
	let c = validateClaims(s.value, r.value);
	return c.ok ? successResult({
		verified: !0,
		header: a.value.header,
		claims: s.value,
		registered: c.value
	}) : c;
}
/**
* Signs a JWT. The header carries `typ: "JWT"` unless `header.typ` says otherwise.
*
* Throws a `ResultError` coded `SignJoseErrorCode` for an unusable key, algorithm or header, and
* `invalid_claims` when `claims` cannot be serialized.
*/
async function signJwt(e) {
	let t;
	try {
		t = JSON.stringify(e.claims);
	} catch {
		t = void 0;
	}
	if (typeof t != "string") return throwMicro509Error("invalid_claims", "JWT claims are not JSON-serializable");
	let { claims: n, ...r } = e;
	return await signCompactJws({
		...r,
		payload: new TextEncoder().encode(t),
		header: {
			typ: "JWT",
			...e.header
		}
	});
}
// ../../dist/jose/remote-jwks.js
const c = Symbol("micro509.jose.aborted");
const l = {
	timeoutMs: 5e3,
	maxResponseBytes: 65536,
	maxKeys: 32,
	defaultTtlMs: 6e5,
	maxTtlMs: 864e5,
	cooldownMs: 3e4
};
const u = /* @__PURE__ */ new Set([
	301,
	302,
	303,
	307,
	308
]);
const d = /* @__PURE__ */ new Set([
	"localhost",
	"127.0.0.1",
	"[::1]"
]);
function isPermittedUrl(e) {
	return e.protocol === "https:" || e.protocol === "http:" && d.has(e.hostname);
}
function positiveInteger(e, t, n) {
	let r = e ?? t;
	return !Number.isSafeInteger(r) || r <= 0 ? throwMicro509Error("invalid_remote_jwks_config", `${n} must be a positive integer`) : r;
}
function resolveConfig(e) {
	let t;
	try {
		t = new URL(e.url);
	} catch {
		return throwMicro509Error("invalid_remote_jwks_config", "url is not an absolute URL");
	}
	if (!isPermittedUrl(t)) return throwMicro509Error("invalid_remote_jwks_config", "url must use https, or http on a loopback host");
	if (t.username !== "" || t.password !== "") return throwMicro509Error("invalid_remote_jwks_config", "url must not embed credentials");
	let n = e.redirects?.maxRedirects ?? 0;
	if (!Number.isSafeInteger(n) || n < 0 || n > 10) return throwMicro509Error("invalid_remote_jwks_config", "maxRedirects must be an integer from 0 to 10");
	let r = positiveInteger(e.maxTtlMs, l.maxTtlMs, "maxTtlMs"), i = positiveInteger(e.cooldownMs, l.cooldownMs, "cooldownMs");
	return {
		url: t,
		transport: e.transport ?? ((e, t) => globalThis.fetch(e, t)),
		headers: { ...e.headers },
		timeoutMs: positiveInteger(e.timeoutMs, l.timeoutMs, "timeoutMs"),
		maxResponseBytes: positiveInteger(e.maxResponseBytes, l.maxResponseBytes, "maxResponseBytes"),
		maxKeys: positiveInteger(e.maxKeys, l.maxKeys, "maxKeys"),
		maxRedirects: n,
		allowRedirect: e.redirects?.allow ?? ((e, t) => e.origin === t.origin),
		defaultTtlMs: positiveInteger(e.defaultTtlMs, l.defaultTtlMs, "defaultTtlMs"),
		maxTtlMs: r,
		cooldownMs: i,
		now: e.now ?? Date.now
	};
}
function unavailable(t, n) {
	return joseFailure("jwks_unavailable", t, n === void 0 ? void 0 : { status: n });
}
function secondsHeader(e, t) {
	let n = e.get(t);
	return n !== null && /^\d{1,10}$/.test(n) ? Number(n) * 1e3 : NaN;
}
/**
* Remaining freshness in milliseconds, never below zero and never above `maxTtlMs`.
*
* The lifetime is `Cache-Control: max-age`, else `Expires` less `Date`, else `defaultTtlMs`
* (RFC 9111 §4.2.1); `no-store`, `no-cache` and unusable values give none. The response age is the
* larger of the apparent age from `Date` and the `Age` header plus the transit delay
* (RFC 9111 §4.2.3).
*/
function freshnessMs(e, t, n, r) {
	let i = (e.get("cache-control") ?? "").split(",").map((e) => e.trim().toLowerCase()).filter((e) => e.length > 0);
	if (i.includes("no-store") || i.includes("no-cache")) return 0;
	let a = Date.parse(e.get("date") ?? ""), o = Number.isNaN(a) ? 0 : Math.max(0, n - a), s = secondsHeader(e, "age"), c = Math.max(0, n - t), l = Math.max(o, (Number.isNaN(s) ? 0 : s) + c), u = i.find((e) => e.startsWith("max-age")), d = r.defaultTtlMs;
	if (u !== void 0) {
		let e = /^max-age=("?)(\d{1,10})\1$/.exec(u);
		d = e?.[2] === void 0 ? 0 : Number(e[2]) * 1e3;
	} else if (e.has("expires")) {
		let t = Date.parse(e.get("expires") ?? "");
		d = Number.isNaN(t) ? 0 : t - (Number.isNaN(a) ? n : a);
	}
	return Math.min(r.maxTtlMs, Math.max(0, d - l));
}
async function readBounded(t, n, r) {
	let i = joseFailure("jwks_malformed", `The JWKS response exceeds ${n} bytes`), a = t.headers.get("content-length");
	if (a !== null && /^\d+$/.test(a) && Number(a) > n) return await t.body?.cancel(), i;
	if (t.body === null) return successResult(/* @__PURE__ */ new Uint8Array());
	let s = t.body.getReader(), release = () => {
		s.cancel().catch(() => void 0);
	};
	r.addEventListener("abort", release, { once: !0 });
	try {
		let e = [], t = 0;
		for (;;) {
			let { done: a, value: o } = await s.read();
			if (r.aborted) return unavailable("The JWKS request was cancelled");
			if (a) break;
			if (t += o.byteLength, t > n) return release(), i;
			e.push(o);
		}
		let a = new Uint8Array(t), c = 0;
		for (let t of e) a.set(t, c), c += t.byteLength;
		return successResult(a);
	} finally {
		r.removeEventListener("abort", release);
	}
}
function nextHop(e, t, n, r) {
	let i = n.headers.get("location");
	if (r >= e.maxRedirects || i === null) return unavailable("The JWKS endpoint redirected", n.status);
	let a;
	try {
		a = new URL(i, t);
	} catch {
		return unavailable("The JWKS redirect target is not a URL", n.status);
	}
	return !isPermittedUrl(a) || a.username !== "" || a.password !== "" || !e.allowRedirect(a, t) ? unavailable("The JWKS redirect target is not permitted", n.status) : successResult(a);
}
async function readJwks(t, n, i, a) {
	if (n.status !== 200) return await n.body?.cancel(), unavailable("The JWKS endpoint did not answer 200", n.status);
	let s = t.now(), c = await readBounded(n, t.maxResponseBytes, a);
	if (!c.ok) return c;
	let l = parseJwks(c.value, {
		maxBytes: t.maxResponseBytes,
		maxKeys: t.maxKeys
	});
	return l.ok ? successResult({
		jwks: l.value,
		expiresAt: s + freshnessMs(n.headers, i, s, t)
	}) : joseFailure("jwks_malformed", l.message);
}
async function fetchJwks(e, t, n) {
	let r = e.url;
	for (let i = 0;; i++) {
		let a = await e.transport(r.href, {
			method: "GET",
			redirect: "manual",
			credentials: "omit",
			cache: "no-store",
			headers: r.origin === e.url.origin ? e.headers : {},
			signal: t
		});
		if (t.aborted) return await a.body?.cancel(), unavailable("The JWKS request was cancelled");
		if (a.type === "opaqueredirect") return unavailable("The runtime hides redirects, so they cannot be validated");
		if (!u.has(a.status)) return await readJwks(e, a, n, t);
		await a.body?.cancel();
		let o = nextHop(e, r, a, i);
		if (!o.ok) return o;
		r = o.value;
	}
}
function carryOver(e, t) {
	let r = /* @__PURE__ */ new Map();
	for (let i of e.jwks.keys) if (i.kind !== "unsupported") for (let e of f) {
		let a = jwkEntryCacheKey(i, e), o = t?.imported.get(a);
		o !== void 0 && r.set(a, o);
	}
	return {
		jwks: e.jwks,
		expiresAt: e.expiresAt,
		imported: r
	};
}
const f$2 = Symbol("micro509.jose.timedOut");
/**
* Creates a key resolver that reads a JWK Set from one trusted URL.
*
* Behaviour, per resolver:
*
* - The first verification fetches the set. Later ones reuse it while fresh. Freshness is the
*   remaining lifetime from `Cache-Control: max-age`, else `Expires`, else `defaultTtlMs`, less the
*   response age (the larger of the apparent age from `Date` and `Age` plus the transit delay),
*   capped at `maxTtlMs`. `no-store`, `no-cache` and a lifetime already spent leave none: the set
*   serves the verification that fetched it and nothing after. No heuristic freshness is applied.
* - A set that is no longer fresh is never used, whether or not a refresh succeeds. There is no
*   stale-if-error. A refresh that fails while the cached set is still fresh keeps that set until
*   it expires.
* - Refreshes are separate from freshness: after any attempt the next one waits `cooldownMs`.
*   Within that interval a token whose `kid` is absent gets `key_not_found`, and a token that
*   needs a set that is no longer fresh gets `jwks_unavailable`. Concurrent verifications share
*   a single request, and unknown `kid` values are never cached.
* - A refresh replaces the whole set, so a rotated-out key stops verifying as soon as the new
*   set is read. Rotation must therefore introduce a new `kid`.
* - The whole request, response body included, is bounded by `timeoutMs` and enforced even when
*   the transport ignores the abort signal. Redirects, bytes and keys are bounded by `redirects`,
*   `maxResponseBytes` and `maxKeys`. No retry happens inside a fetch. Cancelling the last waiting
*   verification aborts the request, and a response that finishes afterwards is discarded.
* - Request headers go only to the configured origin. `jku`, `x5u` and `jwk` headers are never
*   used.
*
* Throws a `ResultError` coded {@linkcode RemoteJwksConfigErrorCode} for unusable configuration.
* Redirect destinations, and the addresses a hostname resolves to, are limited by `redirects` and
* the transport; this module cannot see DNS answers, and browsers hide redirect targets.
*/
function createRemoteJwksKeyResolver(r) {
	let a = resolveConfig(r), s, l, u;
	function startRefresh() {
		let e = new AbortController(), t = a.now(), n = u, r = s;
		u = t;
		async function run() {
			let n, i = new Promise((e) => {
				n = setTimeout(() => e(f$2), a.timeoutMs);
			}), o = fetchJwks(a, e.signal, t);
			o.catch(() => void 0);
			try {
				let t = await Promise.race([o, i]);
				return t === f$2 ? (e.abort(), {
					kind: "failed",
					failure: unavailable("The JWKS request timed out")
				}) : t.ok ? {
					kind: "fresh",
					snapshot: carryOver(t.value, r)
				} : {
					kind: "failed",
					failure: t
				};
			} catch {
				return e.signal.aborted ? { kind: "abandoned" } : {
					kind: "failed",
					failure: unavailable("The JWKS request failed")
				};
			} finally {
				clearTimeout(n);
			}
		}
		let i = run().then((e) => l?.promise === i ? (e.kind === "fresh" && (s = e.snapshot), e) : { kind: "abandoned" }).finally(() => {
			l?.promise === i && (l = void 0);
		});
		return {
			promise: i,
			controller: e,
			startedAt: t,
			previousAttemptAt: n,
			waiters: 0
		};
	}
	async function awaitRefresh(e) {
		if (e?.aborted === !0) return c;
		l ??= startRefresh();
		let t = l;
		return t.waiters++, e === void 0 ? await t.promise : await new Promise((n) => {
			let r = !1, finish = () => {
				r = !0, e.removeEventListener("abort", onAbort);
			}, onAbort = () => {
				r || (finish(), t.waiters--, t.waiters === 0 && (l === t && (l = void 0), u === t.startedAt && (u = t.previousAttemptAt), t.controller.abort()), n(c));
			};
			e.addEventListener("abort", onAbort, { once: !0 }), e.aborted && onAbort(), t.promise.then((e) => {
				r || (finish(), n(e));
			});
		});
	}
	function refreshAllowed() {
		return l !== void 0 || u === void 0 || a.now() - u >= a.cooldownMs;
	}
	async function obtain(t) {
		if (!refreshAllowed()) return successResult(void 0);
		let n = await awaitRefresh(t);
		return n === c || n.kind === "abandoned" ? joseFailure("aborted", "Key resolution was cancelled") : n.kind === "failed" ? n.failure : successResult(n.snapshot);
	}
	async function importFrom(e, r, i) {
		let a = jwkEntryCacheKey(r, i), o = e.imported.get(a);
		if (o !== void 0) return await o;
		let s = importJwkEntry(r, i);
		return e.imported.set(a, s), await s;
	}
	async function currentSnapshot(e) {
		if (s !== void 0 && a.now() < s.expiresAt) return successResult(s);
		s = void 0;
		let t = await obtain(e);
		return t.ok ? t.value === void 0 ? unavailable("The JWKS endpoint is in cooldown") : successResult(t.value) : t;
	}
	async function select(t, n, r) {
		let a = t, o = selectJwk(a.jwks, n);
		if (!o.ok && o.code === "key_not_found") {
			let e = await obtain(r);
			if (!e.ok) return e;
			e.value !== void 0 && (a = e.value, o = selectJwk(a.jwks, n));
		}
		if (!o.ok) return o;
		let s = await importFrom(a, o.value, n.algorithm);
		return r?.aborted === !0 ? joseFailure("aborted", "Key resolution was cancelled") : s;
	}
	return async (t) => {
		if (t.signal?.aborted === !0) return joseFailure("aborted", "Key resolution was cancelled");
		let n = await currentSnapshot(t.signal);
		return n.ok ? await select(n.value, {
			algorithm: t.algorithm,
			...t.kid === void 0 ? {} : { kid: t.kid }
		}, t.signal) : n;
	};
}
export { g as DEFAULT_JOSE_LIMITS, p as DEFAULT_JWKS_LIMITS, f as JWS_ALGORITHMS, f$1 as MAX_CLOCK_TOLERANCE_SECONDS, m as MIN_JWS_RSA_MODULUS_BITS, p$1 as MIN_RS256_MODULUS_BITS, base64UrlDecode, base64UrlEncode, createJwksKeyResolver, createRemoteJwksKeyResolver, decodeJwtUnverified, decryptCompactJwe, encryptCompactJwe, importJwkEntry, parseCompactJws, parseJwks, selectJwk, signCompactJws, signJwt, validateJwks, verifyCompactJws, verifyJwt };
