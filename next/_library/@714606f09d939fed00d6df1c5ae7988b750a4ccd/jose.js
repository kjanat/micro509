import { l as successResult, n as failureResult, u as throwMicro509Error } from "./result-C9WPk47A.js";
import { H as importPublicJwk, mt as t$2 } from "./keys-BmJSvvnO.js";
import { a as verifySignatureWithKey, r as signData } from "./crypto-BGU2UHlj.js";
// ../../dist/internal/jose/base64url.js
const e$1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const t$1 = (() => {
	let t = (/* @__PURE__ */ new Int8Array(128)).fill(-1);
	for (let n = 0; n < 64; n++) t[e$1.charCodeAt(n)] = n;
	return t;
})();
/** Encodes bytes as unpadded base64url (RFC 4648 §5, RFC 7515 §2). */
function base64UrlEncode(t) {
	let n = "", r = 0;
	for (; r + 2 < t.length; r += 3) {
		let i = (t[r] ?? 0) * 65536 + (t[r + 1] ?? 0) * 256 + (t[r + 2] ?? 0);
		n += e$1[i >> 18 & 63] ?? "", n += e$1[i >> 12 & 63] ?? "", n += e$1[i >> 6 & 63] ?? "", n += e$1[i & 63] ?? "";
	}
	let i = t.length - r;
	if (i === 1) {
		let i = (t[r] ?? 0) * 65536;
		n += e$1[i >> 18 & 63] ?? "", n += e$1[i >> 12 & 63] ?? "";
	} else if (i === 2) {
		let i = (t[r] ?? 0) * 65536 + (t[r + 1] ?? 0) * 256;
		n += e$1[i >> 18 & 63] ?? "", n += e$1[i >> 12 & 63] ?? "", n += e$1[i >> 6 & 63] ?? "";
	}
	return n;
}
/**
* Decodes canonical unpadded base64url. Returns `undefined` for any character outside the URL-safe
* alphabet, padding, whitespace, an impossible length, or non-zero trailing bits.
*/
function base64UrlDecode(e) {
	if (e.length % 4 == 1) return;
	let n = new Uint8Array(Math.floor(e.length * 3 / 4)), r = 0, i = 0, a = 0;
	for (let o = 0; o < e.length; o++) {
		let s = e.charCodeAt(o), c = s < 128 ? t$1[s] ?? -1 : -1;
		if (c < 0) return;
		i = i << 6 | c, a += 6, a >= 8 && (a -= 8, n[r++] = i >> a & 255, i &= (1 << a) - 1);
	}
	if (i === 0) return n;
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
const d = ["RS256"];
const f$1 = 2048;
const p = {
	maxTokenLength: 32768,
	maxHeaderBytes: 4096,
	maxPayloadBytes: 16384,
	maxSignatureBytes: 1024,
	maxJsonDepth: 16,
	maxJsonNodes: 2048
};
const m = [
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
function resolveJoseLimits(t) {
	if (t !== void 0 && (typeof t != "object" || !t)) return joseFailure("invalid_options", "limits must be an object");
	let n = { ...p };
	for (let e of m) {
		let r = t?.[e];
		if (r === void 0) continue;
		let i = e === "maxJsonDepth" ? 64 : 2 ** 53 - 1;
		if (!Number.isSafeInteger(r) || r < 1 || r > i) return joseFailure("invalid_options", `limits.${e} must be a positive safe integer`);
		n[e] = r;
	}
	return successResult(n);
}
const h = new TextEncoder();
const g = new TextDecoder("utf-8", {
	fatal: !0,
	ignoreBOM: !0
});
function maxEncodedLength(e) {
	return Math.ceil(e * 4 / 3);
}
function parseFailure(e, t) {
	return joseFailure(e, t);
}
function decodeSegment(t, n, r) {
	if (t.length > maxEncodedLength(n)) return parseFailure("limit_exceeded", `JWS ${r} exceeds ${n} bytes`);
	let i = base64UrlDecode(t);
	return i === void 0 ? parseFailure("invalid_encoding", `JWS ${r} is not canonical base64url`) : successResult(i);
}
/** Decodes UTF-8 strictly and parses it as a JSON object with no duplicate members. */
function decodeJsonObject(t, n, r, i) {
	let a;
	try {
		a = g.decode(t);
	} catch {
		return parseFailure("invalid_utf8", `JWS ${r} is not valid UTF-8`);
	}
	let o = parseStrictJson(a, {
		maxDepth: n.maxJsonDepth,
		maxNodes: n.maxJsonNodes
	});
	if (!o.ok) return parseFailure(o.code, `JWS ${r}: ${o.message}`);
	let s = o.value;
	return isJsonObject(s) ? successResult(s) : parseFailure(i, `JWS ${r} is not a JSON object`);
}
function optionalString(t, n) {
	if (!Object.hasOwn(t, n)) return successResult(void 0);
	let r = t[n];
	return typeof r == "string" ? successResult(r) : parseFailure("invalid_header", `JWS header "${n}" is not a string`);
}
function criticalNames(t) {
	if (!Object.hasOwn(t, "crit")) return successResult([]);
	let n = t.crit;
	if (!isJsonArray(n) || n.length === 0) return parseFailure("invalid_header", "JWS header \"crit\" is not a non-empty array");
	let r = [];
	for (let e of n) {
		if (typeof e != "string" || r.includes(e)) return parseFailure("invalid_header", "JWS header \"crit\" holds a non-string or repeated name");
		r.push(e);
	}
	return successResult(r);
}
function parseHeader(t, n) {
	let r = decodeJsonObject(t, n, "header", "invalid_header");
	if (!r.ok) return r;
	let i = r.value, a = i.alg;
	if (typeof a != "string" || a.length === 0) return parseFailure("invalid_header", "JWS header \"alg\" is missing or not a string");
	let o = optionalString(i, "typ");
	if (!o.ok) return o;
	let s = optionalString(i, "kid");
	if (!s.ok) return s;
	let c = optionalString(i, "cty");
	if (!c.ok) return c;
	let l = criticalNames(i);
	return l.ok ? i.b64 === !1 || l.value.includes("b64") ? parseFailure("unsupported_unencoded_payload", "Unencoded and detached payloads (RFC 7797) are not supported") : Object.hasOwn(i, "b64") && typeof i.b64 != "boolean" ? parseFailure("invalid_header", "JWS header \"b64\" is not a boolean") : l.value.length > 0 ? joseFailure("unsupported_critical_header", "JWS header lists critical extensions", {
		alg: a,
		crit: l.value
	}) : successResult({
		alg: a,
		...o.value === void 0 ? {} : { typ: o.value },
		...s.value === void 0 ? {} : { kid: s.value },
		...c.value === void 0 ? {} : { cty: c.value },
		members: i
	}) : l;
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
function parseWithLimits$1(t, n) {
	if (typeof t != "string") return parseFailure("malformed_token", "JWS token is not a string");
	if (t.length > n.maxTokenLength) return parseFailure("token_too_large", `JWS token exceeds ${n.maxTokenLength} characters`);
	let r = t.split("."), [i, a, o] = r;
	if (r.length !== 3 || i === void 0 || a === void 0 || o === void 0 || i.length === 0) return parseFailure("malformed_token", "JWS compact serialization needs three segments");
	let s = decodeSegment(i, n.maxHeaderBytes, "header");
	if (!s.ok) return s;
	let c = parseHeader(s.value, n);
	if (!c.ok) return c;
	let l = decodeSegment(a, n.maxPayloadBytes, "payload");
	if (!l.ok) return l;
	let u = decodeSegment(o, n.maxSignatureBytes, "signature");
	return u.ok ? successResult({
		verified: !1,
		header: c.value,
		payload: l.value,
		signingInput: h.encode(`${i}.${a}`),
		signature: u.value
	}) : u;
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
	return t.includes(e) && d.some((t) => t === e);
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
/**
* Checks a key may verify RS256 (RFC 7518 §3.3, RFC 8725 §3.1) and returns the signature length
* in bytes it requires (RFC 8017 §8.2.2).
*/
function checkRs256VerificationKey(e) {
	try {
		return inspectRs256VerificationKey(e);
	} catch {
		return joseFailure("key_unsuitable", "The key cannot be inspected");
	}
}
function inspectRs256VerificationKey(t) {
	let n = t.algorithm;
	return t.type !== "public" || !t.usages.includes("verify") ? joseFailure("key_unsuitable", "RS256 needs a public key with verify usage") : n.name !== "RSASSA-PKCS1-v1_5" || !("hash" in n) || typeof n.hash != "object" || n.hash === null || !("name" in n.hash) || n.hash.name !== "SHA-256" ? joseFailure("key_unsuitable", "RS256 needs an RSASSA-PKCS1-v1_5 SHA-256 key") : !("modulusLength" in n) || typeof n.modulusLength != "number" || n.modulusLength < 2048 ? joseFailure("key_unsuitable", `RS256 needs an RSA modulus of at least ${f$1} bits`) : !("publicExponent" in n) || !(n.publicExponent instanceof Uint8Array) || !validRsaPublicExponent(n.publicExponent) ? joseFailure("key_unsuitable", "RS256 needs a valid odd RSA public exponent of at least 3") : successResult(Math.ceil(n.modulusLength / 8));
}
function isCryptoKey(e) {
	return e instanceof CryptoKey;
}
/** Validates and copies verification options. Everything the run reads is captured here. */
function prepareVerify(t) {
	if (typeof t != "object" || !t) return joseFailure("invalid_options", "Verification options are required");
	let { algorithms: n, key: r, tokenType: i, limits: a, signal: o } = t;
	if (!Array.isArray(n) || n.length === 0) return joseFailure("invalid_options", "An explicit, non-empty algorithm list is required");
	let s = [];
	for (let e of n) {
		let t = d.find((t) => t === e);
		if (t === void 0) return joseFailure("invalid_options", "The algorithm list names an unsupported algorithm");
		s.push(t);
	}
	if (typeof r != "function" && !isCryptoKey(r)) return joseFailure("invalid_options", "A key or key resolver is required");
	let c = normalizeTokenType(i);
	if (c === void 0) return joseFailure("invalid_options", "A token type policy is required");
	if (o !== void 0 && !(o instanceof AbortSignal)) return joseFailure("invalid_options", "signal must be an AbortSignal");
	let l = resolveJoseLimits(a);
	return l.ok ? successResult({
		algorithms: s,
		key: r,
		typeRule: c,
		limits: l.value,
		signal: o
	}) : l;
}
async function resolveKey(t, n) {
	let { key: r, signal: i } = t;
	if (typeof r != "function") return successResult(r);
	let a;
	try {
		a = await r({
			header: n,
			algorithm: n.alg,
			...n.kid === void 0 ? {} : { kid: n.kid },
			...i === void 0 ? {} : { signal: i }
		});
	} catch {
		return i?.aborted === !0 ? joseFailure("aborted", "Key resolution was cancelled") : joseFailure("key_resolution_failed", "The key resolver failed");
	}
	if (typeof a != "object" || !a) return joseFailure("key_resolution_failed", "The key resolver returned no result");
	if (Reflect.get(a, "ok") === !0) {
		let t = Reflect.get(a, "value");
		return isCryptoKey(t) ? successResult(t) : joseFailure("key_resolution_failed", "The key resolver returned no key");
	}
	let o = Reflect.get(a, "code");
	switch (o) {
		case "key_not_found":
		case "ambiguous_key":
		case "key_unsuitable":
		case "key_resolution_failed":
		case "jwks_unavailable":
		case "jwks_malformed":
		case "aborted": return joseFailure(o, `Key resolution failed: ${o}`, resolverDetails(a));
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
* any key is resolved. A fixed key or the resolver's key must be an RSASSA-PKCS1-v1_5 SHA-256
* public key of at least 2048 bits for RS256. Header members such as `jku`, `jwk`, `x5u` and
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
async function verifyPrepared(t, r) {
	let a = parseWithLimits$1(t, r.limits);
	if (!a.ok) return a;
	let o = a.value, s = o.header.alg;
	if (s === "none") return joseFailure("unsigned_token", "Unsigned tokens are never accepted", { alg: s });
	if (!isAlgorithmAdmitted(s, r.algorithms)) return joseFailure("algorithm_not_allowed", "The token algorithm is not in the allowed list", { alg: s });
	if (!matchesTokenType(o.header, r.typeRule)) return joseFailure("token_type_mismatch", "The token \"typ\" does not match the expected type", { alg: s });
	let c = {
		...o.header,
		alg: s
	}, l = await resolveKey(r, c);
	if (!l.ok) return l;
	let d = checkRs256VerificationKey(l.value);
	if (!d.ok) return d;
	if (o.signature.length !== d.value) return joseFailure("invalid_signature", "The signature length differs from the modulus", { alg: s });
	let f = joseFailure("invalid_signature", "The signature does not verify", {
		alg: s,
		...c.kid === void 0 ? {} : { kid: c.kid }
	}), p = await verifySignatureWithKey({
		publicKey: l.value,
		signatureAlgorithm: { oid: t$2.sha256WithRSAEncryption },
		signatureEncoding: "raw",
		signature: o.signature,
		data: o.signingInput
	});
	return !p.ok || !p.valid ? f : successResult({
		verified: !0,
		header: c,
		payload: o.payload
	});
}
function assertSigningKey(e) {
	let n = e.privateKey.algorithm;
	d.includes(e.algorithm) || throwMicro509Error("unsupported_algorithm", "Unsupported JWS algorithm"), (e.privateKey.type !== "private" || !e.privateKey.usages.includes("sign") || n.name !== "RSASSA-PKCS1-v1_5" || !("hash" in n) || typeof n.hash != "object" || n.hash === null || !("name" in n.hash) || n.hash.name !== "SHA-256" || !("modulusLength" in n) || typeof n.modulusLength != "number" || n.modulusLength < 2048) && throwMicro509Error("incompatible_key", `RS256 signing needs an RSASSA-PKCS1-v1_5 SHA-256 private key of at least 2048 bits`);
}
/**
* Signs a compact JWS with an existing private `CryptoKey`.
*
* The header is `alg` followed by the optional `typ`, `kid` and `cty`. Throws a `ResultError`
* (see `isResultError`) coded {@linkcode SignJoseErrorCode} when the algorithm, key or header
* input is invalid. Intended for issuing tokens and for building synthetic tokens in tests.
*/
async function signCompactJws(e) {
	assertSigningKey(e);
	let n = { alg: e.algorithm };
	for (let r of [
		"typ",
		"kid",
		"cty"
	]) {
		let i = e.header?.[r];
		i !== void 0 && (typeof i != "string" && throwMicro509Error("invalid_header", `Header "${r}" must be a string`), n[r] = i);
	}
	let i = `${base64UrlEncode(h.encode(JSON.stringify(n)))}.${base64UrlEncode(e.payload)}`, { signature: a } = await signData(e.privateKey, h.encode(i));
	return `${i}.${base64UrlEncode(a)}`;
}
// ../../dist/jose/jwks.js
/**
* JSON Web Key Set (RFC 7517) parsing, key selection and a local key resolver. Nothing here
* performs network access.
*
* @module
*/
/** The limits applied when a caller supplies none. */
const l = {
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
function parseEntry(t) {
	if (!isJsonObject(t)) return malformed("JWK Set key is not an object");
	let n = memberString(t, "kty"), r = memberString(t, "kid"), a = memberString(t, "use"), o = memberString(t, "alg"), s = memberStrings(t, "key_ops");
	if (typeof n != "string" || r === null || a === null || o === null || s === null) return successResult({
		kind: "unsupported",
		...typeof n == "string" ? { kty: n } : {},
		members: t
	});
	let c = {
		...r === void 0 ? {} : { kid: r },
		...a === void 0 ? {} : { use: a },
		...o === void 0 ? {} : { alg: o },
		...s === void 0 ? {} : { keyOps: s }
	}, l = t.n, u = t.e;
	return successResult(n !== "RSA" || typeof l != "string" || typeof u != "string" ? {
		kind: "unsupported",
		kty: n,
		...c,
		members: t
	} : {
		kind: "rsa",
		n: l,
		e: u,
		...c,
		members: t
	});
}
/**
* Parses a JWK Set document.
*
* The document must be duplicate-free JSON with a `keys` array within `limits`. Keys with a `kty`
* other than `RSA`, and keys with missing or wrongly typed members, are kept as `unsupported`
* entries and never selected (RFC 7517 §5). A set that is not a duplicate-free object with a
* `keys` array of objects is `jwks_malformed`.
*/
function parseJwks(e, t) {
	let n = resolveJwksLimits(t);
	return n.ok ? parseWithLimits(e, n.value) : n;
}
const u$1 = 16777216;
const d$1 = 1024;
function resolveJwksLimits(t) {
	if (t !== void 0 && (typeof t != "object" || !t)) return joseFailure("invalid_options", "limits must be an object");
	let n = t?.maxBytes === void 0 ? l.maxBytes : t.maxBytes, r = t?.maxKeys === void 0 ? l.maxKeys : t.maxKeys;
	return !Number.isSafeInteger(n) || n < 1 || n > u$1 ? joseFailure("invalid_options", `limits.maxBytes must be from 1 to ${u$1}`) : !Number.isSafeInteger(r) || r < 1 || r > d$1 ? joseFailure("invalid_options", `limits.maxKeys must be from 1 to ${d$1}`) : successResult({
		maxBytes: n,
		maxKeys: r
	});
}
function parseWithLimits(t, n) {
	if (typeof t == "string" && t.length > n.maxBytes) return joseFailure("limit_exceeded", `JWK Set exceeds ${n.maxBytes} bytes`);
	if (typeof t != "string" && !(t instanceof Uint8Array)) return malformed("JWK Set input is neither a string nor bytes");
	let s = typeof t == "string" ? new TextEncoder().encode(t) : t;
	if (s.byteLength > n.maxBytes) return joseFailure("limit_exceeded", `JWK Set exceeds ${n.maxBytes} bytes`);
	let c;
	try {
		c = new TextDecoder("utf-8", {
			fatal: !0,
			ignoreBOM: !0
		}).decode(s);
	} catch {
		return malformed("JWK Set is not valid UTF-8");
	}
	let l = parseStrictJson(c, {
		maxDepth: 8,
		maxNodes: n.maxKeys * 64 + 64
	});
	if (!l.ok) return l.code === "limit_exceeded" ? joseFailure("limit_exceeded", `JWK Set: ${l.message}`) : malformed(`JWK Set: ${l.message}`);
	let u = l.value;
	if (!isJsonObject(u)) return malformed("JWK Set is not an object");
	let d = u.keys;
	if (!isJsonArray(d)) return malformed("JWK Set \"keys\" is not an array");
	if (d.length > n.maxKeys) return joseFailure("limit_exceeded", `JWK Set holds more than ${n.maxKeys} keys`);
	let f = [];
	for (let e of d) {
		let t = parseEntry(e);
		if (!t.ok) return t;
		f.push(t.value);
	}
	return successResult({
		keys: f,
		members: u
	});
}
/** Why a key entry cannot verify a given algorithm, or `undefined` when it can. */
function unsuitableReason(e, t) {
	if (e.kind !== "rsa") return "key type does not match the algorithm";
	if (e.use !== void 0 && e.use !== "sig") return "\"use\" is not \"sig\"";
	if (e.keyOps !== void 0 && !e.keyOps.includes("verify")) return "\"key_ops\" does not include \"verify\"";
	if (e.use === "sig" && e.keyOps?.some((e) => e !== "sign" && e !== "verify")) return "\"use\" and \"key_ops\" are inconsistent";
	if (e.alg !== void 0 && e.alg !== t) return "\"alg\" names another algorithm";
	let r = base64UrlDecode(e.n), i = base64UrlDecode(e.e);
	if (r === void 0 || i === void 0 || r.length === 0) return "RSA parameters are not canonical base64url";
	if (r[0] === 0 || i[0] === 0 || i.length === 0) return "RSA parameters have leading zero octets";
	if (r.length > 1024) return "RSA modulus is too large";
	if ((r.length - 1) * 8 + 32 - Math.clz32(r[0] ?? 0) < 2048) return "RSA modulus is too small";
	if (!validRsaPublicExponent(i, r)) return "RSA public exponent is invalid";
}
/**
* Selects the one key of a set that can verify `selector`.
*
* Keys are filtered by `kid` (when the token has one), key type, `use`, `key_ops`, `alg` and RSA
* parameters. No match is `key_not_found`, or `key_unsuitable` when `kid` matched only keys that
* fail the other checks. More than one match is `ambiguous_key`: a token without `kid` therefore
* resolves only against a set with a single usable key.
*/
function selectJwk(t, n) {
	let r = t.keys.filter((e) => n.kid === void 0 || e.kid === n.kid), i = n.kid === void 0 ? {} : { kid: n.kid };
	if (r.length === 0) return joseFailure("key_not_found", "No key matches the token", i);
	let a = [];
	for (let e of r) e.kind === "rsa" && unsuitableReason(e, n.algorithm) === void 0 && a.push(e);
	let [s, c] = a;
	return s === void 0 ? joseFailure("key_unsuitable", "No matching key can verify this algorithm", i) : c === void 0 ? successResult(s) : joseFailure("ambiguous_key", "More than one key matches the token", i);
}
/** Imports a selected entry as a verify-only RS256 `CryptoKey`. */
async function importJwkEntry(n) {
	let r = unsuitableReason(n, "RS256");
	if (r !== void 0) return joseFailure("key_unsuitable", r, n.kid === void 0 ? void 0 : { kid: n.kid });
	let i = await importPublicJwk({
		kty: "RSA",
		n: n.n,
		e: n.e,
		alg: "RS256",
		key_ops: ["verify"],
		ext: !0
	}, {
		kind: "rsa",
		scheme: "pkcs1-v1_5",
		hash: "SHA-256"
	});
	if (!i.ok) return joseFailure("key_unsuitable", "The RSA JWK cannot be imported", { ...n.kid === void 0 ? {} : { kid: n.kid } });
	let a = checkRs256VerificationKey(i.value);
	return a.ok ? successResult(i.value) : a;
}
/**
* Creates a key resolver over a fixed JWK Set.
*
* The resolver selects with {@linkcode selectJwk} and imports each key once, so repeated
* verifications reuse the same `CryptoKey`.
*/
function createJwksKeyResolver(e) {
	let t = /* @__PURE__ */ new Map();
	return async (n) => {
		let r = selectJwk(e, {
			algorithm: n.algorithm,
			...n.kid === void 0 ? {} : { kid: n.kid }
		});
		if (!r.ok) return r;
		let i = t.get(r.value);
		if (i !== void 0) return await i;
		let a = importJwkEntry(r.value);
		return t.set(r.value, a), await a;
	};
}
// ../../dist/jose/jwt.js
/** Largest clock tolerance {@linkcode JwtClaimsPolicy.clockToleranceSeconds} accepts. */
const f = 600;
function decodeClaims(e, t, n) {
	return e.cty !== void 0 && mediaTypeKey(e.cty) === "application/jwt" ? joseFailure("unsupported_nested_jwt", "Nested JWTs (cty \"JWT\") are not supported") : decodeJsonObject(t, n, "payload", "invalid_payload");
}
/** Decodes a JWT without checking its signature. Every field of the result is unauthenticated. */
function decodeJwtUnverified(t, n) {
	let r = resolveJoseLimits(n);
	if (!r.ok) return r;
	let i = parseCompactJws(t, r.value);
	if (!i.ok) return i;
	let a = decodeClaims(i.value.header, i.value.payload, r.value);
	return a.ok ? successResult({
		verified: !1,
		header: i.value.header,
		claims: a.value
	}) : a;
}
function claimFailure(e, t, n) {
	return joseFailure(e, t, { claim: n });
}
function numericDate(t, n) {
	if (!Object.hasOwn(t, n)) return successResult(void 0);
	let r = t[n];
	return typeof r != "number" || !Number.isFinite(r) ? claimFailure("invalid_claim", `Claim "${n}" is not a NumericDate`, n) : successResult(r);
}
function stringClaim(t, n) {
	if (!Object.hasOwn(t, n)) return successResult(void 0);
	let r = t[n];
	return typeof r == "string" ? successResult(r) : claimFailure("invalid_claim", `Claim "${n}" is not a string`, n);
}
function audienceClaim(t) {
	if (!Object.hasOwn(t, "aud")) return successResult(void 0);
	let r = t.aud;
	if (typeof r == "string") return successResult(r);
	if (!isJsonArray(r)) return claimFailure("invalid_claim", "Claim \"aud\" is neither a string nor an array", "aud");
	let i = [];
	for (let e of r) {
		if (typeof e != "string") return claimFailure("invalid_claim", "Claim \"aud\" holds a non-string", "aud");
		i.push(e);
	}
	return successResult(i);
}
function registeredClaims(t) {
	let n = stringClaim(t, "iss");
	if (!n.ok) return n;
	let r = stringClaim(t, "sub");
	if (!r.ok) return r;
	let i = stringClaim(t, "jti");
	if (!i.ok) return i;
	let a = audienceClaim(t);
	if (!a.ok) return a;
	let o = numericDate(t, "exp");
	if (!o.ok) return o;
	let s = numericDate(t, "nbf");
	if (!s.ok) return s;
	let c = numericDate(t, "iat");
	return c.ok ? successResult({
		...n.value === void 0 ? {} : { iss: n.value },
		...r.value === void 0 ? {} : { sub: r.value },
		...a.value === void 0 ? {} : { aud: a.value },
		...o.value === void 0 ? {} : { exp: o.value },
		...s.value === void 0 ? {} : { nbf: s.value },
		...c.value === void 0 ? {} : { iat: c.value },
		...i.value === void 0 ? {} : { jti: i.value }
	}) : c;
}
function expectedValues(t) {
	return typeof t == "string" ? successResult([t]) : isUncheckedPolicy(t) ? successResult(void 0) : Array.isArray(t) && t.length > 0 && t.every((e) => typeof e == "string") ? successResult([...t]) : joseFailure("invalid_options", "issuer and audience need expected values or { unchecked: true }");
}
function prepareClaims(t) {
	if (typeof t != "object" || !t) return joseFailure("invalid_options", "A claims policy is required");
	let n = t.clockToleranceSeconds ?? 0;
	if (typeof n != "number" || !Number.isFinite(n) || n < 0 || n > 600) return joseFailure("invalid_options", "clockToleranceSeconds must be between 0 and 600");
	let i = t.maxAgeSeconds;
	if (i !== void 0 && (typeof i != "number" || !Number.isFinite(i) || i < 0)) return joseFailure("invalid_options", "maxAgeSeconds must be a non-negative number");
	let a = t.requiredClaims ?? ["exp"];
	if (!Array.isArray(a) || !a.every((e) => typeof e == "string")) return joseFailure("invalid_options", "requiredClaims must be an array of strings");
	if (t.futureIssuedAt !== void 0 && t.futureIssuedAt !== "reject" && t.futureIssuedAt !== "allow") return joseFailure("invalid_options", "futureIssuedAt must be 'reject' or 'allow'");
	if (t.now !== void 0 && typeof t.now != "function") return joseFailure("invalid_options", "now must be a function");
	let o = expectedValues(t.issuer);
	if (!o.ok) return o;
	let s = expectedValues(t.audience);
	return s.ok ? successResult({
		issuers: o.value,
		audiences: s.value,
		required: [...a],
		now: t.now ?? (() => /* @__PURE__ */ new Date()),
		toleranceSeconds: n,
		maxAgeSeconds: i,
		allowFutureIssuedAt: t.futureIssuedAt === "allow"
	}) : s;
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
function clockSeconds(t) {
	let n;
	try {
		n = t.now();
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
async function verifyJwt(t, n) {
	if (typeof n != "object" || !n) return joseFailure("invalid_options", "Verification options are required");
	let i = prepareClaims(n.claims);
	if (!i.ok) return i;
	let a = prepareVerify(n);
	if (!a.ok) return a;
	let o = await verifyPrepared(t, a.value);
	if (!o.ok) return o;
	let s = decodeClaims(o.value.header, o.value.payload, a.value.limits);
	if (!s.ok) return s;
	let l = validateClaims(s.value, i.value);
	return l.ok ? successResult({
		verified: !0,
		header: o.value.header,
		claims: s.value,
		registered: l.value
	}) : l;
}
/**
* Signs a JWT. The header carries `typ: "JWT"` unless `header.typ` says otherwise.
*
* Throws a `ResultError` coded `SignJoseErrorCode` for an unusable key, algorithm or header, and
* `invalid_claims` when `claims` cannot be serialized.
*/
async function signJwt(e) {
	let n;
	try {
		n = JSON.stringify(e.claims);
	} catch {
		n = void 0;
	}
	if (typeof n != "string") return throwMicro509Error("invalid_claims", "JWT claims are not JSON-serializable");
	let { claims: r, ...i } = e;
	return await signCompactJws({
		...i,
		payload: new TextEncoder().encode(n),
		header: {
			typ: "JWT",
			...e.header
		}
	});
}
// ../../dist/jose/remote-jwks.js
const o = Symbol("micro509.jose.aborted");
const s = {
	timeoutMs: 5e3,
	maxResponseBytes: 65536,
	maxKeys: 32,
	defaultTtlMs: 6e5,
	maxTtlMs: 864e5,
	cooldownMs: 3e4
};
const c = /* @__PURE__ */ new Set([
	301,
	302,
	303,
	307,
	308
]);
const l$1 = /* @__PURE__ */ new Set([
	"localhost",
	"127.0.0.1",
	"[::1]"
]);
function isPermittedUrl(e) {
	return e.protocol === "https:" || e.protocol === "http:" && l$1.has(e.hostname);
}
function positiveInteger(e, n, r) {
	let i = e ?? n;
	return !Number.isSafeInteger(i) || i <= 0 ? throwMicro509Error("invalid_remote_jwks_config", `${r} must be a positive integer`) : i;
}
function resolveConfig(e) {
	let n;
	try {
		n = new URL(e.url);
	} catch {
		return throwMicro509Error("invalid_remote_jwks_config", "url is not an absolute URL");
	}
	if (!isPermittedUrl(n)) return throwMicro509Error("invalid_remote_jwks_config", "url must use https, or http on a loopback host");
	if (n.username !== "" || n.password !== "") return throwMicro509Error("invalid_remote_jwks_config", "url must not embed credentials");
	let r = e.redirects?.maxRedirects ?? 0;
	if (!Number.isSafeInteger(r) || r < 0 || r > 10) return throwMicro509Error("invalid_remote_jwks_config", "maxRedirects must be an integer from 0 to 10");
	let i = positiveInteger(e.maxTtlMs, s.maxTtlMs, "maxTtlMs"), a = positiveInteger(e.cooldownMs, s.cooldownMs, "cooldownMs");
	return {
		url: n,
		transport: e.transport ?? ((e, t) => globalThis.fetch(e, t)),
		headers: { ...e.headers },
		timeoutMs: positiveInteger(e.timeoutMs, s.timeoutMs, "timeoutMs"),
		maxResponseBytes: positiveInteger(e.maxResponseBytes, s.maxResponseBytes, "maxResponseBytes"),
		maxKeys: positiveInteger(e.maxKeys, s.maxKeys, "maxKeys"),
		maxRedirects: r,
		allowRedirect: e.redirects?.allow ?? ((e, t) => e.origin === t.origin),
		defaultTtlMs: positiveInteger(e.defaultTtlMs, s.defaultTtlMs, "defaultTtlMs"),
		maxTtlMs: i,
		cooldownMs: a,
		now: e.now ?? Date.now
	};
}
function unavailable(e, t) {
	return joseFailure("jwks_unavailable", e, t === void 0 ? void 0 : { status: t });
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
async function readBounded(t, r, i) {
	let a = joseFailure("jwks_malformed", `The JWKS response exceeds ${r} bytes`), o = t.headers.get("content-length");
	if (o !== null && /^\d+$/.test(o) && Number(o) > r) return await t.body?.cancel(), a;
	if (t.body === null) return successResult(/* @__PURE__ */ new Uint8Array());
	let s = t.body.getReader(), release = () => {
		s.cancel().catch(() => void 0);
	};
	i.addEventListener("abort", release, { once: !0 });
	try {
		let t = [], n = 0;
		for (;;) {
			let { done: e, value: o } = await s.read();
			if (i.aborted) return unavailable("The JWKS request was cancelled");
			if (e) break;
			if (n += o.byteLength, n > r) return release(), a;
			t.push(o);
		}
		let o = new Uint8Array(n), c = 0;
		for (let e of t) o.set(e, c), c += e.byteLength;
		return successResult(o);
	} finally {
		i.removeEventListener("abort", release);
	}
}
function nextHop(t, n, r, i) {
	let a = r.headers.get("location");
	if (i >= t.maxRedirects || a === null) return unavailable("The JWKS endpoint redirected", r.status);
	let o;
	try {
		o = new URL(a, n);
	} catch {
		return unavailable("The JWKS redirect target is not a URL", r.status);
	}
	return !isPermittedUrl(o) || o.username !== "" || o.password !== "" || !t.allowRedirect(o, n) ? unavailable("The JWKS redirect target is not permitted", r.status) : successResult(o);
}
async function readJwks(t, r, a, o) {
	if (r.status !== 200) return await r.body?.cancel(), unavailable("The JWKS endpoint did not answer 200", r.status);
	let s = t.now(), c = await readBounded(r, t.maxResponseBytes, o);
	if (!c.ok) return c;
	let l = parseJwks(c.value, {
		maxBytes: t.maxResponseBytes,
		maxKeys: t.maxKeys
	});
	return l.ok ? successResult({
		jwks: l.value,
		expiresAt: s + freshnessMs(r.headers, a, s, t)
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
		if (!c.has(a.status)) return await readJwks(e, a, n, t);
		await a.body?.cancel();
		let o = nextHop(e, r, a, i);
		if (!o.ok) return o;
		r = o.value;
	}
}
function entryKey(e) {
	return `${e.n}.${e.e}`;
}
function carryOver(e, t) {
	let n = /* @__PURE__ */ new Map();
	for (let r of e.jwks.keys) {
		let e = r.kind === "rsa" ? t?.imported.get(entryKey(r)) : void 0;
		r.kind === "rsa" && e !== void 0 && n.set(entryKey(r), e);
	}
	return {
		jwks: e.jwks,
		expiresAt: e.expiresAt,
		imported: n
	};
}
const u = Symbol("micro509.jose.timedOut");
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
function createRemoteJwksKeyResolver(t) {
	let i = resolveConfig(t), s, c, l;
	function startRefresh() {
		let e = new AbortController(), t = i.now(), n = l, r = s;
		l = t;
		async function run() {
			let n, a = new Promise((e) => {
				n = setTimeout(() => e(u), i.timeoutMs);
			}), o = fetchJwks(i, e.signal, t);
			o.catch(() => void 0);
			try {
				let t = await Promise.race([o, a]);
				return t === u ? (e.abort(), {
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
		let a = run().then((e) => c?.promise === a ? (e.kind === "fresh" && (s = e.snapshot), e) : { kind: "abandoned" }).finally(() => {
			c?.promise === a && (c = void 0);
		});
		return {
			promise: a,
			controller: e,
			startedAt: t,
			previousAttemptAt: n,
			waiters: 0
		};
	}
	async function awaitRefresh(e) {
		if (e?.aborted === !0) return o;
		c ??= startRefresh();
		let t = c;
		return t.waiters++, e === void 0 ? await t.promise : await new Promise((n) => {
			let r = !1, finish = () => {
				r = !0, e.removeEventListener("abort", onAbort);
			}, onAbort = () => {
				r || (finish(), t.waiters--, t.waiters === 0 && (c === t && (c = void 0), l === t.startedAt && (l = t.previousAttemptAt), t.controller.abort()), n(o));
			};
			e.addEventListener("abort", onAbort, { once: !0 }), e.aborted && onAbort(), t.promise.then((e) => {
				r || (finish(), n(e));
			});
		});
	}
	function refreshAllowed() {
		return c !== void 0 || l === void 0 || i.now() - l >= i.cooldownMs;
	}
	async function obtain(t) {
		if (!refreshAllowed()) return successResult(void 0);
		let r = await awaitRefresh(t);
		return r === o || r.kind === "abandoned" ? joseFailure("aborted", "Key resolution was cancelled") : r.kind === "failed" ? r.failure : successResult(r.snapshot);
	}
	async function importFrom(e, t) {
		let n = entryKey(t), i = e.imported.get(n);
		if (i !== void 0) return await i;
		let a = importJwkEntry(t);
		return e.imported.set(n, a), await a;
	}
	async function currentSnapshot(t) {
		if (s !== void 0 && i.now() < s.expiresAt) return successResult(s);
		s = void 0;
		let n = await obtain(t);
		return n.ok ? n.value === void 0 ? unavailable("The JWKS endpoint is in cooldown") : successResult(n.value) : n;
	}
	async function select(e, t, r) {
		let i = e, o = selectJwk(i.jwks, t);
		if (!o.ok && o.code === "key_not_found") {
			let e = await obtain(r);
			if (!e.ok) return e;
			e.value !== void 0 && (i = e.value, o = selectJwk(i.jwks, t));
		}
		if (!o.ok) return o;
		let s = await importFrom(i, o.value);
		return r?.aborted === !0 ? joseFailure("aborted", "Key resolution was cancelled") : s;
	}
	return async (e) => {
		if (e.signal?.aborted === !0) return joseFailure("aborted", "Key resolution was cancelled");
		let t = await currentSnapshot(e.signal);
		return t.ok ? await select(t.value, {
			algorithm: e.algorithm,
			...e.kid === void 0 ? {} : { kid: e.kid }
		}, e.signal) : t;
	};
}
export { p as DEFAULT_JOSE_LIMITS, l as DEFAULT_JWKS_LIMITS, d as JWS_ALGORITHMS, f as MAX_CLOCK_TOLERANCE_SECONDS, f$1 as MIN_RS256_MODULUS_BITS, createJwksKeyResolver, createRemoteJwksKeyResolver, decodeJwtUnverified, importJwkEntry, parseCompactJws, parseJwks, selectJwk, signCompactJws, signJwt, verifyCompactJws, verifyJwt };
