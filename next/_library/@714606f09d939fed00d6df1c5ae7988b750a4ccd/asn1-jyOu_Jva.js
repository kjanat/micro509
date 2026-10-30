import { a as isResultError, n as failureResult, u as throwMicro509Error } from "./result-C9WPk47A.js";
// ../../dist/internal/asn1/decode-refusal.js
/** The limit code alone, for boundaries whose input carries no text. */
const i = ["limit_exceeded"];
/** Throws a {@link ResultError} carrying a decode refusal. */
function throwDecodeRefusal(e, t) {
	return throwMicro509Error(e, t);
}
/** The refusal `error` carries when its code is one of `codes`. */
function decodeRefusalOf(e, t) {
	if (!isResultError(e)) return;
	let r = t.find((t) => t === e.code);
	return r === void 0 ? void 0 : {
		code: r,
		message: e.error.message
	};
}
/** Rethrows `error` when it carries one of the refusal `codes`. */
function rethrowDecodeRefusal(e, t) {
	if (decodeRefusalOf(e, t) !== void 0) throw e;
}
/** A boundary's failure for a thrown decode error: its refusal, else `malformed` with its message. */
function decodeFailureResult(e, n, r) {
	let i = decodeRefusalOf(e, n);
	return i === void 0 ? failureResult("malformed", e instanceof Error ? e.message : r) : failureResult(i.code, i.message);
}
// ../../dist/internal/asn1/der.js
/**
* Low-level DER encoding and reading helpers shared across the library.
*
* These utilities build and traverse ASN.1 TLV (tag-length-value) structures.
*
* @module
*/
/**
* Maximum nesting depth allowed when recursively walking a DER structure.
*
* Guards against stack exhaustion from pathologically nested input.
*/
const t = 64;
/**
* Produces the DER length octets for a given byte count.
*
* Values < 128 use the short form (one octet);
* larger values use the long form (leading octet encodes the number of subsequent length bytes).
*/
function encodeLength(e) {
	if (assertNonNegativeSafeInteger(e, "DER length"), e < 128) return Uint8Array.of(e);
	let t = encodeBase256(e);
	return Uint8Array.of(128 | t.length, ...t);
}
/** Concatenates multiple byte arrays into a single {@linkcode Uint8Array}. */
function concatBytes(e) {
	let t = e.reduce((e, t) => e + t.length, 0), n = new Uint8Array(t), r = 0;
	for (let t of e) n.set(t, r), r += t.length;
	return n;
}
/** Compares two optional byte arrays; two absent values are equal. */
function optionalBytesEqual(e, t) {
	if (e === void 0 || t === void 0) return e === t;
	if (e.length !== t.length) return !1;
	for (let n = 0; n < e.length; n += 1) if (e[n] !== t[n]) return !1;
	return !0;
}
/**
* Builds a complete DER TLV (tag-length-value) element:
*
* - one tag octet,
* - the DER-encoded length, then
* - the raw value bytes.
*/
function tlv(e, t) {
	return assertSingleOctetDerTag(e), concatBytes([
		Uint8Array.of(e),
		encodeLength(t.length),
		t
	]);
}
/** Wraps concatenated children in a SEQUENCE (tag `0x30`). */
function sequence(e) {
	return tlv(48, concatBytes(e));
}
/**
* Wraps children in a SET (tag `0x31`) after DER-sorting them lexicographically by encoded bytes,
* as required by {@linkcode https://www.itu.int/rec/T-REC-X.690-202102-I/en | X.690} DER.
*/
function setOf(e) {
	return tlv(49, concatBytes(e.slice().sort((e, t) => {
		let n = Math.min(e.length, t.length);
		for (let r = 0; r < n; r++) {
			let n = (e[r] ?? 0) - (t[r] ?? 0);
			if (n !== 0) return n;
		}
		return e.length - t.length;
	})));
}
/**
* Wraps a value in an explicit context-specific constructed tag (`0xa0 + tag`).
*
* Used for optional SEQUENCE fields tagged with `[tag] EXPLICIT`.
*/
function explicitContext(e, t) {
	return assertContextSpecificTagNumber(e), tlv(160 + e, t);
}
/**
* Wraps a value in an implicit context-specific constructed tag (`0xa0 + tag`).
*
* Used for `[tag] IMPLICIT` fields whose underlying type is constructed (e.g. SEQUENCE).
*/
function implicitConstructedContext(e, t) {
	return assertContextSpecificTagNumber(e), tlv(160 + e, t);
}
/**
* Wraps a value in an implicit context-specific primitive tag (`0x80 + tag`).
*
* Used for `[tag] IMPLICIT` fields whose underlying type is primitive (e.g. OCTET STRING).
*/
function implicitPrimitiveContext(e, t) {
	return assertContextSpecificTagNumber(e), tlv(128 + e, t);
}
/**
* Encodes raw big-endian bytes as a DER INTEGER (tag `0x02`).
*
* Strips leading zero bytes for minimal encoding and prepends a zero byte when the high bit is set
* to keep the value non-negative.
*/
function integer(e) {
	if (e.length === 0) return tlv(2, Uint8Array.of(0));
	let t = 0;
	for (; t < e.length - 1 && e[t] === 0;) t += 1;
	let n = e.slice(t);
	return (n[0] ?? 0) >= 128 ? tlv(2, concatBytes([Uint8Array.of(0), n])) : tlv(2, n);
}
/**
* Encodes a non-negative JavaScript `number` as a DER INTEGER.
*
* @throws if the value is not a non-negative safe integer.
*/
function integerFromNumber(e) {
	if (!Number.isSafeInteger(e) || e < 0) throw Error("INTEGER must be a non-negative safe integer");
	return integer(e === 0 ? Uint8Array.of(0) : Uint8Array.from(encodeBase256(e)));
}
/** Encodes a DER ENUMERATED (tag `0x0a`) from a non-negative safe integer. */
function enumeratedFromNumber(e) {
	return concatBytes([Uint8Array.of(10), integerFromNumber(e).subarray(1)]);
}
/** Encodes a DER BOOLEAN (tag `0x01`): `true` → `0xff`, `false` → `0x00`. */
function bool(e) {
	return tlv(1, Uint8Array.of(e ? 255 : 0));
}
/** Produces a DER NULL element (tag `0x05`, zero-length value). */
function nullValue() {
	return tlv(5, /* @__PURE__ */ new Uint8Array());
}
/** Wraps raw bytes in an OCTET STRING element (tag `0x04`). */
function octetString(e) {
	return tlv(4, e);
}
/**
* Encodes a DER BIT STRING (tag `0x03`).
*
* The value is prefixed with a single octet indicating how many trailing bits in the last byte are unused.
*
* @param unusedBits Number of unused trailing bits (0–7). Defaults to 0.
*/
function bitString(e, t = 0) {
	if (t < 0 || t > 7) throw Error("unusedBits must be between 0 and 7");
	if (e.length === 0 && t !== 0) throw Error("unusedBits must be 0 when value is empty");
	if (e.length > 0 && t > 0 && (e[e.length - 1] ?? 0) & (1 << t) - 1) throw Error("unused bits in the last byte must be zero");
	return tlv(3, concatBytes([Uint8Array.of(t), e]));
}
function hasLoneSurrogate(e) {
	for (let t = 0; t < e.length; t += 1) {
		let n = e.charCodeAt(t);
		if (n >= 55296 && n <= 56319) {
			let n = e.charCodeAt(t + 1);
			if (n >= 56320 && n <= 57343) {
				t += 1;
				continue;
			}
			return !0;
		}
		if (n >= 56320 && n <= 57343) return !0;
	}
	return !1;
}
/**
* Encodes a DER UTF8String (tag `0x0c`).
*
* @throws on a lone surrogate, which has no UTF-8 encoding.
*/
function utf8String(e) {
	if (hasLoneSurrogate(e)) throw Error("Invalid UTF8String: lone surrogate");
	return tlv(12, new TextEncoder().encode(e));
}
/**
* Encodes a DER PrintableString (tag `0x13`).
*
* @throws if the input contains characters outside the ITU-T X.680 §41.4 Table 10 PrintableString set.
*/
function printableString(e) {
	if (!/^[A-Za-z0-9 '()+,\-./:=?]*$/.test(e)) throw Error("Invalid PrintableString: contains characters outside the allowed set");
	return tlv(19, new TextEncoder().encode(e));
}
/**
* Encodes a DER VisibleString (tag `0x1a`).
*
* @throws if the input contains a character outside the printable ASCII range 0x20 to 0x7e.
*/
function visibleString(e) {
	if (!/^[\x20-\x7e]*$/.test(e)) throw Error("Invalid VisibleString: contains characters outside 0x20 to 0x7e");
	return tlv(26, new TextEncoder().encode(e));
}
/** Validates a string is ASCII (IA5) and returns its content bytes, without a tag. */
function ia5Bytes(e) {
	for (let t = 0; t < e.length; t++) if (e.charCodeAt(t) > 127) throw Error("Invalid IA5String: contains non-ASCII characters");
	return new TextEncoder().encode(e);
}
/**
* Encodes a DER IA5String (tag `0x16`).
*
* @throws if the input contains any non-ASCII character (code point > 0x7f).
*/
function ia5String(e) {
	return tlv(22, ia5Bytes(e));
}
/**
* Encodes a DER BMPString (tag `0x1e`) as big-endian UTF-16.
*
* @throws on lone surrogates, on U+FFFE and U+FFFF, which X.680 §41.15 leaves
* out of BMPString, and on code points above the Basic Multilingual Plane.
*/
function bmpString(e) {
	let t = [];
	for (let n of e) {
		let e = n.codePointAt(0) ?? 0;
		if (e > 65535) throw Error("Invalid BMPString: code point above the Basic Multilingual Plane");
		if (e >= 55296 && e <= 57343) throw Error("Invalid BMPString: lone surrogate");
		if (e >= 65534) throw Error("Invalid BMPString: U+FFFE and U+FFFF are not BMPString characters");
		t.push(e >> 8 & 255, e & 255);
	}
	return tlv(30, Uint8Array.from(t));
}
/**
* Encodes a DER UniversalString (tag `0x1c`) as big-endian UTF-32.
*
* @throws on lone surrogates.
*/
function universalString(e) {
	let t = [];
	for (let n of e) {
		let e = n.codePointAt(0) ?? 0;
		if (e >= 55296 && e <= 57343) throw Error("Invalid UniversalString: lone surrogate");
		t.push(e >> 24 & 255, e >> 16 & 255, e >> 8 & 255, e & 255);
	}
	return tlv(28, Uint8Array.from(t));
}
const n = 1n << BigInt(448);
const r = n.toString().length;
function parseOidArc(e) {
	if (!/^\d+$/.test(e)) throw Error(`Invalid OID segment: ${e}`);
	let t = e.replace(/^0+/, "");
	return t.length > r && throwOidLimit(), BigInt(t.length === 0 ? "0" : t);
}
function throwOidLimit() {
	return throwDecodeRefusal("limit_exceeded", "OID sub-identifier exceeds 64 octets");
}
/** Encode a non-negative integer as a base-128 sub-identifier ({@linkcode https://www.itu.int/rec/T-REC-X.690-202102-I/en | X.690 §8.19.2}). */
function encodeBase128(e) {
	e >= n && throwOidLimit();
	let t = [Number(e & 127n)];
	for (let n = e >> 7n; n > 0n; n >>= 7n) t.push(128 | Number(n & 127n));
	return t.reverse();
}
/**
* Encodes a dotted-decimal OID string as a DER OBJECT IDENTIFIER (tag `0x06`).
*
* Validates arc constraints per X.660 §7.6: the root arc must be 0–2, and under
* roots 0 and 1 the second arc must be 0–39. X.690 §8.19.4 defines the `(X*40)+Y`
* packing of the first two arcs into one subidentifier.\
* Sub-identifiers are encoded with base-128 continuation.
*/
function objectIdentifier(e) {
	let t = e.split(".").map(parseOidArc);
	if (t.length < 2) throw Error(`Invalid OID: ${e}`);
	let [n, r, ...i] = t;
	if (n === void 0 || r === void 0) throw Error(`Invalid OID: ${e}`);
	if (n !== 0n && n !== 1n && n !== 2n) throw Error(`Invalid OID first arc: ${n}`);
	if ((n === 0n || n === 1n) && r >= 40n) throw Error(`Invalid OID second arc: ${r} (must be < 40 when first arc is ${n})`);
	let a = encodeBase128(n * 40n + r);
	for (let e of i) a.push(...encodeBase128(e));
	return tlv(6, Uint8Array.from(a));
}
/**
* Encodes a `Date` as a DER UTCTime (tag `0x17`), format `YYMMDDHHMMSSZ`.
*
* Only the two-digit year is stored; suitable for dates in 1950–2049.
*/
function utcTime(e) {
	assertValidDate(e, "UTCTime");
	let t = e.getUTCFullYear();
	if (t < 1950 || t > 2049) throw RangeError("UTCTime year must be between 1950 and 2049");
	let n = `${[
		twoDigits(t % 100),
		twoDigits(e.getUTCMonth() + 1),
		twoDigits(e.getUTCDate()),
		twoDigits(e.getUTCHours()),
		twoDigits(e.getUTCMinutes()),
		twoDigits(e.getUTCSeconds())
	].join("")}Z`;
	return tlv(23, new TextEncoder().encode(n));
}
/**
* Encodes a {@linkcode Date} as a DER GeneralizedTime (tag `0x18`), format `YYYYMMDDHHMMSSZ`.
*
* Uses a four-digit year; required for dates outside the 1950–2049 range.
*/
function generalizedTime(e) {
	assertValidDate(e, "GeneralizedTime");
	let t = e.getUTCFullYear();
	if (t < 0 || t > 9999) throw RangeError("GeneralizedTime year must be between 0 and 9999");
	let n = `${[
		String(t).padStart(4, "0"),
		twoDigits(e.getUTCMonth() + 1),
		twoDigits(e.getUTCDate()),
		twoDigits(e.getUTCHours()),
		twoDigits(e.getUTCMinutes()),
		twoDigits(e.getUTCSeconds())
	].join("")}Z`;
	return tlv(24, new TextEncoder().encode(n));
}
/**
* Encodes a {@linkcode Date} as the appropriate DER time type per RFC 5280.
*
* - {@linkcode utcTime} for 1950–2049
* - {@linkcode generalizedTime} otherwise
*/
function time(e) {
	return e.getUTCFullYear() >= 2050 || e.getUTCFullYear() < 1950 ? generalizedTime(e) : utcTime(e);
}
/** Zero-pads a number to two digits for time encoding. */
function twoDigits(e) {
	return String(e).padStart(2, "0");
}
/** Encodes a non-negative integer as big-endian base-256 octets. */
function encodeBase256(e) {
	assertNonNegativeSafeInteger(e, "DER integer");
	let t = [], n = e;
	for (; n > 0;) t.unshift(n & 255), n = Math.floor(n / 256);
	return t;
}
/**
* Reads the identifier octets at {@linkcode offset} by X.690 §8.1.2, which BER
* and DER share.
*
* @throws on truncated identifier octets, a high-tag-number form with a leading
* zero group or a tag number below 31, and `limit_exceeded` on a tag number
* above {@linkcode Number.MAX_SAFE_INTEGER}.
*/
function readIdentifier(t, n) {
	let r = t[n];
	if (r === void 0) throw Error("Unexpected end of identifier octets");
	if ((r & 31) != 31) return {
		tag: r,
		tagNumber: r & 31,
		length: 1
	};
	if (t[n + 1] === 128) throw Error("High-tag-number form must not open with a zero group");
	let i = n + 1;
	for (; (t[i] ?? 0) & 128;) i += 1;
	if (t[i] === void 0) throw Error("Unexpected end of identifier octets");
	let a = 0;
	for (let r = n + 1; r <= i; r += 1) {
		let n = (t[r] ?? 0) & 127;
		a > (2 ** 53 - 1 - n) / 128 && throwDecodeRefusal("limit_exceeded", "Tag number exceeds Number.MAX_SAFE_INTEGER"), a = a * 128 + n;
	}
	if (a < 31) throw Error("Tag numbers below 31 must use the low-tag-number form");
	return {
		tag: r,
		tagNumber: a,
		length: i - n + 1
	};
}
/**
* Reads one TLV element from {@linkcode bytes} starting at {@linkcode offset}.
*
* Parses the identifier octets, decodes the DER length octets, and slices out the value bytes.
*
* @throws on truncated input, malformed identifier octets, indefinite lengths, and non-minimal length encodings.
* @param offset Byte position of the leading identifier octet. Defaults to 0.
*/
function readElement(e, t = 0) {
	if (e[t] === void 0) throw Error("Unexpected end of DER input");
	let n = readIdentifier(e, t), r = t + n.length, i = e[r];
	if (i === void 0) throw Error("Unexpected end of DER input");
	let { lengthOctets: a, length: o } = readDerLength(e, r, i), s = n.length + a, c = t + s, l = c + o;
	if (l > e.length) throw Error("DER element exceeds input length");
	return {
		tag: n.tag,
		tagNumber: n.tagNumber,
		headerLength: s,
		length: o,
		start: c,
		end: l,
		value: e.slice(c, l)
	};
}
/** Decodes and validates the definite-length field of a DER element. */
function readDerLength(e, t, n) {
	if (!(n & 128)) return {
		lengthOctets: 1,
		length: n
	};
	let r = n & 127;
	if (r === 0) throw Error("Indefinite lengths are not supported");
	let i = e[t + 1];
	if (i === void 0) throw Error("Unexpected end of DER input");
	if (i === 0) throw Error("Non-minimal DER length encoding");
	let a = readLongFormDerLength(e, t, r);
	if (a < 128) throw Error("Non-minimal DER length encoding");
	return {
		lengthOctets: 1 + r,
		length: a
	};
}
function readLongFormDerLength(e, t, n) {
	let r = 0;
	for (let i = 0; i < n; i += 1) {
		let n = e[t + 1 + i];
		if (n === void 0) throw Error("Unexpected end of DER input");
		if (r > Math.floor((2 ** 53 - 1 - n) / 256)) throw Error("DER length exceeds safe integer range");
		r = r * 256 + n;
	}
	return r;
}
/**
* Walks the full DER tree rooted in {@linkcode bytes}.
*
* Constructed tags with content that cannot be parsed as valid children are tolerated when listed in {@linkcode options | allowOpaqueConstructedTags}.
*
* @throws if nesting exceeds {@linkcode maxDepth}.
*/
function assertDerMaxDepth(e, t = 64, n) {
	walkDerTree(e, t, n, () => void 0);
}
/**
* Walks the full DER tree rooted in {@linkcode bytes}, calling {@linkcode visit}
* on each element before reading its children.
*
* @throws if the tree is malformed or nests beyond {@linkcode maxDepth}.
*/
function walkDerTree(t, n, r, i) {
	if (!Number.isSafeInteger(n) || n < 1) throw Error("DER max depth must be a positive safe integer");
	let a = readElement(t, 0);
	if (a.end !== t.length) throw Error("Trailing data after DER element");
	let o = [{
		element: a,
		depth: 1
	}];
	for (; o.length > 0;) {
		let a = o.pop();
		a !== void 0 && (a.depth > n && throwDecodeRefusal("limit_exceeded", `DER exceeds max depth of ${n}`), i(a.element), a.element.tag & 32 && pushDerChildren(t, a, o, r));
	}
}
function pushDerChildren(e, t, n, r) {
	let i = t.element.start, a = !1;
	for (; i < t.element.end;) {
		let o = readDerChildOrOpaque(e, t.element, i, r);
		if (o === void 0) {
			a = !0, i = t.element.end;
			break;
		}
		n.push({
			element: o,
			depth: t.depth + 1
		}), i = o.end;
	}
	if (!a && i !== t.element.end) throw Error("Malformed DER container");
}
function readDerChildOrOpaque(e, t, n, r) {
	let i;
	try {
		i = readElement(e, n);
	} catch (e) {
		if (canTreatAsOpaqueLeaf(t, n, r)) return;
		throw e;
	}
	if (i.end <= t.end) return i;
	if (!canTreatAsOpaqueLeaf(t, n, r)) throw Error("DER child exceeds parent length");
}
/**
* Reads the single top-level TLV element from {@linkcode bytes}.
*
* Optionally validates nesting depth.
*
* @throws if there is trailing data after the element.
*/
function readRootElement(e, t) {
	assertDerMaxDepth(e, t?.maxDepth ?? 64, t);
	let n = readElement(e, 0);
	if (n.end !== e.length) throw Error("Trailing data after DER element");
	return n;
}
/**
* Reads a DER-encoded SEQUENCE from {@linkcode bytes} and returns its direct children.
*
* @throws if the root element is not a SEQUENCE or if child boundaries are inconsistent.
*/
function readSequenceChildren(e, t) {
	let n = readRootElement(e, t);
	if (n.tag !== 48) throw Error("Expected SEQUENCE");
	let r = [], i = n.start;
	for (; i < n.end;) {
		let t = readElement(e, i);
		if (t.end > n.end) throw Error("DER child exceeds parent length");
		r.push(t), i = t.end;
	}
	if (i !== n.end) throw Error("Malformed DER sequence");
	return r;
}
/** @throws if {@linkcode value} is not a non-negative safe integer. */
function assertNonNegativeSafeInteger(e, t) {
	if (!Number.isSafeInteger(e) || e < 0) throw Error(`${t} must be a non-negative safe integer`);
}
function assertSingleOctetDerTag(e) {
	if (!Number.isSafeInteger(e) || e < 0 || e > 255) throw RangeError("DER tag octet must be between 0 and 255");
	if ((e & 31) == 31) throw Error("High-tag-number DER tags are not supported");
}
function assertContextSpecificTagNumber(e) {
	if (!Number.isSafeInteger(e) || e < 0 || e >= 31) throw RangeError("Context-specific tag number must be between 0 and 30");
}
function assertValidDate(e, t) {
	if (Number.isNaN(e.getTime())) throw RangeError(`${t} requires a valid Date`);
}
/**
* @returns `true` when a constructed element's content should be treated as an opaque leaf (not recursed into)
* because its tag appears in the {@linkcode options | allowOpaqueConstructedTags} list and the offset is at the element start.
*/
function canTreatAsOpaqueLeaf(e, t, n) {
	return t === e.start && n?.allowOpaqueConstructedTags?.includes(e.tag) === !0;
}
// ../../dist/internal/asn1/asn1.js
/**
* ASN.1 decoding helpers used by the higher-level DER, parse, and crypto modules.
*
* These utilities stay intentionally small and strict so malformed input fails early and
* higher-level modules can build on one consistent decoding layer.
*
* @module
*/
/** Shared UTF-8 text decoder for ASN.1 string types. */
const o = new TextDecoder("utf-8", {
	fatal: !0,
	ignoreBOM: !0
});
const s = /^[A-Za-z0-9 '()+,\-./:=?]*$/u;
/**
* Decodes a DER-encoded OBJECT IDENTIFIER value into its dotted-decimal string form.
*
* @example "1.2.840.113549.1.1.1"
* @throws on empty input, truncated multi-byte sub-identifiers, or incomplete continuation octets,
* and `limit_exceeded` for a sub-identifier encoded in more than
* {@linkcode MAX_OID_SUBIDENTIFIER_OCTETS} octets.
*/
function decodeObjectIdentifier(e) {
	if (e.length === 0) throw Error("OID is empty");
	let t = decodeOidSubidentifier(e, 0), n = t.nextOffset, r = t.value, i = r < 40n ? [0n, r] : r < 80n ? [1n, r - 40n] : [2n, r - 80n];
	for (; n < e.length;) {
		let t = decodeOidSubidentifier(e, n);
		i.push(t.value), n = t.nextOffset;
	}
	return i.join(".");
}
/**
* Reduces an OID to the dotted-decimal form its DER encoding decodes back to, so
* that spellings differing only by redundant leading zeros in an arc resolve to
* one identity.
*
* @example `canonicalizeOid('2.5.029.17')` returns `'2.5.29.17'`
* @throws if the OID has a non-numeric segment or violates the X.660 arc constraints.
*/
function canonicalizeOid(e) {
	return decodeObjectIdentifier(readElement(objectIdentifier(e), 0).value);
}
/** Converts raw bytes to a lowercase hex string with no separator. */
function toHex(e) {
	return Array.from(e, (e) => e.toString(16).padStart(2, "0")).join("");
}
/**
* Copies a {@linkcode Uint8Array} into a standalone {@linkcode ArrayBuffer} suitable for
* Web Crypto operations that require a non-shared backing buffer.
*/
function toArrayBuffer(e) {
	let t = new ArrayBuffer(e.length);
	return new Uint8Array(t).set(e), t;
}
/**
* Iterates through all direct child TLV elements inside a constructed {@linkcode DerElement}
* (SEQUENCE, SET, or context-tagged container).
*
* @throws if any child overflows the parent boundary or if there is leftover data between the last child and the parent end offset.
*/
function childrenOf(e, t) {
	let n = [], r = t.start;
	for (; r < t.end;) {
		let a = readElement(e, r);
		if (a.end > t.end) throw Error("DER child exceeds parent length");
		n.push(a), r = a.end;
	}
	if (r !== t.end) throw Error("Malformed DER container");
	return n;
}
/**
* Asserts that a value is not `undefined`, returning it narrowed.\
* Used to enforce the presence of mandatory ASN.1 fields during parsing.
*
* @param label Human-readable field name included in the error message on failure.
*/
function requireElement(e, t) {
	if (e === void 0) throw Error(`Missing ${t}`);
	return e;
}
/**
* Strips the leading "unused bits" octet from a BIT STRING element, returning just the payload bytes.
*
* Used to extract signature values and public keys from their BIT STRING wrapper.
*
* @throws if the tag is not `0x03`.
*/
function extractBitStringValue(e) {
	if (e.tag !== 3) throw Error("Expected BIT STRING");
	let t = e.value[0];
	if (t === void 0 || t > 7) throw Error("Invalid BIT STRING");
	if (t !== 0) throw Error("BIT STRING must have zero unused bits");
	return e.value.slice(1);
}
/**
* Decodes a BIT STRING element into its payload and unused-bit count.
*
* Accepts a non-zero unused-bit count, so it reads flag strings such as {@linkcode KeyUsage},
* which {@linkcode extractBitStringValue} rejects.
*
* Padding bits that {@linkcode https://www.itu.int/rec/T-REC-X.690-202102-I/en | X.690 §11.2.1} requires to be zero are reported through
* {@linkcode DerBitString.nonZeroPadding} rather than rejected, so a caller can decide.
*/
function decodeBitString(e) {
	if (e.tag !== 3) throw Error("Expected BIT STRING");
	let t = e.value[0];
	if (t === void 0 || t > 7) throw Error("Invalid BIT STRING");
	let n = e.value.slice(1);
	if (n.length === 0 && t !== 0) throw Error("Invalid BIT STRING");
	let r = (1 << t) - 1;
	return {
		bytes: n,
		unusedBits: t,
		nonZeroPadding: t > 0 && n.length > 0 && ((n[n.length - 1] ?? 0) & r) !== 0
	};
}
/**
* Parses a {@linkcode DerElement} with tag UTCTime (`0x17`) or GeneralizedTime (`0x18`) into a {@linkcode Date}.
*
* For UTCTime, the two-digit year is interpreted per RFC 5280:
* - values >= 50 map to 19xx,
* - values < 50 map to 20xx.
*
* @throws on unrecognized time tags.
*/
function parseTime(e) {
	if (e.tag === 23) {
		let t = decodeUtf8Text(e.value, "UTCTime"), n = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(t);
		if (n === null) throw Error("Invalid UTCTime");
		let r = requireElement(n[1], "UTCTime year"), i = requireElement(n[2], "UTCTime month"), a = requireElement(n[3], "UTCTime day"), o = requireElement(n[4], "UTCTime hour"), s = requireElement(n[5], "UTCTime minute"), c = requireElement(n[6], "UTCTime second"), l = Number.parseInt(r, 10);
		return buildStrictUtcDate(l >= 50 ? 1900 + l : 2e3 + l, i, a, o, s, c, "UTCTime");
	}
	if (e.tag === 24) {
		let t = decodeUtf8Text(e.value, "GeneralizedTime"), n = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(t);
		if (n === null) throw Error("Invalid GeneralizedTime");
		let r = requireElement(n[1], "GeneralizedTime year"), i = requireElement(n[2], "GeneralizedTime month"), a = requireElement(n[3], "GeneralizedTime day"), o = requireElement(n[4], "GeneralizedTime hour"), s = requireElement(n[5], "GeneralizedTime minute"), c = requireElement(n[6], "GeneralizedTime second");
		return buildStrictUtcDate(Number.parseInt(r, 10), i, a, o, s, c, "GeneralizedTime");
	}
	throw Error(`Unsupported time tag: ${e.tag}`);
}
/**
* Decodes DER INTEGER content octets holding a non-negative value into a JavaScript `number`.
*
* @throws if the value is empty, negative, non-minimally encoded, or exceeds {@linkcode Number.MAX_SAFE_INTEGER}.
*/
function decodeIntegerNumber(e) {
	let t = decodeIntegerMagnitude(e);
	if (t.type === "unsafe") throw Error(`Integer too large for safe number (${e.length} bytes)`);
	return t.value;
}
/**
* Decodes DER INTEGER content octets holding a non-negative value, stopping at the first octet past {@linkcode Number.MAX_SAFE_INTEGER}.
*
* @param bytes DER INTEGER content octets to decode.
* @param label Field name for error messages (defaults to `"INTEGER"`).
* @throws if the value is empty, negative, or non-minimally encoded.
*/
function decodeIntegerMagnitude(e, t = "INTEGER") {
	let n = e[0];
	if (n === void 0) throw Error(`${t} is empty`);
	if (n & 128) throw Error(`${t} must be non-negative`);
	if (e.length > 1 && n === 0 && !((e[1] ?? 0) & 128)) throw Error(`${t} must use minimal encoding`);
	let r = 0;
	for (let t of e) {
		if (r > Math.floor((2 ** 53 - 1 - t) / 256)) return { type: "unsafe" };
		r = r * 256 + t;
	}
	return {
		type: "safe",
		value: r
	};
}
/**
* Decodes DER INTEGER or ENUMERATED content octets holding a non-negative value of any length into a `bigint`.
*
* @param bytes DER content octets to decode.
* @param label Field name for error messages (defaults to `"INTEGER"`).
* @throws if the value is empty, negative, or non-minimally encoded.
*/
function decodeNonNegativeIntegerBigInt(e, t = "INTEGER") {
	return decodeIntegerMagnitude(e, t), BigInt(`0x${toHex(e)}`);
}
/**
* Like {@linkcode decodeIntegerNumber}, but optionally rewrites thrown error messages with a caller-specific field label.
*
* @param bytes DER INTEGER content octets to decode.
* @param label Field name for error messages (defaults to `"INTEGER"`).
* @throws if the value is empty, negative, non-minimally encoded, or exceeds {@linkcode Number.MAX_SAFE_INTEGER}.
*/
function decodeNonNegativeIntegerNumber(e, t = "INTEGER") {
	if (t === "INTEGER") return decodeIntegerNumber(e);
	try {
		return decodeIntegerNumber(e);
	} catch (n) {
		if (!(n instanceof Error)) throw n;
		switch (n.message) {
			case "INTEGER is empty": throw Error(`${t} is empty`);
			case "INTEGER must be non-negative": throw Error(`${t} must be non-negative`);
			case "INTEGER must use minimal encoding": throw Error(`${t} must use minimal encoding`);
			default: throw n.message.startsWith("Integer too large for safe number") ? Error(`${t} too large for safe number (${e.length} bytes)`) : n;
		}
	}
}
/**
* Converts a hex string (even or odd length) to a {@linkcode Uint8Array}.
* Odd-length strings are left-padded with a zero nibble.
*/
function hexToBytes(e) {
	let t = e.length % 2 == 0 ? e : `0${e}`, n = new Uint8Array(t.length / 2);
	for (let e = 0; e < n.length; e += 1) {
		let r = t.slice(e * 2, e * 2 + 2);
		if (!/^[0-9a-fA-F]{2}$/.test(r)) throw Error(`Invalid hex byte: ${r}`);
		n[e] = Number.parseInt(r, 16);
	}
	return n;
}
/** Decodes a DER BOOLEAN value. X.690 clause 11.1 restricts TRUE to an all-ones octet, so only `0xff` and `0x00` are accepted. */
function decodeBoolean(e) {
	if (e.length !== 1) throw Error("BOOLEAN must contain exactly one octet");
	let t = e[0];
	if (t !== 0 && t !== 255) throw Error("BOOLEAN must use DER encoding");
	return t === 255;
}
function buildStrictUtcDate(e, t, n, r, i, a, o) {
	let s = Number.parseInt(t, 10), c = Number.parseInt(n, 10), l = Number.parseInt(r, 10), u = Number.parseInt(i, 10), d = Number.parseInt(a, 10), f = new Date(Date.UTC(e, s - 1, c, l, u, d));
	if (Number.isNaN(f.getTime()) || f.getUTCFullYear() !== e || f.getUTCMonth() !== s - 1 || f.getUTCDate() !== c || f.getUTCHours() !== l || f.getUTCMinutes() !== u || f.getUTCSeconds() !== d) throw Error(`Invalid ${o}`);
	return f;
}
function decodeOidSubidentifier(e, t) {
	let n = e[t];
	if (n === void 0) throw Error("Malformed OID");
	if (n === 128) throw Error("Malformed OID: non-minimal base-128 encoding");
	let r = findOidSubidentifierEnd(e, t), i = 0n;
	for (let n = t; n <= r; n += 1) i = i << 7n | BigInt((e[n] ?? 0) & 127);
	return {
		value: i,
		nextOffset: r + 1
	};
}
/** The offset of the sub-identifier's last octet, checked before any of it is accumulated. */
function findOidSubidentifierEnd(e, t) {
	for (let r = t; r < e.length; r += 1) {
		if (!((e[r] ?? 0) & 128)) return r;
		r - t + 1 >= 64 && r + 1 < e.length && throwDecodeRefusal("limit_exceeded", "OID sub-identifier exceeds 64 octets");
	}
	throw Error("Malformed OID: incomplete continuation");
}
/**
* Decodes a DER string element by tag.
*
* Supports:
* - UTF8String (`0x0c`),
* - PrintableString (`0x13`),
* - TeletexString (`0x14`) in its X.690 §8.23.5.2 initial state,
* - IA5String (`0x16`),
* - UniversalString (`0x1c`), and
* - BMPString (`0x1e`).
*
* @throws on unsupported string tags.
*/
function decodeString(e, t) {
	switch (e) {
		case 12: return decodeUtf8Text(t, "UTF8String");
		case 19: return decodePrintableString(t);
		case 22: return decodeIa5String(t);
		case 20: return decodeTeletexString(t);
		case 28: return decodeUniversalString(t);
		case 30: return decodeBmpString(t);
		default: throw Error(`Unsupported string tag: ${e}`);
	}
}
function decodeUtf8Text(e, t) {
	try {
		return o.decode(e);
	} catch (e) {
		throw e instanceof Error ? Error(`Invalid ${t}: invalid UTF-8`, { cause: e }) : e;
	}
}
function decodeAsciiString(e, t) {
	let n = "";
	for (let r of e) {
		if (r > 127) throw Error(`Invalid ${t}: contains non-ASCII bytes`);
		n += String.fromCharCode(r);
	}
	return n;
}
function decodeIa5String(e) {
	return decodeAsciiString(e, "IA5String");
}
function decodePrintableString(e) {
	let t = decodeAsciiString(e, "PrintableString");
	if (!s.test(t)) throw Error("Invalid PrintableString: contains characters outside the allowed set");
	return t;
}
/**
* Decodes VisibleString contents, which X.680 §43.7 limits to 0x20 through 0x7E.
*
* @throws on an octet outside that range.
*/
function decodeVisibleString(e) {
	let t = "";
	for (let n of e) {
		if (n < 32 || n > 126) throw Error("Invalid VisibleString: contains octets outside 0x20 to 0x7e");
		t += String.fromCharCode(n);
	}
	return t;
}
/** T.61 Table 1 leaves these positions of register entry 102 empty. */
const c = /* @__PURE__ */ new Set([
	92,
	94,
	96,
	123,
	125,
	126
]);
/**
* Decodes TeletexString contents in the X.690 §8.23.5.2 initial state, reading
* register entry 102 by T.61 Table 1 and Figure 2 Note 4, with the SPACE and
* DELETE that X.680 Table 8 adds.
*
* @throws `unsupported` on any other octet.
*/
function decodeTeletexString(e) {
	let t = "";
	for (let r of e) (r < 32 || r > 127 || c.has(r)) && throwDecodeRefusal("unsupported", `Unsupported TeletexString octet: 0x${r.toString(16).padStart(2, "0")}`), t += r === 36 ? "¤" : String.fromCharCode(r);
	return t;
}
/** X.680 §41.15: BMPString holds code units 0000 to D7FF and E000 to FFFD. */
function decodeBmpString(e) {
	if (e.length % 2 != 0) throw Error("Invalid BMPString length");
	let t = "";
	for (let n = 0; n < e.length; n += 2) {
		let r = e[n], i = e[n + 1];
		if (r === void 0 || i === void 0) throw Error("Invalid BMPString content");
		let a = r << 8 | i;
		if (a >= 55296 && a <= 57343 || a >= 65534) throw Error("Invalid BMPString code point");
		t += String.fromCharCode(a);
	}
	return t;
}
function decodeUniversalString(e) {
	if (e.length % 4 != 0) throw Error("Invalid UniversalString length");
	let t = "";
	for (let n = 0; n < e.length; n += 4) {
		let r = e[n], i = e[n + 1], a = e[n + 2], o = e[n + 3];
		if (r === void 0 || i === void 0 || a === void 0 || o === void 0) throw Error("Invalid UniversalString content");
		let s = ((r * 256 + i) * 256 + a) * 256 + o;
		if (s > 1114111 || s >= 55296 && s <= 57343) throw Error("Invalid UniversalString code point");
		t += String.fromCodePoint(s);
	}
	return t;
}
/**
* Walks {@linkcode bytes} as one DER element and checks each universal-class
* element against the X.690 rules its tag fixes: the identifier form, the
* contents, and the DER restrictions of clauses 10 and 11.
*
* Where those rules rest on ISO/IEC 2022, ISO 8601 or an implicitly tagged
* schema, the element is `unsupported`: TeletexString, VideotexString, TIME,
* EXTERNAL, EMBEDDED PDV, CHARACTER STRING, the types of UNIVERSAL 31 to 36, a
* REAL with a long-form exponent, a GeneralizedTime at second 60, and text
* holding an escape sequence or a code-extension control. A SET or SET OF
* whose children follow neither the DER SET order nor the DER SET OF order is
* `malformed`. Context-specific, application and private elements get framing
* checks only, as do the rules that depend on a schema: DEFAULT omission and
* NamedBitList trailing bits. No value is checked against an ASN.1 type, so
* ENUMERATED membership, INTEGER ranges, SIZE constraints, CHOICE alternatives
* and SEQUENCE or SET components stay unchecked.
*
* @throws `limit_exceeded` past {@linkcode maxDepth} levels of nesting or on a
* tag number of 2^53 or more.
*/
function checkStrictDer(n, r = 64) {
	let i$1 = !1;
	try {
		walkDerTree(n, r, void 0, (e) => {
			let t = checkUniversalElement(e);
			if (t === "malformed") throw Error("DER element breaks the rules of its universal type");
			i$1 ||= t === "unsupported";
		});
	} catch (n) {
		return rethrowDecodeRefusal(n, i), "malformed";
	}
	return i$1 ? "unsupported" : "valid";
}
function verdictOf(e) {
	return e ? "valid" : "malformed";
}
function decodes(e) {
	try {
		return e(), "valid";
	} catch {
		return "malformed";
	}
}
function asciiText(e) {
	try {
		return decodeIa5String(e);
	} catch {
		return;
	}
}
const l = /* @__PURE__ */ new Set([27]);
const u = /* @__PURE__ */ new Set([
	14,
	15,
	27,
	142,
	143,
	155
]);
/** The verdict on text {@linkcode decode} validates, `unsupported` when it holds one of {@linkcode controls}. */
function checkText(e, t) {
	let n;
	try {
		n = e();
	} catch {
		return "malformed";
	}
	for (let e of n) if (t.has(e.codePointAt(0) ?? 0)) return "unsupported";
	return "valid";
}
/** X.690 Table 3: GraphicString and ObjectDescriptor open with register entry 6 as G0 and no C0 or C1 set. */
function checkGraphicString(e) {
	return e.value.includes(27) ? "unsupported" : verdictOf(e.value.every((e) => e >= 32 && e <= 126));
}
/** X.690 Table 3: GeneralString opens with register entry 6 as G0 and entry 1 as C0, beside SPACE and DELETE. */
function checkGeneralString(e) {
	return e.value.some((e) => e === 27 || e === 14 || e === 15) ? "unsupported" : verdictOf(e.value.every((e) => e <= 127));
}
/** X.690 §8.3.2: the first nine bits of a multi-octet INTEGER are neither all ones nor all zeros. */
function isMinimalInteger(e) {
	let [t, n] = e;
	return t === void 0 ? !1 : n === void 0 || (t !== 0 || n >= 128) && (t !== 255 || n < 128);
}
/** X.690 §8.19.2: every subidentifier ends on an octet with bit 8 clear and never opens with 0x80. */
function isSubidentifierList(e) {
	let t = !0;
	for (let n of e) {
		if (t && n === 128) return !1;
		t = !(n & 128);
	}
	return t;
}
function checkBitString(e) {
	try {
		return verdictOf(!decodeBitString(e).nonZeroPadding);
	} catch {
		return "malformed";
	}
}
/** X.680 Table 9: NumericString holds the digits and SPACE. */
function isNumericStringContents(e) {
	return e.every((e) => e === 32 || e >= 48 && e <= 57);
}
function isLeapYear(e) {
	return e % 4 == 0 && e % 100 != 0 || e % 400 == 0;
}
const d = [
	31,
	28,
	31,
	30,
	31,
	30,
	31,
	31,
	30,
	31,
	30,
	31
];
const f = {
	pattern: /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/,
	century: 2e3,
	leapSecond: "malformed"
};
const p = {
	pattern: /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d*[1-9])?Z$/,
	century: 0,
	leapSecond: "unsupported"
};
function checkTime(e, t) {
	let n = t.pattern.exec(asciiText(e.value) ?? "")?.slice(1).map(Number);
	if (n === void 0) return "malformed";
	let [r = 0, i = 0, a = 0, o = 0, s = 0, c = 0] = n, l = (d[i - 1] ?? 0) + (i === 2 && isLeapYear(t.century + r) ? 1 : 0);
	return a < 1 || a > l || o > 23 || s > 59 || c > 60 ? "malformed" : c === 60 ? t.leapSecond : "valid";
}
/**
* X.690 §11.3.2: NR3 without SPACE, a MINUS SIGN only on a negative value, a
* mantissa that neither opens nor closes with 0 followed by `.E`, and an
* exponent written `+0` or with no leading 0 and no PLUS SIGN.
*/
const m = /^-?[1-9](?:\d*[1-9])?\.E(?:\+0|-?[1-9]\d*)$/;
/**
* X.690 §8.5 and §11.3: an empty plus zero, a one-octet special value, a
* base-2 binary form with F = 0, the fewest exponent octets and an odd
* mantissa with no leading zero octet, or a decimal NR3 form. X.690 §8.5.7.4
* d) leaves the length of a long-form exponent ambiguous.
*/
function checkReal(e) {
	let [t] = e.value, n = e.value.subarray(1);
	if (t === void 0) return "valid";
	if (!(t & 128)) return t & 64 ? verdictOf(n.length === 0 && t <= 67) : verdictOf(t === 3 && m.test(asciiText(n) ?? ""));
	let r = t & 3;
	if (t & 60) return "malformed";
	if (r === 3) return "unsupported";
	let i = n.subarray(0, r + 1), a = n.subarray(r + 1);
	return verdictOf(i.length === r + 1 && isMinimalInteger(i) && (a[0] ?? 0) !== 0 && ((a.at(-1) ?? 0) & 1) == 1);
}
/** X.690 §11.6: set-of encodings compare as octet strings, the shorter padded at its end with zero octets. */
function compareSetOfEncodings(e, t) {
	for (let n = 0; n < Math.max(e.length, t.length); n += 1) {
		let r = (e[n] ?? 0) - (t[n] ?? 0);
		if (r !== 0) return r;
	}
	return 0;
}
/**
* X.690 §10.3 orders SET components by the canonical tag order of X.680 §8.6,
* which compares class and number and never the constructed bit, and X.690
* §11.6 orders SET OF components by encoding.
*/
function checkSet(e) {
	let t = [];
	for (let n = 0; n < e.value.length;) {
		let r = readElement(e.value, n);
		t.push(r), n = r.end;
	}
	let encodingOf = (t) => e.value.subarray(t.start - t.headerLength, t.end), n = t.every((e, n) => {
		let r = t[n - 1];
		if (r === void 0) return !0;
		let i = r.tag & 192, a = e.tag & 192;
		return i < a || i === a && r.tagNumber < e.tagNumber;
	}), r = t.every((e, n) => {
		let r = t[n - 1];
		return r === void 0 || compareSetOfEncodings(encodingOf(r), encodingOf(e)) <= 0;
	});
	return verdictOf(n || r);
}
/**
* The identifier octet DER uses for each universal type, mapped to the check
* of its contents. A universal identifier missing here is a reserved tag
* number or a form DER forbids.
*/
const h = /* @__PURE__ */ new Map([
	[1, (e) => decodes(() => decodeBoolean(e.value))],
	[2, (e) => verdictOf(isMinimalInteger(e.value))],
	[3, checkBitString],
	[4, () => "valid"],
	[5, (e) => verdictOf(e.value.length === 0)],
	[6, (e) => verdictOf(e.value.length > 0 && isSubidentifierList(e.value))],
	[7, checkGraphicString],
	[9, checkReal],
	[10, (e) => verdictOf(isMinimalInteger(e.value))],
	[12, (e) => checkText(() => decodeUtf8Text(e.value, "UTF8String"), l)],
	[13, (e) => verdictOf(e.value.length > 0 && isSubidentifierList(e.value))],
	[14, () => "unsupported"],
	[18, (e) => verdictOf(isNumericStringContents(e.value))],
	[19, (e) => decodes(() => decodePrintableString(e.value))],
	[20, () => "unsupported"],
	[21, () => "unsupported"],
	[22, (e) => checkText(() => decodeIa5String(e.value), l)],
	[23, (e) => checkTime(e, f)],
	[24, (e) => checkTime(e, p)],
	[25, checkGraphicString],
	[26, (e) => decodes(() => decodeVisibleString(e.value))],
	[27, checkGeneralString],
	[28, (e) => checkText(() => decodeUniversalString(e.value), u)],
	[30, (e) => checkText(() => decodeBmpString(e.value), u)],
	[40, () => "unsupported"],
	[43, () => "unsupported"],
	[48, () => "valid"],
	[49, checkSet],
	[61, () => "unsupported"]
]);
function checkUniversalElement(e) {
	return e.tag & 192 ? "valid" : (e.tag & 31) == 31 ? e.tagNumber <= 36 ? "unsupported" : "malformed" : h.get(e.tag)?.(e) ?? "malformed";
}
export { visibleString as $, ia5Bytes as A, printableString as B, bool as C, explicitContext as D, enumeratedFromNumber as E, integerFromNumber as F, sequence as G, readIdentifier as H, nullValue as I, time as J, setOf as K, objectIdentifier as L, implicitConstructedContext as M, implicitPrimitiveContext as N, generalizedTime as O, integer as P, utf8String as Q, octetString as R, bmpString as S, encodeLength as T, readRootElement as U, readElement as V, readSequenceChildren as W, universalString as X, tlv as Y, utcTime as Z, requireElement as _, decodeBoolean as a, assertDerMaxDepth as b, decodeNonNegativeIntegerBigInt as c, decodeString as d, decodeFailureResult as et, decodeVisibleString as f, parseTime as g, isNumericStringContents as h, decodeBitString as i, throwDecodeRefusal as it, ia5String as j, hasLoneSurrogate as k, decodeNonNegativeIntegerNumber as l, hexToBytes as m, checkStrictDer as n, i as nt, decodeIntegerMagnitude as o, extractBitStringValue as p, t as q, childrenOf as r, rethrowDecodeRefusal as rt, decodeIntegerNumber as s, canonicalizeOid as t, decodeRefusalOf as tt, decodeObjectIdentifier as u, toArrayBuffer as v, concatBytes as w, bitString as x, toHex as y, optionalBytesEqual as z };
