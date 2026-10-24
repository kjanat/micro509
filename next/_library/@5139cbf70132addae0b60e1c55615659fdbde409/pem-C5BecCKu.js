import { c as rethrowIfInvariant, l as successResult, n as failureResult } from "./result-C9WPk47A.js";
// ../../dist/internal/shared/base64.js
/** Encode raw bytes as standard base64 without line breaks. */
function base64Encode(e) {
	let t = [];
	for (let n of e) t.push(String.fromCharCode(n));
	return btoa(t.join(""));
}
/** Decode a standard base64 string into raw bytes. */
function base64Decode(e) {
	let t = atob(e), n = new Uint8Array(t.length);
	for (let e = 0; e < t.length; e++) n[e] = t.charCodeAt(e);
	return assertCanonicalFinalQuantum(e, n), n;
}
/** RFC 4648 §4 completes a final quantum with pad characters and bits of value zero. */
function assertCanonicalFinalQuantum(e, t) {
	let n = e.replace(/[\t\n\f\r ]/g, "");
	if (n.length % 4 != 0) throw Error("Base64 final quantum is missing its padding");
	if (n.length !== 0 && base64Encode(t.slice(t.length - ((t.length - 1) % 3 + 1))) !== n.slice(-4)) throw Error("Base64 final quantum has non-zero pad bits");
}
// ../../dist/pem/pem.js
/**
* PEM helpers used across the public API.
*
* Encodes, decodes, splits, and categorizes PEM blocks as defined by
* RFC 7468.
*
* @module
*/
const a = /^(?:[!-,.-~](?:[- ]?[!-,.-~])*)?$/;
/**
* Wraps DER bytes in a PEM envelope with 64-character base64 lines.
*
* @param label PEM type label (e.g. `"CERTIFICATE"`, `"PRIVATE KEY"`).
* @param der Raw DER-encoded content.
*/
function pemEncode(e, t) {
	if (!isPemLabel(e)) throw Error("Invalid PEM label");
	return `-----BEGIN ${e}-----\n${(base64Encode(t).match(/.{1,64}/g) ?? []).join("\n")}\n-----END ${e}-----\n`;
}
/**
* Throwing core for {@linkcode pemDecode}: extracts and base64-decodes the
* DER content from a PEM string. Text ahead of the `BEGIN` line is ignored.
* Throws if the `BEGIN`/`END` markers don't match `label`.
*
* @param label Expected PEM type label.
* @param pem PEM-encoded text (may contain `\r`).
*/
function pemDecodeOrThrow(e, t) {
	let n = trimPemDocument(t.replace(/\r\n?/g, "\n")).split("\n"), i = findPreEncapsulationBoundary(n);
	if (i === void 0 || parsePemBoundaryLine(n[i] ?? "", "BEGIN") !== e || parsePemBoundaryLine(n[n.length - 1] ?? "", "END") !== e || n.length - i < 3) throw Error(`Invalid PEM for ${e}`);
	let a = normalizePemBodyLines(n.slice(i + 1, -1));
	if (a === void 0) throw Error(`Invalid PEM for ${e}`);
	try {
		return base64Decode(a.join(""));
	} catch {
		throw Error(`Invalid PEM for ${e}`);
	}
}
/**
* Finds all `BEGIN`/`END`-delimited PEM blocks in a string and returns
* them as parsed {@linkcode PemBlock} entries. Handles concatenated PEM files
* and ignores non-PEM text between blocks.
*/
function splitPemBlocksOrThrow(e) {
	let t = e.replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n"), n = [], r, i = 0;
	for (; i < t.length;) {
		let e = t.indexOf("\n", i), a = e === -1 ? t.length : e, o = e === -1 ? t.length : e + 1, s = t.slice(i, a), c = s.replace(/^[ \t]+/, ""), l = parsePemBoundaryLine(s, "BEGIN"), u = parsePemBoundaryLine(s, "END");
		if (l !== void 0) {
			if (r !== void 0) throw Error("Malformed PEM block");
			r = {
				label: l,
				start: i + s.length - c.length
			};
		} else if (u !== void 0) n.push(closePemBlock(t, r, u, o)), r = void 0;
		else if (looksLikePemBoundary(s)) throw Error("Malformed PEM block");
		if (e === -1) break;
		i = o;
	}
	if (r !== void 0) throw Error("Malformed PEM block");
	return n;
}
function closePemBlock(e, t, n, r) {
	if (t === void 0 || t.label !== n) throw Error("Malformed PEM block");
	let i = e.slice(t.start, r);
	return {
		label: t.label,
		bytes: pemDecodeOrThrow(t.label, i),
		pem: i
	};
}
/**
* Groups PEM blocks by label into well-known PKI categories
* (certificates, CSRs, private keys, public keys, and everything else).
* Accepts either raw PEM text or pre-split {@linkcode PemBlock} entries.
*/
function categorizePemBlocksOrThrow(e) {
	let t = typeof e == "string" ? splitPemBlocksOrThrow(e) : e, n = [], r = [], i = [], a = [], o = [];
	for (let e of t) switch (e.label) {
		case "CERTIFICATE":
			n.push(e);
			break;
		case "CERTIFICATE REQUEST":
			r.push(e);
			break;
		case "PRIVATE KEY":
		case "RSA PRIVATE KEY":
		case "EC PRIVATE KEY":
			i.push(e);
			break;
		case "PUBLIC KEY":
			a.push(e);
			break;
		default: o.push(e);
	}
	return {
		certificates: n,
		certificateRequests: r,
		privateKeys: i,
		publicKeys: a,
		others: o
	};
}
function normalizePemBodyLines(e) {
	let t = e.map((e) => e.replace(/[ \t]/g, "")).filter((e) => e !== "");
	return t.length === 0 ? [""] : t.every((e) => /^[A-Za-z0-9+/=]+$/.test(e)) ? t : void 0;
}
function parsePemBoundaryLine(e, t) {
	let n = `-----${t} `, r = trimLwsp(e);
	if (!r.startsWith(n) || !r.endsWith("-----")) return;
	let i = r.slice(n.length, -5);
	return isPemLabel(i) ? i : void 0;
}
/** RFC 7468 §2: data before the encapsulation boundaries is permitted. */
function findPreEncapsulationBoundary(e) {
	for (let [t, n] of e.entries()) {
		if (parsePemBoundaryLine(n, "BEGIN") !== void 0) return t;
		if (looksLikePemBoundary(n)) return;
	}
}
function looksLikePemBoundary(e) {
	return /^[ \t]*-{5,}(?:BEGIN|END)/.test(e);
}
/** RFC 822 §3.2: `field-name = 1*<any CHAR, excluding CTLs, SPACE, and ":">`. */
const o = /^[\x21-\x39\x3b-\x7e]+$/;
/** RFC 822 §3.3: `LWSP-char = SPACE / HTAB`. */
function isLwspChar(e) {
	return e === " " || e === "	";
}
/**
* Strips the whitespace surrounding a PEM document: `LWSP-char`s and the line
* terminators that separate the boundary lines from the body.
*
* `String.prototype.trim` would also strip VT, FF, NBSP, and every Unicode
* `Zs`, making those characters acceptable at a document edge while
* {@linkcode parsePemBoundaryLine} rejects them everywhere else.
*/
function trimPemDocument(e) {
	return e.replace(/^[ \t\n]+|[ \t\n]+$/g, "");
}
/**
* @internal Strips surrounding RFC 822 §3.3 `LWSP-char`s.
*
* `String.prototype.trim` would also strip VT, FF, NBSP, and every Unicode `Zs`,
* none of which the grammar admits.
*/
function trimLwsp(e) {
	return e.replace(/^[ \t]+|[ \t]+$/g, "");
}
/**
* @internal Parses a PEM block with RFC 1421 §4.6 encapsulated headers.
*
* RFC 7468 §2 forbids headers, so this path exists only for the legacy
* OpenSSL-style encrypted PKCS#1 and SEC1 blocks that predate it.
*/
function parseTraditionalPemOrThrow(e) {
	let t = trimPemDocument(e.replace(/\r\n?/g, "\n")).split("\n"), n = parsePemBoundaryLine(t[0] ?? "", "BEGIN");
	if (n === void 0 || t.length < 2) throw Error("Invalid PEM block");
	if (parsePemBoundaryLine(t[t.length - 1] ?? "", "END") !== n) throw Error("PEM boundaries do not match");
	let r = /* @__PURE__ */ new Map(), i = 1, a;
	for (; i < t.length - 1;) {
		let e = t[i];
		if (e === void 0) break;
		if (e.length === 0) {
			i += 1;
			break;
		}
		if (a !== void 0 && isLwspChar(e.charAt(0))) {
			r.set(a, `${r.get(a) ?? ""}${e}`), i += 1;
			continue;
		}
		let n = e.indexOf(":");
		if (n === -1) break;
		let s = e.slice(0, n);
		if (!o.test(s)) throw Error(`Invalid PEM header name: ${s}`);
		if (r.has(s)) throw Error(`Duplicate PEM header: ${s}`);
		r.set(s, e.slice(n + 1).replace(/^[ \t]+/, "")), a = s, i += 1;
	}
	return {
		label: n,
		headers: r,
		base64Body: t.slice(i, t.length - 1).join("")
	};
}
function isPemLabel(e) {
	return a.exec(e)?.[0] === e;
}
/**
* Extracts and base64-decodes the DER content from a PEM string.
* Text ahead of the `BEGIN` line is ignored.
*
* Returns a typed failure (`code: 'malformed'`) when the `BEGIN`/`END`
* markers don't match `label` or the body is not valid base64. For the
* throwing form use {@linkcode pemDecodeOrThrow}.
*/
function pemDecode(e, t) {
	return toPemResult(() => pemDecodeOrThrow(e, t), "Invalid PEM");
}
/**
* Finds all `BEGIN`/`END`-delimited PEM blocks in a string and returns them
* as parsed {@linkcode PemBlock} entries. Handles concatenated PEM files and
* ignores non-PEM text between blocks.
*
* Returns a typed failure (`code: 'malformed'`) on stray or truncated PEM
* markers. For the throwing form use {@linkcode splitPemBlocksOrThrow}.
*/
function splitPemBlocks(e) {
	return toPemResult(() => splitPemBlocksOrThrow(e), "Malformed PEM block");
}
/**
* Groups PEM blocks by label into well-known PKI categories
* (certificates, CSRs, private keys, public keys, and everything else).
* Accepts either raw PEM text or pre-split {@linkcode PemBlock} entries.
*
* Returns a typed failure (`code: 'malformed'`) when raw text contains stray
* or truncated PEM markers. For the throwing form use
* {@linkcode categorizePemBlocksOrThrow}.
*/
function categorizePemBlocks(e) {
	return toPemResult(() => categorizePemBlocksOrThrow(e), "Malformed PEM block");
}
/** Shared Result wrapper around the throwing PEM cores. */
function toPemResult(r, i) {
	try {
		return successResult(r());
	} catch (n) {
		return rethrowIfInvariant(n), failureResult("malformed", n instanceof Error ? n.message : i);
	}
}
export { pemDecodeOrThrow as a, splitPemBlocksOrThrow as c, base64Encode as d, pemDecode as i, trimLwsp as l, categorizePemBlocksOrThrow as n, pemEncode as o, parseTraditionalPemOrThrow as r, splitPemBlocks as s, categorizePemBlocks as t, base64Decode as u };
