import { D as explicitContext, F as integerFromNumber, G as sequence, I as nullValue, L as objectIdentifier, P as integer, U as readRootElement, W as readSequenceChildren, _ as requireElement, l as decodeNonNegativeIntegerNumber, nt as i, r as childrenOf, rt as rethrowDecodeRefusal, u as decodeObjectIdentifier } from "./asn1-jyOu_Jva.js";
import { mt as t, pt as getCrypto } from "./keys-BmJSvvnO.js";
// ../../dist/internal/crypto/rsa-pss.js
/** Return the canonical {@linkcode RsaPssParameters} profile for a given hash algorithm. */
function rsaPssParametersForHash(e) {
	switch (e) {
		case "SHA-256": return {
			hash: "SHA-256",
			mgfHash: "SHA-256",
			saltLength: 32,
			trailerField: 1
		};
		case "SHA-384": return {
			hash: "SHA-384",
			mgfHash: "SHA-384",
			saltLength: 48,
			trailerField: 1
		};
		case "SHA-512": return {
			hash: "SHA-512",
			mgfHash: "SHA-512",
			saltLength: 64,
			trailerField: 1
		};
		default: throw Error(`Unhandled RsaPssHash: ${String(e)}`);
	}
}
/** DER-encode an {@linkcode RsaPssParameters} profile as an ASN.1 RSASSA-PSS-params SEQUENCE. */
function encodeRsaPssParameters(e) {
	let t$3 = hashOidForName(e.hash), i = encodeHashAlgorithmIdentifier(t$3);
	return sequence([
		explicitContext(0, i),
		explicitContext(1, sequence([objectIdentifier(t.mgf1), encodeHashAlgorithmIdentifier(t$3)])),
		explicitContext(2, integerFromNumber(e.saltLength)),
		...e.trailerField === 1 ? [] : [explicitContext(3, integerFromNumber(e.trailerField))]
	]);
}
/**
* Parse and validate DER-encoded RSASSA-PSS-params.
*
* Returns a typed result: success with a supported profile, unsupported with
* a reason code, or malformed with an error message.
*
* @throws `limit_exceeded` on an OID sub-identifier over 64 octets.
*/
function parseRsaPssParameters(n) {
	if (n === void 0) return unsupportedResult("default_hash_sha1");
	try {
		let e = readRootElement(n, { maxDepth: 64 });
		if (e.tag !== 48) throw Error("RSA-PSS parameters must be a SEQUENCE");
		return validateRsaPssParameterProfile(parseRsaPssParameterFields(n, e));
	} catch (n) {
		return rethrowDecodeRefusal(n, i), {
			ok: !1,
			code: "malformed_rsa_pss_parameters",
			reason: n instanceof Error ? n.message : "Malformed RSA-PSS parameters"
		};
	}
}
/** Parses the optional context-specific RSA-PSS fields into their defaulted state. */
function parseRsaPssParameterFields(e, t$4) {
	let n = {
		hashOid: t.sha1,
		maskGenAlgorithm: {
			oid: t.mgf1,
			hashOid: t.sha1
		},
		saltLength: 20,
		trailerField: 1,
		sawHash: !1,
		sawMaskGen: !1,
		sawSaltLength: !1,
		sawTrailerField: !1
	};
	for (let r of childrenOf(e, t$4)) parseRsaPssParameterField(e, r, n);
	return n;
}
function parseRsaPssParameterField(e, t, n) {
	switch (t.tag) {
		case 160:
			if (n.sawHash) throw Error("RSA-PSS parameters contain duplicate hashAlgorithm");
			n.hashOid = parseHashAlgorithmIdentifier(e, requireSingleExplicitChild(e, t, "hashAlgorithm"), "hashAlgorithm"), n.sawHash = !0;
			return;
		case 161:
			if (n.sawMaskGen) throw Error("RSA-PSS parameters contain duplicate maskGenAlgorithm");
			n.maskGenAlgorithm = parseMaskGenAlgorithmIdentifier(e, requireSingleExplicitChild(e, t, "maskGenAlgorithm")), n.sawMaskGen = !0;
			return;
		case 162:
			n.saltLength = parseUniqueRsaPssIntegerField(e, t, n.sawSaltLength, "saltLength", "RSA-PSS saltLength"), n.sawSaltLength = !0;
			return;
		case 163:
			n.trailerField = parseUniqueRsaPssIntegerField(e, t, n.sawTrailerField, "trailerField", "RSA-PSS trailerField"), n.sawTrailerField = !0;
			return;
		default: throw Error(`RSA-PSS parameters contain unexpected field tag 0x${t.tag.toString(16)}`);
	}
}
function parseUniqueRsaPssIntegerField(e, t, n, r, i) {
	if (n) throw Error(`RSA-PSS parameters contain duplicate ${r}`);
	return parseExplicitInteger(e, t, r, i);
}
function validateRsaPssParameterProfile(e) {
	let t$5 = hashNameFromOid(e.hashOid);
	if (t$5 === void 0) return e.hashOid === t.sha1 ? unsupportedResult("default_hash_sha1") : unsupportedResult("unsupported_hash");
	if (e.maskGenAlgorithm.oid !== t.mgf1) return unsupportedResult("unsupported_mgf_algorithm");
	let n = hashNameFromOid(e.maskGenAlgorithm.hashOid);
	if (n === void 0) return unsupportedResult("unsupported_mgf_hash");
	if (n !== t$5) return unsupportedResult("mgf_hash_mismatch");
	let r = rsaPssParametersForHash(t$5);
	return e.saltLength === r.saltLength ? e.trailerField === 1 ? {
		ok: !0,
		value: r
	} : unsupportedResult("unsupported_trailer_field") : unsupportedResult("unsupported_salt_length");
}
/** Unwrap an explicit context tag and assert it contains exactly one child element. */
function requireSingleExplicitChild(e, t, n) {
	let r = childrenOf(e, t);
	if (r.length !== 1) throw Error(`RSA-PSS ${n} must wrap exactly one value`);
	return requireElement(r[0], `RSA-PSS ${n}`);
}
/** Extract a non-negative integer from an explicit context-tagged wrapper. */
function parseExplicitInteger(e, t, n, r) {
	let i = requireSingleExplicitChild(e, t, n);
	if (i.tag !== 2) throw Error(`RSA-PSS ${n} must be an INTEGER`);
	return decodeNonNegativeIntegerNumber(i.value, r);
}
/** Parse an AlgorithmIdentifier SEQUENCE and return the algorithm OID. */
function parseHashAlgorithmIdentifier(e, t, n) {
	if (t.tag !== 48) throw Error(`RSA-PSS ${n} must be a SEQUENCE`);
	let r = childrenOf(e, t);
	if (r.length === 0 || r.length > 2) throw Error(`Malformed RSA-PSS ${n} AlgorithmIdentifier`);
	let i = requireElement(r[0], `${n} OID`);
	if (i.tag !== 6) throw Error(`Malformed RSA-PSS ${n} AlgorithmIdentifier`);
	if (r.length === 2 && requireElement(r[1], `${n} parameters`).tag !== 5) throw Error(`RSA-PSS ${n} AlgorithmIdentifier parameters must be NULL when present`);
	return decodeObjectIdentifier(i.value);
}
/** Parse an MGF AlgorithmIdentifier SEQUENCE into OID and optional inner hash OID. */
function parseMaskGenAlgorithmIdentifier(e, t$6) {
	if (t$6.tag !== 48) throw Error("RSA-PSS maskGenAlgorithm must be a SEQUENCE");
	let n = childrenOf(e, t$6);
	if (n.length === 0 || n.length > 2) throw Error("Malformed RSA-PSS maskGenAlgorithm AlgorithmIdentifier");
	let r = requireElement(n[0], "maskGenAlgorithm OID");
	if (r.tag !== 6) throw Error("Malformed RSA-PSS maskGenAlgorithm AlgorithmIdentifier");
	let i = decodeObjectIdentifier(r.value);
	return i === t.mgf1 ? {
		oid: i,
		hashOid: parseHashAlgorithmIdentifier(e, requireElement(n[1], "maskGenAlgorithm parameters"), "MGF1 hashAlgorithm")
	} : { oid: i };
}
/** DER-encode a hash AlgorithmIdentifier as `SEQUENCE { OID, NULL }`. */
function encodeHashAlgorithmIdentifier(e) {
	return sequence([objectIdentifier(e), nullValue()]);
}
/** Map a hash algorithm name to its ASN.1 OID string. */
function hashOidForName(e) {
	switch (e) {
		case "SHA-256": return t.sha256;
		case "SHA-384": return t.sha384;
		case "SHA-512": return t.sha512;
		default: throw Error(`Unhandled RsaPssHash: ${String(e)}`);
	}
}
/** Reverse-map a hash OID to a supported {@linkcode RsaPssHash} name, or `undefined` if unsupported. */
function hashNameFromOid(e) {
	switch (e) {
		case t.sha256: return "SHA-256";
		case t.sha384: return "SHA-384";
		case t.sha512: return "SHA-512";
		default: return;
	}
}
/** Build an unsupported-parameters failure result. */
function unsupportedResult(e) {
	return {
		ok: !1,
		code: "unsupported_rsa_pss_parameters",
		reason: e
	};
}
// ../../dist/internal/crypto/ecdsa.js
/**
* ECDSA signature encoding conversion between ASN.1 DER (r, s INTEGER) and the
* fixed-width raw format used by WebCrypto.
*
* @module
*/
/** Convert a DER-encoded ECDSA signature (SEQUENCE of two INTEGERs) to fixed-width raw `r || s`. */
function derEcdsaSignatureToRaw(e, n) {
	let r = readSequenceChildren(e), i = r[0], a = r[1];
	if (i === void 0 || a === void 0 || r.length !== 2) throw Error("Malformed ECDSA DER signature");
	if (i.tag !== 2 || a.tag !== 2) throw Error("ECDSA DER signature must contain two INTEGERs");
	return concatFixedWidth(derIntegerMagnitude(i.value), derIntegerMagnitude(a.value), n);
}
/** Convert a fixed-width raw `r || s` ECDSA signature to DER-encoded SEQUENCE of two INTEGERs. */
function rawEcdsaSignatureToDer(t, r) {
	if (t.length !== r * 2) throw Error("Unexpected ECDSA raw signature length");
	return sequence([integer(t.slice(0, r)), integer(t.slice(r))]);
}
/**
* Normalize a WebCrypto ECDSA signature to DER.
*
* Spec-compliant WebCrypto always returns fixed-width raw `r || s`
* (exactly `rawSignatureBytes` long), which needs conversion. Detection is
* by length, never by sniffing the first byte: a raw signature whose `r`
* happens to start with `0x30` (1-in-256 per signature) is
* indistinguishable from DER by tag, and embedding it unconverted produces
* a certificate/CRL that OpenSSL rejects with a signature failure.
*/
function ecdsaSignatureToDer(e, t) {
	return e.length === t ? rawEcdsaSignatureToDer(e, t / 2) : e;
}
/**
* Try the opposite ECDSA encoding: DER→raw or raw→DER.
*
* Returns `undefined` if conversion fails, letting callers retry verification
* with the alternate encoding.
*/
function alternateEcdsaSignatureEncoding(e, t) {
	if (e[0] === 48) try {
		return derEcdsaSignatureToRaw(e, t);
	} catch {}
	try {
		return rawEcdsaSignatureToDer(e, t);
	} catch {
		return;
	}
}
/** Left-pad and concatenate `r` and `s` into a fixed-width `partLength * 2` byte buffer. */
function concatFixedWidth(e, t, n) {
	if (e.length > n || t.length > n) throw Error("ECDSA signature integer too large");
	let r = new Uint8Array(n * 2);
	return r.set(e, n - e.length), r.set(t, r.length - t.length), r;
}
/** Validate a non-negative DER INTEGER and return its unsigned magnitude. */
function derIntegerMagnitude(e) {
	let t = e[0];
	if (t === void 0) throw Error("ECDSA DER signature INTEGER must not be empty");
	if (t & 128) throw Error("ECDSA DER signature INTEGER must be non-negative");
	if (t === 0 && e.length > 1) {
		let t = e[1];
		if (t === void 0 || !(t & 128)) throw Error("ECDSA DER signature INTEGER must use minimal encoding");
		return e.slice(1);
	}
	return e;
}
// ../../dist/internal/crypto/signing.js
/**
* Signing helpers that map WebCrypto keys and signature profiles to on-wire
* `AlgorithmIdentifier` values. Used by certificate and CSR builders.
*
* @module
*/
/** Resolve a private key and optional profile into a {@linkcode SignatureAlgorithmIdentifier}. */
function getSignatureAlgorithm(t$1, n = {}) {
	let r = t$1.algorithm;
	if (n.kind === "rsa-pss") return getRsaPssSignatureAlgorithm(t$1, n.saltLength);
	if (r.name === "RSASSA-PKCS1-v1_5") {
		if (!hasHash(r)) throw Error("RSA key is missing hash metadata");
		switch (r.hash.name) {
			case "SHA-256": return {
				algorithmOid: t.sha256WithRSAEncryption,
				parameters: nullValue(),
				signParams: { name: "RSASSA-PKCS1-v1_5" }
			};
			case "SHA-384": return {
				algorithmOid: t.sha384WithRSAEncryption,
				parameters: nullValue(),
				signParams: { name: "RSASSA-PKCS1-v1_5" }
			};
			case "SHA-512": return {
				algorithmOid: t.sha512WithRSAEncryption,
				parameters: nullValue(),
				signParams: { name: "RSASSA-PKCS1-v1_5" }
			};
			default: throw Error(`Unsupported RSA hash: ${r.hash.name}`);
		}
	}
	if (r.name === "RSA-PSS") throw Error("RSA-PSS signing requires an explicit signature profile");
	if (r.name === "ECDSA") {
		if (!hasNamedCurve(r)) throw Error("ECDSA key is missing namedCurve metadata");
		switch (r.namedCurve) {
			case "P-256": return {
				algorithmOid: t.ecdsaWithSHA256,
				signParams: {
					name: "ECDSA",
					hash: "SHA-256"
				},
				ecdsaRawSignatureBytes: 64
			};
			case "P-384": return {
				algorithmOid: t.ecdsaWithSHA384,
				signParams: {
					name: "ECDSA",
					hash: "SHA-384"
				},
				ecdsaRawSignatureBytes: 96
			};
			case "P-521": return {
				algorithmOid: t.ecdsaWithSHA512,
				signParams: {
					name: "ECDSA",
					hash: "SHA-512"
				},
				ecdsaRawSignatureBytes: 132
			};
			default: throw Error(`Unsupported curve: ${r.namedCurve}`);
		}
	}
	if (r.name === "Ed25519") return {
		algorithmOid: t.ed25519,
		signParams: { name: "Ed25519" }
	};
	throw Error(`Unsupported signing key algorithm: ${r.name}`);
}
/** Build an RSA-PSS {@linkcode SignatureAlgorithmIdentifier} from an RSA-PSS private key. */
function getRsaPssSignatureAlgorithm(e, t$2) {
	let n = e.algorithm;
	if (n.name !== "RSA-PSS") throw Error("RSA-PSS signature profile requires an RSA-PSS private key");
	if (!hasHash(n)) throw Error("RSA-PSS key is missing hash metadata");
	let r = rsaPssHashFromWebCryptoName(n.hash.name), s = rsaPssParametersForHash(r);
	if (t$2 !== void 0 && t$2 !== s.saltLength) throw Error(`Unsupported RSA-PSS saltLength ${t$2} for ${r}; expected ${s.saltLength}`);
	return {
		algorithmOid: t.rsassaPss,
		parameters: encodeRsaPssParameters(s),
		signParams: {
			name: "RSA-PSS",
			saltLength: s.saltLength
		}
	};
}
/** DER-encode a {@linkcode SignatureAlgorithmIdentifier} as an ASN.1 `AlgorithmIdentifier` SEQUENCE. */
function encodeAlgorithmIdentifier(e) {
	let r = [objectIdentifier(e.algorithmOid)];
	return e.parameters !== void 0 && r.push(e.parameters), sequence(r);
}
/** Sign `data` and return a DER-encoded signature. ECDSA raw signatures are auto-converted to DER. */
async function signBytes(e, t, n) {
	let i = new Uint8Array(n), a = new Uint8Array(await getCrypto().subtle.sign(t.signParams, e, i));
	return t.ecdsaRawSignatureBytes === void 0 ? a : ecdsaSignatureToDer(a, t.ecdsaRawSignatureBytes);
}
/** Type guard: does this key algorithm carry a `hash` property (RSA keys). */
function hasHash(e) {
	return "hash" in e;
}
/** Type guard: does this key algorithm carry a `namedCurve` property (EC keys). */
function hasNamedCurve(e) {
	return "namedCurve" in e;
}
/** Narrow a WebCrypto hash name string to the supported {@linkcode RsaPssHash} union. */
function rsaPssHashFromWebCryptoName(e) {
	switch (e) {
		case "SHA-256": return "SHA-256";
		case "SHA-384": return "SHA-384";
		case "SHA-512": return "SHA-512";
		default: throw Error(`Unsupported RSA hash: ${e}`);
	}
}
export { derEcdsaSignatureToRaw as a, alternateEcdsaSignatureEncoding as i, getSignatureAlgorithm as n, rawEcdsaSignatureToDer as o, signBytes as r, parseRsaPssParameters as s, encodeAlgorithmIdentifier as t };
