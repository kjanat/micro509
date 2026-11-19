import { G as readSequenceChildren, H as readElement, it as rethrowDecodeRefusal, rt as i, t as canonicalizeOid, y as toArrayBuffer } from "./asn1-BRvd063X.js";
import { $ as importSpkiDerOrThrow, gt as t, mt as getCrypto } from "./keys-CBcCBjvO.js";
import { a as derEcdsaSignatureToRaw, i as alternateEcdsaSignatureEncoding, s as parseRsaPssParameters } from "./signing-fWhaMlw-.js";
// ../../dist/internal/crypto/sig-verify.js
/**
* Signature-verification helpers that resolve parsed algorithm OIDs into WebCrypto
* verification configuration for higher-level validators.
*
* @module
*/
const f = /* @__PURE__ */ new Set([
	t.sha256WithRSAEncryption,
	t.sha384WithRSAEncryption,
	t.sha512WithRSAEncryption,
	t.rsassaPss,
	t.ecdsaWithSHA256,
	t.ecdsaWithSHA384,
	t.ecdsaWithSHA512,
	t.ed25519
]);
/**
* Validates caller verifiers and indexes them by canonical OID.
*
* @throws RangeError for a key that is no encodable OID, a natively verified
* algorithm, or a value that is no function.
*/
function resolveSignatureVerifiers(e) {
	let t = /* @__PURE__ */ new Map();
	if (e === void 0) return t;
	for (let [n, r] of Object.entries(e)) {
		let e = canonicalVerifierOid(n);
		if (f.has(e)) throw RangeError(`signatureVerifiers cannot replace native verification of ${n}`);
		if (typeof r != "function") throw RangeError(`signatureVerifiers value for ${n} is not a function`);
		if (t.has(e)) throw RangeError(`signatureVerifiers names ${e} twice`);
		t.set(e, r);
	}
	return t;
}
function canonicalVerifierOid(t) {
	if (!/^\d+(?:\.\d+)+$/.test(t)) throw RangeError(`signatureVerifiers key is not an OID: ${t}`);
	try {
		return canonicalizeOid(t);
	} catch (e) {
		throw rethrowDecodeRefusal(e, i), RangeError(`signatureVerifiers key is not an OID: ${t}`);
	}
}
/** No caller verifiers: every signature goes through WebCrypto. */
const p = { verifiers: /* @__PURE__ */ new Map() };
/** Caller verification with `verifiers` and the signer's own key parameters. */
function callerVerification(e) {
	return { verifiers: resolveSignatureVerifiers(e) };
}
/** DER key parameters, or `undefined` when they are absent or NULL (RFC 5280 §6.1.4 (e)). */
function explicitParameters(e) {
	if (e !== void 0) return e.length === 2 && e[0] === 5 && e[1] === 0 ? void 0 : e;
}
/** The AlgorithmIdentifier parameters of a SubjectPublicKeyInfo; a malformed one has none. */
function spkiAlgorithmParametersDer(e) {
	try {
		let [t] = readSequenceChildren(e);
		if (t === void 0) return;
		let n = e.subarray(t.start - t.headerLength, t.end), [, r] = readSequenceChildren(n);
		return r === void 0 ? void 0 : n.subarray(r.start - r.headerLength, r.end);
	} catch (e) {
		rethrowDecodeRefusal(e, i);
		return;
	}
}
/** Non-throwing variant of {@linkcode getVerifySignatureConfig} — returns a typed result union. */
function getVerifySignatureConfigResult(e, t$1, n, r, i = "issuer") {
	switch (e) {
		case t.sha256WithRSAEncryption: {
			let e = requireDerNullOrAbsentSignatureAlgorithmParameters(t$1, "SHA-256 with RSA");
			return e === void 0 ? requireRsaPublicKey(n, "SHA-256", "pkcs1-v1_5", i) : e;
		}
		case t.sha384WithRSAEncryption: {
			let e = requireDerNullOrAbsentSignatureAlgorithmParameters(t$1, "SHA-384 with RSA");
			return e === void 0 ? requireRsaPublicKey(n, "SHA-384", "pkcs1-v1_5", i) : e;
		}
		case t.sha512WithRSAEncryption: {
			let e = requireDerNullOrAbsentSignatureAlgorithmParameters(t$1, "SHA-512 with RSA");
			return e === void 0 ? requireRsaPublicKey(n, "SHA-512", "pkcs1-v1_5", i) : e;
		}
		case t.rsassaPss: return requireRsaPssVerifyConfig(t$1, n, i);
		case t.ecdsaWithSHA256: {
			let e = requireAbsentSignatureAlgorithmParameters(t$1, "ECDSA with SHA-256");
			return e === void 0 ? requireEcPublicKey(n, r, "SHA-256", i) : e;
		}
		case t.ecdsaWithSHA384: {
			let e = requireAbsentSignatureAlgorithmParameters(t$1, "ECDSA with SHA-384");
			return e === void 0 ? requireEcPublicKey(n, r, "SHA-384", i) : e;
		}
		case t.ecdsaWithSHA512: {
			let e = requireAbsentSignatureAlgorithmParameters(t$1, "ECDSA with SHA-512");
			return e === void 0 ? requireEcPublicKey(n, r, "SHA-512", i) : e;
		}
		case t.ed25519: {
			let e = requireAbsentSignatureAlgorithmParameters(t$1, "Ed25519");
			return e === void 0 ? n === t.ed25519 ? ok({
				importAlgorithm: { kind: "ed25519" },
				verifyParams: { name: "Ed25519" }
			}) : unsupported("Ed25519", `requires Ed25519 ${i} public key`) : e;
		}
		default: return unsupported(e, "unrecognized signature algorithm OID");
	}
}
/** Validate that the public key OID is `rsaEncryption` and return an RSA verification config result. */
function requireRsaPublicKey(e, t$2, n = "pkcs1-v1_5", r = "issuer", i) {
	return e === t.rsaEncryption ? ok({
		importAlgorithm: {
			kind: "rsa",
			hash: t$2,
			scheme: n
		},
		verifyParams: n === "pss" ? {
			name: "RSA-PSS",
			saltLength: i ?? 0
		} : { name: "RSASSA-PKCS1-v1_5" }
	}) : unsupported("RSA", `requires RSA ${r} public key`);
}
/** Validate that the public key OID is `ecPublicKey`, resolve the curve, and return an ECDSA verification config result. */
function requireEcPublicKey(e, t$3, n, r = "issuer") {
	if (e !== t.ecPublicKey) return unsupported("ECDSA", `requires EC ${r} public key`);
	switch (t$3) {
		case t.prime256v1: return ok({
			importAlgorithm: {
				kind: "ecdsa",
				curve: "P-256"
			},
			verifyParams: {
				name: "ECDSA",
				hash: n
			},
			ecdsaRawSignatureBytes: 64
		});
		case t.secp384r1: return ok({
			importAlgorithm: {
				kind: "ecdsa",
				curve: "P-384"
			},
			verifyParams: {
				name: "ECDSA",
				hash: n
			},
			ecdsaRawSignatureBytes: 96
		});
		case t.secp521r1: return ok({
			importAlgorithm: {
				kind: "ecdsa",
				curve: "P-521"
			},
			verifyParams: {
				name: "ECDSA",
				hash: n
			},
			ecdsaRawSignatureBytes: 132
		});
		default: return unsupported("ECDSA", `unsupported EC curve OID: ${t$3 ?? "missing"}`);
	}
}
/**
* Verifies a signature against the signer's SPKI and the signed bytes. Returns
* a typed {@linkcode VerifySignedDataResult} for unsupported algorithms and
* runtime verification failures.
*
* Tries both DER and raw ECDSA encodings when the first attempt fails.
*
* @throws `limit_exceeded` on algorithm parameters or a public key that exceed
* a micro509 decoding limit.
*/
async function verifySignedDataDetailed(e, t, i$1, a, o, s, c, l, u = p) {
	let f = getVerifySignatureConfigResult(e, t, i$1, a);
	if (!f.ok) {
		let n = u.verifiers.get(e);
		if (n === void 0) return f;
		let r = u.workingParameters === void 0 ? explicitParameters(spkiAlgorithmParametersDer(o)) : u.workingParameters.parametersDer;
		return await runCallerVerifier(n, {
			signatureAlgorithm: {
				oid: e,
				...t === void 0 ? {} : { parametersDer: new Uint8Array(t) }
			},
			signerSpkiDer: new Uint8Array(o),
			...r === void 0 ? {} : { signerPublicKeyParametersDer: new Uint8Array(r) },
			signature: new Uint8Array(s),
			signatureUnusedBits: c,
			data: new Uint8Array(l)
		});
	}
	if (c !== 0) return {
		ok: !0,
		valid: !1
	};
	try {
		return await verifyWithConfiguredKey(await importSpkiDerOrThrow(o, f.value.importAlgorithm), f.value, s, l, "auto");
	} catch (e) {
		return rethrowDecodeRefusal(e, i), verificationError(e instanceof Error ? e.message : "signature verification failed");
	}
}
async function runCallerVerifier(e, t) {
	try {
		return {
			ok: !0,
			valid: await e(t) === !0
		};
	} catch (e) {
		return verificationError(e instanceof Error ? `signature verifier failed: ${e.message}` : "signature verifier failed");
	}
}
/** Execute verification for imported SPKI and caller-owned keys with the same configuration. */
async function verifyWithConfiguredKey(e, i$2, a, o, l) {
	try {
		if (l === "der" && i$2.ecdsaRawSignatureBytes !== void 0) try {
			a = derEcdsaSignatureToRaw(a, i$2.ecdsaRawSignatureBytes / 2);
		} catch (e) {
			return rethrowDecodeRefusal(e, i), {
				ok: !0,
				valid: !1
			};
		}
		let d = getCrypto().subtle, f = toArrayBuffer(a), p = toArrayBuffer(o);
		if (await d.verify(i$2.verifyParams, e, f, p)) return {
			ok: !0,
			valid: !0
		};
		if (l === "auto" && i$2.ecdsaRawSignatureBytes !== void 0) {
			let n = alternateEcdsaSignatureEncoding(a, i$2.ecdsaRawSignatureBytes / 2);
			if (n !== void 0) return {
				ok: !0,
				valid: await d.verify(i$2.verifyParams, e, toArrayBuffer(n), p)
			};
		}
		return {
			ok: !0,
			valid: !1
		};
	} catch (e) {
		return rethrowDecodeRefusal(e, i), verificationError(e instanceof Error ? e.message : "signature verification failed");
	}
}
/** Resolve a caller-owned key without exporting it, then run the shared verifier. */
async function verifySignedDataWithKeyDetailed(e, t$4, n, r, i, a) {
	if (e.type !== "public" || !e.usages.includes("verify")) return verificationError("Signature verification requires a public key with verify usage");
	let s = e.algorithm, c, l;
	switch (s.name) {
		case "RSASSA-PKCS1-v1_5":
		case "RSA-PSS":
			c = t.rsaEncryption;
			break;
		case "ECDSA":
			if (c = t.ecPublicKey, "namedCurve" in s) switch (s.namedCurve) {
				case "P-256":
					l = t.prime256v1;
					break;
				case "P-384":
					l = t.secp384r1;
					break;
				case "P-521": l = t.secp521r1;
			}
			break;
		case "Ed25519":
			c = t.ed25519;
			break;
		default: return unsupported(s.name, "unsupported public key algorithm");
	}
	let u = getVerifySignatureConfigResult(t$4, n, c, l);
	return u.ok ? a !== "raw" && a !== "der" ? unsupported(t$4, "signature encoding must be raw or der") : a === "der" && u.value.ecdsaRawSignatureBytes === void 0 ? unsupported(t$4, "DER signature encoding requires ECDSA") : s.name === u.value.verifyParams.name ? u.value.importAlgorithm.kind === "rsa" && (!("hash" in s) || typeof s.hash != "object" || s.hash === null || !("name" in s.hash) || s.hash.name !== u.value.importAlgorithm.hash) ? unsupported(t$4, "signature hash does not match the RSA public key") : await verifyWithConfiguredKey(e, u.value, r, i, a) : unsupported(t$4, "signature scheme does not match the public key") : u;
}
/** Parse RSA-PSS algorithm parameters and build a verification config, or return failure. */
function requireRsaPssVerifyConfig(e, t, n) {
	let r = parseRsaPssParameters(e);
	return r.ok ? requireRsaPublicKey(t, r.value.hash, "pss", n, r.value.saltLength) : unsupported("RSA-PSS", r.reason);
}
/** RFC 4055 §5 requires generators to encode NULL and implementations to accept absent parameters too. */
function requireDerNullOrAbsentSignatureAlgorithmParameters(e, t) {
	if (e === void 0) return;
	let a = "signature AlgorithmIdentifier parameters must be DER NULL or absent";
	try {
		let n = readElement(e);
		return n.tag !== 5 || n.length !== 0 || n.end !== e.length ? unsupported(t, a) : void 0;
	} catch (e) {
		return rethrowDecodeRefusal(e, i), unsupported(t, a);
	}
}
function requireAbsentSignatureAlgorithmParameters(e, t) {
	if (e !== void 0) return unsupported(t, "signature AlgorithmIdentifier parameters must be absent");
}
/** Wrap a config in a success result. */
function ok(e) {
	return {
		ok: !0,
		value: e
	};
}
/** Build an unsupported-algorithm failure result. */
function unsupported(e, t) {
	return {
		ok: !1,
		code: "unsupported_signature_algorithm_parameters",
		reason: `${e} parameters unsupported: ${t}`
	};
}
function verificationError(e) {
	return {
		ok: !1,
		code: "verification_error",
		reason: e
	};
}
export { resolveSignatureVerifiers as a, verifySignedDataWithKeyDetailed as c, p as i, explicitParameters as n, spkiAlgorithmParametersDer as o, getVerifySignatureConfigResult as r, verifySignedDataDetailed as s, callerVerification as t };
