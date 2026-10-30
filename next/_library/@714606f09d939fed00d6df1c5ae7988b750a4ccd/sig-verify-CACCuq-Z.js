import { V as readElement, nt as i, rt as rethrowDecodeRefusal, v as toArrayBuffer } from "./asn1-jyOu_Jva.js";
import { Z as importSpkiDerOrThrow, mt as t, pt as getCrypto } from "./keys-BmJSvvnO.js";
import { a as derEcdsaSignatureToRaw, i as alternateEcdsaSignatureEncoding, s as parseRsaPssParameters } from "./signing-Cr_Ky8wY.js";
// ../../dist/internal/crypto/sig-verify.js
/**
* Signature-verification helpers that resolve parsed algorithm OIDs into WebCrypto
* verification configuration for higher-level validators.
*
* @module
*/
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
* Non-throwing variant of {@linkcode verifySignedData} — returns a typed
* {@linkcode VerifySignedDataResult} instead of throwing on unsupported algorithms
* or runtime verification failures.
*
* Tries both DER and raw ECDSA encodings when the first attempt fails.
*
* @throws `limit_exceeded` on algorithm parameters or a public key that exceed
* a micro509 decoding limit.
*/
async function verifySignedDataDetailed(n, r, i$1, a, o, s, c) {
	let u = getVerifySignatureConfigResult(n, r, i$1, a);
	if (!u.ok) return u;
	try {
		return await verifyWithConfiguredKey(await importSpkiDerOrThrow(o, u.value.importAlgorithm), u.value, s, c, "auto");
	} catch (n) {
		return rethrowDecodeRefusal(n, i), verificationError(n instanceof Error ? n.message : "signature verification failed");
	}
}
/** Execute verification for imported SPKI and caller-owned keys with the same configuration. */
async function verifyWithConfiguredKey(n, o, s, l, u) {
	try {
		if (u === "der" && o.ecdsaRawSignatureBytes !== void 0) try {
			s = derEcdsaSignatureToRaw(s, o.ecdsaRawSignatureBytes / 2);
		} catch (n) {
			return rethrowDecodeRefusal(n, i), {
				ok: !0,
				valid: !1
			};
		}
		let d = getCrypto().subtle, f = toArrayBuffer(s), p = toArrayBuffer(l);
		if (await d.verify(o.verifyParams, n, f, p)) return {
			ok: !0,
			valid: !0
		};
		if (u === "auto" && o.ecdsaRawSignatureBytes !== void 0) {
			let e = alternateEcdsaSignatureEncoding(s, o.ecdsaRawSignatureBytes / 2);
			if (e !== void 0) return {
				ok: !0,
				valid: await d.verify(o.verifyParams, n, toArrayBuffer(e), p)
			};
		}
		return {
			ok: !0,
			valid: !1
		};
	} catch (n) {
		return rethrowDecodeRefusal(n, i), verificationError(n instanceof Error ? n.message : "signature verification failed");
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
function requireDerNullOrAbsentSignatureAlgorithmParameters(r, i$2) {
	if (r === void 0) return;
	let a = "signature AlgorithmIdentifier parameters must be DER NULL or absent";
	try {
		let e = readElement(r);
		return e.tag !== 5 || e.length !== 0 || e.end !== r.length ? unsupported(i$2, a) : void 0;
	} catch (n) {
		return rethrowDecodeRefusal(n, i), unsupported(i$2, a);
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
export { verifySignedDataDetailed as n, verifySignedDataWithKeyDetailed as r, getVerifySignatureConfigResult as t };
