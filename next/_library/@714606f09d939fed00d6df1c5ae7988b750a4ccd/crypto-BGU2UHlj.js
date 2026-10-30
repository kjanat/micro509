import { nt as i, tt as decodeRefusalOf } from "./asn1-jyOu_Jva.js";
import { a as derEcdsaSignatureToRaw, n as getSignatureAlgorithm, o as rawEcdsaSignatureToDer, r as signBytes } from "./signing-Cr_Ky8wY.js";
import { n as verifySignedDataDetailed, r as verifySignedDataWithKeyDetailed } from "./sig-verify-CACCuq-Z.js";
// ../../dist/crypto/crypto.js
/**
* Detached-signature primitives: verify a signature against a signer's SPKI or CryptoKey,
* sign arbitrary bytes with a WebCrypto private key, and convert ECDSA
* signatures between DER `ECDSA-Sig-Value` and fixed-width raw encodings.
*
* @module
*/
/**
* Verifies a detached signature using an existing WebCrypto public key without
* exporting or importing it. Repeated calls may reuse non-extractable keys.
* Signature algorithms and parameters follow {@linkcode verifySignature}; RSA
* scheme and hash must match the key. ECDSA encoding is explicit and never retried.
* Returns the same validity, unsupported-parameter, operational-error and decoding-limit
* branches as {@linkcode verifySignature}.
*/
async function verifySignatureWithKey(n) {
	try {
		return await verifySignedDataWithKeyDetailed(n.publicKey, n.signatureAlgorithm.oid, n.signatureAlgorithm.parametersDer, n.signature, n.data, n.signatureEncoding);
	} catch (n) {
		let r = decodeRefusalOf(n, i);
		if (r === void 0) throw n;
		return {
			ok: !1,
			code: r.code,
			reason: r.message
		};
	}
}
/**
* Verifies a detached signature against the signer's DER `SubjectPublicKeyInfo`.
*
* Supports RSA PKCS#1 v1.5 (SHA-256/384/512), RSA-PSS with parsed parameters,
* ECDSA P-256/P-384/P-521, and Ed25519. When an ECDSA signature fails to
* verify under one encoding, the alternate DER/raw encoding is retried.
*
* Returns a typed union: `{ ok: true, valid }` when verification ran,
* `unsupported_signature_algorithm_parameters`, `verification_error` or
* `limit_exceeded` failures otherwise.
*/
async function verifySignature(n) {
	try {
		return await verifySignedDataDetailed(n.signatureAlgorithm.oid, n.signatureAlgorithm.parametersDer, n.publicKeyAlgorithm.oid, n.publicKeyAlgorithm.parametersOid, n.signerSpkiDer, n.signature, n.data);
	} catch (n) {
		let r = decodeRefusalOf(n, i);
		if (r === void 0) throw n;
		return {
			ok: !1,
			code: r.code,
			reason: r.message
		};
	}
}
/**
* Signs `data` with a WebCrypto private key and returns the signature beside
* the resolved `AlgorithmIdentifier` material for embedding in a signed
* structure.
*
* The algorithm is inferred from the key (RSASSA-PKCS1-v1_5, ECDSA, Ed25519);
* RSA-PSS keys require an explicit `{ kind: 'rsa-pss' }` profile. ECDSA
* signatures are returned DER-encoded. Throws on unsupported key algorithms.
*/
async function signData(e, t, n) {
	let r = getSignatureAlgorithm(e, n), i = await signBytes(e, r, t);
	return r.parameters === void 0 ? {
		signature: i,
		algorithmOid: r.algorithmOid
	} : {
		signature: i,
		algorithmOid: r.algorithmOid,
		parametersDer: r.parameters
	};
}
/**
* Converts a DER `ECDSA-Sig-Value` (RFC 5480: SEQUENCE of INTEGERs r and s)
* to the fixed-width raw `r || s` encoding WebCrypto and JOSE use.
* Throws on malformed DER or integers too large for the curve.
*/
function ecdsaSignatureDerToRaw(e, t) {
	return derEcdsaSignatureToRaw(e, ecdsaPartLength(t));
}
/**
* Converts a fixed-width raw `r || s` ECDSA signature to the DER
* `ECDSA-Sig-Value` encoding X.509 and CMS structures embed.
* Throws when the input length does not match the curve.
*/
function ecdsaSignatureRawToDer(e, t) {
	return rawEcdsaSignatureToDer(e, ecdsaPartLength(t));
}
/** Byte width of one ECDSA signature integer for the given curve. */
function ecdsaPartLength(e) {
	switch (e) {
		case "P-256": return 32;
		case "P-384": return 48;
		case "P-521": return 66;
		default: throw Error(`Unhandled EcNamedCurve: ${String(e)}`);
	}
}
export { verifySignatureWithKey as a, verifySignature as i, ecdsaSignatureRawToDer as n, signData as r, ecdsaSignatureDerToRaw as t };
