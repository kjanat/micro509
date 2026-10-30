import { c as rethrowIfInvariant, i as indexedMicro509Error, l as successResult, n as failureResult, o as micro509Error, r as indexedErrorResult, s as n, t as errorResult, u as throwMicro509Error } from "./result-C9WPk47A.js";
import { a as pemDecodeOrThrow, d as base64Encode, o as pemEncode } from "./pem-C5BecCKu.js";
import { D as explicitContext, E as enumeratedFromNumber, F as integerFromNumber, G as sequence, I as nullValue, J as time, L as objectIdentifier, M as implicitConstructedContext, N as implicitPrimitiveContext, O as generalizedTime, P as integer, R as octetString, U as readRootElement, V as readElement, W as readSequenceChildren, Y as tlv, _ as requireElement, a as decodeBoolean, c as decodeNonNegativeIntegerBigInt, d as decodeString, et as decodeFailureResult, g as parseTime, l as decodeNonNegativeIntegerNumber, m as hexToBytes, nt as i, o as decodeIntegerMagnitude, p as extractBitStringValue, r as childrenOf, rt as rethrowDecodeRefusal, s as decodeIntegerNumber, t as canonicalizeOid, tt as decodeRefusalOf, u as decodeObjectIdentifier, v as toArrayBuffer, w as concatBytes, x as bitString, y as toHex, z as optionalBytesEqual } from "./asn1-jyOu_Jva.js";
import { mt as t, pt as getCrypto } from "./keys-BmJSvvnO.js";
import { $ as issuerKeyIdentifier, At as compareDistinguishedNames, C as parseCertificateSigningRequestDerOrThrow, Dt as describeHashAlgorithm, E as parseCertificatesFromSource, Et as parseDistributionPointReasonFlagsContent, H as encodeCrlDistributionPoints, Mt as directoryNameSubtreeMatch, Ot as describeSignatureAlgorithm, St as decodeIpAddress, T as parseCertificateSigningRequestPemOrThrow, Tt as encodeDistributionPointReasonFlagsContent, W as encodeExtension, X as encodeSubjectAltName, _ as parseCertificateDerOrThrow, _t as nameFieldKeyFromOid, at as normalizeLabelSeparators, bt as parseGeneralNames, ct as parseUriNameConstraint, dt as isMailboxDomain, ft as presentedSmtpUtf8MailboxDomain, g as parseCertificateDer, gt as referenceDomainToAscii, ht as presentedDomainToAscii, it as isNameInputEmpty, jt as compareRelativeDistinguishedNames, kt as canonicalDnKey, lt as hostportHost, mt as domainToAscii, nt as encodeName, ot as parsePresentedSrvName, pt as asciiLowercase$1, rt as encodeRelativeDistinguishedName, st as parseSrvNameRestriction, ut as uriAuthorityHost, v as parseCertificateFromSource, wt as parseIpAddressToBytes, xt as allOnesMaskForIpAddress, yt as parseGeneralName } from "./parse-JoeMiwMh.js";
import { n as getSignatureAlgorithm, r as signBytes, t as encodeAlgorithmIdentifier } from "./signing-Cr_Ky8wY.js";
import { n as verifySignedDataDetailed, t as getVerifySignatureConfigResult } from "./sig-verify-CACCuq-Z.js";
// ../../dist/revocation/crl.js
/**
* Full CRL lifecycle: create, parse, verify, validate, and revocation check.
*
* Supports complete and delta CRLs, issuing distribution point scoping,
* indirect CRL processing, per-entry reason codes, and invalidity dates.
*
* @module
*/
/** RFC 5280 §5.3.1 CRLReason integer codes, keyed by reason name. */
const le = {
	unspecified: 0,
	keyCompromise: 1,
	cACompromise: 2,
	affiliationChanged: 3,
	superseded: 4,
	cessationOfOperation: 5,
	certificateHold: 6,
	removeFromCRL: 8,
	privilegeWithdrawn: 9,
	aACompromise: 10
};
const Q = Object.freeze([
	"keyCompromise",
	"cACompromise",
	"affiliationChanged",
	"superseded",
	"cessationOfOperation",
	"certificateHold",
	"privilegeWithdrawn",
	"aACompromise"
]);
/** True when `reasons` covers every RFC 5280 §4.2.1.13 reason — a complete-scope CRL verdict. */
function coversAllDistributionPointReasons(e) {
	let t = e instanceof Set ? e : new Set(e);
	return Q.every((e) => t.has(e));
}
/**
* Signs and encodes an X.509 v2 CRL.
*
* Always embeds the Authority Key Identifier and CRLNumber extensions
* (RFC 5280 §5.2), plus delta CRL indicator, issuing distribution point and
* freshest-CRL extensions as configured.
*
* @example
* ```ts
* import { createCertificateRevocationList } from 'micro509';
*
* const crl = await createCertificateRevocationList({
*   issuer: { commonName: 'Example CA' },
*   signerPrivateKey: caPrivateKey,
*   issuerCertificate: caCertificatePem,
*   thisUpdate: new Date('2025-01-01'),
*   nextUpdate: new Date('2025-02-01'),
*   crlNumber: 42,
*   revokedCertificates: [
*     { serialNumber: revokedSerial, reasonCode: 'keyCompromise' },
*   ],
* });
* // crl.pem, crl.der, crl.base64
* ```
*/
async function createCertificateRevocationList(e) {
	isNameInputEmpty(e.issuer) && throwCrlEncoderError("issuer_distinguished_name_empty", "issuer must be a non-empty distinguished name");
	let t = issuerCertificateOf(e.issuerCertificate), n = encodeCrlNumber(e.crlNumber, "crlNumber"), r = e.baseCrlNumber === void 0 ? void 0 : encodeCrlNumber(e.baseCrlNumber, "baseCrlNumber"), i = getSignatureAlgorithm(e.signerPrivateKey), a = e.thisUpdate ?? /* @__PURE__ */ new Date(), o = e.nextUpdate;
	assertCrlDate(a, "thisUpdate"), assertCrlDate(o, "nextUpdate");
	for (let t of e.revokedCertificates ?? []) assertCrlDate(t.revocationDate, "revocationDate"), assertCrlDate(t.invalidityDate, "invalidityDate");
	Math.floor(o.getTime() / 1e3) <= Math.floor(a.getTime() / 1e3) && throwCrlEncoderError("next_update_not_after_this_update", "nextUpdate must be at least one second later than thisUpdate");
	let s = buildCrlExtensions(t, n, r, e.issuingDistributionPoint, e.freshestCrlDistributionPoints), l = e.revokedCertificates ?? [], d = l.length === 0 ? [] : [sequence(l.map((e) => createRevokedCertificate(e, a)))], f = sequence([
		integerFromNumber(1),
		encodeAlgorithmIdentifier(i),
		encodeName(e.issuer),
		time(a),
		time(o),
		...d,
		explicitContext(0, sequence(s))
	]), p = await signBytes(e.signerPrivateKey, i, f), m = sequence([
		f,
		encodeAlgorithmIdentifier(i),
		bitString(p)
	]);
	return {
		der: m,
		pem: pemEncode("X509 CRL", m),
		base64: base64Encode(m)
	};
}
/**
* Throwing core for {@linkcode parseCertificateRevocationListDer}.
*
* Does not verify the signature — call {@linkcode verifyCertificateRevocationListSignature} or
* {@linkcode validateCertificateRevocationList} for that.
*/
function parseCertificateRevocationListDerOrThrow(e) {
	let t = readSequenceChildren(e, { maxDepth: 64 });
	if (t.length !== 3) throw Error("Malformed CRL");
	let n = requireElement(t[0], "TBSCertList"), r = requireElement(t[1], "signatureAlgorithm"), i = requireElement(t[2], "signatureValue"), a = parseSignedCrlFields(e.slice(n.start - n.headerLength, n.end)), o = parseAlgorithmIdentifier(e, r);
	return assertMatchingCrlSignatureAlgorithms(a.signature, o), {
		der: new Uint8Array(e),
		version: a.version,
		tbsCertListDer: e.slice(n.start - n.headerLength, n.end),
		signatureValue: extractBitStringValue(i),
		issuer: a.issuer,
		thisUpdate: a.thisUpdate,
		...a.nextUpdate === void 0 ? {} : { nextUpdate: a.nextUpdate },
		signatureAlgorithmOid: o.oid,
		signatureAlgorithmName: describeSignatureAlgorithm(o.oid, o.parametersDer),
		...o.parametersDer === void 0 ? {} : { signatureAlgorithmParametersDer: o.parametersDer },
		...a.authorityKeyIdentifier === void 0 ? {} : { authorityKeyIdentifier: a.authorityKeyIdentifier },
		...a.crlNumber === void 0 ? {} : { crlNumber: a.crlNumber },
		...a.baseCrlNumber === void 0 ? {} : { baseCrlNumber: a.baseCrlNumber },
		...a.issuingDistributionPoint === void 0 ? {} : { issuingDistributionPoint: a.issuingDistributionPoint },
		...a.freshestCrlDistributionPoints === void 0 ? {} : { freshestCrlDistributionPoints: a.freshestCrlDistributionPoints },
		revokedCertificates: a.revokedCertificates
	};
}
/**
* Decodes a PEM-encoded X.509 CRL (`-----BEGIN X509 CRL-----`).
*
* @example
* ```ts
* import { parseCertificateRevocationListPemOrThrow } from 'micro509';
*
* const crl = parseCertificateRevocationListPemOrThrow(pemString); // throws if malformed
* console.log(crl.issuer.values.commonName, crl.revokedCertificates.length);
* ```
*/
function parseCertificateRevocationListPemOrThrow(e) {
	return parseCertificateRevocationListDerOrThrow(pemDecodeOrThrow("X509 CRL", e));
}
/**
* Decodes a DER-encoded X.509 CRL into a structured {@linkcode ParsedCertificateRevocationList}.
*
* Returns a typed failure (`code: 'malformed'`) on malformed input. For the
* throwing form use {@linkcode parseCertificateRevocationListDerOrThrow}.
* Does not verify the signature — call {@linkcode verifyCertificateRevocationListSignature} or
* {@linkcode validateCertificateRevocationList} for that.
*/
function parseCertificateRevocationListDer(t) {
	try {
		return successResult(parseCertificateRevocationListDerOrThrow(t));
	} catch (t) {
		return rethrowIfInvariant(t), decodeFailureResult(t, n, "Malformed CRL");
	}
}
/**
* Decodes a PEM-encoded X.509 CRL (`-----BEGIN X509 CRL-----`).
*
* Returns a typed failure (`code: 'malformed'`) on malformed input. For the
* throwing form use {@linkcode parseCertificateRevocationListPemOrThrow}.
*/
function parseCertificateRevocationListPem(t) {
	try {
		return successResult(parseCertificateRevocationListPemOrThrow(t));
	} catch (t) {
		return rethrowIfInvariant(t), decodeFailureResult(t, n, "Malformed CRL");
	}
}
/**
* Verifies the CRL signature against the issuer certificate's public key.
*
* Does **not** check issuer name match, key-usage, or freshness — use
* {@linkcode validateCertificateRevocationList} for full validation.
*/
async function verifyCertificateRevocationListSignature(t, n$25) {
	let r, i;
	try {
		r = typeof t == "string" ? parseCertificateRevocationListPemOrThrow(t) : parseCertificateRevocationListDerOrThrow(new Uint8Array(t)), i = typeof n$25 == "string" ? parseIssuerCertificatePem(n$25) : parseIssuerCertificateDer(new Uint8Array(n$25));
	} catch (t) {
		let n$24 = decodeRefusalOf(t, n);
		return n$24 === void 0 ? verifyCertificateRevocationListFailureResult("signature_invalid", "certificate revocation list or issuer certificate input is malformed") : verifyCertificateRevocationListFailureResult(n$24.code, n$24.message);
	}
	let a;
	try {
		a = await verifySignedDataDetailed(r.signatureAlgorithmOid, r.signatureAlgorithmParametersDer, i.publicKeyAlgorithmOid, i.publicKeyParametersOid, i.subjectPublicKeyInfoDer, r.signatureValue, r.tbsCertListDer);
	} catch (t) {
		let n$26 = decodeRefusalOf(t, n);
		return n$26 === void 0 ? verifyCertificateRevocationListFailureResult("signature_invalid", "certificate revocation list signature verification failed") : verifyCertificateRevocationListFailureResult(n$26.code, n$26.message);
	}
	return a.ok ? a.valid ? {
		ok: !0,
		value: r
	} : verifyCertificateRevocationListFailureResult("signature_invalid", "certificate revocation list signature does not verify") : a.code === "verification_error" ? verifyCertificateRevocationListFailureResult("signature_invalid", "certificate revocation list signature verification failed") : verifyCertificateRevocationListFailureResult("signature_invalid", "certificate revocation list signature uses unsupported algorithm parameters");
}
/**
* Full CRL validation: issuer name match, authority key identifier match,
* a v3 issuer certificate's key usage must be present and assert cRLSign
* (RFC 10007 §4), signature verification, `thisUpdate`/`nextUpdate`
* freshness check (with optional clock-skew tolerance), and the optional
* `maxAgeMs` bound on `thisUpdate`. A CRL that omits `nextUpdate` fails with
* `stale_crl` unless `maxAgeMs` is set.
*/
async function validateCertificateRevocationList(e) {
	assertCrlMaxAge(e.maxAgeMs);
	let t = await authenticateCrl(e.crl, e.issuerCertificate);
	if (!t.ok) return t;
	let n = crlFreshnessFailure(t.value, e.at ?? /* @__PURE__ */ new Date(), e.clockSkewMs ?? 0, e.maxAgeMs);
	return n === void 0 ? t : validateCertificateRevocationListFailureResult("stale_crl", n);
}
/**
* Verifies the issuer binding, cRLSign permission and signature of `crl`
* against `issuerCertificate`, without freshness checks.
*
* @internal
*/
async function authenticateCrl(t, n$28) {
	let r;
	try {
		r = normalizeCrl(t);
	} catch (t) {
		let n$27 = decodeRefusalOf(t, n);
		return n$27 === void 0 ? validateCertificateRevocationListFailureResult("signature_invalid", "certificate revocation list signed content is malformed") : validateCertificateRevocationListFailureResult(n$27.code, n$27.message);
	}
	let i;
	try {
		i = normalizeCrlCertificate(n$28);
	} catch (t) {
		let n$29 = decodeRefusalOf(t, n);
		return n$29 === void 0 ? validateCertificateRevocationListFailureResult("signature_invalid", "issuer certificate input is malformed") : validateCertificateRevocationListFailureResult(n$29.code, n$29.message);
	}
	if (!compareDistinguishedNames(r.issuer, i.subject)) return validateCertificateRevocationListFailureResult("issuer_mismatch", "CRL issuer name does not match certificate subject");
	if (r.authorityKeyIdentifier !== void 0 && i.subjectKeyIdentifier !== void 0 && r.authorityKeyIdentifier !== i.subjectKeyIdentifier) return validateCertificateRevocationListFailureResult("issuer_mismatch", "CRL authority key identifier does not match issuer subject key identifier");
	if (i.keyUsage === void 0 && i.version === 3) return validateCertificateRevocationListFailureResult("crl_sign_not_permitted", "v3 issuer certificate has no key usage extension");
	if (i.keyUsage !== void 0 && !i.keyUsage.flags.includes("cRLSign")) return validateCertificateRevocationListFailureResult("crl_sign_not_permitted", "issuer certificate key usage does not permit CRL signing");
	let a;
	try {
		a = await verifySignedDataDetailed(r.signatureAlgorithmOid, r.signatureAlgorithmParametersDer, i.publicKeyAlgorithmOid, i.publicKeyParametersOid, i.subjectPublicKeyInfoDer, r.signatureValue, r.tbsCertListDer);
	} catch (t) {
		let n$30 = decodeRefusalOf(t, n);
		return n$30 === void 0 ? validateCertificateRevocationListFailureResult("signature_invalid", "certificate revocation list signature verification failed") : validateCertificateRevocationListFailureResult(n$30.code, n$30.message);
	}
	return a.ok ? a.valid ? {
		ok: !0,
		value: r
	} : validateCertificateRevocationListFailureResult("signature_invalid", "certificate revocation list signature does not verify") : a.code === "verification_error" ? validateCertificateRevocationListFailureResult("signature_invalid", "certificate revocation list signature verification failed") : validateCertificateRevocationListFailureResult("signature_invalid", "certificate revocation list signature uses unsupported algorithm parameters");
}
function assertCrlMaxAge(e) {
	if (e !== void 0 && (!Number.isFinite(e) || e < 0)) throw RangeError(`Invalid maxAgeMs: must be a non-negative number, got ${e}`);
}
function crlFreshnessFailure(e, t, n, r) {
	if (e.thisUpdate.getTime() - n > t.getTime() || e.nextUpdate !== void 0 && e.nextUpdate.getTime() + n < t.getTime()) return "CRL is not valid at requested time";
	if (e.nextUpdate === void 0 && r === void 0) return "CRL has no nextUpdate and no maximum age is set";
	if (r !== void 0 && t.getTime() - e.thisUpdate.getTime() > r + n) return "CRL thisUpdate is older than the maximum age";
}
function isCurrentDeltaCrl(e, t, n, r) {
	return e.nextUpdate !== void 0 && crlFreshnessFailure(e, t, n, r) === void 0;
}
/**
* End-to-end revocation check: validates the CRL (and optional delta CRL),
* verifies applicability via distribution-point and scope matching, then
* resolves the certificate's revocation status.
*
* Returns `good` if the serial is absent, `revoked` with date/reason if present,
* or an error if the CRL cannot be validated or is non-applicable.
*
* @example
* ```ts
* import { checkCertificateRevocationAgainstCrl } from 'micro509';
*
* const result = await checkCertificateRevocationAgainstCrl({
*   certificate: leafPem,
*   issuerCertificate: caPem,
*   crl: crlPem,
* });
* if (result.ok && result.value.status === 'revoked') {
*   console.log('revoked on', result.value.revocationDate);
* }
* ```
*/
async function checkCertificateRevocationAgainstCrl(t) {
	assertCrlMaxAge(t.maxAgeMs);
	let n$32;
	try {
		n$32 = normalizeCrlCertificate(t.certificate);
	} catch (t) {
		let n$31 = decodeRefusalOf(t, n);
		return n$31 === void 0 ? checkCertificateRevocationAgainstCrlFailureResult("non_applicable", "certificate input is malformed") : checkCertificateRevocationAgainstCrlFailureResult(n$31.code, n$31.message);
	}
	let r = await authenticateCrl(t.crl, t.issuerCertificate);
	if (!r.ok) return checkCertificateRevocationAgainstCrlFailureResult(r.code, r.message);
	let i = await checkRevocationAgainstAuthenticatedCrl(n$32, r.value, t);
	return i.kind === "checked" ? i.result : i.failure;
}
/**
* Checks `certificate` against a complete CRL that {@linkcode authenticateCrl}
* accepted for `input.issuerCertificate`, updated by `input.deltaCrl` when given.
*
* @internal
*/
async function checkRevocationAgainstAuthenticatedCrl(e, t, n) {
	if (n.deltaCrl === void 0) {
		let e = crlFreshnessFailure(t, n.at ?? /* @__PURE__ */ new Date(), n.clockSkewMs ?? 0, n.maxAgeMs);
		if (e !== void 0) return {
			kind: "checked",
			result: checkCertificateRevocationAgainstCrlFailureResult("stale_crl", e)
		};
	}
	let r = await validateOptionalDeltaCrl(n, t);
	if (!r.ok) return {
		kind: "delta_rejected",
		failure: r
	};
	let i = r.value, a = checkCrlApplicability(e, t);
	if (!a.ok) return {
		kind: "checked",
		result: a.failure
	};
	if (i !== void 0) {
		let t = checkCrlApplicability(e, i, !0);
		if (!t.ok) return {
			kind: "delta_rejected",
			failure: t.failure
		};
	}
	let o = findRevokedCertificateEntry(e, t);
	if (!o.ok) return {
		kind: "checked",
		result: o
	};
	let s;
	if (i !== void 0) {
		let r = findRevokedCertificateEntry(e, i);
		if (!r.ok) return {
			kind: "delta_unresolved",
			failure: r,
			complete: resolveCertificateRevocationStatus(e, void 0, t, o.entry, void 0, a.coveredReasons, n.unrecognizedReasonCode ?? "revoked")
		};
		s = r.entry;
	}
	return {
		kind: "checked",
		result: resolveCertificateRevocationStatus(e, i?.thisUpdate, t, o.entry, s, a.coveredReasons, n.unrecognizedReasonCode ?? "revoked")
	};
}
/** RFC 5280 §6.3.3 (d): interim_reasons_mask from the matched DP and the CRL's IDP. */
function interimReasonsMask(e, t) {
	let n = e?.reasons?.flags, r = t?.onlySomeReasons?.flags;
	return n !== void 0 && r !== void 0 ? n.filter((e) => r.includes(e)) : n === void 0 ? r === void 0 ? Q : [...r] : [...n];
}
/** Validates an optional delta CRL and checks compatibility with its complete CRL. */
async function validateOptionalDeltaCrl(e, t) {
	if (e.deltaCrl === void 0) return { ok: !0 };
	let n = await validateCertificateRevocationList({
		crl: e.deltaCrl,
		issuerCertificate: e.issuerCertificate,
		...e.at === void 0 ? {} : { at: e.at },
		...e.clockSkewMs === void 0 ? {} : { clockSkewMs: e.clockSkewMs },
		...e.maxAgeMs === void 0 ? {} : { maxAgeMs: e.maxAgeMs }
	});
	if (!n.ok) return checkCertificateRevocationAgainstCrlFailureResult(n.code, n.message);
	if (n.value.nextUpdate === void 0) return checkCertificateRevocationAgainstCrlFailureResult("stale_crl", "delta CRL has no nextUpdate");
	let r;
	try {
		r = checkDeltaCrlCompatibility(t, n.value);
	} catch (e) {
		return crlNameRefusalFailure(e);
	}
	return r ?? {
		ok: !0,
		value: n.value
	};
}
/** Builds a `VerifyCertificateRevocationListSignatureFailureResult`. */
function verifyCertificateRevocationListFailureResult(e, n) {
	return failureResult(e, n);
}
/** Builds a `ValidateCertificateRevocationListFailureResult`. */
function validateCertificateRevocationListFailureResult(e, n) {
	return failureResult(e, n);
}
/** Builds a `CheckCertificateRevocationAgainstCrlFailureResult`. */
function checkCertificateRevocationAgainstCrlFailureResult(e, n, r) {
	return failureResult(e, n, r);
}
/** Wraps a success value into a `CheckCertificateRevocationAgainstCrlResult`. */
function checkCertificateRevocationAgainstCrlSuccess(e) {
	return {
		ok: !0,
		value: e
	};
}
/**
* Quick serial-number lookup — returns `true` if the serial appears in the
* CRL's revoked entries. Does **not** validate the CRL or check applicability.
*/
function isCertificateRevoked(e, t) {
	let n = typeof e == "string" ? normalizeHex$2(e) : toHex(e);
	return t.revokedCertificates.some((e) => normalizeHex$2(e.serialNumberHex) === n);
}
/** Searches CRL entries for the certificate's serial, respecting indirect-CRL issuer overrides. */
function findRevokedCertificateEntry(e, t) {
	try {
		return lookupRevokedCertificateEntry(e, t);
	} catch (e) {
		return crlNameRefusalFailure(e);
	}
}
function lookupRevokedCertificateEntry(e, t) {
	let n = normalizeHex$2(e.serialNumberHex), r, i = !1, a;
	for (let o of t.revokedCertificates) {
		if (o.certificateIssuer !== void 0 && (r = o.certificateIssuer), normalizeHex$2(o.serialNumberHex) !== n) continue;
		let s = matchesRevokedEntryIssuer(e, t, r);
		if (s === "match") {
			if (a !== void 0) return checkCertificateRevocationAgainstCrlFailureResult("signature_invalid", "CRL contains multiple revoked entries for certificate");
			a = o;
		} else s === "unsupported" && (i = !0);
	}
	return a === void 0 ? i ? nonApplicable("unsupported_indirect_crl", "indirect CRL entry certificateIssuer must include a directoryName") : { ok: !0 } : {
		ok: !0,
		entry: a
	};
}
/**
* Whether `crl` covers `certificate` under {@linkcode checkCrlApplicability}.
*
* @internal
*/
function isCrlApplicableTo(e, t) {
	return checkCrlApplicability(e, t).ok;
}
/** RFC 5280 §6.3 CRL applicability: scope, distribution-point, reason, and indirect-CRL checks. */
function checkCrlApplicability(e, t, n = !1) {
	try {
		return evaluateCrlApplicability(e, t, n);
	} catch (e) {
		return {
			ok: !1,
			failure: crlNameRefusalFailure(e)
		};
	}
}
function evaluateCrlApplicability(e, t, n) {
	if (!n && t.baseCrlNumber !== void 0) return notApplicableOutcome("unsupported_delta_crl", "a delta CRL cannot be used as the primary complete CRL input");
	let r = t.issuingDistributionPoint, i = r?.indirectCrl === !0;
	if (!i && !compareDistinguishedNames(e.issuer, t.issuer)) return notApplicableOutcome("issuer_mismatch", "CRL issuer does not match certificate issuer for direct CRL processing");
	if (r?.onlyContainsAttributeCerts === !0) return notApplicableOutcome("certificate_scope_mismatch", "attribute-certificate-only CRLs are not applicable to public-key certificates");
	let a = e.basicConstraints?.ca === !0;
	if (r?.onlyContainsUserCerts === !0 && a) return notApplicableOutcome("certificate_scope_mismatch", "CRL only applies to end-entity certificates");
	if (r?.onlyContainsCACerts === !0 && !a) return notApplicableOutcome("certificate_scope_mismatch", "CRL only applies to CA certificates");
	let o = e.crlDistributionPoints ?? [];
	if (o.length === 0) return r?.distributionPoint !== void 0 && !matchesDistributionPointName(issuerFallbackDistributionPointName(e), r.distributionPoint, t.issuer, void 0) ? notApplicableOutcome("distribution_point_mismatch", "CRL issuing distribution point does not name the certificate issuer") : i && !compareDistinguishedNames(e.issuer, t.issuer) ? notApplicableOutcome("issuer_mismatch", "indirect CRLs for alternate certificate issuers require matching CRLIssuer distribution points") : {
		ok: !0,
		coveredReasons: interimReasonsMask(void 0, r)
	};
	let s = scanCrlDistributionPoints(o, e, t, r, i);
	return typeof s == "string" ? {
		ok: !1,
		failure: crlDistributionPointScanFailure(s)
	} : {
		ok: !0,
		coveredReasons: s.coveredReasons
	};
}
/** Wraps a non-applicability failure into a {@linkcode CrlApplicabilityOutcome}. */
function notApplicableOutcome(e, t) {
	return {
		ok: !1,
		failure: nonApplicable(e, t)
	};
}
/**
* RFC 5280 §6.3.3 final paragraph: for a certificate without a CRLDP extension,
* assume a distribution point named by the certificate issuer and its
* issuerAltName entries, with reasons and cRLIssuer omitted.
*/
function issuerFallbackDistributionPointName(e) {
	return {
		type: "fullName",
		fullName: [{
			type: "directoryName",
			derHex: e.issuer.derHex
		}, ...e.issuerAltNames ?? []]
	};
}
/**
* Aggregates distribution-point matching across a certificate.
*
* RFC 5280 §6.3.3 processes every corresponding DP, so when several match the same CRL their
* interim reason masks (d) are unioned rather than stopping at the first.
*/
function scanCrlDistributionPoints(e, t, n, r, i) {
	let a = /* @__PURE__ */ new Set(), o = /* @__PURE__ */ new Set(), s = !1;
	for (let c of e) {
		let e = scanCrlDistributionPoint(c, t, n, r, i);
		if (e === "matched") {
			s = !0;
			for (let e of interimReasonsMask(c, r)) a.add(e);
		} else o.add(e);
	}
	return s ? { coveredReasons: [...a] } : resolveScanFailure(o);
}
/** Reports the highest-precedence distribution-point scan failure. */
function resolveScanFailure(e) {
	return [
		"reasons_mismatch",
		"unsupported_indirect_crl_issuer",
		"indirect_issuer_mismatch",
		"distribution_point_mismatch",
		"indirect_distribution_point"
	].find((t) => e.has(t)) ?? "scope_mismatch";
}
function scanCrlDistributionPoint(e, t, n, r, i) {
	let a = scanCrlDistributionPointIssuer(e, t, n, i);
	return a === void 0 ? matchesDistributionPointName(e.distributionPoint, r?.distributionPoint, n.issuer, e.crlIssuer) ? hasOverlappingReasons(e.reasons, r?.onlySomeReasons) ? "matched" : "reasons_mismatch" : "distribution_point_mismatch" : a;
}
function scanCrlDistributionPointIssuer(e, t, n, r) {
	if (!r) return e.crlIssuer === void 0 ? void 0 : "indirect_distribution_point";
	if (compareDistinguishedNames(t.issuer, n.issuer) && e.crlIssuer === void 0) return;
	let i = matchesIndirectCrlIssuer(e.crlIssuer, n);
	return i === "unsupported" ? "unsupported_indirect_crl_issuer" : i ? void 0 : "indirect_issuer_mismatch";
}
function crlDistributionPointScanFailure(e) {
	return e === "reasons_mismatch" ? nonApplicable("reasons_mismatch", "certificate distribution point reasons do not overlap the CRL reason scope") : e === "unsupported_indirect_crl_issuer" ? nonApplicable("unsupported_indirect_crl", "indirect CRL distribution points must identify the CRL issuer with directoryName") : e === "indirect_issuer_mismatch" ? nonApplicable("issuer_mismatch", "certificate distribution points do not authorize this indirect CRL issuer") : e === "distribution_point_mismatch" ? nonApplicable("distribution_point_mismatch", "certificate distribution points do not match the CRL issuing distribution point") : e === "indirect_distribution_point" ? nonApplicable("unsupported_indirect_crl", "certificate distribution points that name alternate CRL issuers are not supported yet") : nonApplicable("distribution_point_mismatch", "certificate distribution points do not match the CRL scope");
}
/** Verifies that a delta CRL is compatible with the given complete CRL (same issuer, AKI, IDP, and valid numbering). */
function checkDeltaCrlCompatibility(e, t) {
	if (e.baseCrlNumber !== void 0) return nonApplicable("delta_crl_incompatible", "complete CRL input must not itself be a delta CRL");
	if (t.baseCrlNumber === void 0) return nonApplicable("delta_crl_incompatible", "delta CRL input must include a delta CRL indicator");
	if (!compareDistinguishedNames(e.issuer, t.issuer)) return nonApplicable("delta_crl_incompatible", "complete and delta CRLs must share the same issuer");
	if (e.authorityKeyIdentifier !== t.authorityKeyIdentifier) return nonApplicable("delta_crl_incompatible", "complete and delta CRLs must share the same authority key identifier");
	if (!sameIssuingDistributionPoint(e.issuingDistributionPoint, t.issuingDistributionPoint)) return nonApplicable("delta_crl_incompatible", "complete and delta CRLs must share the same issuing distribution point scope");
	if (e.crlNumber === void 0 || t.crlNumber === void 0) return nonApplicable("delta_crl_incompatible", "complete and delta CRLs must both carry CRL numbers for delta processing");
	if (e.crlNumber < t.baseCrlNumber) return nonApplicable("delta_crl_incompatible", "delta CRL base number must not exceed the complete CRL number");
	if (e.crlNumber >= t.crlNumber) return nonApplicable("delta_crl_incompatible", "delta CRL number must be newer than the complete CRL number");
	if (e.thisUpdate.getTime() > t.thisUpdate.getTime()) return nonApplicable("delta_crl_incompatible", "delta CRL thisUpdate must not precede the complete CRL thisUpdate");
}
/** RFC 5280 §4.2.1.13 requires only the CRL issuer DN, with identical DER encoding. */
function matchesIndirectCrlIssuer(e, t) {
	return e === void 0 || e.length === 0 ? !1 : e.some((e) => e.type !== "directoryName") ? "unsupported" : e.every((e) => e.type === "directoryName" && e.derHex.toLowerCase() === t.issuer.derHex.toLowerCase());
}
/** Determines whether a revoked entry's effective issuer matches the certificate's issuer. */
function matchesRevokedEntryIssuer(e, t, n) {
	if (n === void 0) return compareDistinguishedNames(e.issuer, t.issuer) ? "match" : "mismatch";
	let r = !1;
	for (let t of n) if (t.type === "directoryName") {
		if (directoryNameDerHexMatchesParsedName(t.derHex, e.issuer)) return "match";
	} else r = !0;
	return r ? "unsupported" : "mismatch";
}
/** Shorthand for building a `non_applicable` failure result with the given reason. */
function nonApplicable(e, t) {
	return checkCertificateRevocationAgainstCrlFailureResult("non_applicable", t, { reason: e });
}
/**
* Merges complete and delta CRL entries into a final `good`/`revoked` status
* per the RFC 5280 §6.3.3 (i)-(k) relying-party algorithm.
*
* Deliberately harder than (i)-(k) on `removeFromCRL`: the entry clears a
* revocation only in the two situations §5.2.4(b)/§5.3.1 permit an issuer to
* emit it, a complete-CRL `certificateHold` entry or a certificate that
* expired before the delta CRL's thisUpdate.
*/
function resolveCertificateRevocationStatus(e, t, n, r, i, a, o) {
	if (i !== void 0) {
		if (i.reasonCode === "removeFromCRL") {
			if (r?.reasonCode === "certificateHold" || t !== void 0 && e.notAfter.getTime() < t.getTime()) return checkCertificateRevocationAgainstCrlSuccess({
				status: "good",
				crl: n,
				coveredReasons: a
			});
		} else return revokedEntryResult(n, i, o);
	}
	return r === void 0 ? checkCertificateRevocationAgainstCrlSuccess({
		status: "good",
		crl: n,
		coveredReasons: a
	}) : revokedEntryResult(n, r, o);
}
function revokedEntryResult(e, t, n) {
	return n === "reject" && typeof t.reasonCode == "object" ? checkCertificateRevocationAgainstCrlFailureResult("reason_code_unrecognized", `CRL entry carries unrecognized reason code ${String(t.reasonCode.code)}`) : checkCertificateRevocationAgainstCrlSuccess({
		status: "revoked",
		crl: e,
		revocationDate: t.revocationDate,
		...t.reasonCode === void 0 ? {} : { reasonCode: t.reasonCode }
	});
}
/**
* Returns `true` if the certificate's distribution-point name matches the CRL's IDP name.
*
* Per RFC 5280 §4.2.1.13, when the certificate uses `nameRelativeToCRLIssuer` (relativeName),
* the full distribution point name is formed by appending that RDN to the CRL issuer's DN.
* This resolved name is then compared against the CRL's IDP fullName directoryName entries.
*/
function matchesDistributionPointName(e, t, n, r) {
	if (t === void 0) return !0;
	if (e === void 0) return matchesIdpNameAgainstCrlIssuer(t, r, n);
	if (e.type === "fullName" && t.type === "fullName") return e.fullName.some((e) => t.fullName.some((t) => compareGeneralNames(e, t)));
	if (e.type === "relativeName" && t.type === "fullName") {
		let r = resolveRelativeNameToDnHex(n, e.relativeName);
		return t.fullName.some((e) => e.type === "directoryName" && e.derHex === r);
	}
	if (e.type === "relativeName" && t.type === "relativeName") return compareRelativeDistinguishedNames(e.relativeName, t.relativeName);
	if (e.type === "fullName" && t.type === "relativeName") {
		let r = resolveRelativeNameToDnHex(n, t.relativeName);
		return e.fullName.some((e) => e.type === "directoryName" && e.derHex === r);
	}
	return !1;
}
/**
* RFC 5280 §6.3.3 (b)(2)(i): when the certificate's distribution point omits the
* distributionPoint field, match the CRL IDP's distributionPoint names against
* the distribution point's `cRLIssuer` names.
*/
function matchesIdpNameAgainstCrlIssuer(e, t, n) {
	if (t === void 0) return !1;
	if (e.type === "fullName") return t.some((t) => e.fullName.some((e) => compareGeneralNames(t, e)));
	let r = resolveRelativeNameToDnHex(n, e.relativeName);
	return t.some((e) => e.type === "directoryName" && e.derHex === r);
}
/** Constructs a full DN by appending an RDN to an existing Name, returning hex-encoded DER. */
function resolveRelativeNameToDnHex(e, t) {
	let n = e.rdns.map((e) => hexToBytes(e.derHex)), r = rebuildRelativeNameAsSet(hexToBytes(t.derHex));
	return n.push(r), toHex(sequence(n));
}
/** Converts an implicit-tagged [1] relativeName to a proper SET-tagged RDN. */
function rebuildRelativeNameAsSet(e) {
	let t = readRootElement(e, { maxDepth: 64 });
	return tlv(49, t.value);
}
/** Deep-compares two issuing distribution point extensions for delta-CRL compatibility. */
function sameIssuingDistributionPoint(e, t) {
	return e === void 0 || t === void 0 ? e === t : sameDistributionPointName(e.distributionPoint, t.distributionPoint) && e.onlyContainsUserCerts === !0 == (t.onlyContainsUserCerts === !0) && e.onlyContainsCACerts === !0 == (t.onlyContainsCACerts === !0) && e.indirectCrl === !0 == (t.indirectCrl === !0) && e.onlyContainsAttributeCerts === !0 == (t.onlyContainsAttributeCerts === !0) && sameReasonSet(e.onlySomeReasons, t.onlySomeReasons);
}
/** Compares two DistributionPointName values (fullName set or relativeName). */
function sameDistributionPointName(e, t) {
	return e === void 0 || t === void 0 ? e === t : e.type === "fullName" && t.type === "fullName" ? sameGeneralNameSet(e.fullName, t.fullName) : e.type === "relativeName" && t.type === "relativeName" && compareRelativeDistinguishedNames(e.relativeName, t.relativeName);
}
/** Set-equality comparison for GeneralName arrays (order-independent). */
function sameGeneralNameSet(e, t) {
	if (e.length !== t.length) return !1;
	let n = Array.from({ length: t.length }, () => !1);
	for (let r of e) {
		let e = !1;
		for (let i = 0; i < t.length; i += 1) {
			let a = t[i];
			if (!(a === void 0 || n[i]) && compareGeneralNames(r, a)) {
				n[i] = !0, e = !0;
				break;
			}
		}
		if (!e) return !1;
	}
	return !0;
}
/** Set-equality comparison for DistributionPointReason arrays. */
function sameReasonSet(e, t) {
	return e === void 0 || t === void 0 ? e === t : e.flags.length === t.flags.length && e.flags.every((e) => t.flags.includes(e));
}
/** Returns `true` if the certificate's DP reasons overlap the CRL's `onlySomeReasons`, or if either is absent (= all reasons). */
function hasOverlappingReasons(e, t) {
	return e === void 0 || t === void 0 || e.flags.some((e) => t.flags.includes(e));
}
/** Value-equality for two GeneralName entries, using DER comparison for directoryName. */
function compareGeneralNames(e, t) {
	if (e.type === "dns" && t.type === "dns") return e.value.toLowerCase() === t.value.toLowerCase();
	if (e.type === "srv" && t.type === "srv") return compareSrvNames(e.value.toLowerCase(), t.value.toLowerCase());
	if (e.type === "email" && t.type === "email") return compareRfc822Names(e.value, t.value);
	if (e.type === "smtpUtf8Mailbox" && t.type === "smtpUtf8Mailbox" || e.type === "ip" && t.type === "ip") return e.value === t.value;
	if (e.type === "uri" && t.type === "uri") return compareUniformResourceIdentifiers(e.value, t.value);
	if (e.type === "directoryName" && t.type === "directoryName") {
		let n = parseDerHexName(e.derHex), r = parseDerHexName(t.derHex);
		return n === void 0 || r === void 0 ? !1 : compareDistinguishedNames(n, r);
	}
	return compareOpaqueGeneralNames(e, t);
}
function compareSrvNames(e, t) {
	let n = parsePresentedSrvName(e), r = parsePresentedSrvName(t);
	return n === void 0 || r === void 0 ? e === t : n.service === r.service && n.name === r.name;
}
/** Encoding equality for the GeneralName alternatives carried as DER or an OID. */
function compareOpaqueGeneralNames(e, t) {
	return e.type === "otherName" && t.type === "otherName" ? e.typeId === t.typeId && bytesEqual(e.value, t.value) : e.type === "upn" && t.type === "upn" ? e.value === t.value : e.type === "krb5PrincipalName" && t.type === "krb5PrincipalName" ? e.realm === t.realm && e.nameType === t.nameType && e.nameString.length === t.nameString.length && e.nameString.every((e, n) => e === t.nameString[n]) : e.type === "x400Address" && t.type === "x400Address" || e.type === "ediPartyName" && t.type === "ediPartyName" ? bytesEqual(e.value, t.value) : e.type === "registeredID" && t.type === "registeredID" ? e.value === t.value : e.type === "unknown" && t.type === "unknown" && e.tag === t.tag && bytesEqual(e.value, t.value);
}
/** RFC 5280 §7.5: rfc822Name local-part is case-sensitive, the host-part case-insensitive. */
function compareRfc822Names(e, t) {
	let n = e.lastIndexOf("@"), r = t.lastIndexOf("@");
	return n < 0 || r < 0 ? e.toLowerCase() === t.toLowerCase() : e.slice(0, n) === t.slice(0, r) && e.slice(n + 1).toLowerCase() === t.slice(r + 1).toLowerCase();
}
/** RFC 5280 §7.4: URIs compare only after syntax-based and scheme-based normalization. */
function compareUniformResourceIdentifiers(e, t) {
	if (e === t) return !0;
	let n = normalizeUriForComparison(e);
	return n !== void 0 && n === normalizeUriForComparison(t);
}
/**
* The schemes RFC 5280 §7.4 step 5 requires implementations to recognise, with
* the default port that scheme-based normalization elides. `ldaps` is included
* as the TLS form of the mandatory `ldap` scheme.
*/
const ue = /* @__PURE__ */ new Map([
	["ftp", "21"],
	["http", "80"],
	["https", "443"],
	["ldap", "389"],
	["ldaps", "636"]
]);
/**
* Applies the RFC 5280 §7.4 comparison preparation: IDN labels to ASCII
* Compatible Encoding, lowercased scheme and host, percent-encoding and path
* segment normalization, and scheme-based normalization. The URL parser covers
* path segments for every scheme and the scheme case; the remaining steps are
* applied here because it leaves the host of a non-special scheme such as
* `ldap` untouched and never normalizes percent-encoding.
*
* @returns `undefined` when the value does not parse as an absolute URI.
*/
function normalizeUriForComparison(e) {
	let t;
	try {
		t = new URL(e);
	} catch {
		return;
	}
	if (t.hostname !== "") {
		let e = normalizeUriHost(t.hostname);
		if (e === void 0) return;
		t.hostname = e;
	}
	return t.port === ue.get(t.protocol.slice(0, -1)) && (t.port = ""), normalizePercentEncoding(t.href);
}
/**
* Reparses a host under a special scheme so the URL parser applies IDNA and
* lowercasing to it, which it skips for opaque hosts.
*
* @returns `undefined` when the host does not survive the round trip intact.
*/
function normalizeUriHost(e) {
	try {
		let t = new URL(`https://${decodeHostPercentEncoding(e)}`);
		return t.href === `https://${t.hostname}/` ? t.hostname : void 0;
	} catch {
		return;
	}
}
/** Recovers the Unicode host an opaque-host URI carries as percent-encoded UTF-8. */
function decodeHostPercentEncoding(e) {
	try {
		return decodeURIComponent(e);
	} catch {
		return e;
	}
}
const de = /%[0-9A-Fa-f]{2}/g;
/** RFC 3986 §6.2.2.2: unreserved triplets decode, every other triplet uppercases. */
function normalizePercentEncoding(e) {
	return e.replace(de, (e) => {
		let t = Number.parseInt(e.slice(1), 16);
		return isUnreservedUriCharacter(t) ? String.fromCharCode(t) : e.toUpperCase();
	});
}
/** RFC 3986 §2.3 unreserved set: `ALPHA / DIGIT / "-" / "." / "_" / "~"`. */
function isUnreservedUriCharacter(e) {
	return e >= 65 && e <= 90 || e >= 97 && e <= 122 || e >= 48 && e <= 57 || e === 45 || e === 46 || e === 95 || e === 126;
}
/** Constant-length byte-array equality check. */
function bytesEqual(e, t) {
	if (e.length !== t.length) return !1;
	for (let n = 0; n < e.length; n += 1) if (e[n] !== t[n]) return !1;
	return !0;
}
/** Assembles the CRL-level v2 extensions (AKI, CRLNumber, deltaCRLIndicator, IDP, freshestCRL). */
function buildCrlExtensions(e, t$20, n, r, i) {
	let a = [encodeExtension(t.authorityKeyIdentifier, sequence([implicitPrimitiveContext(0, issuerKeyIdentifier(e))])), encodeExtension(t.cRLNumber, t$20)];
	return n !== void 0 && a.push(encodeExtension(t.deltaCRLIndicator, n, !0)), r !== void 0 && a.push(encodeExtension(t.issuingDistributionPoint, encodeIssuingDistributionPoint(r), !0)), i !== void 0 && i.length > 0 && a.push(encodeExtension(t.freshestCRL, encodeCrlDistributionPoints(i))), a;
}
/** DER-encodes a single revokedCertificate SEQUENCE (serial, date, optional extensions). */
function createRevokedCertificate(e, t) {
	let n = buildRevokedCertificateExtensions(e);
	return sequence([
		integer(e.serialNumber),
		time(e.revocationDate ?? t),
		...n.length === 0 ? [] : [sequence(n)]
	]);
}
/** Encodes CRL entry extensions (reasonCode, invalidityDate). */
function buildRevokedCertificateExtensions(e) {
	let t$21 = [];
	return e.reasonCode !== void 0 && t$21.push(encodeExtension(t.cRLReason, tlv(10, Uint8Array.of(le[e.reasonCode])))), e.invalidityDate !== void 0 && t$21.push(encodeExtension(t.invalidityDate, generalizedTime(e.invalidityDate))), t$21;
}
/** Decodes per-entry CRL extensions (reasonCode, invalidityDate, certificateIssuer). */
function parseRevokedCertificateExtensions(e, t) {
	if (e === void 0 || t === void 0) return {};
	let n = {}, r = /* @__PURE__ */ new Set();
	for (let i of childrenOf(e, t)) parseRevokedCertificateExtension(e, i, r, n);
	return {
		...n.reasonCode === void 0 ? {} : { reasonCode: n.reasonCode },
		...n.invalidityDate === void 0 ? {} : { invalidityDate: n.invalidityDate },
		...n.certificateIssuer === void 0 ? {} : { certificateIssuer: n.certificateIssuer }
	};
}
function parseRevokedCertificateExtension(e, t, n, r) {
	let i = childrenOf(e, t);
	if (i.length < 2 || i.length > 3 || i.length === 3 && i[1]?.tag !== 1) throw Error("Malformed revoked certificate extension");
	let a = decodeObjectIdentifier(requireElement(i[0], "revoked certificate extension OID").value);
	if (n.has(a)) throw Error(`Duplicate revoked certificate extension OID: ${a}`);
	n.add(a);
	let o = i.length === 3 && decodeBoolean(requireElement(i[1], "revoked certificate extension critical").value), s = requireElement(i[i.length - 1], "revoked certificate extension value");
	if (s.tag !== 4) throw Error("Revoked certificate extension value must use OCTET STRING");
	if (o && !isSupportedRevokedCertificateExtensionOid(a)) throw Error(`Unsupported critical revoked certificate extension OID: ${a}`);
	applyRevokedCertificateExtensionValue(a, s.value, o, r);
}
function isSupportedRevokedCertificateExtensionOid(e) {
	return e === t.cRLReason || e === t.invalidityDate || e === t.certificateIssuer;
}
function applyRevokedCertificateExtensionValue(e, t$22, n, r) {
	if (e === t.cRLReason) {
		let e = readRootElement(t$22, { maxDepth: 64 });
		if (e.tag !== 10) throw Error("cRLReason must use ENUMERATED");
		let i = parsedRevocationReason(decodeNonNegativeIntegerBigInt(e.value, "cRLReason"));
		if (n && typeof i != "string") throw Error(`Critical cRLReason holds unrecognized reason code ${String(i.code)}`);
		r.reasonCode = i;
	}
	if (e === t.invalidityDate && (r.invalidityDate = parseTime(readRootElement(t$22, { maxDepth: 64 }))), e === t.certificateIssuer) {
		let e = readRootElement(t$22, { maxDepth: 64 });
		if (e.tag !== 48) throw Error("certificateIssuer must use SEQUENCE");
		r.certificateIssuer = parseGeneralNames(t$22, e);
	}
}
/** Decodes the IssuingDistributionPoint extension from its OCTET STRING content. */
function parseIssuingDistributionPoint(e) {
	let t = readRootElement(e, { maxDepth: 64 }), n = {};
	for (let r of childrenOf(e, t)) parseIssuingDistributionPointField(e, r, n);
	return {
		...n.distributionPoint === void 0 ? {} : { distributionPoint: n.distributionPoint },
		...n.onlySomeReasons === void 0 ? {} : { onlySomeReasons: n.onlySomeReasons },
		...n.indirectCrl === void 0 ? {} : { indirectCrl: n.indirectCrl },
		...parseIssuingDistributionPointScope(n)
	};
}
/** RFC 5280 §5.2.5: at most one `onlyContains*` flag may be TRUE. */
function parseIssuingDistributionPointScope(e) {
	let t = e.onlyContainsUserCerts, n = e.onlyContainsCACerts, r = e.onlyContainsAttributeCerts;
	if (t === !0) {
		if (n === !0 || r === !0) throw Error($);
		return {
			onlyContainsUserCerts: !0,
			...unselectedScopeFlags({
				caCerts: n,
				attributeCerts: r
			})
		};
	}
	if (n === !0) {
		if (r === !0) throw Error($);
		return {
			onlyContainsCACerts: !0,
			...unselectedScopeFlags({
				userCerts: t,
				attributeCerts: r
			})
		};
	}
	return r === !0 ? {
		onlyContainsAttributeCerts: !0,
		...unselectedScopeFlags({
			userCerts: t,
			caCerts: n
		})
	} : unselectedScopeFlags({
		userCerts: t,
		caCerts: n,
		attributeCerts: r
	});
}
/** Keeps the explicit-FALSE flags the encoding carried, omitting the ones it left out. */
function unselectedScopeFlags(e) {
	return {
		...e.userCerts === void 0 ? {} : { onlyContainsUserCerts: e.userCerts },
		...e.caCerts === void 0 ? {} : { onlyContainsCACerts: e.caCerts },
		...e.attributeCerts === void 0 ? {} : { onlyContainsAttributeCerts: e.attributeCerts }
	};
}
const $ = "IssuingDistributionPoint scope booleans are mutually exclusive";
function parseIssuingDistributionPointField(e, t, n) {
	switch (t.tag) {
		case 160: {
			if (n.distributionPoint !== void 0) throw Error("IssuingDistributionPoint distributionPoint must not repeat");
			let r = parseDistributionPointName(e, t);
			r !== void 0 && (n.distributionPoint = r);
			return;
		}
		case 129:
			n.onlyContainsUserCerts = parseUniqueIssuingDistributionPointBoolean(n.onlyContainsUserCerts, t, "onlyContainsUserCerts");
			return;
		case 130:
			n.onlyContainsCACerts = parseUniqueIssuingDistributionPointBoolean(n.onlyContainsCACerts, t, "onlyContainsCACerts");
			return;
		case 131:
			if (n.onlySomeReasons !== void 0) throw Error("IssuingDistributionPoint onlySomeReasons must not repeat");
			n.onlySomeReasons = parseDistributionPointReasonFlagsContent(t.value);
			return;
		case 132:
			n.indirectCrl = parseUniqueIssuingDistributionPointBoolean(n.indirectCrl, t, "indirectCrl");
			return;
		case 133:
			n.onlyContainsAttributeCerts = parseUniqueIssuingDistributionPointBoolean(n.onlyContainsAttributeCerts, t, "onlyContainsAttributeCerts");
			return;
		default: throw Error(`Unsupported IssuingDistributionPoint field tag: ${String(t.tag)}`);
	}
}
function parseUniqueIssuingDistributionPointBoolean(e, t, n) {
	if (e !== void 0) throw Error(`IssuingDistributionPoint ${n} must not repeat`);
	return decodeBoolean(t.value);
}
/** Decodes a SEQUENCE OF DistributionPoint from DER. */
function parseDistributionPoints(e) {
	let t = readRootElement(e, { maxDepth: 64 });
	if (t.tag !== 48) throw Error("DistributionPoints must use SEQUENCE");
	let n = childrenOf(e, t);
	if (n.length === 0) throw Error("DistributionPoints must not be empty");
	return n.map((t) => parseDistributionPoint(e, t));
}
/** Decodes a DistributionPointName (fullName or relativeName). */
function parseDistributionPointName(e, t) {
	let n = childrenOf(e, t);
	if (n.length !== 1) throw Error("distributionPointName must contain exactly one choice");
	let r = requireElement(n[0], "distributionPointName");
	if (r.tag === 160) {
		let t = childrenOf(e, r);
		if (t.length === 0) throw Error("distributionPointName fullName must not be empty");
		for (let e of t) if ((e.tag & 192) != 128) throw Error("distributionPointName fullName must contain GeneralName entries");
		return {
			type: "fullName",
			fullName: t.map((t) => parseGeneralName(e, t))
		};
	}
	if (r.tag === 161) return {
		type: "relativeName",
		relativeName: parseRelativeName(e, r)
	};
	throw Error(`Unsupported distributionPointName tag: ${String(r.tag)}`);
}
/** Decodes a single DistributionPoint SEQUENCE. */
function parseDistributionPoint(e, t) {
	if (t.tag !== 48) throw Error("DistributionPoint must use SEQUENCE");
	let n = {};
	for (let r of childrenOf(e, t)) parseDistributionPointField(e, r, n);
	if (n.distributionPoint === void 0 && n.crlIssuer === void 0) throw Error("DistributionPoint must include distributionPoint or crlIssuer");
	return {
		...n.distributionPoint === void 0 ? {} : { distributionPoint: n.distributionPoint },
		...n.reasons === void 0 ? {} : { reasons: n.reasons },
		...n.crlIssuer === void 0 ? {} : { crlIssuer: n.crlIssuer }
	};
}
function parseDistributionPointField(e, t, n) {
	switch (t.tag) {
		case 160: {
			if (n.distributionPoint !== void 0) throw Error("DistributionPoint distributionPoint must not repeat");
			let r = parseDistributionPointName(e, t);
			r !== void 0 && (n.distributionPoint = r);
			return;
		}
		case 129:
			if (n.reasons !== void 0) throw Error("DistributionPoint reasons must not repeat");
			n.reasons = parseDistributionPointReasonFlagsContent(t.value);
			return;
		case 162:
			if (n.crlIssuer !== void 0) throw Error("DistributionPoint crlIssuer must not repeat");
			n.crlIssuer = parseGeneralNames(e, t);
			return;
		default: throw Error(`Unsupported DistributionPoint field tag: ${String(t.tag)}`);
	}
}
/** Decodes a RelativeDistinguishedName SET from an implicitly-tagged context element. */
function parseRelativeName(e, t) {
	let n = [], r = {};
	for (let i of childrenOf(e, t)) {
		let t = childrenOf(e, i), a = decodeObjectIdentifier(requireElement(t[0], "name OID").value), o = requireElement(t[1], "name value"), s = nameFieldKeyFromOid(a), c = decodeNameValue(o), l = s === void 0 ? {
			oid: a,
			valueTag: o.tag,
			value: c
		} : {
			oid: a,
			key: s,
			valueTag: o.tag,
			value: c
		};
		n.push(l), s !== void 0 && r[s] === void 0 && (r[s] = c);
	}
	return {
		derHex: toHex(e.slice(t.start - t.headerLength, t.end)),
		attributes: n,
		values: r
	};
}
/** Decodes an ASN.1 string element (UTF8String, PrintableString, etc.) to a JS string. */
function decodeNameValue(e) {
	return decodeString(e.tag, e.value);
}
/** Throws a {@link ResultError} for a CRL encoder input-validation failure. */
function throwCrlEncoderError(e, t) {
	throwMicro509Error(e, t);
}
/** The parsed issuer certificate of a CRL being built. */
function issuerCertificateOf(t) {
	try {
		return normalizeCrlCertificate(t);
	} catch (t) {
		return rethrowDecodeRefusal(t, n), throwCrlEncoderError("issuer_certificate_invalid", "issuerCertificate must be a PEM, DER or parsed certificate");
	}
}
/** RFC 5280 §5.2.3 `CRLNumber ::= INTEGER (0..MAX)` as a DER INTEGER of at most 20 content octets. */
function encodeCrlNumber(e, t) {
	let n = typeof e == "bigint" ? e : Number.isSafeInteger(e) ? BigInt(e) : -1n, r = n.toString(16), i = n < 0n ? void 0 : hexToBytes(r.length % 2 == 0 ? r : `0${r}`), a = i?.[0];
	return (i === void 0 || a === void 0 || i.length + +(a >= 128) > 20) && throwCrlEncoderError("crl_number_invalid", `${t} must be a non-negative integer of at most 20 octets (RFC 5280 §5.2.3)`), integer(i);
}
/** RFC 5280 §5.2.3: a received CRLNumber of any length, since verifiers MUST handle up to 20 octets. */
function decodeCrlNumber(e) {
	let t = readRootElement(e, { maxDepth: 64 });
	if (t.tag !== 2) throw Error("CRLNumber must be an INTEGER");
	return decodeIntegerMagnitude(t.value, "CRLNumber"), BigInt(`0x${toHex(t.value)}`);
}
function assertCrlDate(e, t) {
	e !== void 0 && Number.isNaN(e.getTime()) && throwCrlEncoderError("invalid_date", `${t} must be a valid date`);
}
/** DER-encodes an IssuingDistributionPoint extension value. Throws on mutually-exclusive scope flags. */
function encodeIssuingDistributionPoint(e) {
	if ([
		e.onlyContainsUserCerts === !0,
		e.onlyContainsCACerts === !0,
		e.onlyContainsAttributeCerts === !0
	].filter(Boolean).length > 1) throw Error("IssuingDistributionPoint can assert at most one of user, CA, or attribute cert scope");
	let t = [];
	return e.distributionPoint !== void 0 && t.push(implicitConstructedContext(0, encodeDistributionPointName(e.distributionPoint))), e.onlyContainsUserCerts && t.push(implicitPrimitiveContext(1, Uint8Array.of(255))), e.onlyContainsCACerts && t.push(implicitPrimitiveContext(2, Uint8Array.of(255))), e.onlySomeReasons !== void 0 && e.onlySomeReasons.length > 0 && t.push(implicitPrimitiveContext(3, encodeDistributionPointReasonFlagsContent(e.onlySomeReasons))), e.indirectCrl && t.push(implicitPrimitiveContext(4, Uint8Array.of(255))), e.onlyContainsAttributeCerts && t.push(implicitPrimitiveContext(5, Uint8Array.of(255))), sequence(t);
}
/** DER-encodes a DistributionPointName (fullName or relativeName). */
function encodeDistributionPointName(e) {
	if (e === void 0) throw Error("IssuingDistributionPoint distributionPoint is required");
	switch (e.type) {
		case "fullName": return e.fullName.length === 0 && throwCrlEncoderError("distribution_point_full_name_empty", "DistributionPointName fullName must not be empty"), implicitConstructedContext(0, concatGeneralNames(e.fullName));
		case "relativeName": {
			let t = encodeRelativeDistinguishedName(e.relativeName), n = readElement(t);
			return implicitConstructedContext(1, t.slice(n.start, n.end));
		}
		default: throw Error(`Unhandled DistributionPointName type: ${String(e)}`);
	}
}
/** DER-encodes and concatenates a list of GeneralName values. */
function concatGeneralNames(e) {
	return concatBytes(e.map((e) => encodeSubjectAltName(e)));
}
/** Parses a Name SEQUENCE element into a full {@linkcode ParsedName}. */
function parseIssuer(e, t) {
	let n = toHex(e.slice(t.start - t.headerLength, t.end)), r = [], i = [], a = {};
	for (let n of childrenOf(e, t)) {
		let t = [], o = {};
		for (let r of childrenOf(e, n)) {
			let n = childrenOf(e, r), s = requireElement(n[0], "issuer attribute OID"), c = requireElement(n[1], "issuer attribute value"), l = decodeObjectIdentifier(s.value), u = decodeNameValue(c), d = nameFieldKeyFromOid(l), f = d === void 0 ? {
				oid: l,
				valueTag: c.tag,
				value: u
			} : {
				oid: l,
				key: d,
				valueTag: c.tag,
				value: u
			};
			t.push(f), i.push(f), d !== void 0 && (o[d] === void 0 && (o[d] = u), a[d] === void 0 && (a[d] = u));
		}
		r.push({
			derHex: toHex(e.slice(n.start - n.headerLength, n.end)),
			attributes: t,
			values: o
		});
	}
	return {
		derHex: n,
		rdns: r,
		attributes: i,
		values: a
	};
}
/**
* Re-parses a hex-encoded DER Name into a {@linkcode ParsedName}. Returns
* `undefined` on malformed input and throws a decode refusal.
*/
function parseDerHexName(t) {
	try {
		let e = hexToBytes(t), n = unwrapNameElement(e, readRootElement(e, { maxDepth: 64 }));
		return n.tag === 48 ? parseIssuer(e, n) : void 0;
	} catch (t) {
		rethrowDecodeRefusal(t, n);
		return;
	}
}
/** The failure for a decode refusal a directoryName comparison threw. */
function crlNameRefusalFailure(t) {
	let n$33 = decodeRefusalOf(t, n);
	if (n$33 === void 0) throw t;
	return checkCertificateRevocationAgainstCrlFailureResult(n$33.code, n$33.message);
}
function unwrapNameElement(e, t) {
	if (t.tag !== 48) return t;
	let n = childrenOf(e, t), r = n[0];
	return n.length === 1 && r?.tag === 48 ? r : t;
}
/** Semantic comparison of a GeneralName directoryName `derHex` against a {@linkcode ParsedName}. */
function directoryNameDerHexMatchesParsedName(e, t) {
	let n = parseDerHexName(e);
	return n !== void 0 && compareDistinguishedNames(n, t);
}
/** Extracts the keyIdentifier field from an AuthorityKeyIdentifier extension value. */
function parseAuthorityKeyIdentifier(e) {
	let t = readRootElement(e, {
		maxDepth: 64,
		allowOpaqueConstructedTags: [161, 162]
	});
	if (t.tag !== 48) throw Error("authorityKeyIdentifier must use SEQUENCE");
	let n = {
		sawAuthorityCertIssuer: !1,
		sawAuthorityCertSerialNumber: !1,
		lastFieldOrder: -1
	};
	for (let r of childrenOf(e, t)) parseAuthorityKeyIdentifierField(e, r, n);
	return n.keyIdentifier;
}
function parseAuthorityKeyIdentifierField(e, t, n) {
	switch (t.tag) {
		case 128:
			parseAuthorityKeyIdentifierKeyId(t, n);
			return;
		case 161:
			parseAuthorityKeyIdentifierIssuer(e, t, n);
			return;
		case 130:
			parseAuthorityKeyIdentifierSerial(t, n);
			return;
		default: throw Error(`Unsupported authorityKeyIdentifier field tag: ${String(t.tag)}`);
	}
}
function parseAuthorityKeyIdentifierKeyId(e, t) {
	if (t.keyIdentifier !== void 0) throw Error("authorityKeyIdentifier keyIdentifier must not repeat");
	if (t.lastFieldOrder >= 0) throw Error("authorityKeyIdentifier fields must preserve DER order");
	t.keyIdentifier = toHex(e.value), t.lastFieldOrder = 0;
}
function parseAuthorityKeyIdentifierIssuer(e, t, n) {
	if (n.sawAuthorityCertIssuer) throw Error("authorityKeyIdentifier authorityCertIssuer must not repeat");
	if (n.lastFieldOrder >= 1) throw Error("authorityKeyIdentifier fields must preserve DER order");
	parseGeneralNames(e, t), n.sawAuthorityCertIssuer = !0, n.lastFieldOrder = 1;
}
function parseAuthorityKeyIdentifierSerial(e, t) {
	if (t.sawAuthorityCertSerialNumber) throw Error("authorityKeyIdentifier authorityCertSerialNumber must not repeat");
	if (t.lastFieldOrder >= 2 || !t.sawAuthorityCertIssuer) throw Error("authorityKeyIdentifier fields must preserve DER order");
	validateImplicitSerialNumberEncoding(e.value, "authorityKeyIdentifier authorityCertSerialNumber"), t.sawAuthorityCertSerialNumber = !0, t.lastFieldOrder = 2;
}
function validateImplicitSerialNumberEncoding(e, t) {
	let n = e[0];
	if (n === void 0) throw Error(`${t} must not be empty`);
	if (n & 128) throw Error(`${t} must be non-negative`);
	if (e.length > 1 && n === 0 && !((e[1] ?? 0) & 128)) throw Error(`${t} must use minimal encoding`);
}
/** RFC 5280 §5.1.1.2: signatureAlgorithm MUST equal the tbsCertList signature field. */
function assertMatchingCrlSignatureAlgorithms(e, t) {
	if (e.oid !== t.oid || !optionalBytesEqual(e.parametersDer, t.parametersDer)) throw Error("CRL signatureAlgorithm must match TBSCertList signature");
}
/** Extracts the algorithm OID from an AlgorithmIdentifier SEQUENCE. */
function parseAlgorithmIdentifier(e, t) {
	let n = childrenOf(e, t), r = requireElement(n[0], "algorithm OID"), i = n[1];
	return i === void 0 ? { oid: decodeObjectIdentifier(r.value) } : {
		oid: decodeObjectIdentifier(r.value),
		parametersDer: e.slice(i.start - i.headerLength, i.end)
	};
}
/** Lowercases a hex string for bytewise serial-number comparison. */
function normalizeHex$2(e) {
	return e.toLowerCase();
}
/**
* Maps an integer CRLReason code to its {@linkcode RevocationReason} name, or to
* an {@linkcode UnrecognizedRevocationReason} carrying a code outside RFC 5280
* §5.3.1. Returns `undefined` only when `code` is `undefined`.
*/
function revocationReasonFromCode(e) {
	return e === void 0 ? void 0 : parsedRevocationReason(e);
}
function parsedRevocationReason(e) {
	switch (e) {
		case 0n: return "unspecified";
		case 1n: return "keyCompromise";
		case 2n: return "cACompromise";
		case 3n: return "affiliationChanged";
		case 4n: return "superseded";
		case 5n: return "cessationOfOperation";
		case 6n: return "certificateHold";
		case 8n: return "removeFromCRL";
		case 9n: return "privilegeWithdrawn";
		case 10n: return "aACompromise";
		default: return {
			type: "unrecognized",
			code: e
		};
	}
}
/** Thin wrapper — parses a DER-encoded certificate for use as a CRL issuer. */
function parseIssuerCertificateDer(e) {
	return parseCertificateFromSource(e);
}
/** Thin wrapper — parses a PEM-encoded certificate for use as a CRL issuer. */
function parseIssuerCertificatePem(e) {
	return parseCertificateFromSource(e);
}
/**
* Parses PEM, DER, or an already-parsed CRL's `der`, so every decoded field
* comes from the signed bytes.
*
* @internal
*/
function normalizeCrl(e) {
	if (typeof e == "string") return parseCertificateRevocationListPemOrThrow(e);
	if (e instanceof Uint8Array) return parseCertificateRevocationListDerOrThrow(new Uint8Array(e));
	if (hasReparseableCrlShape(e)) return parseCertificateRevocationListDerOrThrow(new Uint8Array(e.der));
	throw Error("certificate revocation list input is malformed");
}
function parseSignedCrlFields(e) {
	let t = readRootElement(e, { maxDepth: 64 }), n = childrenOf(e, t), r = parseCrlVersionField(n), i = r.version, a = requireElement(n[r.nextIndex], "signature"), o = r.nextIndex + 1, s = requireElement(n[o], "issuer"), c = requireElement(n[o + 1], "thisUpdate"), l = o + 2, u = n[l], d = u !== void 0 && (u.tag === 23 || u.tag === 24) ? parseTime(u) : void 0;
	d !== void 0 && (l += 1);
	let f = n[l], p = f?.tag === 48 ? parseRevokedCertificates(e, f, i) : [];
	f?.tag === 48 && (l += 1);
	let m = n[l], h = parseCrlExtensionFields(e, m, i);
	return {
		version: i,
		signature: parseAlgorithmIdentifier(e, a),
		issuer: parseIssuer(e, s),
		thisUpdate: parseTime(c),
		...d === void 0 ? {} : { nextUpdate: d },
		...h.authorityKeyIdentifier === void 0 ? {} : { authorityKeyIdentifier: h.authorityKeyIdentifier },
		...h.crlNumber === void 0 ? {} : { crlNumber: h.crlNumber },
		...h.baseCrlNumber === void 0 ? {} : { baseCrlNumber: h.baseCrlNumber },
		...h.issuingDistributionPoint === void 0 ? {} : { issuingDistributionPoint: h.issuingDistributionPoint },
		...h.freshestCrlDistributionPoints === void 0 ? {} : { freshestCrlDistributionPoints: h.freshestCrlDistributionPoints },
		revokedCertificates: p
	};
}
function parseCrlVersionField(e) {
	let t = e[0];
	if (t !== void 0 && t.tag !== 2 && t.tag !== 48) throw Error("version must use INTEGER");
	if (t?.tag !== 2) return {
		version: 1,
		nextIndex: 0
	};
	let n = decodeIntegerNumber(t.value) + 1;
	if (n !== 2) throw Error(`Unsupported CRL version: ${String(n)}`);
	return {
		version: n,
		nextIndex: 1
	};
}
function parseRevokedCertificates(e, t, n) {
	return childrenOf(e, t).map((t) => parseRevokedCertificateEntry(e, t, n));
}
function parseRevokedCertificateEntry(e, t, n) {
	let r = e.slice(t.start - t.headerLength, t.end), i = readSequenceChildren(r), a = requireElement(i[0], "revoked serialNumber");
	if (a.tag !== 2) throw Error("revoked serialNumber must use INTEGER");
	let o = i[2];
	if (o !== void 0 && n !== 2) throw Error("revoked certificate extensions require CRL version 2");
	let s = parseRevokedCertificateExtensions(r, o);
	return {
		serialNumberHex: toHex(a.value),
		revocationDate: parseTime(requireElement(i[1], "revocationDate")),
		...s.reasonCode === void 0 ? {} : { reasonCode: s.reasonCode },
		...s.invalidityDate === void 0 ? {} : { invalidityDate: s.invalidityDate },
		...s.certificateIssuer === void 0 ? {} : { certificateIssuer: s.certificateIssuer }
	};
}
function parseCrlExtensionFields(e, t, n) {
	if (t?.tag !== 160) return {};
	if (n !== 2) throw Error("CRL extensions require version 2");
	let r = {}, i = /* @__PURE__ */ new Set(), a = requireElement(childrenOf(e, t)[0], "crl extensions");
	for (let t of childrenOf(e, a)) parseCrlExtensionField(e, t, i, r);
	return r;
}
function parseCrlExtensionField(e, t, n, r) {
	let i = childrenOf(e, t);
	if (i.length < 2 || i.length > 3 || i.length === 3 && i[1]?.tag !== 1) throw Error("Malformed CRL extension");
	let a = decodeObjectIdentifier(requireElement(i[0], "extension OID").value);
	if (n.has(a)) throw Error(`Duplicate CRL extension OID: ${a}`);
	n.add(a);
	let o = i.length === 3 && decodeBoolean(requireElement(i[1], "extension critical").value), s = requireElement(i[i.length - 1], "extension value");
	if (s.tag !== 4) throw Error("CRL extension value must use OCTET STRING");
	if (!isSupportedCrlExtensionOid(a) && o) throw Error(`Unsupported critical CRL extension OID: ${a}`);
	applyParsedCrlExtensionField(a, s.value, r);
}
function isSupportedCrlExtensionOid(e) {
	return e === t.authorityKeyIdentifier || e === t.cRLNumber || e === t.deltaCRLIndicator || e === t.issuingDistributionPoint || e === t.freshestCRL;
}
function applyParsedCrlExtensionField(e, t$23, n) {
	if (e === t.authorityKeyIdentifier) {
		let e = parseAuthorityKeyIdentifier(t$23);
		e !== void 0 && (n.authorityKeyIdentifier = e);
	}
	e === t.cRLNumber && (n.crlNumber = decodeCrlNumber(t$23)), e === t.deltaCRLIndicator && (n.baseCrlNumber = decodeCrlNumber(t$23)), e === t.issuingDistributionPoint && (n.issuingDistributionPoint = parseIssuingDistributionPoint(t$23)), e === t.freshestCRL && (n.freshestCrlDistributionPoints = parseDistributionPoints(t$23));
}
/** Accepts PEM, DER, or already-parsed certificate and returns a parsed certificate. */
function normalizeCrlCertificate(e) {
	return hasParsedCertificateShape$1(e) ? parseCertificateDerOrThrow(new Uint8Array(e.der)) : parseCertificateFromSource(e);
}
function hasParsedCertificateShape$1(e) {
	return typeof e != "string" && "subjectPublicKeyInfoDer" in e;
}
function hasReparseableCrlShape(e) {
	return "der" in e && e.der instanceof Uint8Array;
}
// ../../dist/internal/verify/verify-path.js
/**
* Internal certificate path-building and signature-check helpers.
*
* Loads and parses candidate certificates, ranks issuer candidates by AKI/root
* affinity, matches against bare {@linkcode TrustAnchor}s, and performs the
* depth-first chain search used by the public verify APIs in `verify.ts`.
*
* @module
*/
/** Default upper bound on issuer candidates and trust anchors one path search may try. */
const s = 1e5;
/** Throws when a caller-supplied path-building limit is not a positive safe integer. */
function assertPathBuildingChecks(e) {
	if (e !== void 0 && (!Number.isSafeInteger(e) || e < 1)) throw RangeError(`Invalid maxPathBuildingChecks: must be an integer >= 1, got ${e}`);
}
/** Returns `true` if `at` falls within the certificate's notBefore/notAfter window (inclusive). */
function isWithinValidity(e, t) {
	return e.notBefore.getTime() <= t.getTime() && t.getTime() <= e.notAfter.getTime();
}
/** Returns `true` if the certificate's subject and issuer DNs are semantically equal (RFC 5280 §7.1). */
function isSelfIssued$2(e) {
	return compareDistinguishedNames(e.subject, e.issuer);
}
/** Counts non-self-issued CA certificates in positions 0..(index-1) for pathLength checking. */
function countCaCertificatesBelowParsed(e, t) {
	let n = 0;
	for (let r = 1; r < t; r += 1) {
		let t = e[r];
		t?.basicConstraints?.ca === !0 && !isSelfIssued$2(t) && (n += 1);
	}
	return n;
}
/** Parses an array of PEM/DER sources into parsed certificates, expanding multi-block PEM. */
function loadCertificates(e) {
	let t = [];
	for (let n of e) t.push(...expandSource(n));
	return t;
}
/** Parses exactly one certificate from a PEM/DER source. Throws if the source contains zero or multiple certificates. */
function loadSingleCertificate(e) {
	let t = expandSource(e), n = t[0];
	if (n === void 0) throw Error("No certificate found");
	if (t.length !== 1) throw Error("Expected a single certificate source");
	return n;
}
/** Verifies that `certificate` was signed by `issuer`'s public key. */
function verifyCertificateSignature(e, t) {
	return signatureCheck(() => verifySignedDataDetailed(e.signatureAlgorithmOid, e.signatureAlgorithmParametersDer, t.publicKeyAlgorithmOid, t.publicKeyParametersOid, t.subjectPublicKeyInfoDer, e.signatureValue, e.tbsCertificateDer));
}
/** Runs `verify` as a path check, reporting a runtime failure as `signature_invalid` and a decoding limit as `limit_exceeded`. */
async function signatureCheck(n) {
	let r;
	try {
		r = await n();
	} catch (n) {
		let r = decodeRefusalOf(n, i);
		if (r === void 0) throw n;
		return {
			ok: !1,
			code: r.code,
			reason: r.message
		};
	}
	return !r.ok && r.code === "verification_error" ? {
		ok: !1,
		code: "signature_invalid",
		reason: r.reason
	} : r;
}
/** The real signature checks, used unless a caller injects its own. */
const c = {
	certificate: verifyCertificateSignature,
	trustAnchor: verifyTrustAnchorSignature
};
const l = {
	"specific-failure": 3,
	"untrusted-anchor": 2,
	"missing-issuer": 1,
	none: 0
};
function isMoreSignificant(e, t) {
	let n = l[e.kind], r = l[t.kind];
	return n === r ? e.path.length > t.path.length : n > r;
}
/**
* Moves a diagnostic recorded below the certificate at `nodeIndex` onto a new
* prefix ending at that same certificate. A suffix that repeats a certificate
* of the new prefix cannot form a path, so only the prefix is reported.
*/
function rebaseDiagnostic(e, t, n) {
	let r = e.path.slice(t + 1), i = new Set(n.map((e) => fingerprint(e)));
	if (r.some((e) => i.has(fingerprint(e)))) return {
		kind: "none",
		path: n
	};
	let a = [...n, ...r], o = n.length - 1 - t;
	switch (e.kind) {
		case "none":
		case "untrusted-anchor": return {
			kind: e.kind,
			path: a
		};
		case "missing-issuer": return {
			kind: "missing-issuer",
			path: a,
			missingIssuerAt: e.missingIssuerAt + o
		};
		case "specific-failure": return {
			kind: "specific-failure",
			path: a,
			failure: e.failure.index === void 0 ? e.failure : {
				...e.failure,
				index: e.failure.index + o
			}
		};
		default: throw Error(`unreachable diagnostic ${String(e)}`);
	}
}
/**
* Depth-first chain search from leaf to root. Tries all issuer candidates,
* checking validity, CA constraints, AKI, pathLength, and signatures at each
* step. Returns the first fully anchored path or the deepest partial path
* with the best failure encountered.
*/
async function buildChainInternal(e, t, r, a, o, l, u = c, d = s, f = () => Promise.resolve(void 0)) {
	let p, m = [...t, ...r], h = /* @__PURE__ */ new Map(), g = /* @__PURE__ */ new Map(), _ = new Set(r.map((e) => fingerprint(e))), v = /* @__PURE__ */ new Map();
	for (let e of a) {
		let t = canonicalDnKey(e.subject), n = v.get(t);
		n === void 0 ? v.set(t, [e]) : n.push(e);
	}
	let y = { current: {
		kind: "none",
		path: [e]
	} }, b = /* @__PURE__ */ new Map(), x = [], S = /* @__PURE__ */ new Map(), C = {
		remaining: d,
		exhausted: !1
	}, w = /* @__PURE__ */ new Map();
	m.forEach((e, t) => {
		let n = canonicalDnKey(e.subject), r = h.get(n);
		r === void 0 ? h.set(n, [e]) : r.push(e), g.set(fingerprint(e), t);
	});
	let T = m.length + 1, E = fingerprint(e), D = await search(e, [e], /* @__PURE__ */ new Set([E]), 0);
	if (D !== void 0) {
		let e = D[D.length - 1];
		return {
			chain: D,
			foundTrustedRoot: !0,
			...p !== void 0 && { trustAnchor: p },
			anchorCertificateInChain: e !== void 0 && _.has(fingerprint(e))
		};
	}
	let O = y.current;
	if (C.exhausted) return {
		chain: O.path,
		foundTrustedRoot: !1,
		failure: l.failure("path_building_limit_exceeded", "path building stopped at its work limit", void 0, l.detail({
			expected: `at most ${d} issuer and trust-anchor checks`,
			actual: "limit reached before a trusted path was found"
		}))
	};
	switch (O.kind) {
		case "specific-failure": return {
			chain: O.path,
			foundTrustedRoot: !1,
			failure: O.failure
		};
		case "missing-issuer": return {
			chain: O.path,
			foundTrustedRoot: !1,
			missingIssuerAt: O.missingIssuerAt
		};
		case "untrusted-anchor":
		case "none": return {
			chain: O.path,
			foundTrustedRoot: !1
		};
		default: throw Error(`unreachable diagnostic ${String(O)}`);
	}
	async function search(e, t, n, r) {
		if (C.exhausted) return;
		let i = await f(e.subjectPublicKeyInfoDer);
		if (i !== void 0) {
			recordFailure(l.failure("public_key_distrusted", "certificate public key is explicitly distrusted", t.length - 1, l.detail({
				subjectCommonName: e.subject.values.commonName,
				actual: i
			})), t);
			return;
		}
		if (_.has(fingerprint(e))) return t;
		let a = await matchTrustAnchor(e, v, l, t.length - 1, verifyAnchorOnce, chargeBudget, f);
		if (C.exhausted) return;
		if (a.failure !== void 0 && recordFailure(a.failure, t), a.matched) return p = a.anchor, t;
		if (t.length > T) return;
		let o = `${fingerprint(e)}:${r}`, s = b.get(o);
		if (s !== void 0) {
			consider(rebaseDiagnostic(s.diagnostic, s.nodeIndex, t));
			return;
		}
		let c = { best: {
			kind: "none",
			path: t
		} };
		x.push(c);
		try {
			let i = await searchBelow(e, t, n, r);
			if (i !== void 0) return i;
		} finally {
			x.pop();
		}
		b.set(o, {
			diagnostic: c.best,
			nodeIndex: t.length - 1
		});
	}
	async function searchBelow(e, t, n, r) {
		let i = !1;
		for (let a of issuerCandidates(e)) {
			if (!chargeBudget()) return;
			if (!isIssuerOf(a, e)) continue;
			i = !0;
			let o = fingerprint(a);
			if (n.has(o)) continue;
			let s = await searchIssuerCandidate(e, a, o, t, n, r);
			if (s !== void 0) return s;
			if (C.exhausted) return;
		}
		i ? consider({
			kind: "none",
			path: t
		}) : recordMissingIssuers(e, t);
	}
	/** Yields the issuer bucket for `current`: AKI matches first, then roots, then input order. */
	function* issuerCandidates(e) {
		let t = canonicalDnKey(e.issuer), n = w.get(t);
		n === void 0 && (n = rankBucket(h.get(t) ?? [], g, _), w.set(t, n));
		let r = e.authorityKeyIdentifier;
		if (r === void 0) yield* n.ordered;
		else {
			yield* n.bySubjectKeyIdentifier.get(r) ?? [];
			for (let e of n.ordered) e.subjectKeyIdentifier !== r && (yield e);
		}
	}
	function recordMissingIssuers(e, t) {
		isSelfIssued$2(e) ? consider({
			kind: "untrusted-anchor",
			path: t
		}) : t.length > 1 && consider({
			kind: "missing-issuer",
			path: t,
			missingIssuerAt: t.length - 1
		});
	}
	async function searchIssuerCandidate(e, t, n, r, i, a) {
		let s = await evaluateIssuerCandidate(e, t, r, a, o, l, verifySignatureOnce);
		if (!s.ok) {
			recordFailure(s.failure, r);
			return;
		}
		let c = new Set(i);
		return c.add(n), await search(t, [...r, t], c, s.nextCaBelowCount);
	}
	function chargeBudget() {
		return C.remaining === 0 ? (C.exhausted = !0, !1) : (--C.remaining, !0);
	}
	function verifySignatureOnce(e, t) {
		return verifyOnce(`c:${fingerprint(e)}:${toHex(t.subjectPublicKeyInfoDer)}`, () => u.certificate(e, t));
	}
	function verifyAnchorOnce(e, t) {
		let r = `${t.publicKeyAlgorithmOid}:${t.publicKeyParametersOid ?? ""}:${toHex(t.subjectPublicKeyInfoDer)}`;
		return verifyOnce(`a:${fingerprint(e)}:${r}`, () => u.trustAnchor(e, t));
	}
	/** One signature check per distinct certificate-and-key pair for the whole search. */
	function verifyOnce(e, t) {
		let n = S.get(e);
		return n === void 0 && (n = t(), S.set(e, n)), n;
	}
	function consider(e) {
		isMoreSignificant(e, y.current) && (y.current = e);
		for (let t of x) isMoreSignificant(e, t.best) && (t.best = e);
	}
	function recordFailure(e, t) {
		consider({
			kind: "specific-failure",
			path: t,
			failure: e
		});
	}
}
/** Applies issuer constraints and signature verification to one path candidate. */
async function evaluateIssuerCandidate(e, t, n, r, i, a, o) {
	let s = evaluateIssuerConstraints(e, t, n, r, i, a);
	if (!s.ok) return s;
	let c = await o(e, t);
	return c.ok ? c.valid ? s : {
		ok: !1,
		failure: a.failure("signature_invalid", "certificate signature does not verify", n.length - 1, a.detail({
			subjectCommonName: e.subject.values.commonName,
			issuerCommonName: t.subject.values.commonName
		}))
	} : {
		ok: !1,
		failure: a.failure(c.code, c.reason, n.length - 1, a.detail({
			subjectCommonName: e.subject.values.commonName,
			issuerCommonName: t.subject.values.commonName,
			actual: c.reason
		}))
	};
}
function evaluateIssuerConstraints(e, t, n, r, i, a) {
	return isWithinValidity(t, i) ? t.basicConstraints?.ca === !0 ? evaluateIssuerKeyConstraints(e, t, n, r, a) : {
		ok: !1,
		failure: a.failure("ca_required", "issuer must be a CA certificate", n.length, a.detail({ subjectCommonName: t.subject.values.commonName }))
	} : {
		ok: !1,
		failure: a.failure("certificate_expired", "certificate not valid at requested time", n.length, a.detail({
			subjectCommonName: t.subject.values.commonName,
			expected: describeDateTime$1(i),
			actual: `${describeDateTime$1(t.notBefore)}..${describeDateTime$1(t.notAfter)}`
		}))
	};
}
function evaluateIssuerKeyConstraints(e, t, n, r, i) {
	if (t.keyUsage !== void 0 && !t.keyUsage.flags.includes("keyCertSign")) return {
		ok: !1,
		failure: i.failure("key_cert_sign_required", "issuer missing keyCertSign", n.length, i.detail({ subjectCommonName: t.subject.values.commonName }))
	};
	if (authorityKeyIdentifierMismatch(e, t)) return {
		ok: !1,
		failure: i.failure("authority_key_identifier_mismatch", "authorityKeyIdentifier does not match issuer subjectKeyIdentifier", n.length - 1, i.detail({
			subjectCommonName: e.subject.values.commonName,
			issuerCommonName: t.subject.values.commonName,
			expected: t.subjectKeyIdentifier,
			actual: e.authorityKeyIdentifier
		}))
	};
	let a = r + +(e.basicConstraints?.ca === !0 && !isSelfIssued$2(e) && n.length > 1), o = t.basicConstraints?.pathLength;
	return isNonNegativeInteger$2(o) && a > o ? {
		ok: !1,
		failure: i.failure("path_length_exceeded", "path length constraint exceeded", n.length, i.detail({
			subjectCommonName: t.subject.values.commonName,
			expected: String(o),
			actual: String(a)
		}))
	} : {
		ok: !0,
		nextCaBelowCount: a
	};
}
function authorityKeyIdentifierMismatch(e, t) {
	return e.authorityKeyIdentifier !== void 0 && t.subjectKeyIdentifier !== void 0 && e.authorityKeyIdentifier !== t.subjectKeyIdentifier;
}
/** Expands a PEM (possibly multi-block) or DER source into parsed certificates. */
function expandSource(e) {
	return parseCertificatesFromSource(e);
}
/** Orders one subject bucket once, roots first and then input order, and indexes it by SKI. */
function rankBucket(e, t, n) {
	let r = [...e].sort((e, r) => {
		let i = fingerprint(e), a = fingerprint(r), o = compareBooleans(n.has(i), n.has(a));
		return o === 0 ? (t.get(i) ?? 2 ** 53 - 1) - (t.get(a) ?? 2 ** 53 - 1) : o;
	}), i = /* @__PURE__ */ new Map();
	for (let e of r) {
		let t = e.subjectKeyIdentifier;
		if (t === void 0) continue;
		let n = i.get(t);
		n === void 0 ? i.set(t, [e]) : n.push(e);
	}
	return {
		ordered: r,
		bySubjectKeyIdentifier: i
	};
}
/** Sort comparator: `true` sorts before `false`. Returns -1, 0, or 1. */
function compareBooleans(e, t) {
	return e === t ? 0 : e ? -1 : 1;
}
/** Returns `true` if `issuer`'s subject DN semantically matches `child`'s issuer DN (RFC 5280 §7.1). */
function isIssuerOf(e, t) {
	return compareDistinguishedNames(t.issuer, e.subject);
}
/** Attempts to verify `certificate` against each bare trust anchor whose subject DN matches. */
async function matchTrustAnchor(e, t, n, r, o, s, c) {
	let l = t.get(canonicalDnKey(e.issuer));
	if (l === void 0) return { matched: !1 };
	let u;
	for (let t of l) {
		if (!s()) return { matched: !1 };
		if (trustAnchorAkiMismatch(e, t) || !compareDistinguishedNames(e.issuer, t.subject)) continue;
		let i = await c(t.subjectPublicKeyInfoDer);
		if (i !== void 0) {
			u = n.failure("public_key_distrusted", "bare trust anchor public key is explicitly distrusted", void 0, n.detail({ actual: i }));
			continue;
		}
		let l = await o(e, t);
		if (!l.ok) u ??= n.failure(l.code, l.reason, r, n.detail({
			subjectCommonName: e.subject.values.commonName,
			actual: l.reason
		}));
		else if (!l.valid) u === void 0 && (u = n.failure("signature_invalid", "certificate signature does not verify", r, n.detail({
			subjectCommonName: e.subject.values.commonName,
			actual: "certificate signature does not verify"
		})));
		else return {
			matched: !0,
			anchor: t
		};
	}
	return u === void 0 ? { matched: !1 } : {
		matched: !1,
		failure: u
	};
}
function trustAnchorAkiMismatch(e, t) {
	return t.subjectKeyIdentifier !== void 0 && e.authorityKeyIdentifier !== void 0 && t.subjectKeyIdentifier !== e.authorityKeyIdentifier;
}
/** Verifies that `certificate` was signed by a bare trust anchor's key. */
function verifyTrustAnchorSignature(e, t) {
	return signatureCheck(() => verifySignedDataDetailed(e.signatureAlgorithmOid, e.signatureAlgorithmParametersDer, t.publicKeyAlgorithmOid, t.publicKeyParametersOid, t.subjectPublicKeyInfoDer, e.signatureValue, e.tbsCertificateDer));
}
function describeDateTime$1(e) {
	return Number.isNaN(e.getTime()) ? "<invalid date>" : e.toISOString();
}
function isNonNegativeInteger$2(e) {
	return e !== void 0 && Number.isInteger(e) && e >= 0;
}
/** Cache for computed fingerprints to avoid repeated toHex() calls. */
const u = /* @__PURE__ */ new WeakMap();
/** Returns a hex fingerprint of the certificate's raw DER, used for cycle detection and dedup. */
function fingerprint(e) {
	let t = u.get(e);
	return t === void 0 && (t = toHex(e.der), u.set(e, t)), t;
}
// ../../dist/verify/identity.js
/**
* Service-identity matching (RFC 9525), with opt-in CN fallback from the
* obsoleted RFC 6125 §6.4.4.
*
* Compares a reference identifier (hostname, IP, URI, SRV name) against the
* presented identifiers in a certificate's SAN extension, with optional
* common-name fallback for DNS names.
*
* @module
*/
/**
* Checks whether a certificate covers the requested service identity.
*
* Delegates to {@linkcode matchCertificateServiceIdentity} — this overload
* accepts a single options object.
*
* @example
* ```ts
* const result = matchServiceIdentity({
*   certificate: parsed,
*   serviceIdentity: { type: 'dns', value: 'example.com' },
* });
* if (!result.ok) console.error(result.error.message);
* ```
*/
function matchServiceIdentity(e) {
	return matchCertificateServiceIdentity(e.certificate, e.serviceIdentity);
}
/**
* Compares a reference identifier against a certificate's SAN entries.
*
* Supports DNS (with wildcard matching), IP, URI-ID, and SRV-ID.
* For DNS, optionally falls back to subject CN when no SAN of a supported type is present.
*
* @example
* ```ts
* const result = matchCertificateServiceIdentity(parsed, {
*   type: 'ip',
*   value: '192.168.1.1',
* });
* ```
*
* @example
* ```ts
* const result = matchCertificateServiceIdentity(parsed, {
*   type: 'dns',
*   value: 'mail.example.com',
*   allowCommonNameFallback: true,
* });
* ```
*/
function matchCertificateServiceIdentity(t, n$23) {
	let r;
	try {
		r = parseCertificateDerOrThrow(new Uint8Array(t.der));
	} catch (t) {
		let n$22 = decodeRefusalOf(t, n);
		return n$22 === void 0 ? failure$1("subject_alt_name_mismatch", "certificate input is malformed") : failure$1(n$22.code, n$22.message);
	}
	switch (n$23.type) {
		case "dns": return matchDnsServiceIdentity(r, n$23);
		case "ip": return matchIpServiceIdentity(r, n$23);
		case "uri": return matchScopedServiceIdentity(r, n$23, {
			parse: tryParseUriServiceIdentity,
			sanType: "uri",
			missingMessage: "URI-ID not present in SAN",
			serviceMismatchMessage: "URI scheme not present in SAN",
			domainMismatchMessage: "URI host not present in SAN"
		});
		case "srv": return matchScopedServiceIdentity(r, n$23, {
			parse: tryParseSrvServiceIdentity,
			sanType: "srv",
			missingMessage: "SRV-ID not present in SAN",
			serviceMismatchMessage: "SRV service not present in SAN",
			domainMismatchMessage: "SRV domain not present in SAN"
		});
		default: return failure$1("unsupported_service_identity_type", "Unsupported service identity type");
	}
}
/** Matches a DNS service identity against SANs and the explicitly enabled CN fallback. */
function matchDnsServiceIdentity(e, t) {
	if (typeof t.value != "string") return malformedServiceIdentityFailure(e, "dns", t.value);
	let n = t.value, r = e.subjectAltNames?.filter((e) => e.type === "dns") ?? [];
	return r.some((e) => matchesDnsName(e.value, n)) ? success() : matchDnsFallback(e, n, r, t.allowCommonNameFallback === !0);
}
function matchDnsFallback(e, t, n, r) {
	let i = presentedDnsIdentifierTypes(e);
	return r && i.length > 0 ? failure$1("common_name_fallback_suppressed", "DNS name not present in SAN; CN fallback suppressed because supported SAN identifiers exist", details(e.subject.values.commonName, t, n.map((e) => e.value).join(","), {
		presentedIdentifierTypes: i,
		commonNameFallbackReason: "suppressed_by_presented_identifier"
	})) : n.length > 0 ? failure$1("subject_alt_name_mismatch", "DNS name not present in SAN", details(e.subject.values.commonName, t, n.map((e) => e.value).join(","))) : r ? matchCommonNameFallback(e, t) : failure$1("subject_alt_name_mismatch", "DNS name not present in SAN", details(e.subject.values.commonName, t, "", { commonNameFallbackReason: "disabled" }));
}
function matchCommonNameFallback(e, t) {
	let n = e.subject.values.commonName;
	return n !== void 0 && matchesDnsName(n, t) ? success() : failure$1("subject_alt_name_mismatch", "DNS name not present in SAN or CN", details(n, t, n ?? "", { commonNameFallbackReason: n === void 0 ? "common_name_missing" : "common_name_mismatch" }));
}
function matchIpServiceIdentity(e, t) {
	if (typeof t.value != "string") return malformedServiceIdentityFailure(e, "ip", t.value);
	let n = tryParsePresentedIpAddress(t.value);
	return n === void 0 ? malformedServiceIdentityFailure(e, "ip", t.value) : matchParsedIpServiceIdentity(e, n);
}
function matchParsedIpServiceIdentity(e, t) {
	let n = decodeIpAddress(t), r = e.subjectAltNames?.filter((e) => e.type === "ip") ?? [], i = [];
	for (let a of r) {
		let r = tryParsePresentedIpAddress(a.value);
		if (r === void 0) return failure$1("subject_alt_name_mismatch", "IP address SAN is malformed", details(e.subject.values.commonName, n, `ip:${a.value}`));
		if (i.push(decodeIpAddress(r)), sameIpAddressBytes(r, t)) return success();
	}
	return failure$1("subject_alt_name_mismatch", "IP address not present in SAN", details(e.subject.values.commonName, n, i.join(",")));
}
function matchScopedServiceIdentity(e, t, n) {
	if (typeof t.value != "string") return malformedServiceIdentityFailure(e, t.type, t.value);
	let r = n.parse(t.value, "reference");
	if (r === void 0) return malformedServiceIdentityFailure(e, t.type, t.value);
	let i = e.subjectAltNames?.filter((e) => isScopedSubjectAltName(e, n.sanType)) ?? [], a = i.flatMap((e) => {
		let t = n.parse(e.value, "presented");
		return t === void 0 || t.serviceType !== r.serviceType ? [] : [t];
	});
	return a.some((e) => matchesServiceHost(e.host, r.host)) ? success() : scopedServiceIdentityFailure(e, r, i, a, n);
}
function isScopedSubjectAltName(e, t) {
	return e.type === t;
}
function scopedServiceIdentityFailure(e, t, n, r, i) {
	return r.length > 0 ? failure$1("subject_alt_name_mismatch", i.domainMismatchMessage, details(e.subject.values.commonName, serviceHostText(t.host), r.map((e) => serviceHostText(e.host)).join(","))) : n.length > 0 ? failure$1("service_identity_mismatch", i.serviceMismatchMessage, details(e.subject.values.commonName, t.serviceType, n.flatMap((e) => serviceTypeFromSanValue(e.value, i.parse)).join(","))) : failure$1("subject_alt_name_mismatch", i.missingMessage, details(e.subject.values.commonName, serviceHostText(t.host), ""));
}
function serviceTypeFromSanValue(e, t) {
	let n = t(e, "presented");
	return n === void 0 ? [] : [n.serviceType];
}
/** Compares a presented DNS identifier (possibly wildcarded) against a reference name. */
function matchesDnsName(e, t) {
	let n = normalizeDnsPattern(e), r = tryNormalizeDnsName(t);
	if (r === void 0) return !1;
	if (!n.includes("*")) return n === r;
	if (!n.startsWith("*.")) return !1;
	let i = n.slice(1);
	if (!r.endsWith(i)) return !1;
	let a = r.slice(0, r.length - i.length);
	return a.length > 0 && !a.includes(".");
}
/**
* Lowercases the ASCII letters of a presented DNS identifier and nothing else:
* RFC 9549 §2.3 compares DNS names by a case-insensitive exact match, so no
* percent-decoding, IPv4 parsing or IDNA mapping applies to what the
* certificate presents.
*/
function normalizeDnsPattern(e) {
	return e.replace(/[A-Z]/g, (e) => e.toLowerCase());
}
/**
* RFC 9525 §6.3: a reference domain name in A-labels, lowercased. Returns
* `undefined` for a name with URI delimiters or one that is not valid IDNA2008.
*/
function tryNormalizeDnsName(e) {
	if (!(e.length === 0 || /[/:?#@[\]]/.test(e))) return referenceDomainToAscii(e);
}
/** RFC 9525 §6.3 compares domain names and §6.4 compares IP addresses by their octets. */
function matchesServiceHost(e, t) {
	return e.type === "ip" ? t.type === "ip" && sameIpAddressBytes(e.bytes, t.bytes) : t.type === "dns" && matchesDnsName(e.name, t.name);
}
function serviceHostText(e) {
	return e.type === "ip" ? decodeIpAddress(e.bytes) : e.name;
}
/** Returns which SAN types (dns, uri, srv) the certificate presents, used for CN-fallback suppression. */
function presentedDnsIdentifierTypes(e) {
	let t = e.subjectAltNames ?? [], n = [];
	for (let e of [
		"dns",
		"uri",
		"srv"
	]) t.some((t) => t.type === e) && n.push(e);
	return n;
}
/** RFC 9525 §6.2: a URI-ID's scheme and the host of its authority, or of a SIP URI. */
function tryParseUriServiceIdentity(e, t) {
	let n = e.indexOf(":");
	if (n <= 0 || !/^[A-Za-z][A-Za-z0-9+.-]*$/.test(e.slice(0, n))) return;
	let r = e.slice(0, n).toLowerCase(), i = r === "sip" || r === "sips", a = uriServiceHost(i ? sipUriHost(e.slice(n + 1), t) : uriAuthorityHost(e, t), t === "presented" && !i);
	return a === void 0 ? void 0 : {
		serviceType: r,
		host: a
	};
}
/** RFC 3261 §25.1 userinfo without its "@": a non-empty user and an optional password. */
const p = /^(?:[A-Za-z0-9\-_.!~*'()&=+$,;?/]|%[0-9A-Fa-f]{2})+(?::(?:[A-Za-z0-9\-_.!~*'()&=+$,]|%[0-9A-Fa-f]{2})*)?$/;
const m = /^(?:;(?:[A-Za-z0-9\-_.!~*'()[\]/:&+$]|%[0-9A-Fa-f]{2})+(?:=(?:[A-Za-z0-9\-_.!~*'()[\]/:&+$]|%[0-9A-Fa-f]{2})+)?)*$/;
const h = /^(?:\?(?:[A-Za-z0-9\-_.!~*'()[\]/?:+$]|%[0-9A-Fa-f]{2})+=(?:[A-Za-z0-9\-_.!~*'()[\]/?:+$]|%[0-9A-Fa-f]{2})*(?:&(?:[A-Za-z0-9\-_.!~*'()[\]/?:+$]|%[0-9A-Fa-f]{2})+=(?:[A-Za-z0-9\-_.!~*'()[\]/?:+$]|%[0-9A-Fa-f]{2})*)*)?$/;
const g = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z](?:[a-z0-9-]*[a-z0-9])?$/i;
/**
* RFC 3261 §25.1: the only "@" a SIP URI may hold ends its userinfo, and its
* hostport is a hostname or IP address with no escaped octets and a port of at
* least one digit. The uri-parameters and headers after it follow their
* grammar, with every "%" opening an escaped octet (§19.1.2), and no parameter
* name appears twice (§19.1.1). RFC 5922 §7.1 forbids accepting a presented
* SIP URI with a userpart as a SIP domain identity.
*/
function sipUriHost(e, t) {
	let n = e.indexOf("@"), r = e.slice(n + 1), i = r.split(/[;?]/, 1)[0] ?? "", a = r.slice(i.length), o = a.includes("?") ? a.indexOf("?") : a.length, s = a.slice(0, o);
	if (n >= 0 && t === "presented" || n >= 0 && !p.test(e.slice(0, n)) || !m.test(s) || !h.test(a.slice(o)) || hasRepeatedParameter(s) || i.includes("%") || i.endsWith(":")) return { type: "invalid" };
	let c = hostportHost(i, t);
	return c.type === "ip" || c.type === "dns" && g.test(c.name) ? c : { type: "invalid" };
}
/** RFC 3261 §19.1.4 compares parameter names without regard to case. */
function hasRepeatedParameter(e) {
	let t = e.split(";").slice(1).map((e) => (e.split("=", 1)[0] ?? "").toLowerCase());
	return new Set(t).size !== t.length;
}
/**
* RFC 9525 §6.3: a presented wildcard is the whole left-most label of the
* domain name. RFC 5922 §7.2 prohibits wildcards for SIP domains.
*/
function uriServiceHost(e, t) {
	switch (e.type) {
		case "dns":
		case "ip": return e;
		case "regName": {
			let n = t && e.value.startsWith("*.") ? presentedDomainToAscii(e.value.slice(2)) : void 0;
			return n === void 0 ? void 0 : {
				type: "dns",
				name: `*.${n}`
			};
		}
		case "absent":
		case "invalid": return;
		default: throw Error(`Unhandled UriHost type: ${String(e)}`);
	}
}
/**
* RFC 4985 §2 `_Service.Name`. RFC 9525 §6.3 lets a presented Name open with
* a `*` label.
*/
function tryParseSrvServiceIdentity(e, t) {
	if (!e.startsWith("_")) return;
	let n = e.indexOf(".");
	if (n <= 1 || n === e.length - 1) return;
	let r = e.slice(n + 1), i = t === "presented" && r.startsWith("*."), a = tryNormalizeDnsName(i ? r.slice(2) : r), o = a === void 0 ? void 0 : parsePresentedSrvName(`${e.slice(0, n).toLowerCase()}.${a}`);
	return o === void 0 ? void 0 : {
		serviceType: o.service.slice(1),
		host: {
			type: "dns",
			name: i ? `*.${o.name}` : o.name
		}
	};
}
/** Constructs a failure result with the given error code and diagnostic details. */
function failure$1(e, r, i) {
	let a = {
		ok: !1,
		...micro509Error(e, r, i)
	};
	return errorResult(a);
}
/** Constructs a success result indicating the identity matched. */
function success() {
	return successResult(void 0);
}
function malformedServiceIdentityFailure(e, t, n) {
	let r = typeof n == "string" ? n : "<malformed>";
	return failure$1("subject_alt_name_mismatch", "service identity input is malformed", details(e.subject.values.commonName, `${t}:${r}`, t));
}
function tryParsePresentedIpAddress(e) {
	try {
		return parseIpAddressToBytes(e);
	} catch {
		return;
	}
}
function sameIpAddressBytes(e, t) {
	if (e.length !== t.length) return !1;
	for (let n = 0; n < e.length; n += 1) if (e[n] !== t[n]) return !1;
	return !0;
}
/** Assembles failure detail fields, merging optional CN-fallback and identifier-type info. */
function details(e, t, n, r) {
	return {
		...e === void 0 ? {} : { subjectCommonName: e },
		expected: t,
		actual: n,
		...r?.presentedIdentifierTypes === void 0 ? {} : { presentedIdentifierTypes: r.presentedIdentifierTypes },
		...r?.commonNameFallbackReason === void 0 ? {} : { commonNameFallbackReason: r.commonNameFallbackReason }
	};
}
// ../../dist/internal/verify/name-constraints-engine.js
/**
* Internal name-constraints evaluation engine.
*
* Accumulates and evaluates the shipped RFC 5280
* [§4.2.1.10](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10) / [§6.1](https://datatracker.ietf.org/doc/html/rfc5280#section-6.1)
* name-constraint subset during certificate path validation.
*
* @module
*/
/** Constructs a {@linkcode NameConstraintValidationFailure} with optional details. */
function nameConstraintFailure(e, t, n, r) {
	return {
		ok: !1,
		code: e,
		message: t,
		index: n,
		...r === void 0 ? {} : { details: r }
	};
}
/** Strips undefined fields and returns `undefined` when all fields are empty. */
function nameConstraintDetails(e) {
	let t = {
		...e.subjectCommonName === void 0 ? {} : { subjectCommonName: e.subjectCommonName },
		...e.actual === void 0 ? {} : { actual: e.actual }
	};
	return Object.keys(t).length === 0 ? void 0 : t;
}
/** A certificate is self-issued when subject and issuer DNs are semantically equal (RFC 5280 §7.1). */
function isSelfIssued$1(e) {
	return compareDistinguishedNames(e.subject, e.issuer);
}
/**
* Initializes validation state from caller-supplied initial constraints.
*
* Call once before {@linkcode evaluateNameConstraints}.
*/
function createNameConstraintValidationState(e) {
	return {
		initialPermittedSubtrees: e.permittedSubtrees?.map((e) => e.base) ?? [],
		initialExcludedSubtrees: e.excludedSubtrees?.map((e) => e.base) ?? []
	};
}
/**
* Walks the chain root-to-leaf, accumulating nameConstraints from CA
* certificates and checking each non-self-issued certificate's names
* against the accumulated constraints.
*
* RFC 5280 §6.1.3(b)-(c) for name checks, §6.1.4(g) for constraint accumulation.
*/
function evaluateNameConstraints(e, t) {
	let n = seedInitialNameConstraints(t), r = e[e.length - 1];
	r?.nameConstraints !== void 0 && (n = accumulateConstraints(n, r.nameConstraints, hasCriticalNameConstraintsExtension(r)));
	for (let t = e.length - 2; t >= 0; --t) {
		let r = e[t];
		if (r === void 0) throw Error(`Certificate chain contains undefined at index ${String(t)}`);
		if (!isSelfIssued$1(r) || t === 0) {
			let e = checkCertificateNames(r, n, t);
			if (!e.ok) return e;
		}
		r.nameConstraints !== void 0 && (n = accumulateConstraints(n, r.nameConstraints, hasCriticalNameConstraintsExtension(r)));
	}
	return { ok: !0 };
}
/** True when the certificate carries a critical nameConstraints extension. */
function hasCriticalNameConstraintsExtension(e) {
	return e.extensions.some((e) => e.oid === t.nameConstraints && e.critical);
}
/** Converts initial state into the starting accumulated-constraints snapshot. */
function seedInitialNameConstraints(e) {
	return {
		permittedLevels: e.initialPermittedSubtrees.length > 0 ? [e.initialPermittedSubtrees] : [],
		excluded: e.initialExcludedSubtrees,
		unsupportedCriticalForms: /* @__PURE__ */ new Set(),
		unsupportedCriticalOtherNames: /* @__PURE__ */ new Set()
	};
}
/**
* Merges one certificate's nameConstraints extension into the running totals.
*
* Unsupported constraint forms from a critical extension are recorded so
* subsequent certificates carrying a name of that form fail closed
* (RFC 5280 §4.2.1.10). Unsupported forms in a non-critical extension are
* dropped — the RFC's rejection requirement is scoped to critical
* extensions (conforming CAs MUST mark nameConstraints critical anyway).
*/
function accumulateConstraints(e, t, n) {
	let r = t.permittedSubtrees !== void 0 && t.permittedSubtrees.length > 0 ? [...e.permittedLevels, t.permittedSubtrees.flatMap((e) => isSupportedNameConstraintForm(e.base) ? [e.base] : [])] : e.permittedLevels, i = t.excludedSubtrees !== void 0 && t.excludedSubtrees.length > 0 ? [...e.excluded, ...t.excludedSubtrees.flatMap((e) => isSupportedNameConstraintForm(e.base) ? [e.base] : [])] : e.excluded, a = n ? listUnsupportedNameConstraintForms(t) : [];
	return {
		permittedLevels: r,
		excluded: i,
		unsupportedCriticalForms: /* @__PURE__ */ new Set([...e.unsupportedCriticalForms, ...a.flatMap((e) => e.type === "otherName" ? [] : [e.type])]),
		unsupportedCriticalOtherNames: /* @__PURE__ */ new Set([...e.unsupportedCriticalOtherNames, ...a.flatMap((e) => e.type === "otherName" ? [e.typeId] : [])])
	};
}
/** Collects the unsupported GeneralName forms from a nameConstraints extension. */
function listUnsupportedNameConstraintForms(e) {
	return [...e.permittedSubtrees ?? [], ...e.excludedSubtrees ?? []].flatMap((e) => isSupportedNameConstraintForm(e.base) ? [] : [e.base]);
}
/** True for name forms this engine can evaluate: dns, email, uri, ip, directoryName, srv. */
function isSupportedNameConstraintForm(e) {
	switch (e.type) {
		case "dns":
		case "email":
		case "uri":
		case "ip":
		case "directoryName":
		case "srv": return !0;
		case "otherName":
		case "x400Address":
		case "ediPartyName":
		case "registeredID": return !1;
		default: throw Error(`Unhandled NameConstraintForm type: ${String(e)}`);
	}
}
/**
* Checks a certificate's subject DN and SANs against accumulated
* name constraints. Returns a failure if any name violates constraints.
*/
function checkCertificateNames(n$21, r, i) {
	try {
		let e = checkCertificateSubjectName(n$21, r, i);
		if (!e.ok) return e;
		let t = checkCertificateSubjectAltNames(n$21, r, i);
		return t.ok ? checkCertificateSubjectEmailFallback(n$21, r, i) : t;
	} catch (r) {
		let a = decodeRefusalOf(r, n);
		if (a === void 0) throw r;
		return nameConstraintFailure(a.code, a.message, i, nameConstraintDetails({
			subjectCommonName: n$21.subject.values.commonName,
			actual: a.message
		}));
	}
}
/** Checks a certificate subject DN against the accumulated directory-name constraints. */
function checkCertificateSubjectName(e, t, n) {
	return e.subject.derHex === "3000" || isNamePermitted({
		type: "directoryName",
		derHex: e.subject.derHex
	}, t) ? { ok: !0 } : nameConstraintFailure("name_constraints_violated", "subject distinguished name violates name constraints", n, nameConstraintDetails({ subjectCommonName: e.subject.values.commonName }));
}
function checkCertificateSubjectAltNames(e, t, n) {
	for (let r of e.subjectAltNames ?? []) {
		let i = checkCertificateSubjectAltName(e, t, r, n);
		if (!i.ok) return i;
	}
	return { ok: !0 };
}
function checkCertificateSubjectAltName(e, t, n, r) {
	let i = unprocessableConstraintFormOf(n, t);
	if (i !== void 0) return nameConstraintFailure("unsupported_name_constraints", `critical name constraints impose ${i} constraints that cannot be processed, and the certificate contains a ${i} subject alternative name`, r, nameConstraintDetails({
		subjectCommonName: e.subject.values.commonName,
		actual: i
	}));
	if (n.type === "smtpUtf8Mailbox") return checkSmtpUtf8Mailbox(e, t, n.value, r);
	let a = sanToConstraintCheckable(n);
	if (!a.ok) return nameConstraintFailure("name_constraints_violated", `SAN ${a.actual} is malformed and cannot be checked against name constraints`, r, nameConstraintDetails({
		subjectCommonName: e.subject.values.commonName,
		actual: a.actual
	}));
	let o = a.value;
	return o?.type === "srv" && accumulatedHasConstraintsOfType("srv", t) && parsePresentedSrvName(asciiLowercase(o.value)) === void 0 ? nameConstraintFailure("name_constraints_violated", `SAN srv:${o.value} is not _Service.Name and cannot be evaluated against SRVName constraints`, r, nameConstraintDetails({
		subjectCommonName: e.subject.values.commonName,
		actual: `srv:${o.value}`
	})) : o?.type === "uri" && accumulatedHasConstraintsOfType("uri", t) && uriConstraintHost(o.value) === void 0 ? nameConstraintFailure("name_constraints_violated", `SAN uri:${o.value} has no FQDN authority host and cannot be evaluated against URI name constraints`, r, nameConstraintDetails({
		subjectCommonName: e.subject.values.commonName,
		actual: `uri:${o.value}`
	})) : o === void 0 || isNamePermitted(o, t) ? { ok: !0 } : nameConstraintFailure("name_constraints_violated", `SAN ${formatConstraintForm(o)} violates name constraints`, r, nameConstraintDetails({
		subjectCommonName: e.subject.values.commonName,
		actual: formatConstraintForm(o)
	}));
}
/**
* RFC 9598 §6 applies rfc822Name constraints to a SmtpUTF8Mailbox by its domain
* alone: the Local-part and "@" are stripped from the name and the constraint,
* and the remaining domains compare octet for octet after lowercasing, as a
* suffix when the constraint starts with ".". A mailbox that breaks the §3
* syntax cannot be compared, so it fails whenever rfc822Name constraints are
* in force.
*/
function checkSmtpUtf8Mailbox(e, t, n, r) {
	return !accumulatedHasEmailConstraints(t) || isSmtpUtf8MailboxDomainPermitted(n, t) ? { ok: !0 } : nameConstraintFailure("name_constraints_violated", `SAN smtpUtf8Mailbox:${n} violates name constraints`, r, nameConstraintDetails({
		subjectCommonName: e.subject.values.commonName,
		actual: `smtpUtf8Mailbox:${n}`
	}));
}
/** RFC 9598 §5: a presented SmtpUTF8Mailbox whose domain the email constraints permit. */
function isSmtpUtf8MailboxDomainPermitted(e, t) {
	let n = presentedSmtpUtf8MailboxDomain(e);
	return n !== void 0 && isMailboxDomainPermitted(n, t);
}
function isMailboxDomainPermitted(e, t) {
	if (hasMalformedConstraint("email", t)) return !1;
	let matches = (t) => t.type === "email" && matchesMailboxDomainConstraint(e, t.value);
	return !t.excluded.some(matches) && t.permittedLevels.every((e) => !e.some((e) => e.type === "email") || e.some(matches));
}
/**
* A dNSName or rfc822Name constraint whose domain is not a well-formed name
* cannot be compared, so no name of its type is permitted while one is in force.
*/
function hasMalformedConstraint(e, t) {
	return [...t.excluded, ...t.permittedLevels.flat()].some((t) => t.type === e && !isWellFormedConstraint(t));
}
function isWellFormedConstraint(e) {
	switch (e.type) {
		case "dns": {
			let t = asciiLowercase(e.value);
			return t.length === 0 || isComparableDomain(t.startsWith(".") ? t.slice(1) : t);
		}
		case "email": return constraintMailboxDomain(e.value) !== void 0;
		case "srv": return parseSrvNameRestriction(asciiLowercase(e.value)) !== void 0;
		case "directoryName": return parseDirectoryNameDerHex(e.derHex) !== void 0;
		case "uri": return parseUriNameConstraint(e.value) !== void 0;
		case "ip": return !0;
		default: throw Error(`Unhandled NameConstraintForm type: ${String(e)}`);
	}
}
/** Labels of 1 to 63 letters, digits, hyphens or underscores, with each `xn--` label an A-label. */
function isComparableDomain(e) {
	return e.length <= 253 && e.split(".").every((e) => /^[a-z0-9_-]{1,63}$/.test(e)) && domainToAscii(e, "lookup").ok;
}
/** RFC 9598 §6: the lowercased domain of an rfc822Name constraint, keeping a leading ".". */
function constraintMailboxDomain(e) {
	let t = asciiLowercase(e.slice(e.lastIndexOf("@") + 1)), n = t.startsWith(".") ? t.slice(1) : t;
	return isMailboxDomain(n, "lookup") ? t : void 0;
}
function matchesMailboxDomainConstraint(e, t) {
	let n = constraintMailboxDomain(t);
	return n?.startsWith(".") === !0 ? e.endsWith(n) : e === n;
}
function asciiLowercase(e) {
	return e.replace(/[A-Z]/g, (e) => e.toLowerCase());
}
function checkCertificateSubjectEmailFallback(e, t, n) {
	return accumulatedHasEmailConstraints(t) && !(e.subjectAltNames?.some((e) => e.type === "email") ?? !1) && e.subject.values.emailAddress !== void 0 && !isNamePermitted({
		type: "email",
		value: e.subject.values.emailAddress
	}, t) ? nameConstraintFailure("name_constraints_violated", `subject emailAddress ${e.subject.values.emailAddress} violates name constraints`, n, nameConstraintDetails({
		subjectCommonName: e.subject.values.commonName,
		actual: e.subject.values.emailAddress
	})) : { ok: !0 };
}
/** True when any level of accumulated constraints addresses the email name form. */
function accumulatedHasEmailConstraints(e) {
	for (let t of e.permittedLevels) if (t.some((e) => e.type === "email")) return !0;
	return e.excluded.some((e) => e.type === "email");
}
/** True when any level of accumulated constraints addresses the given name form. */
function accumulatedHasConstraintsOfType(e, t) {
	return [...t.excluded, ...t.permittedLevels.flat()].some((t) => t.type === e);
}
/**
* The unprocessable critical constraint form a SAN instantiates, if one is in
* force. An otherName is its own form per type-id. Raw `unknown` input carries
* the DER tag byte, and an unknown otherName meets every otherName type-id.
*/
function unprocessableConstraintFormOf(e, t$19) {
	let otherName = (e) => t$19.unsupportedCriticalOtherNames.has(e) ? `otherName ${e}` : void 0, direct = (e) => t$19.unsupportedCriticalForms.has(e) ? e : void 0;
	switch (e.type) {
		case "otherName": return otherName(e.typeId);
		case "smtpUtf8Mailbox": return otherName(t.idOnSmtpUtf8Mailbox);
		case "upn": return otherName(t.ntPrincipalName);
		case "krb5PrincipalName": return otherName(t.idPkinitSan);
		case "x400Address":
		case "ediPartyName":
		case "registeredID": return direct(e.type);
		case "unknown": return unknownTagForm(e.tag, t$19);
		default: return;
	}
}
function unknownTagForm(e, t) {
	let n;
	switch (e) {
		case 163:
			n = "x400Address";
			break;
		case 165:
			n = "ediPartyName";
			break;
		case 136:
			n = "registeredID";
			break;
		case 160: return t.unsupportedCriticalOtherNames.size > 0 ? "otherName" : void 0;
		default: return;
	}
	return t.unsupportedCriticalForms.has(n) ? n : void 0;
}
/**
* Converts a SubjectAltName to a NameConstraintForm for checking.
* Returns `undefined` for name forms that don't participate in
* constraint checking (unknown tags).
*/
function sanToConstraintCheckable(e) {
	switch (e.type) {
		case "dns": return {
			ok: !0,
			value: {
				type: "dns",
				value: e.value
			}
		};
		case "email": return {
			ok: !0,
			value: {
				type: "email",
				value: e.value
			}
		};
		case "uri": return {
			ok: !0,
			value: {
				type: "uri",
				value: e.value
			}
		};
		case "srv": return {
			ok: !0,
			value: {
				type: "srv",
				value: e.value
			}
		};
		case "smtpUtf8Mailbox":
		case "upn":
		case "krb5PrincipalName":
		case "otherName":
		case "x400Address":
		case "ediPartyName":
		case "registeredID": return {
			ok: !0,
			value: void 0
		};
		case "ip": try {
			return {
				ok: !0,
				value: {
					type: "ip",
					addressBytes: parseIpAddressToBytes(e.value),
					maskBytes: allOnesMaskForIpAddress(e.value)
				}
			};
		} catch {
			return {
				ok: !1,
				actual: `ip:${e.value}`
			};
		}
		case "directoryName": return {
			ok: !0,
			value: {
				type: "directoryName",
				derHex: e.derHex
			}
		};
		case "unknown": return {
			ok: !0,
			value: void 0
		};
		default: throw Error(`Unhandled SubjectAltName type: ${String(e)}`);
	}
}
/**
* Checks whether a name is permitted by the accumulated constraints.
* A name is permitted if:
* 1. It does NOT match any excluded constraint, AND
* 2. For every permitted level that contains constraints of the same
*    name form, it matches at least one.
*/
function isNamePermitted(e, t) {
	if (hasMalformedConstraint(e.type, t) || endsInRootDot(e) && accumulatedHasConstraintsOfType(e.type, t)) return !1;
	for (let n of t.excluded) if (nameConstraintMatch(e, n) !== "mismatch") return !1;
	for (let n of t.permittedLevels) {
		let t = n.filter((t) => t.type === e.type);
		if (t.length !== 0 && !t.some((t) => nameConstraintMatch(e, t) === "match")) return !1;
	}
	return !0;
}
/** RFC 5280 §4.2.1.6: a dNSName or rfc822Name host in RFC 1034 §3.5 preferred name syntax has no trailing root dot. */
function endsInRootDot(e) {
	return (e.type === "dns" || e.type === "email") && e.value.endsWith(".");
}
/** RFC 4518 §2: a comparison that string preparation cannot perform is Undefined. */
function nameConstraintMatch(e, t) {
	return e.type === "directoryName" && t.type === "directoryName" ? matchesDnConstraint(e.derHex, t.derHex) : nameMatchesConstraint(e, t) ? "match" : "mismatch";
}
/** Dispatches to the type-specific matching function for the name form. */
function nameMatchesConstraint(e, t) {
	return e.type === "dns" && t.type === "dns" ? matchesDnsConstraint(e.value, t.value) : e.type === "email" && t.type === "email" ? matchesEmailConstraint(e.value, t.value) : e.type === "uri" && t.type === "uri" ? matchesUriConstraint(e.value, t.value) : e.type === "ip" && t.type === "ip" ? matchesIpConstraint(e.addressBytes, t.addressBytes, t.maskBytes) : e.type === "srv" && t.type === "srv" && matchesSrvConstraint(e.value, t.value);
}
/**
* RFC 4985 §4: a restriction's service, when present, must equal the SRVName's
* service case-insensitively (§2), and its Name, when present, is satisfied by
* that domain or any subdomain added to the left.
*/
function matchesSrvConstraint(e, t) {
	let n = parsePresentedSrvName(asciiLowercase(e)), r = parseSrvNameRestriction(asciiLowercase(t));
	return n !== void 0 && r !== void 0 && (r.service.length === 0 || n.service === r.service) && (r.name.length === 0 || n.name === r.name || n.name.endsWith(`.${r.name}`));
}
/**
* DNS name constraint matching. RFC 5280 §4.2.1.10 adds zero or more labels on
* the left; §7.2 compares label by label case-insensitively. Constraint
* "example.com" matches "example.com" and any subdomain. RFC 5280 defines no
* leading-period dNSName form; ".example.com" matches subdomains only, as in
* OpenSSL, BoringSSL, Go, NSS, mozilla::pkix and rustls-webpki (RFC 5280
* erratum 5997).
*/
function matchesDnsConstraint(e, t) {
	let n = e.toLowerCase(), r = t.toLowerCase();
	return r.length === 0 ? !0 : r.startsWith(".") ? n.endsWith(r) : n === r || n.endsWith(`.${r}`);
}
/**
* RFC 5280 §4.2.1.10 email constraint matching, deferring to §7.5 (as
* replaced by RFC 9549 §7.5.1): the local part matches exactly, the host part
* case-insensitively.
* - "user@example.com" constrains the local part exactly and the host case-insensitively.
* - "example.com" matches any address whose host is example.com.
* - ".example.com" matches any address under a subdomain of example.com.
*/
function matchesEmailConstraint(e, t) {
	if (t.includes("@")) {
		let n = e.lastIndexOf("@"), r = t.lastIndexOf("@");
		return n < 0 || r < 0 || e.slice(0, n) !== t.slice(0, r) ? !1 : e.slice(n + 1).toLowerCase() === t.slice(r + 1).toLowerCase();
	}
	let n = e.lastIndexOf("@");
	if (n < 0) return !1;
	let r = e.slice(n + 1).toLowerCase(), i = t.toLowerCase();
	return i.startsWith(".") ? r.endsWith(i) : r === i;
}
/**
* RFC 5280 §4.2.1.10: a URI constraint applies to the host part, a constraint
* without a leading period names one host, and ".example.com" is satisfied by
* its subdomains only.
*/
function matchesUriConstraint(e, t) {
	let n = uriConstraintHost(e), r = parseUriNameConstraint(t);
	if (n === void 0 || r === void 0) return !1;
	switch (r.type) {
		case "any": return !0;
		case "host": return n === r.name;
		case "subdomains": return n.endsWith(`.${r.name}`);
		default: throw Error(`Unhandled UriNameConstraint type: ${String(r)}`);
	}
}
/**
* RFC 5280 §4.2.1.10: the domain name of a URI's authority host, which a URI
* constraint in force requires. `undefined` for no authority, an IP address, a
* reg-name that is not a domain name, or a single-label host.
*/
function uriConstraintHost(e) {
	let t = uriAuthorityHost(e, "presented");
	return t.type === "dns" && t.name.includes(".") ? t.name : void 0;
}
/**
* RFC 5280 §4.2.1.10: IP constraint matching.
* (nameiP & mask) == (constraintiP & mask)
*/
function matchesIpConstraint(e, t, n) {
	if (e.length !== t.length) return !1;
	for (let r = 0; r < e.length; r += 1) {
		let i = e[r] ?? 0, a = t[r] ?? 0, o = n[r] ?? 0;
		if ((i & o) !== (a & o)) return !1;
	}
	return !0;
}
/**
* RFC 5280 §4.2.1.10: DirectoryName constraint matching.
* The subject DN must equal or be subordinate to the constraint DN,
* using RFC 5280 section 7.1 name comparison semantics.
*/
function matchesDnConstraint(e, t) {
	let n = parseDirectoryNameDerHex(e), r = parseDirectoryNameDerHex(t);
	return n === void 0 || r === void 0 ? "mismatch" : directoryNameSubtreeMatch(n, r);
}
/** Re-parses a hex-encoded DER Name for RDN-by-RDN comparison. Returns `undefined` on malformed input. */
function parseDirectoryNameDerHex(t) {
	if (/^(?:[0-9a-fA-F]{2})+$/.test(t)) try {
		let e = hexToBytes(t), n = unwrapDirectoryNameElement(e, readRootElement(e, { maxDepth: 64 }));
		if (n.tag !== 48) return;
		let a = [], o = [], c = {};
		for (let t of childrenOf(e, n)) {
			let n = parseDirectoryNameRdn(e, t);
			if (n === void 0) return;
			a.push(n);
			for (let e of n.attributes) o.push(e), e.key !== void 0 && c[e.key] === void 0 && (c[e.key] = e.value);
		}
		return {
			derHex: toHex(e),
			rdns: a,
			attributes: o,
			values: c
		};
	} catch (t) {
		rethrowDecodeRefusal(t, n);
		return;
	}
}
/**
* Unwraps doubly-nested directoryName SEQUENCE encoding.
*
* Some encoders produce `[4] { SEQ { SEQ { SET... } } }` instead of `[4] { SEQ { SET... } }`.
* A single SEQUENCE child indicates the extra wrapper (valid Names have SET children).
*/
function unwrapDirectoryNameElement(e, t) {
	if (t.tag !== 48) return t;
	let n = childrenOf(e, t), r = n[0];
	return n.length === 1 && r?.tag === 48 ? r : t;
}
/** Parses one SET element (a single RDN) from the DER Name SEQUENCE. */
function parseDirectoryNameRdn(t, r) {
	if (r.tag !== 49) return;
	let s = childrenOf(t, r);
	if (s.length === 0) return;
	let u = [], d = {};
	for (let r of s) {
		if (r.tag !== 48) return;
		let s = childrenOf(t, r), l = s[0], f = s[1];
		if (l === void 0 || f === void 0 || s.length !== 2 || l.tag !== 6) return;
		let p = decodeObjectIdentifier(requireElement(l, "directoryName OID").value), m;
		try {
			m = decodeString(f.tag, requireElement(f, "directoryName value").value);
		} catch (t) {
			rethrowDecodeRefusal(t, n);
			return;
		}
		let h = nameFieldKeyFromOid(p), g = h === void 0 ? {
			oid: p,
			valueTag: f.tag,
			value: m
		} : {
			oid: p,
			key: h,
			valueTag: f.tag,
			value: m
		};
		u.push(g), h !== void 0 && d[h] === void 0 && (d[h] = m);
	}
	if (u.length !== 0) return {
		derHex: toHex(t.slice(r.start - r.headerLength, r.end)),
		attributes: u,
		values: d
	};
}
/** Human-readable label for a constraint form, used in error messages. */
function formatConstraintForm(e) {
	switch (e.type) {
		case "dns": return `dns:${e.value}`;
		case "email": return `email:${e.value}`;
		case "uri": return `uri:${e.value}`;
		case "ip": return `ip:${decodeIpAddress(e.addressBytes)}`;
		case "directoryName": return `dn:${e.derHex.slice(0, 20)}${e.derHex.length > 20 ? "..." : ""}`;
		case "srv": return `srv:${e.value}`;
		default: throw Error(`Unhandled NameConstraintForm type: ${String(e)}`);
	}
}
// ../../dist/internal/verify/policy-engine.js
/**
* Internal RFC 9618 policy-validation engine.
*
* Tracks the policy graph and counter state through each certificate in a
* chain, then derives the {@linkcode PolicyValidationOutcome}.
*
* @module
*/
/**
* Initializes mutable policy state from caller options.
*
* Counter values default to `chainLength + 1` (effectively disabled) unless
* the corresponding input flag is `true`.
*/
function createPolicyValidationState(e, t) {
	let n = t + 1;
	return {
		initialPolicySet: e.initialPolicySet ?? "any",
		explicitPolicy: e.requireExplicitPolicy === !0 ? 0 : n,
		inhibitPolicyMapping: e.inhibitPolicyMapping === !0 ? 0 : n,
		inhibitAnyPolicy: e.inhibitAnyPolicy === !0 ? 0 : n,
		validPolicyGraph: createInitialPolicyGraph()
	};
}
/**
* Walks the chain root-to-leaf, updating policy state per certificate,
* then checks whether the resulting policy set satisfies caller requirements.
*/
function evaluatePolicyChain(e, t, n = !0) {
	if (e.length === 0) throw RangeError("policy validation requires at least one certificate");
	processPolicyState(e, t, n);
	let r = derivePolicyValidationOutcome(t);
	return t.explicitPolicy === 0 && r.userConstrainedPolicies.length === 0 ? {
		ok: !1,
		error: {
			code: "explicit_policy_required",
			message: "policy validation requires an explicit permitted policy",
			details: {
				expected: t.initialPolicySet === "any" ? "explicit policy" : t.initialPolicySet.join(","),
				actual: describeFinalPolicies(r.userConstrainedPolicies)
			}
		}
	} : t.initialPolicySet !== "any" && r.userConstrainedPolicies.length === 0 ? {
		ok: !1,
		error: {
			code: "initial_policy_set_not_satisfied",
			message: "certificate chain does not satisfy the requested initial policy set",
			details: {
				expected: t.initialPolicySet.join(","),
				actual: describeFinalPolicies(r.userConstrainedPolicies)
			}
		}
	} : {
		ok: !0,
		value: r
	};
}
/** Builds the depth-0 graph with a single anyPolicy root node. */
function createInitialPolicyGraph() {
	let t$10 = createPolicyGraphNode(0, t.anyPolicy, void 0, [t.anyPolicy], []);
	return { nodesByDepth: [/* @__PURE__ */ new Map([[policyNodeKey(0, t.anyPolicy), t$10]])] };
}
/** Constructs a new {@linkcode PolicyGraphNode} with empty child-key set. */
function createPolicyGraphNode(e, t, n, r, i) {
	return {
		depth: e,
		validPolicy: t,
		...n === void 0 ? {} : { qualifierSet: n },
		expectedPolicySet: new Set(r),
		parentKeys: new Set(i),
		childKeys: /* @__PURE__ */ new Set()
	};
}
/** Canonical map key for a graph node: `"depth:policyOID"`. */
function policyNodeKey(e, t) {
	return `${String(e)}:${t}`;
}
/**
* Applies each path certificate's policies to the state, top CA first. When
* `anchorInChain` is true the terminal certificate is the trust anchor and is
* excluded; a bare anchor leaves the terminal certificate a path certificate
* that must be processed.
*/
function processPolicyState(e, t, n) {
	if (e.length === 1) {
		let n = e[0];
		if (n === void 0) throw Error(`missing certificate at chain index 0 (chain length ${String(e.length)})`);
		processPolicyCertificate(t, n, 1, !0);
		return;
	}
	let r = n ? e.length - 1 : e.length;
	for (let n = r - 1; n >= 0; --n) {
		let i = e[n];
		if (i === void 0) throw Error(`missing certificate at chain index ${String(n)} (chain length ${String(e.length)})`);
		let a = r - n;
		processPolicyCertificate(t, i, a, a === r);
	}
}
/** Extracts the authority- and user-constrained policy sets from the completed graph (RFC 9618 §5.5 step (g)). */
function derivePolicyValidationOutcome(e) {
	let t = collectAuthorityConstrainedPolicies(e.validPolicyGraph);
	return {
		authorityConstrainedPolicies: [...t.values()].sort(comparePolicies),
		userConstrainedPolicies: deriveUserConstrainedPolicies(t, e.initialPolicySet)
	};
}
/**
* RFC 9618 §5.5 (g)(2)-(4) authority_constrained_policy_set. The
* valid_policy_node_set is every graph node, at any depth, whose valid_policy is
* not anyPolicy and whose single parent is an anyPolicy node, plus a depth-n
* anyPolicy node when present. Pruning has already removed nodes with no path to
* the leaf, so the whole graph is the final tree.
*/
function collectAuthorityConstrainedPolicies(t$11) {
	if (t$11 === null) return /* @__PURE__ */ new Map();
	let n = /* @__PURE__ */ new Map(), record = (e) => {
		let r = n.get(e.validPolicy) ?? [];
		r.push(...gatherLineageQualifiers(t$11, e)), n.set(e.validPolicy, r);
	};
	for (let n of t$11.nodesByDepth) for (let r of n.values()) r.validPolicy !== t.anyPolicy && r.parentKeys.size === 1 && getSingleParent(t$11, r)?.validPolicy === t.anyPolicy && record(r);
	let r = t$11.nodesByDepth.length - 1, i = t$11.nodesByDepth[r]?.get(policyNodeKey(r, t.anyPolicy));
	i !== void 0 && record(i);
	let a = /* @__PURE__ */ new Map();
	for (let [e, t] of n) a.set(e, buildConstrainedPolicy(e, dedupeQualifiers(t)));
	return a;
}
/** Returns the sole parent of a node whose parent list has exactly one entry. */
function getSingleParent(e, t) {
	let n = [...t.parentKeys][0];
	return n === void 0 ? void 0 : getPolicyGraphNode(e, n);
}
/** RFC 9618 §5.5 (g)(4)(ii): qualifiers from a node, its ancestors, and its descendants. */
function gatherLineageQualifiers(e, t) {
	let n = [...t.qualifierSet ?? []];
	return collectDirectionalQualifiers(e, t.parentKeys, (e) => e.parentKeys, n), collectDirectionalQualifiers(e, t.childKeys, (e) => e.childKeys, n), n;
}
/** Follows one edge direction transitively, appending each visited node's qualifiers. */
function collectDirectionalQualifiers(e, t, n, r) {
	let i = /* @__PURE__ */ new Set(), a = [...t];
	for (; a.length > 0;) {
		let t = a.pop();
		if (t === void 0 || i.has(t)) continue;
		i.add(t);
		let o = getPolicyGraphNode(e, t);
		if (o !== void 0) {
			o.qualifierSet !== void 0 && r.push(...o.qualifierSet);
			for (let e of n(o)) a.push(e);
		}
	}
}
/** Deduplicates qualifiers by value, returning `undefined` when none remain. */
function dedupeQualifiers(e) {
	let t = /* @__PURE__ */ new Set(), n = [];
	for (let r of e) {
		let e = JSON.stringify(r, (e, t) => t instanceof Uint8Array ? Array.from(t) : t);
		t.has(e) || (t.add(e), n.push(r));
	}
	return n.length === 0 ? void 0 : n;
}
/**
* RFC 9618 §5.5 (g)(5)-(6) user_constrained_policy_set. It equals the
* authority-constrained set when the initial-policy-set is anyPolicy. Otherwise
* it keeps the members named in the initial-policy-set, and, when the authority
* set holds anyPolicy, adds the remaining requested OIDs with anyPolicy's
* qualifiers.
*/
function deriveUserConstrainedPolicies(t$12, n) {
	if (n === "any") return [...t$12.values()].sort(comparePolicies);
	let r = /* @__PURE__ */ new Map();
	for (let [e, i] of t$12) n.includes(e) && r.set(e, i);
	let i = t$12.get(t.anyPolicy);
	if (i !== void 0) for (let e of n) r.has(e) || r.set(e, buildConstrainedPolicy(e, i.policyQualifiers));
	return [...r.values()].sort(comparePolicies);
}
/** Constructs a {@linkcode ConstrainedPolicy}, omitting qualifiers when absent. */
function buildConstrainedPolicy(e, t) {
	return {
		policyIdentifier: e,
		...t === void 0 ? {} : { policyQualifiers: t }
	};
}
/** Lexicographic comparator for sorting policies by OID string. */
function comparePolicies(e, t) {
	return e.policyIdentifier.localeCompare(t.policyIdentifier);
}
/** Human-readable comma-joined OID list for error messages; `"<none>"` when empty. */
function describeFinalPolicies(e) {
	return e.length === 0 ? "<none>" : e.map((e) => e.policyIdentifier).join(",");
}
/** Applies one certificate's policies, mappings, and constraints to the running state. */
function processPolicyCertificate(e, t, n, r) {
	let i = normalizeCertificatePolicies(t.certificatePolicies);
	e.validPolicyGraph !== null && i === void 0 ? e.validPolicyGraph = null : e.validPolicyGraph !== null && i !== void 0 && (applyCertificatePolicyStep(e.validPolicyGraph, i, n, e.inhibitAnyPolicy > 0 || !r && isSelfIssued(t)), !r && t.policyMappings !== void 0 && applyPolicyMappingsStep(e.validPolicyGraph, n, t.policyMappings, e.inhibitPolicyMapping > 0)), updatePolicyCounters(e, t, r);
}
/** Deduplicates certificate policies by OID, keeping the first occurrence. */
function normalizeCertificatePolicies(e) {
	if (e === void 0) return;
	let t = /* @__PURE__ */ new Map();
	for (let n of e) t.has(n.policyIdentifier) || t.set(n.policyIdentifier, n);
	return t;
}
/** Extends the policy graph by one depth level using a certificate's policy extension. */
function applyCertificatePolicyStep(t$13, n, r, i) {
	let a = t$13.nodesByDepth[r - 1] ?? /* @__PURE__ */ new Map(), o = /* @__PURE__ */ new Map();
	t$13.nodesByDepth[r] = o;
	let s = n.get(t.anyPolicy), c = a.get(policyNodeKey(r - 1, t.anyPolicy)), l = policyNodeKey(r - 1, t.anyPolicy);
	addPolicyNodesFromExpectedParents(t$13, o, a, n, r), c !== void 0 && addPolicyNodesFromPreviousAnyPolicy(t$13, o, n, r, l), s !== void 0 && i && addAnyPolicyExpansionNodes(t$13, o, a, r, s, l, c !== void 0), prunePolicyGraph(t$13, r - 1);
}
/** Adds explicit certificate-policy nodes whose expected policies match parent nodes. */
function addPolicyNodesFromExpectedParents(t$14, n, r, i, a) {
	for (let o of i.values()) {
		if (o.policyIdentifier === t.anyPolicy) continue;
		let i = collectParentsForExpectedPolicy(r, o.policyIdentifier);
		i.length !== 0 && addOrMergePolicyNode(t$14, n, a, o.policyIdentifier, o.policyQualifiers, i, [o.policyIdentifier]);
	}
}
function addPolicyNodesFromPreviousAnyPolicy(t$15, n, r, i, a) {
	for (let o of r.values()) o.policyIdentifier !== t.anyPolicy && (n.has(policyNodeKey(i, o.policyIdentifier)) || addOrMergePolicyNode(t$15, n, i, o.policyIdentifier, o.policyQualifiers, [a], [o.policyIdentifier]));
}
/** Expands an accepted anyPolicy entry into the policies expected by the previous depth. */
function addAnyPolicyExpansionNodes(e, t, n, r, i, a, o) {
	for (let [s, c] of collectExpectedPolicyParents(n)) {
		if (t.has(policyNodeKey(r, s))) continue;
		let n = collectAnyPolicyExpansionParents(s, c, a, o);
		n.length !== 0 && addOrMergePolicyNode(e, t, r, s, i.policyQualifiers, n, [s]);
	}
}
function collectAnyPolicyExpansionParents(t$16, n, r, i) {
	return t$16 === t.anyPolicy ? i ? [r] : [] : n;
}
/** Finds all previous-depth nodes whose expectedPolicySet contains the given OID. */
function collectParentsForExpectedPolicy(e, t) {
	let n = [];
	for (let [r, i] of e) i.expectedPolicySet.has(t) && n.push(r);
	return n;
}
/** Groups all previous-depth nodes by each OID in their expectedPolicySet. */
function collectExpectedPolicyParents(e) {
	let t = /* @__PURE__ */ new Map();
	for (let [n, r] of e) for (let e of r.expectedPolicySet) {
		let r = t.get(e);
		r === void 0 ? t.set(e, [n]) : r.push(n);
	}
	return t;
}
/** Inserts a node at the current depth, or merges parents/expected-policies into an existing one. */
function addOrMergePolicyNode(e, t, n, r, i, a, o) {
	let s = policyNodeKey(n, r), c = t.get(s);
	if (c !== void 0) {
		for (let t of a) c.parentKeys.add(t), getPolicyGraphNode(e, t)?.childKeys.add(s);
		for (let e of o) c.expectedPolicySet.add(e);
		c.qualifierSet === void 0 && i !== void 0 && (c.qualifierSet = i);
		return;
	}
	let l = createPolicyGraphNode(n, r, i, o, a);
	t.set(s, l);
	for (let t of a) getPolicyGraphNode(e, t)?.childKeys.add(s);
}
/** Looks up a node by its `"depth:oid"` key, parsing the depth prefix. */
function getPolicyGraphNode(e, t) {
	let n = t.indexOf(":");
	if (n <= 0) return;
	let r = t.slice(0, n), i = Number.parseInt(r, 10);
	if (!Number.isNaN(i)) return e.nodesByDepth[i]?.get(t);
}
/** Removes childless leaf nodes bottom-up, cascading deletions through parent links. */
function prunePolicyGraph(e, t) {
	for (let n = t; n >= 0; --n) {
		let t = e.nodesByDepth[n];
		if (t !== void 0) for (let n of t.keys()) {
			let r = t.get(n);
			r === void 0 || r.childKeys.size > 0 || deletePolicyGraphNode(e, n);
		}
	}
}
/** Removes a node and recursively prunes its parents if they become childless. */
function deletePolicyGraphNode(e, t) {
	let n = getPolicyGraphNode(e, t);
	if (n !== void 0) {
		e.nodesByDepth[n.depth]?.delete(t);
		for (let r of n.parentKeys) {
			let n = getPolicyGraphNode(e, r);
			n !== void 0 && (n.childKeys.delete(t), n.childKeys.size === 0 && deletePolicyGraphNode(e, r));
		}
	}
}
/** Applies issuer→subject policy mappings at the current depth, or deletes mapped nodes when disallowed. */
function applyPolicyMappingsStep(t$18, n, r, i) {
	let a = t$18.nodesByDepth[n];
	if (a === void 0) return;
	let o = /* @__PURE__ */ new Map();
	for (let t$17 of r) {
		if (t$17.issuerDomainPolicy === t.anyPolicy || t$17.subjectDomainPolicy === t.anyPolicy) continue;
		let n = o.get(t$17.issuerDomainPolicy);
		n === void 0 ? o.set(t$17.issuerDomainPolicy, [t$17.subjectDomainPolicy]) : n.push(t$17.subjectDomainPolicy);
	}
	let s = a.get(policyNodeKey(n, t.anyPolicy));
	for (let [e, r] of o) {
		let o = policyNodeKey(n, e), c = a.get(o);
		if (i) {
			if (c !== void 0) {
				c.expectedPolicySet = new Set(r);
				continue;
			}
			s !== void 0 && addOrMergePolicyNode(t$18, a, n, e, s.qualifierSet, [...s.parentKeys], r);
		} else c !== void 0 && deletePolicyGraphNode(t$18, o);
	}
	prunePolicyGraph(t$18, n - 1);
}
/** Decrements explicitPolicy / inhibitPolicyMapping / inhibitAnyPolicy and applies policyConstraints overrides. */
function updatePolicyCounters(e, t, n) {
	n ? updateLeafPolicyCounter(e, t) : (isSelfIssued(t) || decrementPolicyCounters(e), applyPolicyCounterOverrides(e, t));
}
function updateLeafPolicyCounter(e, t) {
	decrementPositiveCounter(e, "explicitPolicy"), t.policyConstraints?.requireExplicitPolicy === 0 && (e.explicitPolicy = 0);
}
function decrementPolicyCounters(e) {
	decrementPositiveCounter(e, "explicitPolicy"), decrementPositiveCounter(e, "inhibitPolicyMapping"), decrementPositiveCounter(e, "inhibitAnyPolicy");
}
function decrementPositiveCounter(e, t) {
	e[t] > 0 && --e[t];
}
function applyPolicyCounterOverrides(e, t) {
	let n = t.policyConstraints;
	isNonNegativeInteger$1(n?.requireExplicitPolicy) && n.requireExplicitPolicy < e.explicitPolicy && (e.explicitPolicy = n.requireExplicitPolicy), isNonNegativeInteger$1(n?.inhibitPolicyMapping) && n.inhibitPolicyMapping < e.inhibitPolicyMapping && (e.inhibitPolicyMapping = n.inhibitPolicyMapping), isNonNegativeInteger$1(t.inhibitAnyPolicy?.skipCerts) && t.inhibitAnyPolicy.skipCerts < e.inhibitAnyPolicy && (e.inhibitAnyPolicy = t.inhibitAnyPolicy.skipCerts);
}
function isNonNegativeInteger$1(e) {
	return e !== void 0 && Number.isInteger(e) && e >= 0;
}
/** A certificate is self-issued when subject and issuer DNs are semantically equal (RFC 5280 §7.1). */
function isSelfIssued(e) {
	return compareDistinguishedNames(e.subject, e.issuer);
}
// ../../dist/internal/verify/spki-distrust.js
/** Caller-supplied SHA-256 SPKI distrust, scoped to one verification operation. */
/** Validates and snapshots the caller's hashes before any asynchronous work. */
function createSpkiDistrustCheck(r) {
	let i = /* @__PURE__ */ new Set();
	for (let e of r ?? []) {
		if (typeof e != "string" || !/^[0-9a-fA-F]{64}$/.test(e)) throw RangeError("distrustedSpkiSha256 entries must be 64 hexadecimal characters");
		i.add(e.toLowerCase());
	}
	let a = /* @__PURE__ */ new Map();
	return async (r) => {
		if (i.size === 0) return;
		let o = toHex(r), s = a.get(o);
		s === void 0 && (s = getCrypto().subtle.digest("SHA-256", toArrayBuffer(r)).then((e) => toHex(new Uint8Array(e))), a.set(o, s));
		let c = await s;
		return i.has(c) ? c : void 0;
	};
}
// ../../dist/revocation/ocsp.js
/**
* Full OCSP lifecycle: build requests, create/parse/verify/validate responses.
*
* Supports SHA-1 and SHA-256 cert-ID hashing, nonce replay protection,
* delegated responder certificate validation (direct and chain-based),
* and embedded responder certificate discovery.
*
* @module
*/
/** Throws a {@link ResultError} for an OCSP encoder input-validation failure. */
function throwOcspEncoderError(e, t) {
	throwMicro509Error(e, t);
}
function assertOcspDate(e, t) {
	e !== void 0 && Number.isNaN(e.getTime()) && throwOcspEncoderError("invalid_date", `${t} must be a valid date`);
}
function assertOcspRevocationReasonCode(e) {
	e !== void 0 && !(Number.isSafeInteger(e) && e >= 0) && throwOcspEncoderError("invalid_revocation_reason_code", "revocationReasonCode must be a non-negative integer");
}
/**
* Builds a DER-encoded OCSP request containing one or more CertID entries
* and an optional nonce extension.
*
* @example
* ```ts
* import { createOcspRequest } from 'micro509';
*
* const req = await createOcspRequest({
*   requests: [{ certificate: leafPem, issuerCertificate: caPem }],
*   hashAlgorithm: 'SHA-256',
*   nonce: crypto.getRandomValues(new Uint8Array(16)),
* });
* // POST req.der to the OCSP responder URI
* ```
*/
async function createOcspRequest(e) {
	let t$4 = e.hashAlgorithm ?? "SHA-256", n = [];
	for (let r of e.requests) {
		let e = normalizeCertificate(r.certificate), i = normalizeCertificate(r.issuerCertificate);
		n.push(sequence([await encodeOcspCertId(e, i, t$4)]));
	}
	let r = [sequence(n)];
	e.nonce !== void 0 && r.push(explicitContext(2, sequence([sequence([objectIdentifier(t.ocspNonce), octetString(octetString(e.nonce))])])));
	let i = sequence([sequence(r)]);
	return {
		der: i,
		pem: pemEncode("OCSP REQUEST", i),
		base64: base64Encode(i)
	};
}
/** Throwing core for {@linkcode parseOcspRequestDer}. */
function parseOcspRequestDerOrThrow(e) {
	let t = readSequenceChildren(e, { maxDepth: 64 });
	if (t.length < 1 || t.length > 2) throw Error("Malformed OCSP request");
	let n = requireElement(t[0], "tbsRequest"), r = t[1];
	if (r !== void 0 && r.tag !== 160) throw Error("Malformed OCSP request");
	r !== void 0 && validateOcspOptionalSignature(e, r);
	let i = childrenOf(e, n), a = skipOcspRequestVersion(e, i, 0);
	a = skipOcspRequestorName(e, i, a);
	let o = requireElement(i[a], "requestList");
	if (o.tag !== 48) throw Error("requestList must use SEQUENCE");
	if (childrenOf(e, o).length === 0) throw Error("requestList must not be empty");
	let s = childrenOf(e, o).map((t) => {
		let n = childrenOf(e, t);
		if (n.length < 1 || n.length > 2 || n[1] !== void 0 && n[1].tag !== 160) throw Error("Malformed OCSP request entry");
		let r = requireElement(n[0], "reqCert");
		return parseOcspCertId(e.slice(r.start - r.headerLength, r.end));
	});
	a += 1;
	let c = i[a];
	if (c !== void 0 && c.tag !== 162 || i.length !== a + (c === void 0 ? 0 : 1)) throw Error("Malformed OCSP request");
	let l = c === void 0 ? void 0 : parseOcspNonceFromExtensions(e, c);
	return {
		der: new Uint8Array(e),
		requests: s,
		...l === void 0 ? {} : { nonce: l }
	};
}
function skipOcspRequestVersion(e, t, n) {
	if (t[n]?.tag !== 160) return n;
	let r = requireElement(t[n], "version"), i = childrenOf(e, r), a = requireElement(i[0], "version");
	if (i.length !== 1 || a.tag !== 2) throw Error("version must use INTEGER");
	if (decodeNonNegativeIntegerNumber(a.value, "OCSP request version") !== 0) throw Error("Unsupported OCSP request version");
	return n + 1;
}
function skipOcspRequestorName(e, t, n) {
	let r = t[n];
	return r?.tag === 161 ? (validateOcspRequestorName(e, r), n + 1) : n;
}
/** Decodes a PEM-encoded OCSP request (`-----BEGIN OCSP REQUEST-----`). */
function parseOcspRequestPemOrThrow(e) {
	return parseOcspRequestDerOrThrow(pemDecodeOrThrow("OCSP REQUEST", e));
}
/**
* Decodes a DER-encoded OCSP request into a structured {@linkcode ParsedOcspRequest}.
*
* Returns a typed failure (`code: 'malformed'`) on malformed input. For the
* throwing form use {@linkcode parseOcspRequestDerOrThrow}.
*/
function parseOcspRequestDer(t) {
	try {
		return successResult(parseOcspRequestDerOrThrow(t));
	} catch (t) {
		return rethrowIfInvariant(t), decodeFailureResult(t, n, "Malformed OCSP request");
	}
}
/**
* Decodes a PEM-encoded OCSP request (`-----BEGIN OCSP REQUEST-----`).
*
* Returns a typed failure (`code: 'malformed'`) on malformed input. For the
* throwing form use {@linkcode parseOcspRequestPemOrThrow}.
*/
function parseOcspRequestPem(t) {
	try {
		return successResult(parseOcspRequestPemOrThrow(t));
	} catch (t) {
		return rethrowIfInvariant(t), decodeFailureResult(t, n, "Malformed OCSP request");
	}
}
/** Throwing core for {@linkcode parseOcspResponseDer}. */
function parseOcspResponseDerOrThrow(e) {
	let t$5 = readSequenceChildren(e, { maxDepth: 64 });
	if (t$5.length < 1 || t$5.length > 2) throw Error("Malformed OCSP response");
	let n = requireElement(t$5[0], "responseStatus");
	if (n.tag !== 10) throw Error("responseStatus must use ENUMERATED");
	let r = ocspResponseStatusFromCode(decodeNonNegativeIntegerNumber(n.value, "OCSP responseStatus")), i = t$5[1];
	if (i === void 0) return {
		der: new Uint8Array(e),
		responseStatus: r
	};
	if (i.tag !== 160) throw Error("Malformed OCSP response");
	let a = childrenOf(e, i), o = requireElement(a[0], "responseBytes");
	if (a.length !== 1 || o.tag !== 48) throw Error("Malformed OCSP response");
	let s = childrenOf(e, o);
	if (s.length !== 2) throw Error("responseBytes must contain responseType and response");
	let c = requireElement(s[0], "responseType"), l = requireElement(s[1], "response");
	if (l.tag !== 4) throw Error("response must use OCTET STRING");
	let u = decodeObjectIdentifier(c.value);
	if (u !== t.ocspBasicResponse) return {
		der: new Uint8Array(e),
		responseStatus: r,
		responseTypeOid: u
	};
	let d = l.value, f = readSequenceChildren(d);
	if (f.length < 3 || f.length > 4) throw Error("Malformed BasicOCSPResponse");
	let p = requireElement(f[0], "responseData"), m = requireElement(f[1], "signatureAlgorithm"), h = requireElement(f[2], "signatureValue"), g = f[3];
	if (g !== void 0 && g.tag !== 160) throw Error("Malformed BasicOCSPResponse");
	let _ = childrenOf(d, m), y = decodeObjectIdentifier(requireElement(_[0], "signatureAlgorithm OID").value), b = _[1], S = b === void 0 ? void 0 : d.slice(b.start - b.headerLength, b.end), T = d.slice(p.start - p.headerLength, p.end), D = parseSignedOcspResponseData(T);
	return {
		der: new Uint8Array(e),
		responseStatus: r,
		responseTypeOid: u,
		responseDataDer: T,
		responderId: D.responderId,
		signatureAlgorithmOid: y,
		...S === void 0 ? {} : { signatureAlgorithmParametersDer: S },
		signatureAlgorithmName: describeSignatureAlgorithm(y, S),
		signatureValue: extractBitStringValue(h),
		producedAt: D.producedAt,
		responses: D.responses,
		...D.nonce === void 0 ? {} : { nonce: D.nonce },
		...g?.tag === 160 ? { certificates: parseEmbeddedCertificates(d, g) } : {}
	};
}
/**
* Decodes a PEM-encoded OCSP response (`-----BEGIN OCSP RESPONSE-----`).
*
* @example
* ```ts
* import { parseOcspResponsePemOrThrow } from 'micro509';
*
* const resp = parseOcspResponsePemOrThrow(pemString);
* if (resp.responseStatus === 'successful') {
*   for (const entry of resp.responses ?? []) {
*     console.log(entry.certId.serialNumberHex, entry.certStatus);
*   }
* }
* ```
*/
function parseOcspResponsePemOrThrow(e) {
	return parseOcspResponseDerOrThrow(pemDecodeOrThrow("OCSP RESPONSE", e));
}
/**
* Decodes a DER-encoded OCSP response into a structured {@linkcode ParsedOcspResponse}.
*
* Returns a typed failure (`code: 'malformed'`) on malformed input. For the
* throwing form use {@linkcode parseOcspResponseDerOrThrow}.
*/
function parseOcspResponseDer(t) {
	try {
		return successResult(parseOcspResponseDerOrThrow(t));
	} catch (t) {
		return rethrowIfInvariant(t), decodeFailureResult(t, n, "Malformed OCSP response");
	}
}
/**
* Decodes a PEM-encoded OCSP response (`-----BEGIN OCSP RESPONSE-----`).
*
* Returns a typed failure (`code: 'malformed'`) on malformed input. For the
* throwing form use {@linkcode parseOcspResponsePemOrThrow}.
*/
function parseOcspResponsePem(t) {
	try {
		return successResult(parseOcspResponsePemOrThrow(t));
	} catch (t) {
		return rethrowIfInvariant(t), decodeFailureResult(t, n, "Malformed OCSP response");
	}
}
/**
* Signs and encodes an OCSP BasicResponse with a `successful` status.
*
* The responder is identified by key hash (SHA-1 of the signer's SubjectPublicKey).
* Use `includedCertificates` to embed the responder's chain for relying parties.
*
* @example
* ```ts
* import { createOcspResponse } from 'micro509';
*
* const resp = await createOcspResponse({
*   signerPrivateKey: responderPrivateKey,
*   signerCertificate: responderCertPem,
*   responses: [
*     {
*       certificate: leafPem,
*       issuerCertificate: caPem,
*       certStatus: 'good',
*       thisUpdate: new Date('2025-01-01'),
*       nextUpdate: new Date('2025-01-08'),
*     },
*   ],
*   nonce: requestNonce,
* });
* // resp.der, resp.pem, resp.base64
* ```
*/
async function createOcspResponse(e) {
	let t$6 = normalizeCertificate(e.signerCertificate), n = getSignatureAlgorithm(e.signerPrivateKey);
	getVerifySignatureConfigResult(n.algorithmOid, n.parameters, t$6.publicKeyAlgorithmOid, t$6.publicKeyParametersOid, "signer").ok || throwOcspEncoderError("signer_certificate_key_mismatch", "signerCertificate must carry a public key that verifies the signer key algorithm");
	let r = e.producedAt ?? /* @__PURE__ */ new Date();
	assertOcspDate(r, "producedAt");
	let i = e.hashAlgorithm ?? "SHA-256", a = [];
	for (let t of e.responses) {
		assertOcspDate(t.thisUpdate, "thisUpdate"), assertOcspDate(t.nextUpdate, "nextUpdate"), assertOcspDate(t.revokedAt, "revokedAt"), assertOcspRevocationReasonCode(t.revocationReasonCode);
		let e = normalizeCertificate(t.certificate), n = normalizeCertificate(t.issuerCertificate);
		a.push(await encodeSingleResponse(e, n, t, i));
	}
	let o = await digestBytes("SHA-1", extractSubjectPublicKeyBytes(t$6.subjectPublicKeyInfoDer)), c = [
		explicitContext(2, octetString(o)),
		generalizedTime(r),
		sequence(a)
	];
	e.nonce !== void 0 && c.push(explicitContext(1, sequence([sequence([objectIdentifier(t.ocspNonce), octetString(octetString(e.nonce))])])));
	let l = sequence(c), f = await signBytes(e.signerPrivateKey, n, l), p = e.includedCertificates === void 0 ? [] : await Promise.all(e.includedCertificates.map(normalizeCertificate)), g = [
		l,
		encodeAlgorithmIdentifier(n),
		bitString(f)
	];
	p.length > 0 && g.push(explicitContext(0, sequence(p.map((e) => e.der))));
	let _ = sequence(g), v = sequence([tlv(10, Uint8Array.of(0)), explicitContext(0, sequence([objectIdentifier(t.ocspBasicResponse), octetString(_)]))]);
	return {
		der: v,
		pem: pemEncode("OCSP RESPONSE", v),
		base64: base64Encode(v)
	};
}
/**
* Verifies the OCSP response signature against the given signer certificate.
*
* Does **not** check responder binding, freshness, or nonce — use
* {@linkcode validateOcspResponse} for full validation.
*/
async function verifyOcspResponseSignature(t, n$9) {
	let r;
	try {
		r = normalizeOcspResponse(t);
	} catch (t) {
		let n$8 = decodeRefusalOf(t, n);
		return n$8 === void 0 ? verifyOcspResponseFailureResult("signature_invalid", "OCSP response signed content is malformed") : verifyOcspResponseFailureResult(n$8.code, n$8.message);
	}
	if (r.responseDataDer === void 0 || r.signatureAlgorithmOid === void 0 || r.signatureValue === void 0) return verifyOcspResponseFailureResult("signature_invalid", "OCSP response is not signed");
	let i;
	try {
		i = normalizeCertificate(n$9);
	} catch (t) {
		let n$10 = decodeRefusalOf(t, n);
		return n$10 === void 0 ? verifyOcspResponseFailureResult("signature_invalid", "OCSP signer certificate input is malformed") : verifyOcspResponseFailureResult(n$10.code, n$10.message);
	}
	let a;
	try {
		a = await verifySignedDataDetailed(r.signatureAlgorithmOid, r.signatureAlgorithmParametersDer, i.publicKeyAlgorithmOid, i.publicKeyParametersOid, i.subjectPublicKeyInfoDer, r.signatureValue, r.responseDataDer);
	} catch (t) {
		let n$11 = decodeRefusalOf(t, n);
		return n$11 === void 0 ? verifyOcspResponseFailureResult("signature_invalid", "OCSP response signature verification failed") : verifyOcspResponseFailureResult(n$11.code, n$11.message);
	}
	return a.ok ? a.valid ? {
		ok: !0,
		value: r
	} : verifyOcspResponseFailureResult("signature_invalid", "OCSP response signature does not verify") : a.code === "verification_error" ? verifyOcspResponseFailureResult("signature_invalid", "OCSP response signature verification failed") : verifyOcspResponseFailureResult("signature_invalid", "OCSP response signature uses unsupported algorithm parameters");
}
/**
* Full OCSP response validation: response status check, signature verification,
* responder ID binding (byName or byKeyHash), delegated-responder chain and
* ocspSigning EKU checks, `producedAt`/`thisUpdate`/`nextUpdate` freshness,
* nonce match, and request-coverage completeness.
*
* @example
* ```ts
* import { validateOcspResponse } from 'micro509';
*
* const result = await validateOcspResponse({
*   response: ocspResponseDer,
*   issuerCertificate: caPem,
*   request: ocspRequestDer,
* });
* if (result.ok) {
*   const entry = result.value.responses?.[0];
*   console.log(entry?.certStatus); // 'good' | 'revoked' | 'unknown'
* }
* ```
*/
async function validateOcspResponse(t) {
	assertCrlMaxAge(t.responderRevocationCrlMaxAgeMs);
	let n$13;
	try {
		n$13 = normalizeOcspResponse(t.response);
	} catch (t) {
		let n$12 = decodeRefusalOf(t, n);
		return n$12 === void 0 ? validateOcspResponseFailureResult("signature_invalid", "OCSP response signed content is malformed") : validateOcspResponseFailureResult(n$12.code, n$12.message);
	}
	if (n$13.responseStatus !== "successful") return validateOcspResponseFailureResult("response_status_invalid", `OCSP response status is ${n$13.responseStatus}`);
	let r = await normalizeOcspValidationInput(t, n$13);
	if (!r.ok) return r;
	let { issuer: i, trustedResponders: a, signer: s } = r, c = await verifyOcspResponseSignature(n$13, s);
	if (!c.ok) return validateOcspResponseFailureResult(c.code, c.message);
	let l = await validateOcspResponderAuthorization(t, n$13, i, s, a);
	if (l !== void 0) return l;
	let u = t.at ?? /* @__PURE__ */ new Date(), d = t.clockSkewMs ?? 0, f = await validateOcspResponseFreshness(n$13, i, {
		at: u,
		skew: d,
		profile: t.profile ?? "rfc6960"
	});
	if (f !== void 0) return f;
	if (hasDuplicateOcspResponseCertificateSerial(n$13.responses ?? [])) return validateOcspResponseFailureResult("signature_invalid", "OCSP response contains multiple status entries for the same certificate");
	if (t.request !== void 0) {
		let e = validateOcspRequestCoverage(t.request, n$13);
		if (e !== void 0) return e;
	}
	return {
		ok: !0,
		value: n$13
	};
}
/** Re-parses OCSP validation certificates and resolves the response signer. */
async function normalizeOcspValidationInput(t, n$15) {
	let r;
	try {
		r = normalizeCertificate(t.issuerCertificate);
	} catch (t) {
		let n$14 = decodeRefusalOf(t, n);
		return n$14 === void 0 ? validateOcspResponseFailureResult("signature_invalid", "issuer certificate input is malformed") : validateOcspResponseFailureResult(n$14.code, n$14.message);
	}
	try {
		let e = (t.trustedOcspResponders ?? []).map(normalizeCertificate), i = await resolveOcspResponderCertificate(t, n$15, e);
		return {
			ok: !0,
			parsedResponse: n$15,
			issuer: r,
			trustedResponders: e,
			signer: normalizeCertificate(i)
		};
	} catch (t) {
		let n$16 = decodeRefusalOf(t, n);
		return n$16 === void 0 ? validateOcspResponseFailureResult("signature_invalid", "OCSP responder certificate input is malformed") : validateOcspResponseFailureResult(n$16.code, n$16.message);
	}
}
/** Selects the responder certificate from explicit, embedded, trusted, or issuer inputs. */
async function resolveOcspResponderCertificate(e, t, n) {
	return e.responderCertificate ?? await findMatchingOcspResponderCertificate(t.certificates, t.responderId) ?? await findMatchingOcspResponderCertificate(n, t.responderId) ?? t.certificates?.[0] ?? e.issuerCertificate;
}
async function validateOcspResponderAuthorization(e, t, n, r, i) {
	let a = await safeValidateOcspResponderIdBinding(t, r);
	if (!a.ok) return a;
	let o = i.some((e) => isSameOcspCertificate(r, e));
	if (!(isSameOcspCertificate(r, n) || o)) return await validateDelegatedOcspResponder(e, t, n, r);
}
async function safeValidateOcspResponderIdBinding(t, n$18) {
	try {
		return await validateOcspResponderIdBinding(t.responderId, n$18);
	} catch (t) {
		let n$17 = decodeRefusalOf(t, n);
		return n$17 === void 0 ? validateOcspResponseFailureResult("signature_invalid", "OCSP responder certificate input is malformed") : validateOcspResponseFailureResult(n$17.code, n$17.message);
	}
}
async function validateDelegatedOcspResponder(e, t, n, r) {
	let i = e.allowChainedResponderCertificate === !0;
	if (!i && !isDirectlyIssuedByOcspIssuer(r, n)) return validateOcspResponseFailureResult("responder_chain_invalid", "Delegated OCSP responder must be directly issued by issuer certificate");
	if (!(await verifyCertificateChain({
		leaf: r.der,
		intermediates: i ? buildOcspResponderIntermediates(t.certificates, r, n) : [],
		roots: [n.der],
		...e.at === void 0 ? {} : { at: e.at }
	})).ok) return validateOcspResponseFailureResult("responder_chain_invalid", "OCSP responder certificate chain does not validate");
	if (r.extendedKeyUsage === void 0 || !r.extendedKeyUsage.includes("ocspSigning")) return validateOcspResponseFailureResult("ocsp_signing_missing", "Delegated OCSP responder lacks ocspSigning EKU");
	let a = await checkDelegatedResponderRevocation(r, n, e);
	return a.ok ? void 0 : a;
}
/** Checks response-level and per-certificate OCSP timestamps against the validation time. */
async function validateOcspResponseFreshness(e, t, n) {
	if (e.producedAt !== void 0 && e.producedAt.getTime() - n.skew > n.at.getTime()) return validateOcspResponseFailureResult("stale_response", "OCSP response producedAt is later than requested time");
	for (let r of e.responses ?? []) {
		let i = await validateOcspSingleResponseFreshness(r, e.producedAt, t, n);
		if (i !== void 0) return i;
	}
}
async function validateOcspSingleResponseFreshness(e, t, n, r) {
	let i;
	try {
		i = await buildParsedOcspCertId(e.certId.hashAlgorithmOid, n, e.certId.serialNumberHex);
	} catch {
		return validateOcspResponseFailureResult("signature_invalid", "OCSP response CertID hash algorithm is unsupported");
	}
	return e.certId.issuerNameHashHex !== i.issuerNameHashHex || e.certId.issuerKeyHashHex !== i.issuerKeyHashHex ? validateOcspResponseFailureResult("issuer_mismatch", "OCSP response certId does not match issuer certificate") : validateOcspSingleResponseTimes(e, t, r);
}
function validateOcspSingleResponseTimes(e, t, { at: n, skew: r, profile: i }) {
	if (i === "rfc9919" && e.nextUpdate === void 0) return validateOcspResponseFailureResult("next_update_missing", "OCSP response omits nextUpdate, which the RFC 9919 profile requires");
	if (e.thisUpdate.getTime() - r > n.getTime() || e.nextUpdate !== void 0 && e.nextUpdate.getTime() + r < n.getTime()) return validateOcspResponseFailureResult("stale_response", "OCSP response is not valid at requested time");
	if (t !== void 0 && e.nextUpdate !== void 0 && t.getTime() - r > e.nextUpdate.getTime()) return validateOcspResponseFailureResult("stale_response", "OCSP response producedAt is later than nextUpdate");
}
function validateOcspRequestCoverage(t, n$20) {
	let r;
	try {
		r = normalizeOcspRequest(t);
	} catch (t) {
		let n$19 = decodeRefusalOf(t, n);
		return n$19 === void 0 ? validateOcspResponseFailureResult("request_mismatch", "OCSP request input is malformed") : validateOcspResponseFailureResult(n$19.code, n$19.message);
	}
	return r.nonce !== void 0 && r.nonce !== n$20.nonce ? validateOcspResponseFailureResult("nonce_mismatch", "OCSP response nonce does not match request nonce") : validateOcspRequestIdCoverage(new Set(r.requests.map((e) => serializeCertId(e))), new Set((n$20.responses ?? []).map((e) => serializeCertId(e.certId))), n$20.responses ?? []);
}
function validateOcspRequestIdCoverage(e, t, n) {
	for (let t of n) if (!e.has(serializeCertId(t.certId))) return validateOcspResponseFailureResult("request_mismatch", "OCSP response includes a certId not present in request");
	for (let n of e) if (!t.has(n)) return validateOcspResponseFailureResult("request_mismatch", "OCSP response does not cover every requested certId");
}
/** Builds a `VerifyOcspResponseSignatureFailureResult`. */
function verifyOcspResponseFailureResult(e, n) {
	return failureResult(e, n);
}
/** Builds a `ValidateOcspResponseFailureResult`. */
function validateOcspResponseFailureResult(e, n) {
	return failureResult(e, n);
}
/**
* Reports whether a certificate carries the `id-pkix-ocsp-nocheck` extension
* (RFC 6960 §4.2.2.2.1) — the CA's assertion that relying parties may trust
* this OCSP responder certificate for its lifetime without revocation checks.
* An extension whose value is not the NULL that §4.2.2.2.1 requires does not count.
*/
function hasOcspNoCheckExtension(e) {
	return carriesOcspNoCheck(normalizeCertificate(e));
}
/** Whether a parsed certificate carries `id-pkix-ocsp-nocheck` with its NULL value. */
function carriesOcspNoCheck(e) {
	return e.extensions.some((e) => e.oid === t.ocspNoCheck && e.valueHex === "0500");
}
/** Parses a CRL from PEM string, DER bytes, or an already-parsed CRL. */
function parseResponderCrlFromSource(e) {
	return typeof e == "object" && "issuer" in e ? e : typeof e == "string" ? parseCertificateRevocationListPemOrThrow(e) : parseCertificateRevocationListDerOrThrow(e);
}
function responderCrlCheck(e, t, n) {
	return {
		certificate: e,
		issuerCertificate: t,
		at: n.at ?? /* @__PURE__ */ new Date(),
		...n.responderRevocationCrlMaxAgeMs === void 0 ? {} : { maxAgeMs: n.responderRevocationCrlMaxAgeMs },
		...n.clockSkewMs === void 0 ? {} : { clockSkewMs: n.clockSkewMs },
		...n.responderRevocationUnrecognizedReasonCode === void 0 ? {} : { unrecognizedReasonCode: n.responderRevocationUnrecognizedReasonCode }
	};
}
/**
* Applies the delegated-responder revocation policy (RFC 6960 §4.2.2.2.1).
* See {@linkcode OcspResponderRevocationPolicy} for the policy semantics.
*/
async function checkDelegatedResponderRevocation(e, t, n) {
	let r = n.responderRevocationPolicy ?? "honor-nocheck";
	if (r === "skip" || r === "honor-nocheck" && hasOcspNoCheckExtension(e)) return { ok: !0 };
	let i = responderCrlCheck(e, t, n), a = /* @__PURE__ */ new Set(), o = !1;
	for (let e of n.responderRevocationCrls ?? []) {
		let t;
		try {
			t = parseResponderCrlFromSource(e);
		} catch {
			continue;
		}
		let n = await checkCertificateRevocationAgainstCrl({
			...i,
			crl: t
		});
		if (!n.ok) o ||= n.code === "reason_code_unrecognized";
		else {
			if (n.value.status === "revoked") return validateOcspResponseFailureResult("responder_revoked", "Delegated OCSP responder certificate is revoked");
			for (let e of n.value.coveredReasons) a.add(e);
		}
	}
	return o ? validateOcspResponseFailureResult("responder_revocation_unknown", "Delegated OCSP responder carries an unrecognized CRL reason code") : coversAllDistributionPointReasons(a) || r === "honor-nocheck" ? { ok: !0 } : validateOcspResponseFailureResult("responder_revocation_unknown", "Delegated OCSP responder revocation status could not be established");
}
/** Accepts PEM, DER, or already-parsed OCSP response and returns a parsed response. */
function normalizeOcspResponse(e) {
	if (typeof e == "string") return parseOcspResponsePemOrThrow(e);
	if (e instanceof Uint8Array) return parseOcspResponseDerOrThrow(e);
	if (hasReparseableOcspResponseShape(e)) return parseOcspResponseDerOrThrow(new Uint8Array(e.der));
	throw Error("OCSP response input is malformed");
}
/** Accepts PEM, DER, or already-parsed OCSP request and returns a parsed request. */
function normalizeOcspRequest(e) {
	if (typeof e == "string") return parseOcspRequestPemOrThrow(e);
	if (e instanceof Uint8Array) return parseOcspRequestDerOrThrow(e);
	if (hasReparseableOcspRequestShape(e)) return parseOcspRequestDerOrThrow(new Uint8Array(e.der));
	throw Error("OCSP request input is malformed");
}
function parseSignedOcspResponseData(e) {
	let t = readSequenceChildren(e);
	if (t.length < 3 || t.length > 5) throw Error("Malformed OCSP responseData");
	let n = 0;
	if (t[n]?.tag === 160) {
		let r = requireElement(t[n], "version"), i = childrenOf(e, r), a = requireElement(i[0], "version");
		if (i.length !== 1 || a.tag !== 2) throw Error("version must use INTEGER");
		if (decodeNonNegativeIntegerNumber(a.value, "OCSP response version") !== 0) throw Error("Unsupported OCSP response version");
		n += 1;
	}
	let r = parseOcspResponderId(e, requireElement(t[n], "responderID"));
	n += 1;
	let i = requireElement(t[n], "producedAt"), a = requireElement(t[n + 1], "responses");
	if (a.tag !== 48) throw Error("responses must use SEQUENCE");
	if (childrenOf(e, a).length === 0) throw Error("responses must not be empty");
	let o = t[n + 2];
	if (o !== void 0 && o.tag !== 161 || t.length !== n + 2 + (o === void 0 ? 0 : 1)) throw Error("Malformed OCSP responseData");
	let s = o === void 0 ? void 0 : parseOcspNonceFromExtensions(e, o), c = childrenOf(e, a).map((t) => parseSingleResponse(e, t));
	return assertUniqueOcspResponseCertIds(c), {
		responderId: r,
		producedAt: parseTime(i),
		responses: c,
		...s === void 0 ? {} : { nonce: s }
	};
}
/** Searches embedded certificates for one whose subject or key hash matches the responder ID. */
async function findMatchingOcspResponderCertificate(e, t) {
	if (e !== void 0 && t !== void 0) {
		for (let n of e) if (await matchesOcspResponderId(t, n)) return n;
	}
}
/** Verifies that the signer certificate matches the response's responder ID (byName or byKeyHash). */
async function validateOcspResponderIdBinding(e, t) {
	return e === void 0 || await matchesOcspResponderId(e, t) ? { ok: !0 } : e.type === "byName" ? validateOcspResponseFailureResult("responder_id_mismatch", "OCSP responder certificate subject does not match responderID byName") : validateOcspResponseFailureResult("responder_id_mismatch", "OCSP responder certificate public key does not match responderID byKeyHash");
}
/** Returns `true` if the certificate matches the responder ID (subject name or key hash). */
async function matchesOcspResponderId(e, t) {
	return e.type === "byName" ? compareOcspResponderNames(e.name, t.subject) : toHex(await digestBytes("SHA-1", extractSubjectPublicKeyBytes(t.subjectPublicKeyInfoDer))) === e.keyHashHex;
}
/** Identity check — same serial, issuer, subject, and SPKI. */
function isSameOcspCertificate(e, t) {
	return e.serialNumberHex === t.serialNumberHex && compareDistinguishedNames(e.issuer, t.issuer) && compareDistinguishedNames(e.subject, t.subject) && e.subjectPublicKeyInfoDer.length === t.subjectPublicKeyInfoDer.length && e.subjectPublicKeyInfoDer.every((e, n) => e === t.subjectPublicKeyInfoDer[n]);
}
/** Returns `true` if `signer` was directly issued by `issuer` (name + AKI match). */
function isDirectlyIssuedByOcspIssuer(e, t) {
	return !(!compareDistinguishedNames(e.issuer, t.subject) || e.authorityKeyIdentifier !== void 0 && t.subjectKeyIdentifier !== void 0 && e.authorityKeyIdentifier !== t.subjectKeyIdentifier);
}
/** Filters embedded certificates to produce an intermediate chain (excluding signer and issuer). */
function buildOcspResponderIntermediates(e, t, n) {
	if (e === void 0) return [];
	let r = [];
	for (let i of e) isSameOcspCertificate(i, t) || isSameOcspCertificate(i, n) || r.push(i.der);
	return r;
}
/** DER-encodes a CertID SEQUENCE (hashAlgorithm, issuerNameHash, issuerKeyHash, serialNumber). */
async function encodeOcspCertId(e, t$7, n) {
	let r = n === "SHA-1" ? t.sha1 : t.sha256, i = await buildParsedOcspCertId(r, t$7, e.serialNumberHex);
	return sequence([
		sequence([objectIdentifier(r), nullValue()]),
		octetString(hexToBytes(i.issuerNameHashHex)),
		octetString(hexToBytes(i.issuerKeyHashHex)),
		integer(hexToBytes(i.serialNumberHex))
	]);
}
/** Computes issuer name/key hashes for a CertID given the hash algorithm OID and issuer certificate. */
async function buildParsedOcspCertId(e, t, n) {
	let r = ocspHashAlgorithmFromOid(e);
	return {
		hashAlgorithmOid: e,
		hashAlgorithmName: describeHashAlgorithm(e),
		issuerNameHashHex: toHex(await digestBytes(r, hexToBytes(t.subject.derHex))),
		issuerKeyHashHex: toHex(await digestBytes(r, extractSubjectPublicKeyBytes(t.subjectPublicKeyInfoDer))),
		serialNumberHex: n
	};
}
/** Hashes `bytes` with the given WebCrypto algorithm name. */
async function digestBytes(e, t) {
	return new Uint8Array(await getCrypto().subtle.digest(e, toArrayBuffer(t)));
}
/** DER-encodes a SingleResponse (certId, certStatus, thisUpdate, optional nextUpdate). */
async function encodeSingleResponse(e, t, n, r) {
	let i = await encodeOcspCertId(e, t, r), a = encodeOcspCertStatus(n);
	return sequence([
		i,
		a,
		generalizedTime(n.thisUpdate ?? /* @__PURE__ */ new Date()),
		...n.nextUpdate === void 0 ? [] : [explicitContext(0, generalizedTime(n.nextUpdate))]
	]);
}
/** DER-encodes the CertStatus CHOICE (good [0], revoked [1], unknown [2]). */
function encodeOcspCertStatus(e) {
	switch (e.certStatus) {
		case "good": return tlv(128, /* @__PURE__ */ new Uint8Array());
		case "unknown": return tlv(130, /* @__PURE__ */ new Uint8Array());
		case "revoked": {
			let t = [generalizedTime(e.revokedAt ?? e.thisUpdate ?? /* @__PURE__ */ new Date())];
			return e.revocationReasonCode !== void 0 && t.push(explicitContext(0, enumeratedFromNumber(e.revocationReasonCode))), tlv(161, concatBytes(t));
		}
		default: throw Error(`Unhandled CertStatus type: ${String(e)}`);
	}
}
/** Accepts PEM, DER, or already-parsed certificate and returns a parsed certificate. */
function normalizeCertificate(e) {
	return hasParsedCertificateShape(e) ? parseCertificateDerOrThrow(new Uint8Array(e.der)) : parseCertificateFromSource(e);
}
/** Type guard: distinguishes a `ParsedCertificate` from raw `Uint8Array`. */
function hasParsedCertificateShape(e) {
	return typeof e != "string" && "subjectPublicKeyInfoDer" in e;
}
/** Decodes a DER-encoded CertID SEQUENCE into a {@linkcode ParsedOcspCertId}. */
function parseOcspCertId(e) {
	let t = readRootElement(e, { maxDepth: 64 });
	if (t.tag !== 48) throw Error("CertID must use SEQUENCE");
	let n = childrenOf(e, t);
	if (n.length !== 4) throw Error("CertID must contain hashAlgorithm, issuerNameHash, issuerKeyHash, and serialNumber");
	let r = requireElement(n[0], "hashAlgorithm");
	if (r.tag !== 48) throw Error("hashAlgorithm must use SEQUENCE");
	let i = childrenOf(e, r);
	if (i.length < 1 || i.length > 2) throw Error("Malformed hashAlgorithm");
	let a = requireElement(i[0], "hashAlgorithm OID"), o = decodeObjectIdentifier(a.value);
	if (requireElement(n[1], "issuerNameHash").tag !== 4) throw Error("issuerNameHash must use OCTET STRING");
	if (requireElement(n[2], "issuerKeyHash").tag !== 4) throw Error("issuerKeyHash must use OCTET STRING");
	let s = requireElement(n[3], "serialNumber");
	if (s.tag !== 2) throw Error("serialNumber must use INTEGER");
	return {
		hashAlgorithmOid: o,
		hashAlgorithmName: describeHashAlgorithm(o),
		issuerNameHashHex: toHex(requireElement(n[1], "issuerNameHash").value),
		issuerKeyHashHex: toHex(requireElement(n[2], "issuerKeyHash").value),
		serialNumberHex: toHex(s.value)
	};
}
/** Decodes a SingleResponse from its ASN.1 element within the ResponseData. */
function parseSingleResponse(e, t) {
	let n = childrenOf(e, t);
	if (n.length < 3 || n.length > 5) throw Error("Malformed OCSP SingleResponse");
	let r = requireElement(n[0], "certId"), i = requireElement(n[1], "certStatus"), a = requireElement(n[2], "thisUpdate"), o = 3, s = n[o]?.tag === 160 ? n[o] : void 0;
	s !== void 0 && (validateOcspSingleResponseNextUpdate(e, s), o += 1);
	let c = n[o];
	if (c !== void 0 && c.tag !== 161 || n.length !== o + (c === void 0 ? 0 : 1)) throw Error("Malformed OCSP SingleResponse");
	return {
		certId: parseOcspCertId(e.slice(r.start - r.headerLength, r.end)),
		thisUpdate: parseTime(a),
		...parseOcspSingleResponseNextUpdate(e, s),
		...parseOcspCertStatusFields(e, i)
	};
}
function parseOcspSingleResponseNextUpdate(e, t) {
	return t === void 0 ? {} : { nextUpdate: parseTime(requireElement(childrenOf(e, t)[0], "nextUpdate")) };
}
function parseOcspCertStatusFields(e, t) {
	if (t.tag === 128) {
		if (t.value.length !== 0) throw Error("OCSP good certStatus must be empty");
		return { certStatus: "good" };
	}
	if (t.tag === 130) {
		if (t.value.length !== 0) throw Error("OCSP unknown certStatus must be empty");
		return { certStatus: "unknown" };
	}
	if (t.tag !== 161) throw Error(`Unsupported OCSP certStatus tag: ${String(t.tag)}`);
	let n = childrenOf(e, t);
	if (n.length < 1 || n.length > 2) throw Error("Malformed OCSP revoked certStatus");
	return {
		certStatus: "revoked",
		revokedAt: parseTime(requireElement(n[0], "revocationTime")),
		...parseOcspRevocationReason(e, n[1])
	};
}
function parseOcspRevocationReason(e, t) {
	if (t === void 0) return {};
	if (t.tag !== 160) throw Error("Malformed OCSP revoked certStatus");
	let n = childrenOf(e, t), r = requireElement(n[0], "revocationReason");
	if (n.length !== 1 || r.tag !== 10) throw Error("revocationReason must use ENUMERATED");
	return { revocationReasonCode: decodeNonNegativeIntegerBigInt(r.value, "OCSP revocationReason") };
}
/** Decodes a ResponderID from its context-tagged ASN.1 element (byName [1] or byKeyHash [2]). */
function parseOcspResponderId(e, t) {
	switch (t.tag) {
		case 162: {
			let n = childrenOf(e, t);
			if (n.length !== 1) throw Error("ResponderID byKey must wrap exactly one OCTET STRING");
			let r = requireElement(n[0], "ResponderID byKey");
			if (r.tag !== 4) throw Error("ResponderID byKey must wrap an OCTET STRING");
			if (r.value.length !== 20) throw Error("ResponderID byKey must be a 20-byte SHA-1 KeyHash");
			return {
				type: "byKeyHash",
				keyHashHex: toHex(r.value)
			};
		}
		case 161:
			if (childrenOf(e, t).length !== 1) throw Error("ResponderID byName must wrap exactly one Name");
			return {
				type: "byName",
				name: parseResponderName(e, requireElement(childrenOf(e, t)[0], "ResponderID byName"))
			};
		default: throw Error(`Unsupported OCSP responderID tag: ${String(t.tag)}`);
	}
}
/** Decodes a Name SEQUENCE from the ResponderID byName form. */
function parseResponderName(e, t) {
	if (t.tag !== 48) throw Error("ResponderID byName must use Name SEQUENCE");
	let n = [], r = [], i = {};
	for (let a of childrenOf(e, t)) {
		let t = parseResponderNameAttributeSet(e, a);
		n.push(t);
		for (let e of t.attributes) r.push(e), e.key !== void 0 && i[e.key] === void 0 && (i[e.key] = e.value);
	}
	return {
		derHex: toHex(e.slice(t.start - t.headerLength, t.end)),
		rdns: n,
		attributes: r,
		values: i
	};
}
/** Decodes one RDN SET from a responder name. */
function parseResponderNameAttributeSet(e, t) {
	let n = [], r = {};
	for (let i of childrenOf(e, t)) {
		let t = childrenOf(e, i), a = decodeObjectIdentifier(requireElement(t[0], "name OID").value), o = requireElement(t[1], "name value"), s = responderNameKeyFromOid(a), c = decodeString(o.tag, o.value), l = s === void 0 ? {
			oid: a,
			valueTag: o.tag,
			value: c
		} : {
			oid: a,
			key: s,
			valueTag: o.tag,
			value: c
		};
		n.push(l), s !== void 0 && r[s] === void 0 && (r[s] = c);
	}
	return {
		derHex: toHex(e.slice(t.start - t.headerLength, t.end)),
		attributes: n,
		values: r
	};
}
/** RDN-by-RDN responder name comparison with RFC 4518 string prep. */
function compareOcspResponderNames(e, t) {
	if (e.rdns.length !== t.rdns.length) return !1;
	for (let n = 0; n < e.rdns.length; n += 1) {
		let r = e.rdns[n], i = t.rdns[n];
		if (r === void 0 || i === void 0 || !compareOcspRelativeDistinguishedNames(r, i)) return !1;
	}
	return !0;
}
/** Set-equality comparison for RDN attribute sets (order-independent). */
function compareOcspRelativeDistinguishedNames(e, t) {
	if (e.attributes.length !== t.attributes.length) return !1;
	let n = Array.from({ length: t.attributes.length }, () => !1);
	for (let r of e.attributes) {
		let e = !1;
		for (let i = 0; i < t.attributes.length; i += 1) {
			let a = t.attributes[i];
			if (!(a === void 0 || n[i]) && compareOcspNameAttributeValue(r, a)) {
				n[i] = !0, e = !0;
				break;
			}
		}
		if (!e) return !1;
	}
	return !0;
}
/** Compares two name attributes with RFC 4518 string prep for directory-string types. */
function compareOcspNameAttributeValue(e, t) {
	if (e.oid !== t.oid) return !1;
	if (isOcspDirectoryStringTag(e.valueTag) && isOcspDirectoryStringTag(t.valueTag)) {
		let n = prepareOcspNameCompareString(e.value), r = prepareOcspNameCompareString(t.value);
		return n === void 0 || r === void 0 ? !1 : n === r;
	}
	return e.valueTag === t.valueTag && e.value === t.value;
}
/** Returns `true` for UTF8String (0x0c) and PrintableString (0x13). */
function isOcspDirectoryStringTag(e) {
	return e === 12 || e === 19;
}
/** NFKC-normalises, lowercases, trims, and collapses whitespace for RFC 4518 name comparison. */
function prepareOcspNameCompareString(e) {
	let t = e.normalize("NFKC");
	if (!/[^\P{Cc}\t\n\r]/u.test(t)) return t.toLowerCase().trim().replace(/\s+/gu, " ");
}
/** Maps a directory attribute type OID (X.520 `id-at` arc plus the legacy PKCS #9 emailAddress) to its friendly key name for responder name parsing. */
function responderNameKeyFromOid(e) {
	switch (e) {
		case t.commonName: return "commonName";
		case t.surname: return "surname";
		case t.serialNumber: return "serialNumber";
		case t.countryName: return "country";
		case t.localityName: return "locality";
		case t.stateOrProvinceName: return "state";
		case t.streetAddress: return "street";
		case t.organizationName: return "organization";
		case t.organizationalUnitName: return "organizationalUnit";
		case t.title: return "title";
		case t.givenName: return "givenName";
		case t.emailAddress: return "emailAddress";
		default: return;
	}
}
/** Extracts the nonce value (as hex) from an OCSP extensions wrapper, if present. */
function parseOcspNonceFromExtensions(e, t$9) {
	let n = childrenOf(e, t$9), r = requireElement(n[0], "extensions");
	if (n.length !== 1 || r.tag !== 48) throw Error("Malformed OCSP extensions");
	let i = /* @__PURE__ */ new Set(), a;
	for (let t$8 of childrenOf(e, r)) {
		let n = childrenOf(e, t$8);
		if (n.length < 2 || n.length > 3 || n.length === 3 && n[1]?.tag !== 1) throw Error("Malformed OCSP extension");
		let r = decodeObjectIdentifier(requireElement(n[0], "extension OID").value);
		if (i.has(r)) throw Error(`Duplicate OCSP extension OID: ${r}`);
		i.add(r);
		let o = requireElement(n[n.length - 1], "extnValue");
		if (o.tag !== 4) throw Error("OCSP extension value must use OCTET STRING");
		if (r !== t.ocspNonce) continue;
		let s = readRootElement(o.value, { maxDepth: 64 });
		if (s.tag !== 4) throw Error("OCSP nonce extension value must use OCTET STRING");
		a = toHex(s.value);
	}
	return a;
}
/** Decodes the optional `certs [0]` field from a BasicOCSPResponse. */
function parseEmbeddedCertificates(e, t) {
	let n = [], r = childrenOf(e, t)[0];
	if (r === void 0 || r.tag !== 48) throw Error("Malformed BasicOCSPResponse certs");
	let i = r.start;
	for (; i < r.end;) {
		let t = readElement(e, i);
		n.push(parseCertificateDerOrThrow(e.slice(i, t.end))), i = t.end;
	}
	return n;
}
/** Extracts the raw public key bytes (without BIT STRING padding byte) from SPKI DER. */
function extractSubjectPublicKeyBytes(e) {
	let t = childrenOf(e, readElement(e)), n = requireElement(t[1], "subjectPublicKey BIT STRING");
	if (n.tag !== 3) throw Error("SPKI missing subjectPublicKey BIT STRING");
	return n.value.slice(1);
}
/** Maps an integer response-status code to its {@linkcode OcspResponseStatus} string. */
function ocspResponseStatusFromCode(e) {
	switch (e) {
		case 0: return "successful";
		case 1: return "malformedRequest";
		case 2: return "internalError";
		case 3: return "tryLater";
		case 5: return "sigRequired";
		case 6: return "unauthorized";
		default: throw Error(`Unsupported OCSP responseStatus value: ${String(e)}`);
	}
}
function hasReparseableOcspRequestShape(e) {
	return "der" in e && e.der instanceof Uint8Array;
}
function hasReparseableOcspResponseShape(e) {
	return "der" in e && e.der instanceof Uint8Array;
}
function assertUniqueOcspResponseCertIds(e) {
	let t = /* @__PURE__ */ new Set();
	for (let n of e) {
		let e = serializeCertId(n.certId);
		if (t.has(e)) throw Error("Duplicate OCSP response CertID");
		t.add(e);
	}
}
function hasDuplicateOcspResponseCertificateSerial(e) {
	let t = /* @__PURE__ */ new Set();
	for (let n of e) {
		let e = normalizeHex$1(n.certId.serialNumberHex);
		if (t.has(e)) return !0;
		t.add(e);
	}
	return !1;
}
function validateOcspRequestorName(e, t) {
	let n = childrenOf(e, t), r = requireElement(n[0], "requestorName");
	if (n.length !== 1 || (r.tag & 192) != 128) throw Error("requestorName must wrap exactly one GeneralName");
}
function validateOcspOptionalSignature(e, t) {
	let n = childrenOf(e, t), r = requireElement(n[0], "optionalSignature");
	if (n.length !== 1 || r.tag !== 48) throw Error("optionalSignature must wrap exactly one Signature");
	let i = childrenOf(e, r);
	if (i.length < 2 || i.length > 3 || i[0]?.tag !== 48 || i[2] !== void 0 && i[2]?.tag !== 160) throw Error("Malformed optionalSignature");
	let a = requireElement(i[0], "signatureAlgorithm"), o = requireElement(i[1], "signature"), s = i[2];
	if (validateAlgorithmIdentifierShape(e, a, "optionalSignature algorithm"), extractBitStringValue(o), s !== void 0) {
		let t = childrenOf(e, s);
		if (t.length !== 1 || t[0]?.tag !== 48) throw Error("optionalSignature certs must use SEQUENCE OF Certificate");
	}
}
function validateOcspSingleResponseNextUpdate(e, t) {
	let n = childrenOf(e, t), r = requireElement(n[0], "nextUpdate");
	if (n.length !== 1 || r.tag !== 23 && r.tag !== 24) throw Error("nextUpdate must wrap exactly one time value");
}
function validateAlgorithmIdentifierShape(e, t, n) {
	let r = childrenOf(e, t);
	if (t.tag !== 48 || r.length < 1 || r.length > 2 || r[0]?.tag !== 6) throw Error(`${n} must use AlgorithmIdentifier SEQUENCE`);
	decodeObjectIdentifier(requireElement(r[0], `${n} OID`).value);
}
function normalizeHex$1(e) {
	return e.toLowerCase();
}
/** Maps a hash algorithm OID to the WebCrypto algorithm name. Throws on unsupported OIDs. */
function ocspHashAlgorithmFromOid(e) {
	switch (e) {
		case t.sha1: return "SHA-1";
		case t.sha256: return "SHA-256";
		default: throw Error(`Unsupported OCSP hash algorithm OID: ${e}`);
	}
}
/** Produces a colon-delimited canonical string for CertID set comparison. */
function serializeCertId(e) {
	return [
		e.hashAlgorithmOid,
		e.issuerNameHashHex,
		e.issuerKeyHashHex,
		e.serialNumberHex
	].join(":");
}
// ../../dist/revocation/chain.js
/**
* Chain-level revocation orchestration.
*
* Evaluates CRL and OCSP evidence for an entire validated certificate chain,
* implementing the revocation checking portion of RFC 5280 §6.3.
*
* @see {@link https://datatracker.ietf.org/doc/html/rfc5280#section-6.3 | RFC 5280 §6.3 CRL Validation}
* @module
*/
/**
* Granular reasons why revocation status could not be determined.
*
* Returned in {@linkcode CertificateRevocationStatus}'s `indeterminateReasons`
* when `status` is `'indeterminate'`. Grouped by category:
*
* - **Evidence not found**: `no_applicable_crl`, `no_applicable_ocsp`
* - **Scope mismatch**: `distribution_point_mismatch`, `issuer_name_mismatch`,
*   `reason_scope_mismatch`, `indirect_crl_scope_mismatch`, `reason_coverage_incomplete`
* - **Signer trust**: `crl_signer_not_found`, `crl_signer_not_authorized`,
*   `crl_signer_revoked`, `crl_signer_indeterminate`, and OCSP equivalents
* - **Freshness**: `crl_expired`, `ocsp_response_expired`,
*   `ocsp_next_update_missing`
* - **Delta CRL**: `delta_crl_unusable` when an authenticated, current delta
*   CRL cannot settle the status, `delta_crl_retry_limit_exceeded` when delta
*   CRL candidates remain after the attempt limit. Either one outranks a
*   `good` verdict from other evidence.
* - **Reason code**: `crl_reason_code_unrecognized` and
*   `ocsp_reason_code_unrecognized` when evidence revokes the certificate with
*   an unrecognized CRLReason under `unrecognizedReasonCode: 'reject'`. Either
*   one outranks a `good` verdict from other evidence.
*/
const y = [
	"no_applicable_crl",
	"no_applicable_ocsp",
	"distribution_point_mismatch",
	"issuer_name_mismatch",
	"reason_scope_mismatch",
	"indirect_crl_scope_mismatch",
	"reason_coverage_incomplete",
	"crl_signer_not_found",
	"crl_signer_not_authorized",
	"crl_signer_revoked",
	"crl_signer_indeterminate",
	"ocsp_responder_not_found",
	"ocsp_responder_not_authorized",
	"ocsp_responder_revoked",
	"ocsp_responder_indeterminate",
	"crl_expired",
	"ocsp_response_expired",
	"ocsp_next_update_missing",
	"ocsp_status_unknown",
	"delta_crl_unusable",
	"delta_crl_retry_limit_exceeded",
	"crl_reason_code_unrecognized",
	"ocsp_reason_code_unrecognized"
];
/**
* Parses a certificate from various source formats, returning undefined on failure.
*/
function parseCertificateSafe(e) {
	try {
		return parseCertificateFromSource(e);
	} catch {
		return;
	}
}
/**
* Compares two certificates by DER bytes for identity.
* Reference equality fails when same cert is parsed from different sources.
*/
function sameCertificate(e, t) {
	if (e.der.length !== t.der.length) return !1;
	for (let n = 0; n < e.der.length; n++) if (e.der[n] !== t.der[n]) return !1;
	return !0;
}
/**
* Yields every certificate that could have signed the given CRL, AKI/SKI
* matches before DN matches. All candidates are returned so a certificate whose
* subject DN collides with the genuine CRL issuer cannot shadow it: each is
* tried against the CRL signature and its own path to the trust anchor.
*/
function findIndirectCrlIssuers(e, t, n) {
	let r = [];
	for (let e of t) {
		let t = parseCertificateSafe(e);
		t !== void 0 && r.push(t);
	}
	let i = [...r, ...n], a = [], push = (e) => {
		a.some((t) => sameCertificate(t, e)) || a.push(e);
	};
	if (e.authorityKeyIdentifier !== void 0) for (let t of i) t.subjectKeyIdentifier !== void 0 && normalizeHex(e.authorityKeyIdentifier) === normalizeHex(t.subjectKeyIdentifier) && push(t);
	for (let t of i) e.issuer.derHex === t.subject.derHex && push(t);
	return a;
}
/** Lowercases a hex string for bytewise comparison. */
function normalizeHex(e) {
	return e.toLowerCase();
}
/**
* RFC 5280 §6.3.3(f): confirms the CRL issuer certificate has a valid
* certification path to the same trust anchor as the certificate under test. A
* signer already inside the validated chain is authorized by construction. The
* path check runs without revocation to avoid unbounded recursion.
*/
async function crlSignerChainsToAnchor(e, t, n, r) {
	if (t.some((t) => sameCertificate(t, e))) return !0;
	let i = t[t.length - 1];
	if (i === void 0) return !1;
	let a = [], addCandidate = (t) => {
		sameCertificate(t, e) || sameCertificate(t, i) || a.some((e) => sameCertificate(e, t)) || a.push(t);
	};
	for (let e = 0; e < t.length - 1; e += 1) {
		let n = t[e];
		n !== void 0 && addCandidate(n);
	}
	for (let e of n) {
		let t = parseCertificateSafe(e);
		t !== void 0 && addCandidate(t);
	}
	return (await verifyCertificateChain({
		leaf: e.der,
		intermediates: a.map((e) => e.der),
		roots: [i.der],
		at: r
	})).ok;
}
/**
* Builds a unique cache key for a certificate.
* Uses issuer DN + serial number which uniquely identifies a cert.
*/
function certCacheKey(e) {
	return `${e.issuer.derHex}:${e.serialNumberHex}`;
}
/**
* Validates that a CRL signer certificate is not revoked.
* Uses memoization to avoid redundant checks and detect cycles.
*/
async function validateCrlSigner(e, t) {
	let n = certCacheKey(e), r = t.cache.get(n);
	if (r === "visiting") return "resolved-indeterminate";
	if (r !== void 0) return r;
	t.cache.set(n, "visiting");
	let i = t.chain[t.chain.length - 1];
	if (i !== void 0 && sameCertificate(e, i) || t.chain.some((t) => sameCertificate(t, e))) return t.cache.set(n, "resolved-valid"), "resolved-valid";
	let a = findSignerIssuer(e, t);
	if (a === void 0) return t.cache.set(n, "resolved-indeterminate"), "resolved-indeterminate";
	let o = await checkSignerRevocation(e, a, t);
	return t.cache.set(n, o), o;
}
/**
* Finds the issuer certificate for a CRL signer.
* Searches the chain and extraCertificates by AKI/SKI or DN matching.
*/
function findSignerIssuer(e, t) {
	let n = [];
	for (let e of t.extraCertificates) {
		let t = parseCertificateSafe(e);
		t !== void 0 && n.push(t);
	}
	let r = [...t.chain, ...n];
	for (let t of r) if (e.authorityKeyIdentifier !== void 0 && t.subjectKeyIdentifier !== void 0 && normalizeHex(e.authorityKeyIdentifier) === normalizeHex(t.subjectKeyIdentifier) || e.issuer.derHex === t.subject.derHex) return t;
}
/**
* Checks if a CRL signer certificate is revoked by examining available CRLs.
* Recursively validates the CRL signer of any CRL used to check revocation.
*/
async function checkSignerRevocation(e, t, n) {
	let r = n.chain.some((e) => sameCertificate(e, t)), i = /* @__PURE__ */ new Set(), a = !1;
	for (let r of n.crls) {
		let o = await checkSignerAgainstCrl(e, t, r, n);
		if (o.kind === "revoked") return "resolved-revoked";
		if (o.kind === "unrecognized_reason") a = !0;
		else for (let e of o.reasons) i.add(e);
	}
	return a ? "resolved-indeterminate" : coversAllDistributionPointReasons(i) || r ? "resolved-valid" : "resolved-indeterminate";
}
const b = {
	kind: "reasons",
	reasons: []
};
/**
* Evaluates one CRL against a signer. A CRL that does not parse, does not
* apply, or is itself signed by a signer that is not known good yields no
* evidence rather than a verdict.
*/
async function checkSignerAgainstCrl(e, t, n, r) {
	let i;
	try {
		i = normalizeCrl(n);
	} catch {
		return b;
	}
	let a = await checkCertificateRevocationAgainstCrl({
		certificate: e,
		issuerCertificate: t,
		crl: i,
		at: r.at,
		...r.crlMaxAgeMs === void 0 ? {} : { maxAgeMs: r.crlMaxAgeMs },
		...r.clockSkewMs === void 0 ? {} : { clockSkewMs: r.clockSkewMs },
		unrecognizedReasonCode: r.unrecognizedReasonCode
	});
	return a.ok ? a.value.status === "revoked" ? { kind: "revoked" } : await validateCrlSigner(t, r) === "resolved-valid" ? {
		kind: "reasons",
		reasons: a.value.coveredReasons
	} : b : a.code === "reason_code_unrecognized" ? { kind: "unrecognized_reason" } : b;
}
/** Builds the `revoked` CertificateRevocationStatus for a CRL hit. */
function buildCrlRevokedStatus(e, t, n, r, i) {
	return {
		certificate: e,
		status: "revoked",
		source: {
			kind: "crl",
			signerCertificate: t,
			thisUpdate: n
		},
		revocationInfo: {
			revocationDate: r,
			...i === void 0 ? {} : { reason: i }
		}
	};
}
/** Parses an OCSP response from PEM string or DER bytes. */
function parseOcspResponseFromSource(e) {
	return typeof e == "string" ? parseOcspResponsePemOrThrow(e) : parseOcspResponseDerOrThrow(e);
}
function evidenceParseError(n$7, r) {
	return {
		kind: "parse_error",
		code: decodeRefusalOf(n$7, n)?.code ?? "malformed",
		message: n$7 instanceof Error ? n$7.message : r
	};
}
/** Parses one OCSP source and locates the entry for the certificate under evaluation. */
function findApplicableOcspResponse(e, t) {
	let n;
	try {
		n = parseOcspResponseFromSource(e);
	} catch (e) {
		return {
			kind: "parse_error",
			error: evidenceParseError(e, "OCSP response parse failed")
		};
	}
	let r = (n.responses ?? []).find((e) => normalizeHex(e.certId.serialNumberHex) === normalizeHex(t.serialNumberHex));
	return r === void 0 ? { kind: "not_applicable" } : {
		kind: "applicable",
		parsed: n,
		entry: r
	};
}
/** Returns the later of two evidence timestamps, tolerating an empty accumulator. */
function laterEvidenceDate(e, t) {
	return e === void 0 || t.getTime() > e.getTime() ? t : e;
}
/** Builds a definitive OCSP-revoked status from a validated response entry. */
function buildOcspRevokedStatus(e, t, n, r) {
	return {
		certificate: e,
		status: "revoked",
		source: {
			kind: "ocsp",
			thisUpdate: t
		},
		revocationInfo: {
			revocationDate: n,
			...r === void 0 ? {} : { reason: r }
		}
	};
}
/** Classifies one fully validated OCSP entry for aggregation. */
function classifyValidatedOcspEntry(e, t, n) {
	if (t.certStatus === "good") return {
		kind: "good",
		thisUpdate: t.thisUpdate
	};
	if (t.certStatus === "unknown") return { kind: "unknown" };
	let r = revocationReasonFromCode(t.revocationReasonCode);
	if (n === "reject" && typeof r == "object") return { kind: "unrecognized_reason" };
	let i = buildOcspRevokedStatus(e, t.thisUpdate, t.revokedAt, r);
	return r === "certificateHold" ? {
		kind: "hold",
		evidence: {
			status: i,
			thisUpdate: t.thisUpdate
		}
	} : {
		kind: "revoked",
		status: i
	};
}
/** Builds the definitive OCSP-good result or the accumulated indeterminate result. */
function finalizeOcspEvidence(e, t, n, r) {
	return t === void 0 ? (n.size === 0 && n.add("no_applicable_ocsp"), {
		status: {
			certificate: e,
			status: "indeterminate",
			indeterminateReasons: [...n]
		},
		executionErrors: r
	}) : {
		status: {
			certificate: e,
			status: "good",
			source: {
				kind: "ocsp",
				thisUpdate: t
			}
		},
		executionErrors: r
	};
}
/** Maps a {@linkcode validateOcspResponse} failure code to an indeterminate reason. */
function ocspIndeterminateReasonFromFailure(e) {
	switch (e) {
		case "stale_response": return "ocsp_response_expired";
		case "next_update_missing": return "ocsp_next_update_missing";
		case "responder_id_mismatch":
		case "responder_chain_invalid":
		case "ocsp_signing_missing": return "ocsp_responder_not_authorized";
		case "responder_revoked": return "ocsp_responder_revoked";
		case "signature_invalid":
		case "responder_revocation_unknown":
		case "unsupported":
		case "limit_exceeded": return "ocsp_responder_indeterminate";
		case "response_status_invalid":
		case "issuer_mismatch":
		case "nonce_mismatch":
		case "request_mismatch": return "no_applicable_ocsp";
		default: throw Error(`Unhandled ValidateOcspResponse failure code: ${String(e)}`);
	}
}
/** Validation failures worth retrying with an explicit responder certificate. */
const x = /* @__PURE__ */ new Set([
	"signature_invalid",
	"responder_id_mismatch",
	"responder_chain_invalid",
	"ocsp_signing_missing",
	"unsupported",
	"limit_exceeded"
]);
/**
* Validates an OCSP response, retrying with caller-provided extra certificates
* as explicit responder certificates when embedded discovery fails.
*/
async function validateOcspResponseWithResponderFallback(e, t, n, r) {
	let i = n.trustedOcspResponders?.filter((e) => {
		let n = parseCertificateSafe(e.issuerCertificate);
		return n !== void 0 && sameCertificate(n, t);
	}).map((e) => e.responderCertificate), a = {
		issuerCertificate: t,
		at: r,
		...i === void 0 ? {} : { trustedOcspResponders: i },
		...n.policy?.ocspResponderRevocation === void 0 ? {} : { responderRevocationPolicy: n.policy.ocspResponderRevocation },
		...n.crls === void 0 ? {} : { responderRevocationCrls: n.crls },
		...n.policy?.crlMaxAgeMs === void 0 ? {} : { responderRevocationCrlMaxAgeMs: n.policy.crlMaxAgeMs },
		...n.policy?.clockSkewMs === void 0 ? {} : { clockSkewMs: n.policy.clockSkewMs },
		...n.policy?.ocspProfile === void 0 ? {} : { profile: n.policy.ocspProfile },
		...n.policy?.unrecognizedReasonCode === void 0 ? {} : { responderRevocationUnrecognizedReasonCode: n.policy.unrecognizedReasonCode }
	}, o = await validateOcspResponse({
		response: e,
		...a
	});
	if (o.ok || !x.has(o.code)) return o;
	for (let t of n.extraCertificates ?? []) {
		let n = parseCertificateSafe(t);
		if (n === void 0) continue;
		let r = await validateOcspResponse({
			response: e,
			...a,
			responderCertificate: n
		});
		if (r.ok) return r;
	}
	return o;
}
/**
* Evaluates OCSP evidence for a single certificate (RFC 6960).
*
* Every response is fully validated — signature, responder binding and
* authorization, and freshness — via {@linkcode validateOcspResponse} before
* its status entry is trusted. Issuer binding of each CertID is enforced by
* the validator, so a serial-number match on a validated response is
* sufficient to attribute the entry to `cert`.
*/
async function evaluateOcspEvidence(e, t, n) {
	let { ocspResponses: r = [], at: i = /* @__PURE__ */ new Date() } = n, a = [], o = {
		reasons: /* @__PURE__ */ new Set(),
		sawUnrecognizedReason: !1
	};
	for (let s of r) {
		let r = findApplicableOcspResponse(s, e);
		if (r.kind === "parse_error") {
			a.push(r.error);
			continue;
		}
		if (r.kind === "not_applicable") continue;
		let c = await validateOcspResponseWithResponderFallback(r.parsed, t, n, i);
		if (!c.ok) {
			o.reasons.add(ocspIndeterminateReasonFromFailure(c.code));
			continue;
		}
		let l = classifyValidatedOcspEntry(e, r.entry, n.policy?.unrecognizedReasonCode ?? "revoked");
		if (l.kind === "revoked") return {
			status: l.status,
			executionErrors: a
		};
		recordOcspEvidence(o, l);
	}
	return settleOcspEvidence(e, o, a);
}
function recordOcspEvidence(e, t) {
	t.kind === "good" ? e.freshestGoodThisUpdate = laterEvidenceDate(e.freshestGoodThisUpdate, t.thisUpdate) : t.kind === "hold" ? (e.freshestHold === void 0 || t.evidence.thisUpdate.getTime() > e.freshestHold.thisUpdate.getTime()) && (e.freshestHold = t.evidence) : t.kind === "unrecognized_reason" ? e.sawUnrecognizedReason = !0 : e.reasons.add("ocsp_status_unknown");
}
/** The OCSP verdict once no response revoked the certificate outright. */
function settleOcspEvidence(e, t, n) {
	if (t.sawUnrecognizedReason) return t.reasons.add("ocsp_reason_code_unrecognized"), finalizeOcspEvidence(e, void 0, t.reasons, n);
	let { freshestGoodThisUpdate: r, freshestHold: i } = t;
	return i !== void 0 && (r === void 0 || r.getTime() <= i.thisUpdate.getTime()) ? {
		status: i.status,
		executionErrors: n
	} : finalizeOcspEvidence(e, r, t.reasons, n);
}
/**
* Runs each candidate signer through the full pipeline for one base CRL:
* signature/applicability, RFC 5280 §6.3.3(f) path to the anchor, then signer
* revocation. A candidate that verifies the signature but fails a later step
* does not shadow a subsequent usable signer, so the search continues. Returns
* a revoked status when one is found; otherwise records good or diagnostic
* evidence into `state`.
*/
async function resolveBaseCrlAgainstSigners(e) {
	let { cert: t, baseCrl: n, deltaCandidates: r, issuer: i, extraCertificates: a, chain: o, at: s, crlMaxAgeMs: c, clockSkewMs: l, unrecognizedReasonCode: u, signerCtx: d, deltaBudget: f, state: p } = e, m = { remaining: S };
	for (let e of collectCrlSignerCandidates(n, i, a, o)) {
		let i = await checkCrlAgainstDeltaCandidates({
			cert: t,
			baseCrl: n,
			deltaCandidates: r,
			candidate: e,
			at: s,
			crlMaxAgeMs: c,
			clockSkewMs: l,
			unrecognizedReasonCode: u,
			budgets: [m, f],
			state: p
		});
		if (i.kind === "unusable_base") continue;
		if (!await crlSignerChainsToAnchor(e, o, a, s)) {
			p.sawCrlSignerNotAuthorized = !0;
			continue;
		}
		let h = await validateCrlSigner(e, d);
		if (h === "resolved-revoked") {
			p.sawCrlSignerRevoked = !0;
			continue;
		}
		if (h === "resolved-indeterminate") {
			p.sawCrlSignerIndeterminate = !0;
			continue;
		}
		if (i.kind === "reason_code_unrecognized") {
			p.sawUnrecognizedReasonCode = !0;
			return;
		}
		if (i.kind === "delta_unusable") {
			p.sawDeltaCrlUnusable = !0;
			return;
		}
		if (i.kind === "retry_limit") {
			p.sawDeltaCrlRetryLimit = !0;
			return;
		}
		let { checked: g, crlThisUpdate: _ } = i;
		if (g.value.status === "revoked") return buildCrlRevokedStatus(t, e, _, g.value.revocationDate, g.value.reasonCode);
		recordGoodCrlEvidence(p, e, _, g.value.coveredReasons);
		return;
	}
}
async function evaluateCrlEvidence(e, t, n, r, i) {
	let { crls: a = [], extraCertificates: o = [], chain: s = [], at: c = /* @__PURE__ */ new Date() } = n, d = {
		executionErrors: [],
		coveredReasons: /* @__PURE__ */ new Set(),
		sawCrlSignerRevoked: !1,
		sawCrlSignerIndeterminate: !1,
		sawCrlSignerNotAuthorized: !1,
		sawStaleCrl: !1,
		sawDeltaCrlUnusable: !1,
		sawDeltaCrlRetryLimit: !1,
		sawUnrecognizedReasonCode: !1,
		sawGood: !1
	}, f = parseCrlEvidenceSources(a, d.executionErrors), p = distinctSignedCrls(f.filter((t) => t.baseCrlNumber === void 0 && isCrlApplicableTo(e, t))), m = distinctSignedCrls(f.filter((e) => e.baseCrlNumber !== void 0)), h = n.policy?.crlMaxAgeMs, g = n.policy?.clockSkewMs;
	for (let a of p) {
		let l = await resolveBaseCrlAgainstSigners({
			cert: e,
			baseCrl: a,
			deltaCandidates: rankApplicableDeltaCrls(a, m, c, g ?? 0, h),
			issuer: t,
			extraCertificates: o,
			chain: s,
			at: c,
			crlMaxAgeMs: h,
			clockSkewMs: g,
			unrecognizedReasonCode: n.policy?.unrecognizedReasonCode ?? "revoked",
			signerCtx: r,
			deltaBudget: i,
			state: d
		});
		if (l !== void 0) return {
			status: l,
			executionErrors: d.executionErrors
		};
	}
	let _ = blockingCrlIndeterminateReasons(d);
	return _.length > 0 ? {
		status: {
			certificate: e,
			status: "indeterminate",
			indeterminateReasons: _
		},
		executionErrors: d.executionErrors
	} : d.sawGood && d.freshestGood !== void 0 ? coversAllDistributionPointReasons(d.coveredReasons) ? {
		status: {
			certificate: e,
			status: "good",
			source: {
				kind: "crl",
				signerCertificate: d.freshestGood.signer,
				thisUpdate: d.freshestGood.thisUpdate
			}
		},
		executionErrors: d.executionErrors
	} : {
		status: {
			certificate: e,
			status: "indeterminate",
			indeterminateReasons: ["reason_coverage_incomplete"]
		},
		executionErrors: d.executionErrors
	} : {
		status: {
			certificate: e,
			status: "indeterminate",
			indeterminateReasons: [crlUnavailableReason(d)]
		},
		executionErrors: d.executionErrors
	};
}
/** CRL conditions that keep the status indeterminate despite `good` evidence. */
function blockingCrlIndeterminateReasons(e) {
	return [
		...e.sawDeltaCrlUnusable ? ["delta_crl_unusable"] : [],
		...e.sawDeltaCrlRetryLimit ? ["delta_crl_retry_limit_exceeded"] : [],
		...e.sawUnrecognizedReasonCode ? ["crl_reason_code_unrecognized"] : []
	];
}
/** Most specific indeterminate reason when no CRL yielded a usable verdict. */
function crlUnavailableReason(e) {
	return e.sawCrlSignerRevoked ? "crl_signer_revoked" : e.sawCrlSignerNotAuthorized ? "crl_signer_not_authorized" : e.sawCrlSignerIndeterminate ? "crl_signer_indeterminate" : e.sawStaleCrl ? "crl_expired" : "no_applicable_crl";
}
/** Parses complete and delta CRL evidence while retaining source provenance. */
function parseCrlEvidenceSources(e, t) {
	let n = [];
	for (let r of e) try {
		n.push(normalizeCrl(r));
	} catch (e) {
		t.push(evidenceParseError(e, "CRL parse failed"));
	}
	return n;
}
/** `crls` without repeats of the same signed content and signature. */
function distinctSignedCrls(e) {
	let t = /* @__PURE__ */ new Set();
	return e.filter((e) => {
		let r = [
			e.signatureAlgorithmOid,
			toHex(e.signatureAlgorithmParametersDer ?? /* @__PURE__ */ new Uint8Array()),
			toHex(e.signatureValue),
			toHex(e.tbsCertListDer)
		].join(":");
		return !t.has(r) && (t.add(r), !0);
	});
}
/** Every delta CRL that can update `baseCrl`, newest first, in the order to try authenticating them. */
function rankApplicableDeltaCrls(e, t, n, r, i) {
	let a = e.crlNumber;
	return a === void 0 ? [] : t.filter((t) => t.issuer.derHex === e.issuer.derHex && t.baseCrlNumber !== void 0 && t.baseCrlNumber <= a && t.crlNumber !== void 0 && t.crlNumber > a && t.thisUpdate.getTime() >= e.thisUpdate.getTime() && isCurrentDeltaCrl(t, n, r, i)).sort((e, t) => isNewerDeltaCrl(e, t) ? -1 : +!!isNewerDeltaCrl(t, e));
}
const S = 4;
/**
* Authenticates `baseCrl` with `candidate` once, then checks it with each
* ranked delta CRL while the budgets last, and alone once every delta CRL is
* rejected. A delta CRL that passes authentication, freshness, compatibility
* and applicability ends the search.
*/
async function checkCrlAgainstDeltaCandidates(e) {
	let { cert: t, baseCrl: n, deltaCandidates: r, candidate: i, at: a, crlMaxAgeMs: s, clockSkewMs: l, unrecognizedReasonCode: u, budgets: d, state: f } = e, p = await authenticateCrl(n, i);
	if (!p.ok) return { kind: "unusable_base" };
	let m = {
		certificate: t,
		issuerCertificate: i,
		crl: p.value,
		at: a,
		...s === void 0 ? {} : { maxAgeMs: s },
		...l === void 0 ? {} : { clockSkewMs: l },
		unrecognizedReasonCode: u
	};
	for (let e of r) {
		let r = takeDeltaCrlAttempt(d) ? settleAuthenticatedCrlOutcome(await checkRevocationAgainstAuthenticatedCrl(t, p.value, {
			...m,
			deltaCrl: e
		}), laterEvidenceDate(n.thisUpdate, e.thisUpdate), f) : { kind: "retry_limit" };
		if (r !== void 0) {
			if (r.kind === "delta_unusable") return irremovableRevocation(t, r.complete, a, n.thisUpdate) ?? r;
			if (r.kind === "retry_limit") {
				let e = await checkRevocationAgainstAuthenticatedCrl(t, p.value, m);
				return (e.kind === "checked" ? irremovableRevocation(t, e.result, a, n.thisUpdate) : void 0) ?? r;
			}
			return r;
		}
	}
	return settleAuthenticatedCrlOutcome(await checkRevocationAgainstAuthenticatedCrl(t, p.value, m), n.thisUpdate, f) ?? { kind: "unusable_base" };
}
/**
* The base CRL's revocation of `cert` in `complete` when no delta CRL could
* remove it at `at`. RFC 5280 §5.3.1 lets removeFromCRL clear only a
* certificateHold entry or a certificate that has expired.
*/
function irremovableRevocation(e, t, n, r) {
	if (!(e.notAfter.getTime() < n.getTime() || !t.ok || t.value.status !== "revoked" || t.value.reasonCode === "certificateHold")) return {
		kind: "checked",
		checked: t,
		crlThisUpdate: r
	};
}
/** Spends one delta CRL check from every budget, or none when any is empty. */
function takeDeltaCrlAttempt(e) {
	if (e.some((e) => e.remaining <= 0)) return !1;
	for (let t of e) --t.remaining;
	return !0;
}
/** Maps one staged CRL check to the search outcome, or `undefined` to try the next delta CRL. */
function settleAuthenticatedCrlOutcome(e, t, n) {
	if (e.kind === "delta_unresolved") return {
		kind: "delta_unusable",
		complete: e.complete
	};
	let r = e.kind === "checked" ? e.result : e.failure;
	if (!r.ok && r.code === "stale_crl" && (n.sawStaleCrl = !0), !r.ok && r.code === "reason_code_unrecognized") return { kind: "reason_code_unrecognized" };
	if (e.kind !== "delta_rejected") return r.ok ? {
		kind: "checked",
		checked: r,
		crlThisUpdate: t
	} : { kind: "unusable_base" };
}
function isNewerDeltaCrl(e, t) {
	let n = e.thisUpdate.getTime(), r = t.thisUpdate.getTime();
	return n === r ? (e.crlNumber ?? 0n) > (t.crlNumber ?? 0n) : n > r;
}
/** The direct issuer first, then deduplicated indirect CRL-issuer candidates. */
function collectCrlSignerCandidates(e, t, n, r) {
	let i = [t];
	for (let t of findIndirectCrlIssuers(e, n, r)) i.some((e) => sameCertificate(e, t)) || i.push(t);
	return i;
}
function recordGoodCrlEvidence(e, t, n, r) {
	e.sawGood = !0, (e.freshestGood === void 0 || n.getTime() > e.freshestGood.thisUpdate.getTime()) && (e.freshestGood = {
		signer: t,
		thisUpdate: n
	});
	for (let t of r) e.coveredReasons.add(t);
}
/** Indeterminate reasons that keep other evidence from settling the status as `good`. */
const C = /* @__PURE__ */ new Set([
	"delta_crl_unusable",
	"delta_crl_retry_limit_exceeded",
	"crl_reason_code_unrecognized",
	"ocsp_reason_code_unrecognized"
]);
/**
* Evaluates revocation status for a single certificate by combining OCSP and
* CRL evidence.
*
* Both evidence kinds are always evaluated: a validated `revoked` verdict from
* either source wins regardless of {@linkcode RevocationPolicy.prefer}
* (fail-closed). Otherwise the preferred source's `good` verdict is reported —
* for `'best-available'` the source with the later evidence `thisUpdate` wins,
* ties favoring OCSP. An indeterminate reason in
* {@linkcode GOOD_BLOCKING_REASONS} from either source outranks a `good`
* verdict. If neither source is definitive, indeterminate reasons from both
* are merged.
*/
async function evaluateCertificateRevocation(e, t, n, r, i) {
	let a = n.policy?.prefer ?? "best-available", o = await evaluateOcspEvidence(e, t, n), s = await evaluateCrlEvidence(e, t, n, r, i), c = [...o.executionErrors, ...s.executionErrors], l = a === "crl" ? [s, o] : a === "ocsp" ? [o, s] : [o, s].sort((e, t) => (t.status.source?.thisUpdate?.getTime() ?? 0) - (e.status.source?.thisUpdate?.getTime() ?? 0)), u = l.find((e) => e.status.status === "revoked");
	if (u !== void 0) return {
		status: u.status,
		executionErrors: c
	};
	let d = l.find((e) => e.status.status === "good"), f = [s, o].some((e) => e.status.indeterminateReasons?.some((e) => C.has(e)));
	if (d !== void 0 && !f) return {
		status: d.status,
		executionErrors: c
	};
	let p = /* @__PURE__ */ new Set();
	for (let e of l) for (let t of e.status.indeterminateReasons ?? []) p.add(t);
	return {
		status: {
			certificate: e,
			status: "indeterminate",
			indeterminateReasons: [...p]
		},
		executionErrors: c
	};
}
/**
* RFC 9608 §4: path validation skips RFC 5280 §6.1.3 step (a)(3) for a
* certificate carrying noRevAvail or id-pkix-ocsp-nocheck, read from its
* signed DER.
*/
function revocationSkipReason(e) {
	let t = parseCertificateDer(e.der);
	if (t.ok) return t.value.noRevAvail === !0 ? "no_rev_avail" : carriesOcspNoCheck(t.value) ? "ocsp_nocheck" : void 0;
}
/**
* Checks revocation status for all certificates in a validated chain.
*
* Evaluates CRL and OCSP evidence against each certificate (except the trust
* anchor), applies the revocation policy, and returns a unified decision. A
* certificate carrying noRevAvail or id-pkix-ocsp-nocheck is reported as
* `skipped` without consulting evidence (RFC 9608 §4).
*
* @example
* ```ts
* const result = await checkChainRevocation({
*   chain: validatedChain,
*   crls: [crl1, crl2],
*   ocspResponses: [ocspResponseDer],
*   policy: { mode: 'hard-fail' },
* });
* if (result.value.decision === 'deny') {
*   console.log('Revocation check failed');
* }
* ```
*/
async function checkChainRevocation(e) {
	let { chain: t, policy: n, crls: r = [], extraCertificates: i = [], at: o = /* @__PURE__ */ new Date() } = e;
	assertCrlMaxAge(n?.crlMaxAgeMs);
	let s = n?.mode ?? "hard-fail";
	if (t.length === 0) return {
		ok: !0,
		value: {
			decision: "allow",
			summary: {
				revokedCertificates: [],
				indeterminateCertificates: []
			},
			certificates: []
		}
	};
	let c = {
		cache: /* @__PURE__ */ new Map(),
		chain: t,
		crls: r,
		extraCertificates: i,
		at: o,
		crlMaxAgeMs: n?.crlMaxAgeMs,
		clockSkewMs: n?.clockSkewMs,
		unrecognizedReasonCode: n?.unrecognizedReasonCode ?? "revoked"
	}, l = { remaining: 32 }, u = t.slice(0, -1), d = [], f = [], p = [], m = [];
	for (let n = 0; n < u.length; n++) {
		let r = u[n], i = t[n + 1];
		if (r === void 0 || i === void 0) continue;
		let a = revocationSkipReason(r);
		if (a !== void 0) {
			d.push({
				certificate: r,
				status: "skipped",
				skipReason: a
			});
			continue;
		}
		let { status: o, executionErrors: s } = await evaluateCertificateRevocation(r, i, e, c, l);
		d.push(o), m.push(...s), o.status === "revoked" ? f.push(r) : o.status === "indeterminate" && p.push(r);
	}
	let h = f.length > 0, g = p.length > 0;
	return {
		ok: !0,
		value: {
			decision: h || g && s === "hard-fail" ? "deny" : "allow",
			summary: {
				revokedCertificates: f,
				indeterminateCertificates: p
			},
			certificates: d,
			...m.length > 0 ? { executionErrors: m } : {}
		}
	};
}
// ../../dist/verify/verify.js
/**
* Public certificate and CSR verification APIs.
*
* Builds and validates certificate paths per RFC 5280 §6, enforcing purpose
* constraints, policy state, name constraints, and optional service identity
* checks against a leaf certificate.
*
* Three levels of granularity:
* - {@linkcode buildCandidatePath} — signature-verified path only
* - {@linkcode validateCandidatePath} — time/constraint/policy validation on a pre-built path
* - {@linkcode verifyCertificateChain} — all-in-one build + validate
*
* Purpose-scoped convenience wrappers: {@linkcode validateForTlsServer},
* {@linkcode validateForTlsClient}, {@linkcode validateForCodeSigning}, {@linkcode validateForCa}.
*
* @module
*/
/**
* Discriminant for every failure a verify operation can produce.
*
* - `no_trusted_root` — chain could not be anchored to any root or {@linkcode TrustAnchor}.
* - `issuer_not_found` — an intermediate's issuer was not in the candidate set, or its issuer DN does not match the candidate issuer's subject DN.
* - `signature_invalid` — a certificate's signature failed cryptographic verification.
* - `certificate_expired` — a certificate's notBefore/notAfter window excludes the validation time.
* - `ca_required` — an issuer lacks `basicConstraints.ca = true`.
* - `key_cert_sign_required` — an issuer has keyUsage but omits `keyCertSign`.
* - `path_length_exceeded` — the number of CA certificates below an issuer exceeds its pathLength.
* - `path_building_limit_exceeded` — candidate-path construction exceeded its bounded work limits.
* - `authority_key_identifier_mismatch` — a certificate's AKI does not match the issuer's SKI.
* - `extended_key_usage_invalid` — the leaf certificate lacks the required EKU for the requested purpose.
* - `subject_alt_name_mismatch` — no SAN entry matches the requested service identity.
* - `common_name_fallback_suppressed` — CN fallback was attempted but suppressed (SAN present or disabled).
* - `self_signed_leaf_not_allowed` — the leaf is self-signed and `allowSelfSignedLeaf` was not set.
* - `unrecognized_critical_extension` — a certificate contains a critical extension the verifier cannot process.
* - `no_rev_avail_conflict` — a certificate carries noRevAvail alongside a CA basicConstraints, cRLDistributionPoints, freshestCRL, or an id-ad-ocsp authorityInfoAccess entry (RFC 9608 §3).
* - `display_text_oversized` — under `rejectOversizedDisplayText`, a certificate's user notice `explicitText` or `noticeRef` organization exceeds the 200 characters of RFC 5280 §4.2.1.4.
* - `intermediate_eku_constraint` — an intermediate CA's EKU set does not include the required purpose.
* - `explicit_policy_required` — `requireExplicitPolicy` was set but no acceptable policy was found.
* - `initial_policy_set_not_satisfied` — the chain's policies do not intersect `initialPolicySet`.
* - `unsupported_initial_name_constraints` — caller-supplied initial name constraints use unsupported or malformed forms.
* - `unsupported_name_constraints` — a certificate's nameConstraints use an unsupported form.
* - `name_constraints_violated` — a subject name violates a permitted/excluded subtree.
* - `unsupported_signature_algorithm_parameters` — the signature algorithm uses unrecognized parameters.
* - `ec_domain_parameters_missing` — an elliptic curve public key carries no namedCurve domain parameters.
* - `public_key_distrusted` — a certificate or bare trust anchor uses an explicitly distrusted SHA-256 SPKI.
* - `certificate_revoked` — revocation evidence confirms a chain certificate is revoked.
* - `revocation_indeterminate` — revocation status could not be determined under a hard-fail policy.
* - `unsupported` — a certificate source holds a construct micro509 does not decode (see `ParseCertificateErrorCode`).
* - `limit_exceeded` — a certificate source exceeds a micro509 decoding limit (see `ParseCertificateErrorCode`).
*/
const z = /* @__PURE__ */ "no_trusted_root.issuer_not_found.signature_invalid.certificate_expired.ca_required.key_cert_sign_required.path_length_exceeded.path_building_limit_exceeded.authority_key_identifier_mismatch.extended_key_usage_invalid.subject_alt_name_mismatch.common_name_fallback_suppressed.self_signed_leaf_not_allowed.unrecognized_critical_extension.no_rev_avail_conflict.display_text_oversized.intermediate_eku_constraint.explicit_policy_required.initial_policy_set_not_satisfied.unsupported_initial_name_constraints.unsupported_name_constraints.name_constraints_violated.unsupported_signature_algorithm_parameters.ec_domain_parameters_missing.public_key_distrusted.certificate_revoked.revocation_indeterminate.unsupported.limit_exceeded".split(".");
const B = /* @__PURE__ */ new Set([
	t.basicConstraints,
	t.keyUsage,
	t.extendedKeyUsage,
	t.subjectAltName,
	t.issuerAltName,
	t.nameConstraints,
	t.authorityKeyIdentifier,
	t.subjectKeyIdentifier,
	t.authorityInfoAccess,
	t.cRLDistributionPoints,
	t.certificatePolicies,
	t.policyMappings,
	t.policyConstraints,
	t.inhibitAnyPolicy,
	t.noRevAvail
]);
function loadCertificatePool(e, t) {
	let n = [];
	for (let [r, i] of e.entries()) try {
		n.push(...loadCertificates([i]));
	} catch (e) {
		return certificateSourceFailure(e, {
			kind: t,
			position: r
		});
	}
	return {
		ok: !0,
		certificates: n
	};
}
function certificateSourceFailure(t, n$1) {
	let r = decodeRefusalOf(t, n);
	return r === void 0 ? failure("issuer_not_found", "certificate source is malformed or leaf source does not contain exactly one certificate", 0, detail({
		actual: t instanceof Error ? t.message : "certificate source is malformed",
		source: n$1
	})) : failure(r.code, r.message, 0, detail({
		actual: r.message,
		source: n$1
	}));
}
/**
* Discovers and signature-verifies a candidate certification path from a
* leaf certificate to a trusted root or trust anchor. Does NOT validate
* time, constraints, or leaf policy — use {@linkcode validateCandidatePath}
* for that, or {@linkcode verifyCertificateChain} for the all-in-one API.
*/
async function buildCandidatePathRaw(e) {
	assertPathBuildingChecks(e.maxPathBuildingChecks);
	let t = createSpkiDistrustCheck(e.distrustedSpkiSha256), n;
	try {
		n = loadSingleCertificate(e.leaf);
	} catch (e) {
		return certificateSourceFailure(e, void 0);
	}
	let r = loadCertificatePool(e.intermediates ?? [], "intermediates");
	if (!r.ok) return r;
	let i = loadCertificatePool(e.roots, "roots");
	if (!i.ok) return i;
	let a = e.trustAnchors ?? [], o = e.at ?? /* @__PURE__ */ new Date(), s = await buildChainInternal(n, r.certificates, i.certificates, a, o, {
		failure,
		detail
	}, void 0, e.maxPathBuildingChecks, t), c = s.chain;
	if (!s.foundTrustedRoot) return s.failure === void 0 ? s.missingIssuerAt === void 0 ? failure("no_trusted_root", "no trusted root found", void 0, detail({ chainCommonNames: c.map((e) => e.subject.values.commonName ?? "<unnamed>") })) : failure("issuer_not_found", "issuer certificate not found", s.missingIssuerAt, buildFailureDetails(c, s.missingIssuerAt)) : s.failure;
	let l = c[c.length - 1];
	return l === void 0 ? failure("no_trusted_root", "no trusted root found") : {
		ok: !0,
		value: {
			leaf: n,
			chain: c,
			root: l,
			anchorCertificateInChain: s.anchorCertificateInChain ?? !0,
			...s.trustAnchor !== void 0 && { trustAnchor: s.trustAnchor }
		}
	};
}
/**
* Builds a signature-verified path from a leaf certificate to a trusted root.
*
* Parses the supplied certificates, walks the issuer chain, signature-checks
* each link, and returns the first valid path. Does not enforce time, constraints,
* or leaf purpose — call {@linkcode validateCandidatePath} or use the all-in-one
* {@linkcode verifyCertificateChain} for full validation.
*
* @example
* ```ts
* import { buildCandidatePath } from 'micro509';
*
* const result = await buildCandidatePath({
*   leaf: leafPem,
*   intermediates: [intermediatePem],
*   roots: [rootPem],
* });
* if (result.ok) {
*   console.log('path length:', result.value.chain.length);
* }
* ```
*/
async function buildCandidatePath(e) {
	let t = await buildCandidatePathRaw(e);
	return t.ok ? t : verifyFailureResult(t);
}
/**
* Validates a pre-built candidate path: time window, critical extensions,
* inter-certificate signatures, CA/keyUsage/AKI constraints, pathLength,
* policy processing, name constraints, and leaf purpose checks.
*
* The chain must be in leaf-to-root order. The root (last entry) is
* assumed trusted and not re-verified.
*/
async function validateCandidatePathRaw(e) {
	let t = createSpkiDistrustCheck(e.distrustedSpkiSha256);
	if (e.distrustedSpkiSha256?.length && e.anchorCertificateInChain === !1 && e.trustAnchor === void 0) throw RangeError("trustAnchor is required to check distrust on a path with a bare anchor");
	let n = e.chain, r = await validatePathDistrust(e, t);
	if (r !== void 0) return r;
	let i = e.at ?? /* @__PURE__ */ new Date(), a = buildValidationState(e, n.length);
	if (!a.ok) return a;
	let o = n[0];
	if (o === void 0) return failure("issuer_not_found", "chain is empty", 0);
	let s = await validateSelfSignedLeafAllowed(o, n.length, e);
	if (s !== void 0) return s;
	let c = await validatePathCertificates(n, i, e.rejectOversizedDisplayText === !0);
	if (c !== void 0) return c;
	let l = validatePathLengthConstraints(n);
	if (l !== void 0) return l;
	let u = validatePolicyAndNameConstraints(n, a.value, e.anchorCertificateInChain ?? !0);
	return u.ok ? validateLeaf(o, e, u.policyValidation) : u;
}
/** Checks signed certificate SPKIs and the separately supplied bare anchor. */
async function validatePathDistrust(e, t) {
	if (e.distrustedSpkiSha256?.length) {
		for (let [n, r] of e.chain.entries()) {
			let e;
			try {
				e = parseCertificateDerOrThrow(r.der);
			} catch (e) {
				return {
					...certificateSourceFailure(e, void 0),
					index: n
				};
			}
			let i = await t(e.subjectPublicKeyInfoDer);
			if (i !== void 0) return failure("public_key_distrusted", "certificate public key is explicitly distrusted", n, detail({
				subjectCommonName: e.subject.values.commonName,
				actual: i
			}));
		}
		if (e.trustAnchor !== void 0) {
			let n = await t(e.trustAnchor.subjectPublicKeyInfoDer);
			if (n !== void 0) return failure("public_key_distrusted", "bare trust anchor public key is explicitly distrusted", void 0, detail({ actual: n }));
		}
	}
}
/** RFC 5280 §3.2 makes a self-issued certificate self-signed only when the public key it binds verifies its signature. */
async function validateSelfSignedLeafAllowed(e, t, n) {
	if (t !== 1 || !isSelfIssued$2(e) || n.allowSelfSignedLeaf === !0) return;
	let r = await verifyCertificateSignature(e, e);
	if (r.ok && r.valid) return failure("self_signed_leaf_not_allowed", "self-signed leaf not allowed", 0, detail({ subjectCommonName: e.subject.values.commonName }));
}
/** Validates every certificate and issuer relationship in a candidate path. */
async function validatePathCertificates(e, t, n) {
	for (let r = 0; r < e.length; r += 1) {
		let i = e[r];
		if (i === void 0) return failure("issuer_not_found", "chain element missing", r);
		let a = validateCertificateAtPathIndex(i, r, t);
		if (a !== void 0) return a;
		if (n) {
			let e = validateDisplayTextAtPathIndex(i, r);
			if (e !== void 0) return e;
		}
		let o = await validatePathIssuerAtIndex(e, i, r);
		if (o !== void 0) return o;
	}
}
/** RFC 5280 §4.2.1.4 bounds a DisplayText at 200 characters; PKITS 4.8.19 lets the application reject a longer explicitText. */
function validateDisplayTextAtPathIndex(e, t) {
	for (let n of e.certificatePolicies ?? []) for (let r of n.policyQualifiers ?? []) {
		if (r.type !== "userNotice") continue;
		let i = [[
			"explicitText",
			"explicitText",
			r.oversizedExplicitText
		], [
			"noticeRefOrganization",
			"noticeRef organization",
			r.noticeRef?.oversizedOrganization
		]];
		for (let [r, a, o] of i) if (o !== void 0) return failure("display_text_oversized", `certificate policy ${n.policyIdentifier} carries a user notice ${a} of ${String(o.characters)} characters`, t, detail({
			subjectCommonName: e.subject.values.commonName,
			expected: String(o.limit),
			actual: String(o.characters),
			userNoticeField: r
		}));
	}
}
async function validatePathIssuerAtIndex(e, t, n) {
	if (n === e.length - 1) return;
	let r = e[n + 1];
	return r === void 0 ? failure("issuer_not_found", "issuer missing", n) : await validateIssuerAtPathIndex(t, r, n);
}
function validatePathLengthConstraints(e) {
	for (let t = 1; t < e.length; t += 1) {
		let n = e[t];
		if (n === void 0) return failure("issuer_not_found", "chain element missing", t);
		let r = countCaCertificatesBelowParsed(e, t), i = n.basicConstraints?.pathLength;
		if (isNonNegativeInteger(i) && r > i) return pathLengthExceededFailure(n, t, i, r);
	}
}
function pathLengthExceededFailure(e, t, n, r) {
	return failure("path_length_exceeded", "path length constraint exceeded", t, detail({
		subjectCommonName: e.subject.values.commonName,
		expected: String(n),
		actual: String(r)
	}));
}
function validatePolicyAndNameConstraints(e, t, n) {
	let r = evaluatePolicyChain(e, t.policy, n);
	if (!r.ok) return failure(r.error.code, r.error.message, 0, detail({
		expected: r.error.details?.expected,
		actual: r.error.details?.actual
	}));
	let i = evaluateNameConstraints(e, t.nameConstraints);
	return i.ok ? {
		ok: !0,
		policyValidation: r.value
	} : i;
}
function validateCertificateAtPathIndex(e, t, n) {
	if (!isWithinValidity(e, n)) return failure("certificate_expired", "certificate not valid at requested time", t, detail({
		subjectCommonName: e.subject.values.commonName,
		expected: describeDateTime(n),
		actual: `${describeDateTime(e.notBefore)}..${describeDateTime(e.notAfter)}`
	}));
	let r = findUnprocessedCriticalExtension(e);
	if (r !== void 0) return failure("unrecognized_critical_extension", `certificate contains unrecognized critical extension ${r}`, t, detail({
		subjectCommonName: e.subject.values.commonName,
		actual: r
	}));
	let i = findNoRevAvailConflict(e);
	return i === void 0 ? validateEcDomainParametersAtPathIndex(e, t) : failure("no_rev_avail_conflict", `certificate carries noRevAvail with ${i}`, t, detail({
		subjectCommonName: e.subject.values.commonName,
		actual: i
	}));
}
/**
* RFC 9608 §3: a relying party MUST consider a certificate carrying noRevAvail
* invalid when it also asserts cA, points at a CRL, or names an OCSP responder.
*/
function findNoRevAvailConflict(e) {
	if (e.noRevAvail === !0) {
		if (e.basicConstraints?.ca === !0) return "basicConstraints cA TRUE";
		if (e.crlDistributionPoints !== void 0) return "cRLDistributionPoints";
		if (e.extensions.some((e) => e.oid === t.freshestCRL)) return "freshestCRL";
		if (e.authorityInfoAccess?.some((e) => e.method === "ocsp") === !0) return "an id-ad-ocsp authorityInfoAccess entry";
	}
}
/**
* RFC 5480 §2.1.1 admits only the namedCurve alternative of ECParameters, and
* requires clients to reject a certificate whose elliptic curve domain
* parameters are not present.
*/
function validateEcDomainParametersAtPathIndex(e, t$1) {
	if (e.publicKeyAlgorithmOid === t.ecPublicKey && e.publicKeyParametersOid === void 0) return failure("ec_domain_parameters_missing", "elliptic curve public key carries no namedCurve domain parameters", t$1, detail({
		subjectCommonName: e.subject.values.commonName,
		expected: "namedCurve OBJECT IDENTIFIER",
		actual: e.publicKeyAlgorithmParametersDer === void 0 ? "absent" : `tag 0x${(e.publicKeyAlgorithmParametersDer[0] ?? 0).toString(16).padStart(2, "0")}`
	}));
}
async function validateIssuerAtPathIndex(e, t, n) {
	if (!compareDistinguishedNames(e.issuer, t.subject)) return failure("issuer_not_found", "issuer distinguished name does not match the candidate issuer subject", n, detail({
		subjectCommonName: e.subject.values.commonName,
		issuerCommonName: t.subject.values.commonName
	}));
	let r = await verifyCertificateSignature(e, t);
	return r.ok ? r.valid ? validateIssuerConstraintsAtPathIndex(e, t, n) : failure("signature_invalid", "certificate signature does not verify", n, detail({
		subjectCommonName: e.subject.values.commonName,
		issuerCommonName: t.subject.values.commonName
	})) : failure(r.code, r.reason, n, detail({
		subjectCommonName: e.subject.values.commonName,
		issuerCommonName: t.subject.values.commonName,
		actual: r.reason
	}));
}
function validateIssuerConstraintsAtPathIndex(e, t, n) {
	if (t.basicConstraints?.ca !== !0) return failure("ca_required", "issuer must be a CA certificate", n + 1, detail({ subjectCommonName: t.subject.values.commonName }));
	if (t.keyUsage !== void 0 && !t.keyUsage.flags.includes("keyCertSign")) return failure("key_cert_sign_required", "issuer missing keyCertSign", n + 1, detail({ subjectCommonName: t.subject.values.commonName }));
	if (authorityKeyIdentifierMismatch(e, t)) return failure("authority_key_identifier_mismatch", "authorityKeyIdentifier does not match issuer subjectKeyIdentifier", n, detail({
		subjectCommonName: e.subject.values.commonName,
		issuerCommonName: t.subject.values.commonName,
		expected: t.subjectKeyIdentifier,
		actual: e.authorityKeyIdentifier
	}));
}
/**
* Validates a pre-built certificate chain for time, constraints, policy, and
* optionally leaf purpose. Wrap the result of {@linkcode buildCandidatePath}.
*/
async function validateCandidatePath(t) {
	let n$2 = normalizeValidationChain(t.chain);
	if (!n$2.ok) {
		let { error: t, index: r } = n$2, i = decodeRefusalOf(t, n);
		return verifyFailureResult(i === void 0 ? failure("signature_invalid", "certificate input is malformed", r, detail({ actual: t instanceof Error ? t.message : "certificate input is malformed" })) : failure(i.code, i.message, r, detail({ actual: i.message })));
	}
	let r = await validateCandidatePathRaw({
		...t,
		chain: n$2.chain
	});
	return r.ok ? validateCandidatePathSuccessResult(r.policyValidation) : verifyFailureResult(r);
}
/**
* All-in-one certificate chain verification: builds a candidate path then
* validates time, constraints, policy, purpose, and optional service identity.
*
* Equivalent to calling {@linkcode buildCandidatePath} followed by
* {@linkcode validateCandidatePath} (plus identity matching when configured).
*
* @example
* ```ts
* import { verifyCertificateChain } from 'micro509';
*
* const result = await verifyCertificateChain({
*   leaf: serverCertPem,
*   intermediates: [intermediatePem],
*   roots: [rootCaPem],
*   purpose: 'serverAuth',
*   serviceIdentity: { type: 'dns', value: 'example.com' },
* });
* if (!result.ok) {
*   console.error(result.error.code, result.error.message);
* }
* ```
*/
async function verifyCertificateChain(e) {
	let t = e.distrustedSpkiSha256 === void 0 ? void 0 : [...e.distrustedSpkiSha256];
	assertCrlMaxAge(e.revocation?.policy?.crlMaxAgeMs);
	let n = await buildCandidatePath({
		leaf: e.leaf,
		roots: e.roots,
		...e.intermediates !== void 0 && { intermediates: e.intermediates },
		...e.trustAnchors !== void 0 && { trustAnchors: e.trustAnchors },
		...e.at !== void 0 && { at: e.at },
		...e.maxPathBuildingChecks !== void 0 && { maxPathBuildingChecks: e.maxPathBuildingChecks },
		...t !== void 0 && { distrustedSpkiSha256: t }
	});
	if (!n.ok) return n;
	let r = await validateCandidatePath({
		chain: n.value.chain,
		anchorCertificateInChain: n.value.anchorCertificateInChain,
		...n.value.trustAnchor !== void 0 && { trustAnchor: n.value.trustAnchor },
		...t !== void 0 && { distrustedSpkiSha256: t },
		...e.at !== void 0 && { at: e.at },
		...e.purpose !== void 0 && { purpose: e.purpose },
		...copyValidationInputs(e),
		...e.allowSelfSignedLeaf !== void 0 && { allowSelfSignedLeaf: e.allowSelfSignedLeaf },
		...e.rejectOversizedDisplayText !== void 0 && { rejectOversizedDisplayText: e.rejectOversizedDisplayText }
	});
	if (!r.ok) return r;
	if (e.serviceIdentity !== void 0) {
		let t = validateServiceIdentity(n.value.leaf, e.serviceIdentity);
		if (!t.ok) return verifyFailureResult(t);
	}
	if (e.revocation !== void 0) {
		let t = await validateVerifiedChainRevocation(e, n.value.chain);
		if (t !== void 0) return t;
	}
	return {
		ok: !0,
		value: {
			...n.value,
			policyValidation: r.value.policyValidation
		}
	};
}
/** Applies optional revocation evidence to an otherwise verified certificate chain. */
async function validateVerifiedChainRevocation(e, t) {
	if (e.revocation === void 0) return;
	let n = await checkChainRevocation({
		chain: t,
		...e.revocation.crls === void 0 ? {} : { crls: e.revocation.crls },
		...e.revocation.ocspResponses === void 0 ? {} : { ocspResponses: e.revocation.ocspResponses },
		...e.revocation.extraCertificates === void 0 ? {} : { extraCertificates: e.revocation.extraCertificates },
		...e.revocation.trustedOcspResponders === void 0 ? {} : { trustedOcspResponders: e.revocation.trustedOcspResponders },
		...e.revocation.policy === void 0 ? {} : { policy: e.revocation.policy },
		...e.at === void 0 ? {} : { at: e.at }
	});
	return n.value.decision === "deny" ? revocationFailureResult(n.value) : void 0;
}
function revocationFailureResult(e) {
	let t = e.summary.revokedCertificates[0];
	if (t !== void 0) return verifyFailureResult(failure("certificate_revoked", `certificate revoked: ${t.subject.values.commonName ?? "unknown"}`, revocationFailureIndex(e, "revoked"), detail({ subjectCommonName: t.subject.values.commonName })));
	let n = e.summary.indeterminateCertificates[0], r = e.certificates.find((e) => e.status === "indeterminate")?.indeterminateReasons;
	return verifyFailureResult(failure("revocation_indeterminate", `revocation status indeterminate: ${n?.subject.values.commonName ?? "unknown"}`, revocationFailureIndex(e, "indeterminate"), detail({
		subjectCommonName: n?.subject.values.commonName,
		actual: r?.join(", ")
	})));
}
/** Revocation evaluates each non-anchor chain certificate in path order. */
function revocationFailureIndex(e, t) {
	let n = e.certificates.findIndex((e) => e.status === t);
	return n < 0 ? void 0 : n;
}
/**
* Verifies the self-signature of a PKCS#10 certificate signing request.
*
* Parses the CSR from PEM or DER, then checks that its signature is valid
* against its own embedded public key.
*
* @example
* ```ts
* import { verifyCertificateSigningRequest } from 'micro509';
*
* const result = await verifyCertificateSigningRequest(csrPem);
* if (result.ok) {
*   console.log('subject:', result.value.subject.values.commonName);
* }
* ```
*/
async function verifyCertificateSigningRequest(t) {
	let n$4;
	try {
		n$4 = typeof t == "string" ? parseCertificateSigningRequestPemOrThrow(t) : parseCertificateSigningRequestDerOrThrow(new Uint8Array(t));
	} catch (t) {
		let n$3 = decodeRefusalOf(t, n);
		return n$3 === void 0 ? verifyRequestFailureResult("signature_invalid", "certificate request input is malformed", detail({ actual: t instanceof Error ? t.message : "certificate request input is malformed" })) : verifyRequestFailureResult(n$3.code, n$3.message, detail({ actual: n$3.message }));
	}
	let r;
	try {
		r = await verifySignedDataDetailed(n$4.signatureAlgorithmOid, n$4.signatureAlgorithmParametersDer, n$4.publicKeyAlgorithmOid, n$4.publicKeyParametersOid, n$4.subjectPublicKeyInfoDer, n$4.signatureValue, n$4.certificationRequestInfoDer);
	} catch (t) {
		let r = decodeRefusalOf(t, n);
		return r === void 0 ? verifyRequestFailureResult("signature_invalid", "certificate request input is malformed", detail({
			subjectCommonName: n$4.subject.values.commonName,
			actual: t instanceof Error ? t.message : "certificate request input is malformed"
		})) : verifyRequestFailureResult(r.code, r.message, detail({
			subjectCommonName: n$4.subject.values.commonName,
			actual: r.message
		}));
	}
	return r.ok ? r.valid ? {
		ok: !0,
		value: n$4
	} : verifyRequestFailureResult("signature_invalid", "certificate request signature does not verify", detail({ subjectCommonName: n$4.subject.values.commonName })) : verifyRequestFailureResult(r.code === "verification_error" ? "signature_invalid" : r.code, r.reason, detail({
		subjectCommonName: n$4.subject.values.commonName,
		actual: r.reason
	}));
}
/**
* Standalone EKU check against a verified certificate chain.
* Validates that the leaf has the requested purpose and that
* intermediate CA EKU constraints (if present) permit it.
*
* @example
* ```ts
* import { checkExtendedKeyUsage } from 'micro509';
*
* const result = checkExtendedKeyUsage(chain, 'serverAuth');
* if (!result.ok) {
*   console.error(result.error.code, result.error.message);
* }
* ```
*/
function checkExtendedKeyUsage(t, n$5) {
	let r = normalizeValidationChain(t);
	if (!r.ok) {
		let t = decodeRefusalOf(r.error, n);
		return t === void 0 ? ekuCheckFailureResult("leaf_eku_missing", "certificate input is malformed", r.index) : ekuCheckFailureResult(t.code, t.message, r.index);
	}
	let i = r.chain, o = i[0];
	if (o === void 0) return ekuCheckFailureResult("leaf_eku_missing", "chain is empty", 0);
	if (o.extendedKeyUsage !== void 0 && !o.extendedKeyUsage.includes(n$5)) return ekuCheckFailureResult("leaf_eku_missing", `leaf certificate does not include EKU ${n$5}`, 0);
	for (let e = 1; e < i.length; e += 1) {
		let t = i[e];
		if (t !== void 0 && t.extendedKeyUsage !== void 0 && !t.extendedKeyUsage.includes(n$5)) return ekuCheckFailureResult("intermediate_eku_constraint", `intermediate CA at index ${String(e)} constrains EKU and does not include ${n$5}`, e);
	}
	return {
		ok: !0,
		value: void 0
	};
}
/** Extracts a {@linkcode TrustAnchor} from a parsed certificate, copying the subject, SPKI, and key identifiers. */
function trustAnchorFromCertificate(t) {
	let n$6;
	try {
		n$6 = reparseCertificateForTrust(t);
	} catch (t) {
		throw rethrowDecodeRefusal(t, n), Error("certificate input is malformed");
	}
	return {
		subject: n$6.subject,
		subjectPublicKeyInfoDer: n$6.subjectPublicKeyInfoDer,
		publicKeyAlgorithmOid: n$6.publicKeyAlgorithmOid,
		...n$6.publicKeyParametersOid === void 0 ? {} : { publicKeyParametersOid: n$6.publicKeyParametersOid },
		...n$6.subjectKeyIdentifier === void 0 ? {} : { subjectKeyIdentifier: n$6.subjectKeyIdentifier }
	};
}
/** Extracts defined optional fields from a base input for safe forwarding. */
function baseChainInput(e) {
	return {
		leaf: e.leaf,
		roots: e.roots,
		...e.intermediates !== void 0 && { intermediates: e.intermediates },
		...e.trustAnchors !== void 0 && { trustAnchors: e.trustAnchors },
		...e.at !== void 0 && { at: e.at },
		...e.maxPathBuildingChecks !== void 0 && { maxPathBuildingChecks: e.maxPathBuildingChecks },
		...e.distrustedSpkiSha256 !== void 0 && { distrustedSpkiSha256: e.distrustedSpkiSha256 },
		...copyValidationInputs(e)
	};
}
/**
* Validates a certificate chain for TLS server use:
* chain verification + `serverAuth` EKU (leaf + intermediate propagation)
* + DNS/IP identity matching.
*
* @example
* ```ts
* import { validateForTlsServer } from 'micro509';
*
* const result = await validateForTlsServer({
*   leaf: serverCertPem,
*   roots: [rootCaPem],
*   serviceIdentity: { type: 'dns', value: 'example.com' },
* });
* if (result.ok) {
*   console.log('valid for', result.value.leaf.subject.values.commonName);
* }
* ```
*/
async function validateForTlsServer(e) {
	let t = await verifyChainForExtendedKeyUsageProfile(e, "serverAuth");
	if (!t.ok) return t;
	if (e.serviceIdentity !== void 0) {
		let n = validateServiceIdentity(t.value.leaf, e.serviceIdentity);
		if (!n.ok) return verifyFailureResult(n);
	}
	return t;
}
/**
* Validates a certificate chain for TLS client use:
* chain verification + `clientAuth` EKU (leaf + intermediate propagation).
*
* @example
* ```ts
* import { validateForTlsClient } from 'micro509';
*
* const result = await validateForTlsClient({
*   leaf: clientCertPem,
*   roots: [rootCaPem],
* });
* ```
*/
function validateForTlsClient(e) {
	return verifyChainForExtendedKeyUsageProfile(e, "clientAuth");
}
/**
* Validates a certificate chain for code signing:
* chain verification + `codeSigning` EKU (leaf + intermediate propagation).
*
* @example
* ```ts
* import { validateForCodeSigning } from 'micro509';
*
* const result = await validateForCodeSigning({
*   leaf: codeSigningCertPem,
*   roots: [rootCaPem],
* });
* ```
*/
function validateForCodeSigning(e) {
	return verifyChainForExtendedKeyUsageProfile(e, "codeSigning");
}
/**
* Validates a certificate chain for CA use:
* chain verification + `basicConstraints.ca` check on the leaf.
*
* @example
* ```ts
* import { validateForCa } from 'micro509';
*
* const result = await validateForCa({
*   leaf: intermediateCertPem,
*   roots: [rootCaPem],
* });
* ```
*/
function validateForCa(e) {
	return verifyCertificateChain({
		...baseChainInput(e),
		purpose: "ca"
	});
}
/** Enforces purpose-specific constraints on the leaf certificate (CA flag or EKU). */
function validateLeaf(e, t, n) {
	let r = t.purpose;
	if (r !== void 0) {
		if (r === "ca") {
			if (e.basicConstraints?.ca !== !0) return failure("ca_required", "leaf is not a CA certificate", 0, detail({ subjectCommonName: e.subject.values.commonName }));
		} else if (e.extendedKeyUsage !== void 0 && !e.extendedKeyUsage.includes(r)) return failure("extended_key_usage_invalid", `leaf missing EKU ${r}`, 0, detail({
			subjectCommonName: e.subject.values.commonName,
			expected: r,
			actual: e.extendedKeyUsage.map(formatEku).join(",")
		}));
	}
	return {
		ok: !0,
		policyValidation: n
	};
}
/** Matches the leaf's SAN against the requested service identity. */
function validateServiceIdentity(e, t) {
	let n = validateServiceIdentityInput(t);
	if (!n.ok) return n;
	let r = matchServiceIdentity({
		certificate: reparseCertificateForTrust(e),
		serviceIdentity: t
	});
	if (r.ok) return { ok: !0 };
	let i = r.error;
	return i.code === "service_identity_mismatch" ? {
		ok: !1,
		code: "subject_alt_name_mismatch",
		message: i.message,
		index: 0,
		...i.details === void 0 ? {} : { details: i.details }
	} : i.code !== "subject_alt_name_mismatch" && i.code !== "common_name_fallback_suppressed" && i.code !== "unsupported" && i.code !== "limit_exceeded" ? failure("subject_alt_name_mismatch", "service identity input is malformed", 0, detail({
		expected: t.value,
		actual: i.code
	})) : {
		ok: !1,
		code: i.code,
		message: i.message,
		index: 0,
		...i.details === void 0 ? {} : { details: i.details }
	};
}
function validateServiceIdentityInput(e) {
	if (!isRecord(e)) return failure("subject_alt_name_mismatch", "service identity input is malformed", 0);
	if (e.type !== "dns" && e.type !== "ip" && e.type !== "uri" && e.type !== "srv") return failure("subject_alt_name_mismatch", "service identity input is malformed", 0, detail({ actual: String(e.type) }));
	if (typeof e.value != "string") return failure("subject_alt_name_mismatch", "service identity input is malformed", 0, detail({ actual: e.type }));
	if (e.type === "ip") try {
		parseIpAddressToBytes(e.value);
	} catch {
		return failure("subject_alt_name_mismatch", "service identity input is malformed", 0, detail({
			expected: e.value,
			actual: "ip"
		}));
	}
	return { ok: !0 };
}
/** Applies an EKU check to a successfully verified chain and maps failures to verify error codes. */
function applyEkuCheck(e, t) {
	let n = checkExtendedKeyUsage(e.value.chain, t);
	return n.ok ? e : verifyFailureResult(failure(n.code === "leaf_eku_missing" ? "extended_key_usage_invalid" : "intermediate_eku_constraint", n.message, n.index));
}
/** Verifies a chain then checks that all certificates permit the given EKU purpose. */
async function verifyChainForExtendedKeyUsageProfile(e, t) {
	let n = await verifyCertificateChain(baseChainInput(e));
	return n.ok ? applyEkuCheck(n, t) : n;
}
/** Returns the OID of the first critical extension not in {@linkcode PROCESSED_EXTENSION_OIDS}, or `undefined`. */
function findUnprocessedCriticalExtension(e) {
	for (let t$2 of e.extensions) if (t$2.critical && (!B.has(t$2.oid) || t$2.oid === t.subjectAltName && e.subjectAltNames?.some(isUninterpretedGeneralName) === !0)) return t$2.oid;
}
const V = /* @__PURE__ */ new Set([
	"otherName",
	"upn",
	"krb5PrincipalName",
	"x400Address",
	"ediPartyName",
	"unknown"
]);
function isUninterpretedGeneralName(e) {
	switch (e.type) {
		case "srv": return parsePresentedSrvName(asciiLowercase$1(e.value)) === void 0;
		case "smtpUtf8Mailbox": return presentedSmtpUtf8MailboxDomain(e.value) === void 0;
		default: return V.has(e.type);
	}
}
/** Constructs a {@linkcode VerifyChainFailure} with the given code, message, optional chain index, and details. */
function failure(e, t, n, i) {
	return {
		ok: !1,
		...indexedMicro509Error(e, t, n, i)
	};
}
/** Wraps a {@linkcode VerifyChainFailure} into the standard indexed error result shape. */
function verifyFailureResult(e) {
	return indexedErrorResult(e);
}
/** Wraps a policy outcome into the validate-candidate-path success result shape. */
function validateCandidatePathSuccessResult(e) {
	return {
		ok: !0,
		value: { policyValidation: e }
	};
}
/** Describes a date in ISO format, or `'<invalid date>'` if invalid. */
function describeDateTime(e) {
	return Number.isNaN(e.getTime()) ? "<invalid date>" : e.toISOString();
}
function normalizeValidationChain(e) {
	let t = [];
	for (let [n, r] of e.entries()) try {
		t.push(reparseCertificateForTrust(r));
	} catch (e) {
		return {
			ok: !1,
			index: n,
			error: e
		};
	}
	return {
		ok: !0,
		chain: t
	};
}
function reparseCertificateForTrust(e) {
	return parseCertificateDerOrThrow(new Uint8Array(e.der));
}
/** Returns `true` if the value is a non-negative integer (including zero). */
function isNonNegativeInteger(e) {
	return e !== void 0 && Number.isInteger(e) && e >= 0;
}
/** Constructs a CSR verification failure result. */
function verifyRequestFailureResult(e, n, r) {
	let a = {
		ok: !1,
		...micro509Error(e, n, r)
	};
	return errorResult(a);
}
/** Constructs an EKU check failure result at the given chain index. */
function ekuCheckFailureResult(e, t, i) {
	let a = {
		ok: !1,
		...indexedMicro509Error(e, t, i),
		index: i
	};
	return indexedErrorResult(a);
}
/** Merges flat and nested policy fields, with nested taking precedence. */
function resolvePolicyValidationInput(e) {
	let t = normalizeInitialPolicySet(e.initialPolicySet), n = normalizeInitialPolicySet(e.policy?.initialPolicySet);
	return {
		...t === void 0 ? {} : { initialPolicySet: t },
		...e.requireExplicitPolicy === void 0 ? {} : { requireExplicitPolicy: e.requireExplicitPolicy },
		...e.inhibitPolicyMapping === void 0 ? {} : { inhibitPolicyMapping: e.inhibitPolicyMapping },
		...e.inhibitAnyPolicy === void 0 ? {} : { inhibitAnyPolicy: e.inhibitAnyPolicy },
		...n === void 0 ? {} : { initialPolicySet: n },
		...e.policy?.requireExplicitPolicy === void 0 ? {} : { requireExplicitPolicy: e.policy.requireExplicitPolicy },
		...e.policy?.inhibitPolicyMapping === void 0 ? {} : { inhibitPolicyMapping: e.policy.inhibitPolicyMapping },
		...e.policy?.inhibitAnyPolicy === void 0 ? {} : { inhibitAnyPolicy: e.policy.inhibitAnyPolicy }
	};
}
/** Merges flat and nested name-constraint fields, with nested taking precedence. */
function resolveInitialNameConstraintsInput(e) {
	return {
		...e.permittedSubtrees === void 0 ? {} : { permittedSubtrees: e.permittedSubtrees },
		...e.excludedSubtrees === void 0 ? {} : { excludedSubtrees: e.excludedSubtrees },
		...e.nameConstraints?.permittedSubtrees === void 0 ? {} : { permittedSubtrees: e.nameConstraints.permittedSubtrees },
		...e.nameConstraints?.excludedSubtrees === void 0 ? {} : { excludedSubtrees: e.nameConstraints.excludedSubtrees }
	};
}
/** Extracts the resolved policy and name-constraint inputs for forwarding. */
function copyValidationInputs(e) {
	let t = resolvePolicyValidationInput(e), n = resolveInitialNameConstraintsInput(e);
	return {
		...hasPolicyValidationInput(t) ? { policy: t } : {},
		...hasInitialNameConstraintsInput(n) ? { nameConstraints: n } : {}
	};
}
/** Returns `true` if any policy validation field is defined. */
function hasPolicyValidationInput(e) {
	return e.initialPolicySet !== void 0 || e.requireExplicitPolicy !== void 0 || e.inhibitPolicyMapping !== void 0 || e.inhibitAnyPolicy !== void 0;
}
/** Returns `true` if any initial name constraint field is defined. */
function hasInitialNameConstraintsInput(e) {
	return e.permittedSubtrees !== void 0 || e.excludedSubtrees !== void 0;
}
/** Constructs failure details with subject/issuer CNs and full chain CN list. */
function buildFailureDetails(e, t) {
	let n = e[t];
	return detail({
		subjectCommonName: n?.subject.values.commonName,
		issuerCommonName: n?.issuer.values.commonName,
		chainCommonNames: e.map((e) => e.subject.values.commonName ?? "<unnamed>")
	});
}
/** Formats an EKU value as a human-readable string (name or raw OID). */
function formatEku(e) {
	return typeof e == "string" ? e : e.value;
}
/** Strips `undefined` values from a loose input to produce a clean {@linkcode VerifyFailureDetails}. */
function detail(e) {
	return {
		...e.subjectCommonName === void 0 ? {} : { subjectCommonName: e.subjectCommonName },
		...e.issuerCommonName === void 0 ? {} : { issuerCommonName: e.issuerCommonName },
		...e.expected === void 0 ? {} : { expected: e.expected },
		...e.actual === void 0 ? {} : { actual: e.actual },
		...e.chainCommonNames === void 0 ? {} : { chainCommonNames: e.chainCommonNames },
		...e.presentedIdentifierTypes === void 0 ? {} : { presentedIdentifierTypes: e.presentedIdentifierTypes },
		...e.commonNameFallbackReason === void 0 ? {} : { commonNameFallbackReason: e.commonNameFallbackReason },
		...e.userNoticeField === void 0 ? {} : { userNoticeField: e.userNoticeField },
		...e.source === void 0 ? {} : { source: e.source }
	};
}
/** Initializes policy and name-constraint validation state for a chain walk. */
function buildValidationState(e, t) {
	let n = createPolicyValidationState(resolvePolicyValidationInput(e), t), r = validateInitialNameConstraintsInput(resolveInitialNameConstraintsInput(e));
	return r.ok ? {
		ok: !0,
		value: {
			policy: n,
			nameConstraints: createNameConstraintValidationState(r.value)
		}
	} : r;
}
function normalizeInitialPolicySet(e) {
	if (e === void 0) return;
	if (e === "any") return e;
	if (!Array.isArray(e)) return [];
	let t$3 = [];
	for (let n of e) {
		if (typeof n != "string") return [];
		try {
			t$3.push(canonicalizeOid(n));
		} catch {
			return [];
		}
	}
	return t$3.includes(t.anyPolicy) ? "any" : t$3;
}
function validateInitialNameConstraintsInput(e) {
	let t = validateInitialNameConstraintSubtrees(e.permittedSubtrees, "permittedSubtrees");
	if (!t.ok) return t;
	let n = validateInitialNameConstraintSubtrees(e.excludedSubtrees, "excludedSubtrees");
	return n.ok ? {
		ok: !0,
		value: {
			...t.value === void 0 ? {} : { permittedSubtrees: t.value },
			...n.value === void 0 ? {} : { excludedSubtrees: n.value }
		}
	} : n;
}
function validateInitialNameConstraintSubtrees(e, t) {
	if (e === void 0) return { ok: !0 };
	if (!Array.isArray(e)) return invalidInitialNameConstraintsFailure(t);
	let n = [];
	for (let t of e) {
		let e = describeInvalidInitialNameConstraintForm(t);
		if (e !== void 0) return invalidInitialNameConstraintsFailure(e);
		let r = toAsciiInitialNameConstraint(t);
		if (r === void 0) return invalidInitialNameConstraintsFailure(t.base.type);
		n.push(r);
	}
	return {
		ok: !0,
		value: n
	};
}
/**
* RFC 9549 §1, RFC 9598 §6 and RFC 4985 §3: a DNS or mail domain constraint, or
* the Name of a SRVName constraint, in A-labels.
*/
function toAsciiInitialNameConstraint(e) {
	let { base: t } = e;
	if (t.type !== "dns" && t.type !== "email" && t.type !== "srv") return e;
	let n = t.type === "srv" ? normalizeLabelSeparators(t.value) : t.value, r = unconvertedConstraintPrefix(t.type, n), i = n.slice(r.length);
	if (t.type !== "srv" && i.endsWith(".")) return;
	let a = t.type === "srv" && i.length === 0 ? void 0 : domainToAscii(i, "lookup");
	if (a !== void 0 && !a.ok) return;
	let o = `${r}${a?.value ?? ""}`;
	if (!(!/^[\x20-\x7e]*$/.test(o) || t.type === "srv" && parseSrvNameRestriction(o) === void 0)) return {
		...e,
		base: {
			...t,
			value: o
		}
	};
}
/** The leading `.` of a domain constraint, or the `_Service` label of a SRVName constraint with its dot. */
function unconvertedConstraintPrefix(e, t) {
	if (e !== "srv") return t.startsWith(".") ? "." : "";
	if (!t.startsWith("_")) return "";
	let n = t.indexOf(".");
	return n < 0 ? t : t.slice(0, n + 1);
}
function describeInvalidInitialNameConstraintForm(e) {
	if (!isRecord(e)) return "invalid subtree";
	let t = e.base;
	if (!isRecord(t) || typeof t.type != "string") return "invalid subtree";
	switch (t.type) {
		case "dns": return typeof t.value == "string" ? void 0 : t.type;
		case "uri": return typeof t.value == "string" && parseUriNameConstraint(t.value) !== void 0 ? void 0 : t.type;
		case "email": return typeof t.value == "string" && !t.value.includes("@") ? void 0 : t.type;
		case "srv": return typeof t.value == "string" && t.value.length > 0 ? void 0 : t.type;
		case "directoryName": return typeof t.derHex == "string" ? void 0 : t.type;
		case "ip": return t.addressBytes instanceof Uint8Array && t.maskBytes instanceof Uint8Array ? void 0 : t.type;
		case "otherName":
		case "x400Address":
		case "ediPartyName":
		case "registeredID": return t.type;
		default: return t.type;
	}
}
function invalidInitialNameConstraintsFailure(e) {
	return failure("unsupported_initial_name_constraints", "initial name constraints use unsupported or malformed forms", void 0, detail({ actual: e }));
}
function isRecord(e) {
	return typeof e == "object" && !!e;
}
export { assertCrlMaxAge as A, validateCertificateRevocationList as B, parseOcspResponsePem as C, matchCertificateServiceIdentity as D, verifyOcspResponseSignature as E, parseCertificateRevocationListDer as F, parseCertificateRevocationListDerOrThrow as I, parseCertificateRevocationListPem as L, coversAllDistributionPointReasons as M, createCertificateRevocationList as N, matchServiceIdentity as O, isCertificateRevoked as P, parseCertificateRevocationListPemOrThrow as R, parseOcspResponseDerOrThrow as S, validateOcspResponse as T, verifyCertificateRevocationListSignature as V, parseOcspRequestDer as _, validateForCa as a, parseOcspRequestPemOrThrow as b, validateForTlsServer as c, z as d, checkChainRevocation as f, hasOcspNoCheckExtension as g, createOcspResponse as h, validateCandidatePath as i, checkCertificateRevocationAgainstCrl as j, isSelfIssued$2 as k, verifyCertificateChain as l, createOcspRequest as m, checkExtendedKeyUsage as n, validateForCodeSigning as o, y as p, trustAnchorFromCertificate as r, validateForTlsClient as s, buildCandidatePath as t, verifyCertificateSigningRequest as u, parseOcspRequestDerOrThrow as v, parseOcspResponsePemOrThrow as w, parseOcspResponseDer as x, parseOcspRequestPem as y, revocationReasonFromCode as z };
