import { nt as decodeRefusalOf } from "./asn1-BRvd063X.js";
import { a as resolveSignatureVerifiers, t as callerVerification } from "./sig-verify-DtKqpUW9.js";
import { c as rethrowIfInvariant, s as n } from "./result-C9WPk47A.js";
import { F as coversAllDistributionPointReasons, G as signedCrlKey, L as distinctSignedCrls, M as assertCrlMaxAge, P as checkCertificateRevocationAgainstCrlsBy, W as revocationReasonFromCode, j as assertClockSkew, p as validateOcspResponseWith, z as normalizeCrl } from "./ocsp-Djmj6jOx.js";
import { _ as parseCertificateDerOrThrow, v as parseCertificateFromSource } from "./parse-igeoXhGd.js";
// ../../dist/revocation/revocation.js
/**
* Revocation orchestration: evaluates CRL and OCSP evidence to produce a
* unified `good`/`revoked`/`indeterminate` status for a certificate.
*
* @module
*/
/** Every {@linkcode RevocationIndeterminateReasonCode}, as a runtime array. */
const g = [
	"certificate_status_missing",
	"certificate_status_unknown",
	"crl_sign_not_permitted",
	"delta_crl_retry_limit_exceeded",
	"delta_crl_unusable",
	"issuer_mismatch",
	"malformed",
	"next_update_missing",
	"non_applicable",
	"nonce_mismatch",
	"ocsp_signing_missing",
	"reason_code_unrecognized",
	"reason_coverage_incomplete",
	"request_mismatch",
	"responder_id_mismatch",
	"responder_chain_invalid",
	"responder_revoked",
	"responder_revocation_unknown",
	"response_status_invalid",
	"signature_invalid",
	"stale_crl",
	"stale_response",
	"unsupported",
	"limit_exceeded"
];
/** Extracts OCSP responder URIs from the certificate's Authority Information Access extension. */
function getCertificateOcspResponderUris(e) {
	let t;
	try {
		t = normalizeCertificate(e);
	} catch {
		return [];
	}
	let n = [], r = /* @__PURE__ */ new Set();
	for (let e of t.authorityInfoAccess ?? []) {
		if (e.method !== "ocsp" || e.location.type !== "uri") continue;
		let t = e.location.value;
		r.has(t) || (r.add(t), n.push(t));
	}
	return n;
}
/**
* Merges configured OCSP responders with those discovered from the certificate's
* AIA extension. Configured responders take priority; duplicates are deduplicated by URI.
*/
function resolveOcspResponderCandidates(e) {
	let t = [], n = /* @__PURE__ */ new Map();
	for (let t of e.configuredResponders ?? []) {
		let e = n.get(t.uri);
		(e === void 0 || e.responderCertificate === void 0 && t.responderCertificate !== void 0) && n.set(t.uri, t);
	}
	let r = /* @__PURE__ */ new Set();
	for (let e of n.values()) r.add(e.uri), t.push({
		source: "configured",
		uri: e.uri,
		...e.responderCertificate === void 0 ? {} : { responderCertificate: e.responderCertificate }
	});
	for (let n of getCertificateOcspResponderUris(e.certificate)) r.has(n) || (r.add(n), t.push({
		source: "authorityInfoAccess",
		uri: n
	}));
	return t;
}
/**
* Evaluates all provided CRL and OCSP evidence to determine the certificate's
* revocation status. Returns the first `revoked` if any. Otherwise an OCSP
* `good` settles the status, then a CRL `good` once the CRLs together cover
* every revocation reason, else `indeterminate` with diagnostic details about
* each indeterminate evidence.
* Each CRL in `evidence` counts as a delta CRL when it carries the delta CRL
* indicator and as a complete CRL otherwise, whichever field holds it. Each
* distinct complete CRL is checked once, updated by the newest delta CRL
* among them that applies to it, as `checkChainRevocation` does, within the
* same attempt limits, which the CRL checks of delegated OCSP responders
* share. A delta CRL that cannot settle the status records
* `delta_crl_unusable` in `details.indeterminateEvidence`, and a candidate
* the limits leave unread that counts under `unreadSupersededDeltaCrls`
* records `delta_crl_retry_limit_exceeded` there; either keeps other evidence
* from settling the status as `good`. Unless other evidence revokes the
* certificate, the result is then `indeterminate` with the top-level code
* `revocation_status_indeterminate`.
* A certificate carrying noRevAvail is `skipped` without consulting evidence
* (RFC 9608 §4). One carrying id-pkix-ocsp-nocheck is still checked against
* the evidence, which may list it as revoked.
*
* @example
* ```ts
* import { checkCertificateRevocation } from 'micro509';
*
* const result = await checkCertificateRevocation({
*   certificate: leafPem,
*   issuerCertificate: caPem,
*   evidence: [{ kind: 'crl', crl: crlPem }],
* });
* if (result.ok && result.value.status === 'revoked') {
*   console.log('revoked at', result.value.revokedAt);
* }
* ```
*/
async function checkCertificateRevocation(e) {
	let t = {
		...e,
		at: e.at ?? /* @__PURE__ */ new Date()
	};
	assertCrlMaxAge(t.crlMaxAgeMs), assertClockSkew(t.clockSkewMs), resolveSignatureVerifiers(t.signatureVerifiers);
	let r = t.evidence ?? [], i = r.map((e) => e.kind);
	if (carriesNoRevAvail(t.certificate)) return revocationSuccess({
		status: "skipped",
		skipReason: "no_rev_avail",
		message: "Certificate carries noRevAvail, so no revocation evidence applies"
	});
	if (r.length === 0) return revocationSuccess({
		status: "indeterminate",
		code: "revocation_evidence_missing",
		message: "No CRL or OCSP evidence provided",
		details: {
			checkedSources: i,
			indeterminateEvidence: []
		}
	});
	let s;
	try {
		s = normalizeCertificate(t.certificate);
	} catch (e) {
		return undecodableCertificateResult(e, i);
	}
	let c, l, u = /* @__PURE__ */ new Set(), d = [];
	for (let e of await checkRevocationEvidence(t, r, s)) {
		if (e.status === "revoked") return revocationSuccess(e.result);
		if (e.status === "good") {
			if (e.coveredReasons === void 0) c ??= e.result;
			else {
				l ??= e.result;
				for (let t of e.coveredReasons) u.add(t);
			}
		} else d.push(e.detail);
	}
	return settleRevocationEvidence(c, l, u, d, i);
}
/** The result once no evidence revoked the certificate outright. */
function settleRevocationEvidence(e, t, n, r, i) {
	let a = r.some((e) => e.code === "reason_code_unrecognized" || e.code === "delta_crl_unusable" || e.code === "delta_crl_retry_limit_exceeded");
	return e !== void 0 && !a ? revocationSuccess(e) : t !== void 0 && !a && coversAllDistributionPointReasons(n) ? revocationSuccess(t) : (t !== void 0 && !coversAllDistributionPointReasons(n) && r.push({
		kind: "crl",
		code: "reason_coverage_incomplete",
		message: "CRL evidence covers only some revocation reasons"
	}), revocationSuccess({
		status: "indeterminate",
		code: "revocation_status_indeterminate",
		message: "No revocation evidence established certificate status",
		details: {
			checkedSources: i,
			indeterminateEvidence: r
		}
	}));
}
function undecodableCertificateResult(t, n$1) {
	let i = decodeRefusalOf(t, n);
	return revocationSuccess({
		status: "indeterminate",
		code: i?.code ?? "malformed",
		message: i?.message ?? "Certificate input is malformed",
		details: {
			checkedSources: n$1,
			indeterminateEvidence: []
		}
	});
}
/** The checks of `evidence` in order, up to the first that revokes `certificate`. */
async function checkRevocationEvidence(e, t, n) {
	let r = t.map((e) => e.kind === "crl" ? parseCrlEvidence(e) : void 0), i = distinctSignedCrls(r.flatMap((e) => [e?.crl, e?.deltaCrl].flatMap((e) => e?.kind === "parsed" && e.crl.baseCrlNumber !== void 0 ? [e.crl] : []))), a = { remaining: 32 }, o = /* @__PURE__ */ new Set(), s = [];
	for (let [c, l] of t.entries()) {
		let t = l.kind === "ocsp" ? [await checkCertificateRevocationWithOcsp(e, l, n, a)] : await checkCrlEvidenceEntry(r[c], o, (t) => checkCertificateRevocationWithCrl(e, t, i, n, a));
		if (s.push(...t), t.some((e) => e.status === "revoked")) return s;
	}
	return s;
}
/**
* The checks of one CRL evidence entry: its CRLs that do not decode, then
* `check` on each complete CRL not in `checked`, up to the first that revokes.
*/
async function checkCrlEvidenceEntry(e, t, n) {
	if (e === void 0) return [];
	let r = [e.deltaCrl, e.crl].flatMap((e) => e?.kind === "indeterminate" ? [e.check] : []);
	for (let i of completeCrlsOf(e)) {
		let e = signedCrlKey(i);
		if (t.has(e)) continue;
		t.add(e);
		let a = await n(i);
		if (r.push(a), a.status === "revoked") break;
	}
	return r;
}
/**
* The CRLs of one evidence entry to check as complete CRLs: its `crl`, and
* its `deltaCrl` when that carries no delta CRL indicator. A delta CRL in
* `crl` is still checked, which reports it as no complete CRL.
*/
function completeCrlsOf(e) {
	return [...e.crl.kind === "parsed" ? [e.crl.crl] : [], ...e.deltaCrl?.kind === "parsed" && e.deltaCrl.crl.baseCrlNumber === void 0 ? [e.deltaCrl.crl] : []];
}
function undecodableEvidence(t, n$2) {
	rethrowIfInvariant(n$2);
	let a = decodeRefusalOf(n$2, n);
	return {
		status: "indeterminate",
		detail: {
			kind: t,
			code: a?.code ?? "malformed",
			message: a?.message ?? `${t.toUpperCase()} evidence input is malformed`
		}
	};
}
/** A CRL evidence entry's complete and delta CRLs, each decoded on its own. */
function parseCrlEvidence(e) {
	return {
		crl: parseOneCrl(e.crl),
		deltaCrl: e.deltaCrl === void 0 ? void 0 : parseOneCrl(e.deltaCrl)
	};
}
function parseOneCrl(e) {
	try {
		return {
			kind: "parsed",
			crl: normalizeCrl(e)
		};
	} catch (e) {
		return {
			kind: "indeterminate",
			check: undecodableEvidence("crl", e)
		};
	}
}
/**
* Checks one complete CRL from `evidence`, updated by the newest delta CRL
* among every delta CRL in `evidence` that applies to it, as chain revocation
* does. A delta CRL that cannot settle the status yields `delta_crl_unusable`.
*/
async function checkCertificateRevocationWithCrl(e, n, r, i, a) {
	let o = await checkCertificateRevocationAgainstCrlsBy(i, n, r, {
		kind: "certificate",
		certificate: e.issuerCertificate
	}, {
		...e.at === void 0 ? {} : { at: e.at },
		...e.clockSkewMs === void 0 ? {} : { clockSkewMs: e.clockSkewMs },
		...e.crlMaxAgeMs === void 0 ? {} : { maxAgeMs: e.crlMaxAgeMs },
		...e.unrecognizedReasonCode === void 0 ? {} : { unrecognizedReasonCode: e.unrecognizedReasonCode },
		...e.unreadSupersededDeltaCrls === void 0 ? {} : { unreadSupersededDeltaCrls: e.unreadSupersededDeltaCrls }
	}, callerVerification(e.signatureVerifiers), [a]);
	return o.kind === "checked" ? crlEvidenceCheck(o.result) : {
		status: "indeterminate",
		detail: o.reason === "retry_limit" ? {
			kind: "crl",
			code: "delta_crl_retry_limit_exceeded",
			message: "A delta CRL candidate remained unread after the attempt limit"
		} : {
			kind: "crl",
			code: "delta_crl_unusable",
			message: "An applicable delta CRL could not settle the certificate status"
		}
	};
}
/** The evidence check for one CRL result. */
function crlEvidenceCheck(e) {
	return e.ok ? e.value.status === "revoked" ? {
		status: "revoked",
		result: {
			status: "revoked",
			kind: "crl",
			message: "Certificate is revoked according to CRL evidence",
			revokedAt: e.value.revocationDate,
			...e.value.reasonCode === void 0 ? {} : { revocationReason: e.value.reasonCode }
		}
	} : {
		status: "good",
		result: {
			status: "good",
			kind: "crl",
			message: "Certificate is not revoked according to CRL evidence"
		},
		coveredReasons: e.value.coveredReasons
	} : {
		status: "indeterminate",
		detail: {
			kind: "crl",
			code: e.code,
			message: e.message,
			...e.details?.reason === void 0 ? {} : { reason: e.details.reason }
		}
	};
}
/** The {@linkcode validateOcspResponseWith} input for one OCSP evidence entry. */
function ocspEvidenceValidationInput(e, t) {
	return {
		response: t.response,
		issuerCertificate: e.issuerCertificate,
		...t.request === void 0 ? {} : { request: t.request },
		...t.responderCertificate === void 0 ? {} : { responderCertificate: t.responderCertificate },
		...e.at === void 0 ? {} : { at: e.at },
		...e.clockSkewMs === void 0 ? {} : { clockSkewMs: e.clockSkewMs },
		...e.ocspProfile === void 0 ? {} : { profile: e.ocspProfile },
		...e.ocspResponderRevocation === void 0 ? {} : { responderRevocationPolicy: e.ocspResponderRevocation },
		responderRevocationCrls: (e.evidence ?? []).flatMap((e) => e.kind === "crl" ? e.deltaCrl === void 0 ? [e.crl] : [e.crl, e.deltaCrl] : []),
		...e.crlMaxAgeMs === void 0 ? {} : { responderRevocationCrlMaxAgeMs: e.crlMaxAgeMs },
		...e.unrecognizedReasonCode === void 0 ? {} : { responderRevocationUnrecognizedReasonCode: e.unrecognizedReasonCode },
		...e.unreadSupersededDeltaCrls === void 0 ? {} : { responderRevocationUnreadSupersededDeltaCrls: e.unreadSupersededDeltaCrls },
		...e.signatureVerifiers === void 0 ? {} : { signatureVerifiers: e.signatureVerifiers }
	};
}
/**
* Evaluates a single OCSP evidence entry via {@linkcode validateOcspResponseWith},
* spending delta CRL checks of a delegated responder from `budget`.
*/
async function checkCertificateRevocationWithOcsp(e, t, r, i) {
	let a = await validateOcspResponseWith(ocspEvidenceValidationInput(e, t), {
		verifiers: resolveSignatureVerifiers(e.signatureVerifiers),
		deltaBudget: i
	});
	if (!a.ok) return {
		status: "indeterminate",
		detail: {
			kind: "ocsp",
			code: a.code,
			message: a.message
		}
	};
	let o = a.value.responses?.find((e) => normalizeHex(e.certId.serialNumberHex) === normalizeHex(r.serialNumberHex));
	return o === void 0 ? {
		status: "indeterminate",
		detail: {
			kind: "ocsp",
			code: "certificate_status_missing",
			message: "OCSP response does not include certificate status for the target certificate"
		}
	} : o.certStatus === "revoked" ? e.unrecognizedReasonCode === "reject" && typeof revocationReasonFromCode(o.revocationReasonCode) == "object" ? {
		status: "indeterminate",
		detail: {
			kind: "ocsp",
			code: "reason_code_unrecognized",
			message: `OCSP response carries unrecognized reason code ${String(o.revocationReasonCode)}`
		}
	} : {
		status: "revoked",
		result: {
			status: "revoked",
			kind: "ocsp",
			message: "Certificate is revoked according to OCSP evidence",
			...o.revokedAt === void 0 ? {} : { revokedAt: o.revokedAt },
			...o.revocationReasonCode === void 0 ? {} : { revocationReasonCode: o.revocationReasonCode }
		}
	} : o.certStatus === "good" ? {
		status: "good",
		result: {
			status: "good",
			kind: "ocsp",
			message: "Certificate is not revoked according to OCSP evidence"
		}
	} : {
		status: "indeterminate",
		detail: {
			kind: "ocsp",
			code: "certificate_status_unknown",
			message: "OCSP responder returned certificate status unknown"
		}
	};
}
/** Accepts PEM, DER, or already-parsed certificate and returns a parsed certificate. */
function normalizeCertificate(e) {
	return hasParsedCertificateShape(e) ? parseCertificateDerOrThrow(new Uint8Array(e.der)) : parseCertificateFromSource(e);
}
/** Whether `source` parses and carries noRevAvail in its signed DER. */
function carriesNoRevAvail(e) {
	try {
		return normalizeCertificate(e).noRevAvail === !0;
	} catch (e) {
		return rethrowIfInvariant(e), !1;
	}
}
function hasParsedCertificateShape(e) {
	return typeof e != "string" && "subjectPublicKeyInfoDer" in e;
}
/** Lowercases a hex string for bytewise serial-number comparison. */
function normalizeHex(e) {
	return e.toLowerCase();
}
/** Wraps a value into a successful `CheckCertificateRevocationResult`. */
function revocationSuccess(e) {
	return {
		ok: !0,
		value: e
	};
}
export { resolveOcspResponderCandidates as i, g as n, getCertificateOcspResponderUris as r, checkCertificateRevocation as t };
