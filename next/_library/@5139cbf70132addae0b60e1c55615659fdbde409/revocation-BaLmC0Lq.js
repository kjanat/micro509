import { c as rethrowIfInvariant, s as n } from "./result-C9WPk47A.js";
import { tt as decodeRefusalOf } from "./asn1-jyOu_Jva.js";
import { _ as parseCertificateDerOrThrow, v as parseCertificateFromSource } from "./parse-JoeMiwMh.js";
import { A as assertCrlMaxAge, M as coversAllDistributionPointReasons, T as validateOcspResponse, j as checkCertificateRevocationAgainstCrl, z as revocationReasonFromCode } from "./verify-B4Zttp8n.js";
// ../../dist/revocation/revocation.js
/**
* Revocation orchestration: evaluates CRL and OCSP evidence to produce a
* unified `good`/`revoked`/`indeterminate` status for a certificate.
*
* @module
*/
/** Every {@linkcode RevocationIndeterminateReasonCode}, as a runtime array. */
const u = [
	"certificate_status_missing",
	"certificate_status_unknown",
	"crl_sign_not_permitted",
	"issuer_mismatch",
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
* revocation status. Returns the first `revoked` if any, else the first `good`,
* else `indeterminate` with diagnostic details about each indeterminate evidence.
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
	assertCrlMaxAge(e.crlMaxAgeMs);
	let t = e.evidence ?? [], n = t.map((e) => e.kind);
	if (t.length === 0) return revocationSuccess({
		status: "indeterminate",
		code: "revocation_evidence_missing",
		message: "No CRL or OCSP evidence provided",
		details: {
			checkedSources: n,
			indeterminateEvidence: []
		}
	});
	let r;
	try {
		r = normalizeCertificate(e.certificate);
	} catch (e) {
		return undecodableCertificateResult(e, n);
	}
	let i, o, s = /* @__PURE__ */ new Set(), c = [];
	for (let n of t) {
		let t = await checkRevocationEvidenceEntry(e, n, r);
		if (t.status === "revoked") return revocationSuccess(t.result);
		if (t.status === "good") {
			if (t.coveredReasons === void 0) i ??= t.result;
			else {
				o ??= t.result;
				for (let e of t.coveredReasons) s.add(e);
			}
		} else c.push(t.detail);
	}
	return settleRevocationEvidence(i, o, s, c, n);
}
/** The result once no evidence revoked the certificate outright. */
function settleRevocationEvidence(e, t, n, r, i) {
	let a = r.some((e) => e.code === "reason_code_unrecognized");
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
function undecodableCertificateResult(t, r) {
	let i = decodeRefusalOf(t, n);
	return revocationSuccess({
		status: "indeterminate",
		code: i?.code ?? "revocation_status_indeterminate",
		message: i?.message ?? "Certificate input is malformed",
		details: {
			checkedSources: r,
			indeterminateEvidence: []
		}
	});
}
async function checkRevocationEvidenceEntry(r, i, a) {
	try {
		return i.kind === "crl" ? await checkCertificateRevocationWithCrl(r, i, a) : await checkCertificateRevocationWithOcsp(r, i, a);
	} catch (r) {
		rethrowIfInvariant(r);
		let a = decodeRefusalOf(r, n);
		return {
			status: "indeterminate",
			detail: {
				kind: i.kind,
				code: a?.code ?? "signature_invalid",
				message: a?.message ?? `${i.kind.toUpperCase()} evidence input is malformed`
			}
		};
	}
}
/** Evaluates a single CRL evidence entry via {@linkcode checkCertificateRevocationAgainstCrl}. */
async function checkCertificateRevocationWithCrl(e, t, n) {
	let r = await checkCertificateRevocationAgainstCrl({
		certificate: n,
		issuerCertificate: e.issuerCertificate,
		crl: t.crl,
		...t.deltaCrl === void 0 ? {} : { deltaCrl: t.deltaCrl },
		...e.at === void 0 ? {} : { at: e.at },
		...e.clockSkewMs === void 0 ? {} : { clockSkewMs: e.clockSkewMs },
		...e.crlMaxAgeMs === void 0 ? {} : { maxAgeMs: e.crlMaxAgeMs },
		...e.unrecognizedReasonCode === void 0 ? {} : { unrecognizedReasonCode: e.unrecognizedReasonCode }
	});
	return r.ok ? r.value.status === "revoked" ? {
		status: "revoked",
		result: {
			status: "revoked",
			kind: "crl",
			message: "Certificate is revoked according to CRL evidence",
			revokedAt: r.value.revocationDate,
			...r.value.reasonCode === void 0 ? {} : { revocationReason: r.value.reasonCode }
		}
	} : {
		status: "good",
		result: {
			status: "good",
			kind: "crl",
			message: "Certificate is not revoked according to CRL evidence"
		},
		coveredReasons: r.value.coveredReasons
	} : {
		status: "indeterminate",
		detail: {
			kind: "crl",
			code: r.code,
			message: r.message,
			...r.details?.reason === void 0 ? {} : { reason: r.details.reason }
		}
	};
}
/** Evaluates a single OCSP evidence entry via {@linkcode validateOcspResponse}. */
async function checkCertificateRevocationWithOcsp(e, t, n) {
	let r = await validateOcspResponse({
		response: t.response,
		issuerCertificate: e.issuerCertificate,
		...t.request === void 0 ? {} : { request: t.request },
		...t.responderCertificate === void 0 ? {} : { responderCertificate: t.responderCertificate },
		...e.at === void 0 ? {} : { at: e.at },
		...e.clockSkewMs === void 0 ? {} : { clockSkewMs: e.clockSkewMs },
		...e.ocspProfile === void 0 ? {} : { profile: e.ocspProfile }
	});
	if (!r.ok) return {
		status: "indeterminate",
		detail: {
			kind: "ocsp",
			code: r.code,
			message: r.message
		}
	};
	let i = r.value.responses?.find((e) => normalizeHex(e.certId.serialNumberHex) === normalizeHex(n.serialNumberHex));
	return i === void 0 ? {
		status: "indeterminate",
		detail: {
			kind: "ocsp",
			code: "certificate_status_missing",
			message: "OCSP response does not include certificate status for the target certificate"
		}
	} : i.certStatus === "revoked" ? e.unrecognizedReasonCode === "reject" && typeof revocationReasonFromCode(i.revocationReasonCode) == "object" ? {
		status: "indeterminate",
		detail: {
			kind: "ocsp",
			code: "reason_code_unrecognized",
			message: `OCSP response carries unrecognized reason code ${String(i.revocationReasonCode)}`
		}
	} : {
		status: "revoked",
		result: {
			status: "revoked",
			kind: "ocsp",
			message: "Certificate is revoked according to OCSP evidence",
			...i.revokedAt === void 0 ? {} : { revokedAt: i.revokedAt },
			...i.revocationReasonCode === void 0 ? {} : { revocationReasonCode: i.revocationReasonCode }
		}
	} : i.certStatus === "good" ? {
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
export { u as i, getCertificateOcspResponderUris as n, resolveOcspResponderCandidates as r, checkCertificateRevocation as t };
