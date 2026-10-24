import { s as n, u as throwMicro509Error } from "./result-C9WPk47A.js";
import { d as base64Encode, o as pemEncode } from "./pem-C5BecCKu.js";
import { D as explicitContext, F as integerFromNumber, G as sequence, J as time, K as setOf, L as objectIdentifier, M as implicitConstructedContext, P as integer, m as hexToBytes, rt as rethrowDecodeRefusal, v as toArrayBuffer, w as concatBytes, x as bitString, y as toHex } from "./asn1-jyOu_Jva.js";
import { mt as t, pt as getCrypto, x as generateKeyPair, y as exportSpkiDer } from "./keys-BmJSvvnO.js";
import { $ as issuerKeyIdentifier, I as buildCertificateExtensions, L as buildRequestedExtensions, O as parseDistinguishedNameDer, R as buildSubjectKeyIdentifier, it as isNameInputEmpty, nt as encodeName, v as parseCertificateFromSource, vt as o } from "./parse-JoeMiwMh.js";
import { n as getSignatureAlgorithm, r as signBytes, t as encodeAlgorithmIdentifier } from "./signing-Cr_Ky8wY.js";
// ../../dist/x509/certificate.js
/**
* Create X.509 certificates from typed names, extensions, and WebCrypto keys.
*
* Use this module to issue a certificate from an existing issuer key pair or to
* generate a self-signed certificate in one step.
*
* @module
*/
/**
* Create a self-signed certificate.
*
* Reuses `input.keyPair` when provided; otherwise generates a new key pair from
* `input.algorithm`. The returned certificate uses `input.subject` as both
* issuer and subject.
*
* @example
* ```ts
* const { certificate, keyPair } = await createSelfSignedCertificate({
* 	subject: { commonName: 'example.com' },
* 	algorithm: { kind: 'ecdsa', curve: 'P-256' },
* });
* ```
*
* @param input Certificate subject, key, validity, and extension settings.
* @returns The certificate plus the key pair used to sign it.
*/
async function createSelfSignedCertificate(e) {
	let t = e.keyPair ?? await generateKeyPair(e.algorithm);
	return {
		certificate: await issueCertificate({
			issuer: e.subject,
			subject: e.subject,
			publicKey: t.publicKey,
			signerPrivateKey: t.privateKey,
			...e.validity === void 0 ? {} : { validity: e.validity },
			...e.serialNumber === void 0 ? {} : { serialNumber: e.serialNumber },
			...e.extensions === void 0 ? {} : { extensions: e.extensions },
			...e.signature === void 0 ? {} : { signature: e.signature }
		}, "subject"),
		keyPair: t
	};
}
/**
* Create an X.509 certificate signed by `input.signerPrivateKey`.
*
* The certificate encodes `input.subject`, `input.publicKey`, and any supplied
* extensions. When `serialNumber` is omitted, a random positive serial number is
* generated. When `validity` is omitted, the certificate is valid from now for
* 30 days.
*
* @example
* ```ts
* const certificate = await createCertificate({
* 	issuer: { commonName: 'Example Root CA' },
* 	subject: { commonName: 'example.com' },
* 	publicKey: leafKeys.publicKey,
* 	signerPrivateKey: issuer.keyPair.privateKey,
* 	issuerCertificate: issuer.certificate.der,
* });
* ```
*
* @param input Issuer, subject, key, validity, and extension settings.
* @returns The encoded certificate material.
*/
function createCertificate(e) {
	return issueCertificate(e, "issuer");
}
/**
* Signs a certificate whose authority key identifier comes from
* `input.issuerCertificate`, or from its own subject key when `authority` is
* `'subject'` (RFC 5280 §4.2.1.1).
*/
async function issueCertificate(e, n) {
	let a = await exportSpkiDer(e.publicKey), l = n === "subject" ? buildSubjectKeyIdentifier(a) : e.issuerCertificate === void 0 ? void 0 : issuerKeyIdentifier(issuerCertificateOf(e.issuerCertificate)), u = getSignatureAlgorithm(e.signerPrivateKey, e.signature), d = resolveValidity(e.validity);
	isNameInputEmpty(e.issuer) && throwMicro509Error("issuer_distinguished_name_empty", "issuer must be a non-empty distinguished name");
	let p = isNameInputEmpty(e.subject), S = buildCertificateExtensions(a, l, e.extensions, p), C = sequence([
		explicitContext(0, integerFromNumber(2)),
		encodeSerialNumber(e.serialNumber),
		encodeAlgorithmIdentifier(u),
		encodeName(e.issuer),
		sequence([time(d.notBefore), time(d.notAfter)]),
		encodeName(e.subject),
		a,
		explicitContext(3, sequence(S))
	]), w = await signBytes(e.signerPrivateKey, u, C);
	return materializeCertificate(sequence([
		C,
		encodeAlgorithmIdentifier(u),
		bitString(w)
	]));
}
/** The parsed issuer certificate of a certificate being built. */
function issuerCertificateOf(r) {
	try {
		return parseCertificateFromSource(r);
	} catch (r) {
		return rethrowDecodeRefusal(r, n), throwMicro509Error("issuer_certificate_invalid", "issuerCertificate must be a PEM, DER or parsed certificate");
	}
}
/**
* Convert DER bytes into all exported certificate encodings.
*
* @param der DER-encoded certificate bytes.
* @returns DER, PEM, and base64 views of the same certificate.
*/
function materializeCertificate(e) {
	return {
		der: e,
		pem: pemEncode("CERTIFICATE", e),
		base64: base64Encode(e)
	};
}
/**
* Resolve defaults for a certificate validity window.
*
* @param input Optional validity settings.
* @returns A concrete `notBefore` and `notAfter` pair.
*/
function resolveValidity(e) {
	let n = e?.notBefore ?? /* @__PURE__ */ new Date(), r = e?.notAfter ?? addDays(n, e?.days ?? 30);
	return (Number.isNaN(n.getTime()) || Number.isNaN(r.getTime())) && throwMicro509Error("validity_date_invalid", "notBefore and notAfter must be valid dates"), r.getTime() <= n.getTime() && throwMicro509Error("validity_not_after_before_not_before", "notAfter must be after notBefore"), {
		notBefore: n,
		notAfter: r
	};
}
/**
* Return a new date offset by a whole number of UTC days.
*
* @param date Base date.
* @param days Number of days to add.
* @returns The shifted date.
*/
function addDays(e, t) {
	let n = new Date(e.getTime());
	return n.setUTCDate(n.getUTCDate() + t), n;
}
/**
* Encode a certificate serial number as a DER INTEGER.
*
* @param serialNumber Serial number bytes, big-endian; a random one is generated when omitted.
* @returns The DER INTEGER element.
* @throws a `ResultError` with code `serial_number_not_positive` or
* `serial_number_too_long` when RFC 5280 §4.1.2.2 forbids the value.
*/
function encodeSerialNumber(e) {
	if (e === void 0) return integer(randomSerialNumber());
	let n = 0;
	for (; n < e.length && e[n] === 0;) n += 1;
	let r = e.subarray(n), i = r[0];
	return i === void 0 && throwMicro509Error("serial_number_not_positive", "serialNumber must be a positive integer"), r.length + +(i >= 128) > 20 && throwMicro509Error("serial_number_too_long", "serialNumber must not exceed 20 octets"), integer(r);
}
/**
* Generate a random positive serial number suitable for certificate issuance.
*
* @returns A 16-byte positive serial number.
*/
function randomSerialNumber() {
	let e = getCrypto().getRandomValues(/* @__PURE__ */ new Uint8Array(16));
	return e[0] = (e[0] ?? 0) & 127, (e[0] ?? 0) === 0 && (e[0] = 1), e;
}
// ../../dist/x509/csr.js
/**
* PKCS#10 Certificate Signing Request (CSR) creation.
*
* Builds a CSR from a subject name, WebCrypto key pair, and optional extensions,
* producing DER, PEM, and base64 outputs.
*
* @module
*/
/**
* Creates a PKCS#10 Certificate Signing Request signed with the given private key.
*
* The CSR embeds the public key's SPKI, the subject name, and any requested extensions
* as attributes. The signature proves possession of the private key.
*
* @example
* ```ts
* import { createCertificateSigningRequest } from 'micro509';
*
* const keyPair = await crypto.subtle.generateKey(
*   { name: 'ECDSA', namedCurve: 'P-256' },
*   true,
*   ['sign', 'verify'],
* );
* const csr = await createCertificateSigningRequest({
*   subject: { commonName: 'example.com' },
*   publicKey: keyPair.publicKey,
*   signerPrivateKey: keyPair.privateKey,
*   extensions: { subjectAltNames: [{ type: 'dns', value: 'example.com' }] },
* });
* console.log(csr.pem);
* ```
*/
async function createCertificateSigningRequest(i) {
	let o = getSignatureAlgorithm(i.signerPrivateKey, i.signature), s = await exportSpkiDer(i.publicKey), h = buildAttributes(i.extensions), g = sequence([
		integerFromNumber(0),
		encodeName(i.subject),
		s,
		implicitConstructedContext(0, concatBytes(h))
	]), _ = await signBytes(i.signerPrivateKey, o, g), v = sequence([
		g,
		encodeAlgorithmIdentifier(o),
		bitString(_)
	]);
	return {
		der: v,
		pem: pemEncode("CERTIFICATE REQUEST", v),
		base64: base64Encode(v)
	};
}
/** Encodes extensions into a CSR extensionRequest attribute, or returns empty. */
function buildAttributes(e) {
	let t$1 = buildRequestedExtensions(e);
	return t$1.length === 0 ? [] : [sequence([objectIdentifier(t.extensionRequest), setOf([sequence(t$1)])])];
}
// ../../dist/x509/fingerprint.js
/**
* Certificate fingerprints: a cryptographic hash over the DER encoding.
*
* This is the identifier that `openssl x509 -fingerprint` and every TLS UI show.
* The helper accepts the same PEM / DER / parsed-certificate source union as
* the verification APIs and returns the digest in the forms callers actually
* paste around: raw bytes, lowercase hex, and uppercase colon-separated hex.
*
* @module
*/
/**
* Compute a certificate fingerprint — a hash over the DER encoding.
*
* The certificate is parsed (validating the input and, for PEM, decoding it to
* DER) before hashing, so the digest is always taken over the canonical DER of
* a well-formed certificate. Malformed input throws, matching the other DER/PEM
* boundaries in the library.
*
* **Asynchronous:** hashing uses WebCrypto's `crypto.subtle.digest`. Await the
* returned promise before reading `bytes`, `hex`, or `colonHex`.
*
* @example
* ```ts
* const fingerprint = await certificateFingerprint(pemString);
* console.log(fingerprint.colonHex); // "AB:CD:…" — matches `openssl x509 -fingerprint -sha256`
* ```
*
* @example
* ```ts
* // Reuse an already-parsed certificate and request SHA-1.
* const parsed = parseCertificatePemOrThrow(pemString);
* const legacy = await certificateFingerprint(parsed, 'SHA-1');
* console.log(legacy.hex);
* ```
*
* @param certificate PEM string, DER bytes, or a {@linkcode ParsedCertificate}.
* @param algorithm Digest algorithm to use. Defaults to `'SHA-256'`.
*/
async function certificateFingerprint(i, a = "SHA-256") {
	let { der: o } = parseCertificateFromSource(i), s = await getCrypto().subtle.digest(a, toArrayBuffer(o)), c = new Uint8Array(s);
	return {
		bytes: c,
		hex: toHex(c),
		colonHex: toColonHex(c)
	};
}
/**
* Compute the SHA-256 fingerprint of a certificate's complete DER
* SubjectPublicKeyInfo. Unlike {@linkcode certificateFingerprint}, this
* identifies the public key rather than the certificate. Cross-signed
* certificates carrying the same SPKI therefore have the same fingerprint.
*
* The SPKI is read from the reparsed certificate DER. No cryptographic key
* import is performed, so this works for algorithms micro509 cannot use with
* WebCrypto.
*/
async function subjectPublicKeyInfoFingerprint(i) {
	let a = typeof i == "string" || i instanceof Uint8Array ? i : i.der, o = parseCertificateFromSource(a), s = await getCrypto().subtle.digest("SHA-256", toArrayBuffer(o.subjectPublicKeyInfoDer)), c = new Uint8Array(s);
	return {
		bytes: c,
		hex: toHex(c),
		colonHex: toColonHex(c)
	};
}
/** Renders bytes as uppercase, colon-separated hex (openssl fingerprint style). */
function toColonHex(e) {
	return Array.from(e, (e) => e.toString(16).padStart(2, "0").toUpperCase()).join(":");
}
// ../../dist/x509/name-text.js
/**
* Human-readable text for parsed names.
*
* Renders a {@linkcode ParsedName} or {@linkcode SubjectAltName} as a display string,
* covering every variant of the union without the caller narrowing it by hand.
*
* @module micro509/x509/name-text
*/
/**
* Renders one {@linkcode SubjectAltName} as text.
*
* | variant | rendering |
* | --- | --- |
* | `dns`, `ip`, `email`, `uri`, `srv` | the value itself |
* | `directoryName` | {@linkcode distinguishedNameToString} of the embedded name, or the DER hex if it does not decode |
* | `unknown` | lowercase hex of the raw content bytes |
*
* @example Render every SAN of a parsed certificate
* ```ts
* const names = (parsed.subjectAltNames ?? []).map((name) => subjectAltNameToString(name));
* // ['example.com', '192.0.2.1', 'CN=Example CA,C=US']
*
* subjectAltNameToString({ type: 'dns', value: 'example.com' }, { prefix: true }); // 'DNS:example.com'
* ```
*/
function subjectAltNameToString(e, t) {
	let n = subjectAltNameText(e);
	return t?.prefix === !0 ? `${subjectAltNameLabel(e)}:${n}` : n;
}
/**
* The `openssl x509 -text` label for a {@linkcode SubjectAltName} variant —
* `DNS`, `IP Address`, `email`, `URI`, `SRV`, `SmtpUTF8Mailbox`, `UPN`, `KRB5PrincipalName`, `DirName`, `othername`, `X400Name`,
* `EdiPartyName`, `Registered ID`, or `[tag <n>]` for raw `unknown` input.
*/
function subjectAltNameLabel(e) {
	switch (e.type) {
		case "dns": return "DNS";
		case "ip": return "IP Address";
		case "email": return "email";
		case "uri": return "URI";
		case "srv": return "SRV";
		case "smtpUtf8Mailbox": return "SmtpUTF8Mailbox";
		case "upn": return "UPN";
		case "krb5PrincipalName": return "KRB5PrincipalName";
		case "directoryName": return "DirName";
		case "otherName": return "othername";
		case "x400Address": return "X400Name";
		case "ediPartyName": return "EdiPartyName";
		case "registeredID": return "Registered ID";
		case "unknown": return `[tag ${String(e.tag)}]`;
		default: throw Error(`Unhandled SubjectAltName type: ${String(e)}`);
	}
}
/**
* Renders a {@linkcode ParsedName} as an RFC 4514 distinguished name string, e.g. `CN=Example CA,O=Acme,C=US`.
*
* RDNs are emitted in reverse encoding order and multi-valued RDNs are joined with `+`,
* both per RFC 4514 [§2](https://datatracker.ietf.org/doc/html/rfc4514#section-2).
* Attribute types outside the RFC 4514 [§3](https://datatracker.ietf.org/doc/html/rfc4514#section-3)
* keyword table use the short names `openssl` prints, falling back to the dotted OID.
*
* @example
* ```ts
* distinguishedNameToString(parsed.subject); // 'CN=example.com,O=Acme\\, Inc.,C=US'
* ```
*/
function distinguishedNameToString(e) {
	return [...e.rdns].reverse().map((e) => relativeDistinguishedNameToString(e)).join(",");
}
/** Renders one {@linkcode ParsedRelativeDistinguishedName}, joining a multi-valued RDN's attributes with `+`. */
function relativeDistinguishedNameToString(e) {
	return e.attributes.map((e) => attributeToString(e)).join("+");
}
/** Characters RFC 4514 [§2.4](https://datatracker.ietf.org/doc/html/rfc4514#section-2.4) escapes wherever they appear. */
const i = /* @__PURE__ */ new Set([
	"\"",
	"+",
	",",
	";",
	"<",
	">",
	"\\"
]);
function attributeToString(e) {
	return `${o[e.oid] ?? e.oid}=${escapeAttributeValue(e.value)}`;
}
function escapeAttributeValue(e) {
	let t = [...e];
	return t.map((e, n) => {
		if (i.has(e)) return `\\${e}`;
		let r = e.codePointAt(0) ?? 0;
		return r < 32 || r === 127 ? `\\${r.toString(16).padStart(2, "0")}` : e === " " && (n === 0 || n === t.length - 1) ? "\\ " : e === "#" && n === 0 ? "\\#" : e;
	}).join("");
}
function subjectAltNameText(e) {
	switch (e.type) {
		case "dns":
		case "ip":
		case "email":
		case "uri":
		case "srv":
		case "smtpUtf8Mailbox":
		case "upn":
		case "registeredID": return e.value;
		case "krb5PrincipalName": return `${e.nameString.join("/")}@${e.realm}`;
		case "directoryName": return directoryNameText(e.derHex);
		case "otherName": return `${e.typeId}:${toHex(e.value)}`;
		case "x400Address":
		case "ediPartyName": return toHex(e.value);
		case "unknown": return toHex(e.value);
		default: throw Error(`Unhandled SubjectAltName type: ${String(e)}`);
	}
}
function directoryNameText(t) {
	try {
		return distinguishedNameToString(parseDistinguishedNameDer(hexToBytes(t)));
	} catch {
		return t;
	}
}
export { certificateFingerprint as a, createCertificate as c, subjectAltNameToString as i, createSelfSignedCertificate as l, relativeDistinguishedNameToString as n, subjectPublicKeyInfoFingerprint as o, subjectAltNameLabel as r, createCertificateSigningRequest as s, distinguishedNameToString as t };
