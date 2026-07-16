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

import { toArrayBuffer, toHex } from '#micro509/internal/asn1/asn1';
import { getCrypto } from '#micro509/internal/crypto/webcrypto';
import type { ParsedCertificate } from '#micro509/x509/parse';
import { parseCertificateFromSource } from '#micro509/x509/parse';

/**
 * A PEM string, raw DER bytes, or an already-parsed certificate.
 *
 * Mirrors the source union accepted by the verification, revocation, and
 * PKCS APIs so a fingerprint can be taken from whatever a caller already holds.
 */
export type CertificateFingerprintSource = string | Uint8Array | ParsedCertificate;

/**
 * Digest algorithms supported by {@linkcode certificateFingerprint}.
 *
 * SHA-1 is intentionally included: legacy ecosystems (PGP-adjacent tooling,
 * older certificate pinning) still identify certificates by their SHA-1
 * fingerprint. Prefer SHA-256 for anything new.
 */
export type CertificateFingerprintAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

/** The three rendered forms of a certificate fingerprint. */
export interface CertificateFingerprint {
	/** Raw digest bytes. */
	readonly bytes: Uint8Array;
	/** Lowercase hex, no separators (e.g. `"a1b2c3…"`). */
	readonly hex: string;
	/** Uppercase hex, colon-separated (e.g. `"A1:B2:C3:…"`, `openssl x509 -fingerprint` style). */
	readonly colonHex: string;
}

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
export async function certificateFingerprint(
	certificate: CertificateFingerprintSource,
	algorithm: CertificateFingerprintAlgorithm = 'SHA-256',
): Promise<CertificateFingerprint> {
	const { der } = parseCertificateFromSource(certificate);
	const digest = await getCrypto().subtle.digest(algorithm, toArrayBuffer(der));
	const bytes = new Uint8Array(digest);
	return {
		bytes,
		hex: toHex(bytes),
		colonHex: toColonHex(bytes),
	};
}

/** Renders bytes as uppercase, colon-separated hex (openssl fingerprint style). */
function toColonHex(bytes: Uint8Array): string {
	return Array.from(bytes, (value) => value.toString(16).padStart(2, '0').toUpperCase()).join(':');
}
