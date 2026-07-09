/**
 * Fuzz-case model for the OpenSSL differential harness.
 *
 * A {@link FuzzCase} is a fully-resolved recipe for one certificate + its key,
 * drawn deterministically from a seeded PRNG across the algorithm matrix plus
 * legal encoding edges (validity crossing the 2049→2050 UTCTime→GeneralizedTime
 * boundary, long / high-bit serials, comma/UTF-8 DN values, mixed GeneralName
 * types). The same case maps to both the OpenSSL generation flags and the
 * expected micro509 decode (import hints, signature-algorithm OID), so the
 * comparator never has to re-derive intent from the artifact it is checking.
 */

import type { PublicKeyImportInput } from '#micro509';
import type { Rng } from '#test/fuzz/prng';

/** Key + signing-hash choice. Hash is irrelevant for Ed25519 (PureEdDSA). */
export type FuzzKeyAlgo =
	| {
			readonly kind: 'rsa';
			readonly bits: 2048 | 3072 | 4096;
			readonly hash: FuzzHash;
			readonly pss: boolean;
	  }
	| {
			readonly kind: 'ecdsa';
			readonly curve: 'P-256' | 'P-384' | 'P-521';
			readonly hash: FuzzHash;
	  }
	| { readonly kind: 'ed25519' };

/** Signing hash shared by the RSA and ECDSA variants. */
type FuzzHash = 'SHA-256' | 'SHA-384' | 'SHA-512';

/** One relative distinguished name attribute (each becomes its own single-attr RDN). */
export interface DnAttr {
	/** Dotted OID (restricted to the six standard attrs with stable OpenSSL short names). */
	readonly oid: string;
	/** Short name as emitted by `openssl -nameopt sname` (CN, O, OU, C, L, ST). */
	readonly short: string;
	/** Decoded string value. */
	readonly value: string;
}

/** A subjectAltName GeneralName the harness knows how to generate and compare. */
export interface FuzzSan {
	readonly type: 'dns' | 'ip' | 'email' | 'uri';
	readonly value: string;
}

/** How the certificate is issued. */
export type Issuance = 'self' | 'ca';

export interface CertSpec {
	readonly algo: FuzzKeyAlgo;
	readonly subject: readonly DnAttr[];
	readonly sans: readonly FuzzSan[];
	/** Days from generation to notAfter; large values deliberately cross year 2050. */
	readonly validityDays: number;
	/** DER INTEGER content as hex (variable length, sometimes high-bit set). */
	readonly serialHex: string;
	readonly isCa: boolean;
	readonly addSki: boolean;
	readonly issuance: Issuance;
}

export interface FuzzCase {
	readonly index: number;
	readonly spec: CertSpec;
}

const HASHES: readonly FuzzHash[] = ['SHA-256', 'SHA-384', 'SHA-512'];
const RSA_BITS: readonly (2048 | 3072 | 4096)[] = [2048, 3072, 4096];
const CURVES: readonly ('P-256' | 'P-384' | 'P-521')[] = ['P-256', 'P-384', 'P-521'];
const COUNTRIES: readonly string[] = ['US', 'NL', 'DE', 'JP', 'BR'];
/** Org values include a comma (RFC2253 escaping) and a UTF-8 char (UTF8String path). */
const ORGS: readonly string[] = [
	'Acme',
	'Beispiel GmbH',
	'Fern, Ridge Co',
	'Müller & Zoon',
	'Œuvre',
];
const UNITS: readonly string[] = ['Eng', 'Ops', 'PKI Team', 'R&D'];
const LOCALITIES: readonly string[] = ['Zwolle', 'München', 'São Paulo', 'Kyoto'];
const REGIONS: readonly string[] = ['Overijssel', 'Bayern', 'Kanto'];

function drawAlgo(rng: Rng): FuzzKeyAlgo {
	// Weight so every family is well-represented; RSA-PSS and each curve appear often.
	const family = rng.pick(['rsa', 'rsa', 'ecdsa', 'ecdsa', 'ed25519'] as const);
	if (family === 'ed25519') return { kind: 'ed25519' };
	if (family === 'ecdsa') return { kind: 'ecdsa', curve: rng.pick(CURVES), hash: rng.pick(HASHES) };
	return { kind: 'rsa', bits: rng.pick(RSA_BITS), hash: rng.pick(HASHES), pss: rng.bool(0.4) };
}

function drawSubject(rng: Rng): readonly DnAttr[] {
	const attrs: DnAttr[] = [{ oid: '2.5.4.3', short: 'CN', value: `fuzz-${rng.hex(4)}.example` }];
	if (rng.bool(0.85)) attrs.push({ oid: '2.5.4.10', short: 'O', value: rng.pick(ORGS) });
	if (rng.bool(0.5)) attrs.push({ oid: '2.5.4.11', short: 'OU', value: rng.pick(UNITS) });
	if (rng.bool(0.5)) attrs.push({ oid: '2.5.4.6', short: 'C', value: rng.pick(COUNTRIES) });
	if (rng.bool(0.4)) attrs.push({ oid: '2.5.4.7', short: 'L', value: rng.pick(LOCALITIES) });
	if (rng.bool(0.4)) attrs.push({ oid: '2.5.4.8', short: 'ST', value: rng.pick(REGIONS) });
	return attrs;
}

function drawSans(rng: Rng): readonly FuzzSan[] {
	const sans: FuzzSan[] = [];
	const count = rng.int(4); // 0..3
	for (let i = 0; i < count; i += 1) {
		const type = rng.pick(['dns', 'ip', 'email', 'uri'] as const);
		if (type === 'dns') sans.push({ type, value: `${rng.hex(3)}.svc.example` });
		else if (type === 'email') sans.push({ type, value: `user-${rng.hex(2)}@example.com` });
		else if (type === 'uri') sans.push({ type, value: `https://example.com/${rng.hex(2)}` });
		else {
			sans.push(
				rng.bool()
					? {
							type,
							value: `${1 + rng.int(223)}.${rng.int(256)}.${rng.int(256)}.${1 + rng.int(254)}`,
						}
					: { type, value: `2001:db8::${rng.hex(2)}` },
			);
		}
	}
	return sans;
}

function drawSerialHex(rng: Rng): string {
	const byteLength = rng.pick([1, 4, 8, 16, 19, 20]); // include RFC 5280 max (20 bytes)
	let hex = rng.hex(byteLength);
	// Guarantee a positive integer: clear the top bit of the leading byte, and
	// avoid an all-zero serial (OpenSSL rejects serial 0).
	const lead = Number.parseInt(hex.slice(0, 2), 16) & 0x7f;
	hex = lead.toString(16).padStart(2, '0') + hex.slice(2);
	if (/^0+$/.test(hex)) hex = `${hex.slice(0, -1)}1`;
	return hex;
}

/** Draw one deterministic fuzz case for the given index. */
export function drawCase(rng: Rng, index: number): FuzzCase {
	const isCa = rng.bool(0.25);
	const spec: CertSpec = {
		algo: drawAlgo(rng),
		subject: drawSubject(rng),
		sans: drawSans(rng),
		// Small (UTCTime) most of the time; ~30% cross 2050 into GeneralizedTime.
		validityDays: rng.bool(0.3) ? 8800 + rng.int(1500) : 1 + rng.int(825),
		serialHex: drawSerialHex(rng),
		isCa,
		addSki: rng.bool(0.6),
		issuance: rng.bool(0.35) ? 'ca' : 'self',
	};
	return { index, spec };
}

/** Compile-time exhaustiveness guard: only reachable if a FuzzKeyAlgo variant is unhandled. */
function assertUnreachable(algo: never): never {
	throw new Error(`unhandled FuzzKeyAlgo variant: ${JSON.stringify(algo)}`);
}

/** micro509 public-key import hint for a spec's algorithm (SPKI is scheme-agnostic). */
export function importInputFor(algo: FuzzKeyAlgo): PublicKeyImportInput {
	switch (algo.kind) {
		case 'ed25519':
			return { kind: 'ed25519' };
		case 'ecdsa':
			return { kind: 'ecdsa', curve: algo.curve };
		case 'rsa':
			return { kind: 'rsa', hash: algo.hash };
		default:
			return assertUnreachable(algo);
	}
}

/** Expected `signatureAlgorithmOid` micro509 must decode, derived from the issuer's algo. */
export function expectedSignatureOid(algo: FuzzKeyAlgo): string {
	switch (algo.kind) {
		case 'ed25519':
			return '1.3.101.112';
		case 'ecdsa':
			return {
				'SHA-256': '1.2.840.10045.4.3.2',
				'SHA-384': '1.2.840.10045.4.3.3',
				'SHA-512': '1.2.840.10045.4.3.4',
			}[algo.hash];
		case 'rsa':
			if (algo.pss) return '1.2.840.113549.1.1.10';
			return {
				'SHA-256': '1.2.840.113549.1.1.11',
				'SHA-384': '1.2.840.113549.1.1.12',
				'SHA-512': '1.2.840.113549.1.1.13',
			}[algo.hash];
		default:
			return assertUnreachable(algo);
	}
}
