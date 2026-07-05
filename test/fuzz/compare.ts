/**
 * Field-level comparator: micro509's decode of an OpenSSL-generated certificate
 * versus OpenSSL's own reading of the same bytes. Every check is either
 * byte-exact (SPKI DER, PEM↔DER codec) or value-normalized in a
 * version-independent way (serial as BigInt, dates as epoch ms, DN via a
 * renderer matching the oracle's nameopt, SAN as a set). A non-empty
 * {@link Mismatch} list means micro509 and OpenSSL disagree — a real decode bug
 * or a genuinely divergent-but-legal encoding worth a fixture.
 */

import { pemDecodeOrThrow, pemEncode } from '#micro509';
import type { ParsedCertificate, ParsedName, SubjectAltName } from '#micro509';
import { expectedSignatureOid } from './spec.ts';
import type { CertSpec } from './spec.ts';
import type { OpenSslCertFields } from '../oracles/openssl-gen.ts';

/** Every field the comparator can report — closed so consumers can't test a typo'd name. */
export type MismatchField =
	| 'serial'
	| 'subject'
	| 'issuer'
	| 'notBefore'
	| 'notAfter'
	| 'signatureAlgorithmOid'
	| 'signatureAlgorithmParams'
	| 'spkiDer'
	| 'subjectAltName'
	| 'subjectKeyIdentifier'
	| 'pemDecode'
	| 'pemEncodeRoundTrip';

export interface Mismatch {
	readonly field: MismatchField;
	readonly openssl: string;
	readonly micro509: string;
}

/** OIDs whose short names OpenSSL's `sname` nameopt emits stably. */
const OID_SHORT: Record<string, string> = {
	'2.5.4.3': 'CN',
	'2.5.4.10': 'O',
	'2.5.4.11': 'OU',
	'2.5.4.6': 'C',
	'2.5.4.7': 'L',
	'2.5.4.8': 'ST',
};

/** Escape a DN attribute value the way OpenSSL's `esc_2253` (sans `esc_msb`) does. */
function escape2253(value: string): string {
	const chars = [...value];
	return chars
		.map((ch, i) => {
			if (',+"\\<>;'.includes(ch)) return `\\${ch}`;
			if (ch === '#' && i === 0) return '\\#';
			if (ch === ' ' && (i === 0 || i === chars.length - 1)) return '\\ ';
			return ch;
		})
		.join('');
}

/** Render a parsed name to the oracle's `esc_2253,utf8,sep_comma_plus,dn_rev,sname` form. */
function renderName(name: ParsedName): string {
	return name.attributes
		.map((a) => `${OID_SHORT[a.oid] ?? a.oid}=${escape2253(a.value)}`)
		.reverse()
		.join(',');
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i += 1) {
		if (a[i] !== b[i]) return false;
	}
	return true;
}

function toHex(bytes: Uint8Array): string {
	return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function sanKey(san: SanLike): string {
	const value = san.type === 'ip' ? san.value.toLowerCase() : san.value;
	return `${san.type}:${value}`;
}

interface SanLike {
	readonly type: string;
	readonly value: string;
}

function comparableSans(sans: readonly SanLike[]): string {
	return sans.map(sanKey).sort().join('\n');
}

/** micro509 SANs restricted to the four GeneralName types this harness generates. */
function microSans(sans: readonly SubjectAltName[] | undefined): readonly SanLike[] {
	if (sans === undefined) return [];
	const out: SanLike[] = [];
	for (const san of sans) {
		if (san.type === 'dns' || san.type === 'ip' || san.type === 'email' || san.type === 'uri') {
			out.push({ type: san.type, value: san.value });
		}
	}
	return out;
}

/** Compare a micro509 parse against OpenSSL's fields; return every disagreement. */
export function compareCertificate(input: {
	readonly micro: ParsedCertificate;
	readonly openssl: OpenSslCertFields;
	readonly spec: CertSpec;
}): readonly Mismatch[] {
	const { micro, openssl, spec } = input;
	const mismatches: Mismatch[] = [];
	const add = (field: MismatchField, o: string, m: string): void => {
		if (o !== m) mismatches.push({ field, openssl: o, micro509: m });
	};

	// Serial: compare as unsigned integers (immune to case / leading-zero drift).
	add(
		'serial',
		BigInt(`0x${openssl.serialHex}`).toString(),
		BigInt(`0x${micro.serialNumberHex}`).toString(),
	);

	add('subject', openssl.subject, renderName(micro.subject));
	add('issuer', openssl.issuer, renderName(micro.issuer));

	add('notBefore', String(openssl.notBeforeMs), String(micro.notBefore.getTime()));
	add('notAfter', String(openssl.notAfterMs), String(micro.notAfter.getTime()));

	add('signatureAlgorithmOid', expectedSignatureOid(spec.algo), micro.signatureAlgorithmOid);

	// Parameters TLV byte-exact against what OpenSSL wrote into the cert, so an
	// RSA-PSS hash/MGF/saltlen decode drift can't hide behind a matching OID.
	add(
		'signatureAlgorithmParams',
		openssl.sigAlgParamsDer === undefined ? '<absent>' : toHex(openssl.sigAlgParamsDer),
		micro.signatureAlgorithmParametersDer === undefined
			? '<absent>'
			: toHex(micro.signatureAlgorithmParametersDer),
	);

	if (!bytesEqual(micro.subjectPublicKeyInfoDer, openssl.spkiDer)) {
		add('spkiDer', toHex(openssl.spkiDer), toHex(micro.subjectPublicKeyInfoDer));
	}

	add(
		'subjectAltName',
		comparableSans(openssl.sans),
		comparableSans(microSans(micro.subjectAltNames)),
	);

	const microSki = micro.subjectKeyIdentifier?.replace(/:/g, '').toLowerCase() ?? '';
	add('subjectKeyIdentifier', openssl.skiHex ?? '', microSki);

	// PEM↔DER codec round-trip against OpenSSL's DER.
	const decoded = pemDecodeOrThrow('CERTIFICATE', openssl.pem);
	if (!bytesEqual(decoded, openssl.der)) {
		add('pemDecode', toHex(openssl.der), toHex(decoded));
	}
	const reDecoded = pemDecodeOrThrow('CERTIFICATE', pemEncode('CERTIFICATE', openssl.der));
	if (!bytesEqual(reDecoded, openssl.der)) {
		add('pemEncodeRoundTrip', toHex(openssl.der), toHex(reDecoded));
	}

	return mismatches;
}
