/**
 * RSA-PSS `AlgorithmIdentifier` parameter parsing, validation, and encoding.
 *
 * Only the three hash-matched profiles (SHA-256/384/512 with MGF1 and matching salt
 * length) are accepted; SHA-1 defaults and mismatched MGF hashes are rejected.
 *
 * @module
 */

import {
	childrenOf,
	decodeNonNegativeIntegerNumber,
	decodeObjectIdentifier,
	requireElement,
} from './asn1.ts';
import {
	DEFAULT_MAX_DER_DEPTH,
	explicitContext,
	integerFromNumber,
	nullValue,
	objectIdentifier,
	readRootElement,
	sequence,
} from './der.ts';
import { OIDS } from './oids.ts';

/** Hash algorithm accepted for RSA-PSS signatures in this library. */
export type RsaPssHash = 'SHA-256' | 'SHA-384' | 'SHA-512';

/**
 * One of the three supported RSA-PSS parameter profiles.
 *
 * Hash, MGF1 hash, and salt length are always matched (e.g. SHA-256 / SHA-256 / 32).
 */
export type RsaPssParameters =
	| {
			/** Message digest algorithm. */
			readonly hash: 'SHA-256';
			/** MGF1 hash — always matches `hash`. */
			readonly mgfHash: 'SHA-256';
			/** Salt length in bytes — equals the hash digest size. */
			readonly saltLength: 32;
			/** Trailer field (always 0xBC per RFC 3447). */
			readonly trailerField: 1;
	  }
	| {
			/** Message digest algorithm. */
			readonly hash: 'SHA-384';
			/** MGF1 hash — always matches `hash`. */
			readonly mgfHash: 'SHA-384';
			/** Salt length in bytes — equals the hash digest size. */
			readonly saltLength: 48;
			/** Trailer field (always 0xBC per RFC 3447). */
			readonly trailerField: 1;
	  }
	| {
			/** Message digest algorithm. */
			readonly hash: 'SHA-512';
			/** MGF1 hash — always matches `hash`. */
			readonly mgfHash: 'SHA-512';
			/** Salt length in bytes — equals the hash digest size. */
			readonly saltLength: 64;
			/** Trailer field (always 0xBC per RFC 3447). */
			readonly trailerField: 1;
	  };

/** Machine-readable reason why an RSA-PSS parameter set is not supported. */
export type UnsupportedRsaPssParametersReason =
	| 'default_hash_sha1'
	| 'unsupported_hash'
	| 'unsupported_mgf_algorithm'
	| 'unsupported_mgf_hash'
	| 'mgf_hash_mismatch'
	| 'unsupported_salt_length'
	| 'unsupported_trailer_field';

/** Success branch of {@linkcode ParsedRsaPssParametersResult}. */
export interface ParsedRsaPssParametersSuccess {
	/** Discriminant for the success branch. */
	readonly ok: true;
	/** The validated RSA-PSS parameter profile. */
	readonly value: RsaPssParameters;
}

/** Failure: valid ASN.1 but an unsupported parameter combination. */
export interface ParsedRsaPssParametersUnsupported {
	/** Discriminant for the failure branch. */
	readonly ok: false;
	/** Machine-readable failure code. */
	readonly code: 'unsupported_rsa_pss_parameters';
	/** Which specific parameter is unsupported. */
	readonly reason: UnsupportedRsaPssParametersReason;
}

/** Failure: the DER encoding is structurally invalid. */
export interface ParsedRsaPssParametersMalformed {
	/** Discriminant for the failure branch. */
	readonly ok: false;
	/** Machine-readable failure code. */
	readonly code: 'malformed_rsa_pss_parameters';
	/** Human-readable description of the structural defect. */
	readonly reason: string;
}

/** Result of {@linkcode parseRsaPssParameters}: success, unsupported, or malformed. */
export type ParsedRsaPssParametersResult =
	| ParsedRsaPssParametersSuccess
	| ParsedRsaPssParametersUnsupported
	| ParsedRsaPssParametersMalformed;

/** Parsed MGF AlgorithmIdentifier from an RSA-PSS parameter SEQUENCE. */
interface ParsedMaskGenAlgorithm {
	/** OID of the mask generation function (expected: id-mgf1). */
	readonly oid: string;
	/** OID of the hash algorithm used by MGF1, if present. */
	readonly hashOid?: string;
}

/** RFC 3447 default salt length when hash is SHA-1 (used to detect the unsupported default). */
const SHA1_SALT_LENGTH = 20;

/** Return the canonical {@linkcode RsaPssParameters} profile for a given hash algorithm. */
export function rsaPssParametersForHash(hash: RsaPssHash): RsaPssParameters {
	switch (hash) {
		case 'SHA-256':
			return {
				hash: 'SHA-256',
				mgfHash: 'SHA-256',
				saltLength: 32,
				trailerField: 1,
			};
		case 'SHA-384':
			return {
				hash: 'SHA-384',
				mgfHash: 'SHA-384',
				saltLength: 48,
				trailerField: 1,
			};
		case 'SHA-512':
			return {
				hash: 'SHA-512',
				mgfHash: 'SHA-512',
				saltLength: 64,
				trailerField: 1,
			};
	}
}

/** DER-encode an {@linkcode RsaPssParameters} profile as an ASN.1 RSASSA-PSS-params SEQUENCE. */
export function encodeRsaPssParameters(parameters: RsaPssParameters): Uint8Array {
	const hashOid = hashOidForName(parameters.hash);
	const hashAlgorithmIdentifier = encodeHashAlgorithmIdentifier(hashOid);
	return sequence([
		explicitContext(0, hashAlgorithmIdentifier),
		explicitContext(
			1,
			sequence([objectIdentifier(OIDS.mgf1), encodeHashAlgorithmIdentifier(hashOid)]),
		),
		explicitContext(2, integerFromNumber(parameters.saltLength)),
		explicitContext(3, integerFromNumber(parameters.trailerField)),
	]);
}

/**
 * Parse and validate DER-encoded RSASSA-PSS-params.
 *
 * Returns a typed result: success with a supported profile, unsupported with
 * a reason code, or malformed with an error message.
 */
export function parseRsaPssParameters(
	parametersDer: Uint8Array | undefined,
): ParsedRsaPssParametersResult {
	if (parametersDer === undefined) {
		return unsupportedResult('default_hash_sha1');
	}

	try {
		const element = readRootElement(parametersDer, { maxDepth: DEFAULT_MAX_DER_DEPTH });
		if (element.tag !== 0x30) {
			throw new Error('RSA-PSS parameters must be a SEQUENCE');
		}
		const children = childrenOf(parametersDer, element);
		let hashOid: string = OIDS.sha1;
		let maskGenAlgorithm: ParsedMaskGenAlgorithm = {
			oid: OIDS.mgf1,
			hashOid: OIDS.sha1,
		};
		let saltLength = SHA1_SALT_LENGTH;
		let trailerField = 1;
		let sawHash = false;
		let sawMaskGen = false;
		let sawSaltLength = false;
		let sawTrailerField = false;

		for (const child of children) {
			switch (child.tag) {
				case 0xa0:
					if (sawHash) {
						throw new Error('RSA-PSS parameters contain duplicate hashAlgorithm');
					}
					hashOid = parseHashAlgorithmIdentifier(
						parametersDer,
						requireSingleExplicitChild(parametersDer, child, 'hashAlgorithm'),
						'hashAlgorithm',
					);
					sawHash = true;
					break;
				case 0xa1:
					if (sawMaskGen) {
						throw new Error('RSA-PSS parameters contain duplicate maskGenAlgorithm');
					}
					maskGenAlgorithm = parseMaskGenAlgorithmIdentifier(
						parametersDer,
						requireSingleExplicitChild(parametersDer, child, 'maskGenAlgorithm'),
					);
					sawMaskGen = true;
					break;
				case 0xa2:
					if (sawSaltLength) {
						throw new Error('RSA-PSS parameters contain duplicate saltLength');
					}
					saltLength = parseExplicitInteger(
						parametersDer,
						child,
						'saltLength',
						'RSA-PSS saltLength',
					);
					sawSaltLength = true;
					break;
				case 0xa3:
					if (sawTrailerField) {
						throw new Error('RSA-PSS parameters contain duplicate trailerField');
					}
					trailerField = parseExplicitInteger(
						parametersDer,
						child,
						'trailerField',
						'RSA-PSS trailerField',
					);
					sawTrailerField = true;
					break;
				default:
					throw new Error(
						`RSA-PSS parameters contain unexpected field tag 0x${child.tag.toString(16)}`,
					);
			}
		}

		const supportedHash = hashNameFromOid(hashOid);
		if (supportedHash === undefined) {
			if (hashOid === OIDS.sha1) {
				return unsupportedResult('default_hash_sha1');
			}
			return unsupportedResult('unsupported_hash');
		}
		if (maskGenAlgorithm.oid !== OIDS.mgf1) {
			return unsupportedResult('unsupported_mgf_algorithm');
		}
		const mgfHash = hashNameFromOid(maskGenAlgorithm.hashOid);
		if (mgfHash === undefined) {
			return unsupportedResult('unsupported_mgf_hash');
		}
		if (mgfHash !== supportedHash) {
			return unsupportedResult('mgf_hash_mismatch');
		}
		const supported = rsaPssParametersForHash(supportedHash);
		if (saltLength !== supported.saltLength) {
			return unsupportedResult('unsupported_salt_length');
		}
		if (trailerField !== 1) {
			return unsupportedResult('unsupported_trailer_field');
		}
		return { ok: true, value: supported };
	} catch (error) {
		return {
			ok: false,
			code: 'malformed_rsa_pss_parameters',
			reason: error instanceof Error ? error.message : 'Malformed RSA-PSS parameters',
		};
	}
}

/** Unwrap an explicit context tag and assert it contains exactly one child element. */
function requireSingleExplicitChild(
	source: Uint8Array,
	element: ReturnType<typeof readRootElement>,
	label: string,
): ReturnType<typeof readRootElement> {
	const children = childrenOf(source, element);
	if (children.length !== 1) {
		throw new Error(`RSA-PSS ${label} must wrap exactly one value`);
	}
	return requireElement(children[0], `RSA-PSS ${label}`);
}

/** Extract a non-negative integer from an explicit context-tagged wrapper. */
function parseExplicitInteger(
	source: Uint8Array,
	element: ReturnType<typeof readRootElement>,
	label: string,
	integerLabel: string,
): number {
	const integerElement = requireSingleExplicitChild(source, element, label);
	if (integerElement.tag !== 0x02) {
		throw new Error(`RSA-PSS ${label} must be an INTEGER`);
	}
	return decodeNonNegativeIntegerNumber(integerElement.value, integerLabel);
}

/** Parse an AlgorithmIdentifier SEQUENCE and return the algorithm OID. */
function parseHashAlgorithmIdentifier(
	source: Uint8Array,
	element: ReturnType<typeof readRootElement>,
	label: string,
): string {
	const children = childrenOf(source, element);
	if (children.length === 0 || children.length > 2) {
		throw new Error(`Malformed RSA-PSS ${label} AlgorithmIdentifier`);
	}
	const oid = requireElement(children[0], `${label} OID`);
	if (oid.tag !== 0x06) {
		throw new Error(`Malformed RSA-PSS ${label} AlgorithmIdentifier`);
	}
	return decodeObjectIdentifier(oid.value);
}

/** Parse an MGF AlgorithmIdentifier SEQUENCE into OID and optional inner hash OID. */
function parseMaskGenAlgorithmIdentifier(
	source: Uint8Array,
	element: ReturnType<typeof readRootElement>,
): ParsedMaskGenAlgorithm {
	const children = childrenOf(source, element);
	if (children.length === 0 || children.length > 2) {
		throw new Error('Malformed RSA-PSS maskGenAlgorithm AlgorithmIdentifier');
	}
	const oidElement = requireElement(children[0], 'maskGenAlgorithm OID');
	if (oidElement.tag !== 0x06) {
		throw new Error('Malformed RSA-PSS maskGenAlgorithm AlgorithmIdentifier');
	}
	const oid = decodeObjectIdentifier(oidElement.value);
	if (oid !== OIDS.mgf1) {
		return { oid };
	}
	const parameters = requireElement(children[1], 'maskGenAlgorithm parameters');
	return { oid, hashOid: parseHashAlgorithmIdentifier(source, parameters, 'MGF1 hashAlgorithm') };
}

/** DER-encode a hash AlgorithmIdentifier as `SEQUENCE { OID, NULL }`. */
function encodeHashAlgorithmIdentifier(oid: string): Uint8Array {
	return sequence([objectIdentifier(oid), nullValue()]);
}

/** Map a hash algorithm name to its ASN.1 OID string. */
function hashOidForName(hash: RsaPssHash): string {
	switch (hash) {
		case 'SHA-256':
			return OIDS.sha256;
		case 'SHA-384':
			return OIDS.sha384;
		case 'SHA-512':
			return OIDS.sha512;
	}
}

/** Reverse-map a hash OID to a supported {@linkcode RsaPssHash} name, or `undefined` if unsupported. */
function hashNameFromOid(oid: string | undefined): RsaPssHash | undefined {
	switch (oid) {
		case OIDS.sha256:
			return 'SHA-256';
		case OIDS.sha384:
			return 'SHA-384';
		case OIDS.sha512:
			return 'SHA-512';
		default:
			return undefined;
	}
}

/** Build an unsupported-parameters failure result. */
function unsupportedResult(
	reason: UnsupportedRsaPssParametersReason,
): ParsedRsaPssParametersUnsupported {
	return {
		ok: false,
		code: 'unsupported_rsa_pss_parameters',
		reason,
	};
}
