/**
 * Internal RSA-PSS parameter helpers.
 *
 * This module parses, validates, and encodes the shipped RSA-PSS `AlgorithmIdentifier`
 * parameter profiles.
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

/**
 * Enumerates the supported RSA PSS hash values.
 */
export type RsaPssHash = 'SHA-256' | 'SHA-384' | 'SHA-512';

/**
 * Describes RSA PSS parameters handled by this module.
 */
export type RsaPssParameters =
	| {
			/**
			 * Carries the hash value.
			 */
			readonly hash: 'SHA-256';
			/**
			 * Carries the mgf hash value.
			 */
			readonly mgfHash: 'SHA-256';
			/**
			 * Carries the salt length value.
			 */
			readonly saltLength: 32;
			/**
			 * Carries the trailer field value.
			 */
			readonly trailerField: 1;
	  }
	| {
			/**
			 * Carries the hash value.
			 */
			readonly hash: 'SHA-384';
			/**
			 * Carries the mgf hash value.
			 */
			readonly mgfHash: 'SHA-384';
			/**
			 * Carries the salt length value.
			 */
			readonly saltLength: 48;
			/**
			 * Carries the trailer field value.
			 */
			readonly trailerField: 1;
	  }
	| {
			/**
			 * Carries the hash value.
			 */
			readonly hash: 'SHA-512';
			/**
			 * Carries the mgf hash value.
			 */
			readonly mgfHash: 'SHA-512';
			/**
			 * Carries the salt length value.
			 */
			readonly saltLength: 64;
			/**
			 * Carries the trailer field value.
			 */
			readonly trailerField: 1;
	  };

/**
 * Enumerates unsupported RSA PSS parameters values used by this module.
 */
export type UnsupportedRsaPssParametersReason =
	| 'default_hash_sha1'
	| 'unsupported_hash'
	| 'unsupported_mgf_algorithm'
	| 'unsupported_mgf_hash'
	| 'mgf_hash_mismatch'
	| 'unsupported_salt_length'
	| 'unsupported_trailer_field';

/**
 * Represents a successful outcome produced by parsed RSA PSS parameters operations.
 */
export interface ParsedRsaPssParametersSuccess {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: true;
	/**
	 * Carries the successful value payload.
	 */
	readonly value: RsaPssParameters;
}

/**
 * Describes the structured RSA PSS parameters unsupported produced by parsing helpers.
 */
export interface ParsedRsaPssParametersUnsupported {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: false;
	/**
	 * Carries the machine-readable error code.
	 */
	readonly code: 'unsupported_rsa_pss_parameters';
	/**
	 * Carries the reason value.
	 */
	readonly reason: UnsupportedRsaPssParametersReason;
}

/**
 * Describes the structured RSA PSS parameters malformed produced by parsing helpers.
 */
export interface ParsedRsaPssParametersMalformed {
	/**
	 * Indicates whether the operation succeeded.
	 */
	readonly ok: false;
	/**
	 * Carries the machine-readable error code.
	 */
	readonly code: 'malformed_rsa_pss_parameters';
	/**
	 * Carries the reason value.
	 */
	readonly reason: string;
}

/**
 * Represents the result returned by parsed RSA PSS parameters operations.
 */
export type ParsedRsaPssParametersResult =
	| ParsedRsaPssParametersSuccess
	| ParsedRsaPssParametersUnsupported
	| ParsedRsaPssParametersMalformed;

/**
 * Describes the structured mask gen algorithm produced by parsing helpers.
 */
interface ParsedMaskGenAlgorithm {
	/**
	 * Carries the oid value.
	 */
	readonly oid: string;
	/**
	 * Carries the OID for hash.
	 */
	readonly hashOid?: string;
}

/**
 * Defines the sha-1 salt length used by this module.
 */
const SHA1_SALT_LENGTH = 20;

/**
 * RSA PSS parameters for hash.
 *
 * @param hash The hash value.
 * @returns The computed value.
 */
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

/**
 * Encodes RSA PSS parameters.
 *
 * @param parameters The parameters value.
 * @returns The encoded RSA PSS parameters.
 */
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
 * Parses RSA PSS parameters.
 *
 * @param parametersDer The parameters DER value.
 * @returns The parsed RSA PSS parameters.
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
			/**
			 * Carries the oid value.
			 */
			oid: OIDS.mgf1,
			/**
			 * Carries the OID for hash.
			 */
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

/**
 * Requires and returns single explicit child.
 *
 * @param source The source value to process.
 * @param element The ASN.1 element to process.
 * @param label The label value.
 * @returns The computed value.
 */
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

/**
 * Parses explicit integer.
 *
 * @param source The source value to process.
 * @param element The ASN.1 element to process.
 * @param label The label value.
 * @param integerLabel The integer label value.
 * @returns The parsed explicit integer.
 */
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

/**
 * Parses hash algorithm identifier.
 *
 * @param source The source value to process.
 * @param element The ASN.1 element to process.
 * @param label The label value.
 * @returns The parsed hash algorithm identifier.
 */
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

/**
 * Parses mask gen algorithm identifier.
 *
 * @param source The source value to process.
 * @param element The ASN.1 element to process.
 * @returns The parsed mask gen algorithm identifier.
 */
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

/**
 * Encodes hash algorithm identifier.
 *
 * @param oid The object identifier.
 * @returns The encoded hash algorithm identifier.
 */
function encodeHashAlgorithmIdentifier(oid: string): Uint8Array {
	return sequence([objectIdentifier(oid), nullValue()]);
}

/**
 * Hash OID for name.
 *
 * @param hash The hash value.
 * @returns The computed value.
 */
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

/**
 * Hash name from OID.
 *
 * @param oid The object identifier.
 * @returns The computed value.
 */
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

/**
 * Unsupported result.
 *
 * @param reason The reason value.
 * @returns The unsupported-result wrapper.
 */
function unsupportedResult(
	reason: UnsupportedRsaPssParametersReason,
): ParsedRsaPssParametersUnsupported {
	return {
		ok: false,
		code: 'unsupported_rsa_pss_parameters',
		reason,
	};
}
