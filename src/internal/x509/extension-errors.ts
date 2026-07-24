/**
 * Stable error codes for X.509 extension encoder input validation.
 *
 * The extension builders throw on invalid construction input (an empty
 * collection, a duplicate OID, an out-of-range value). Each failure carries one
 * of these codes on a {@link ResultError}, so callers branch on `error.code` via
 * `isResultError` instead of matching message strings.
 *
 * @module
 */

import { throwMicro509Error } from '#micro509/result/result';

/** Machine-readable reason an extension encoder rejected its construction input. */
export type ExtensionEncoderErrorCode =
	| 'authority_info_access_empty'
	| 'authority_info_access_ocsp_not_uri'
	| 'certificate_policies_empty'
	| 'crl_distribution_points_empty'
	| 'directory_name_not_sequence'
	| 'display_text_out_of_range'
	| 'distribution_point_crl_issuer_empty'
	| 'distribution_point_crl_issuer_not_directory_name'
	| 'distribution_point_empty'
	| 'distribution_point_full_name_empty'
	| 'distribution_point_name_conflict'
	| 'distribution_point_name_empty'
	| 'distribution_point_relative_name_multiple_crl_issuers'
	| 'duplicate_extension_oid'
	| 'duplicate_policy_oid'
	| 'empty_general_name_value'
	| 'empty_subject_requires_subject_alt_name'
	| 'extended_key_usage_empty'
	| 'extension_not_supported_in_context'
	| 'invalid_general_name_tag'
	| 'invalid_ia5_string'
	| 'invalid_ip_name_constraint'
	| 'invalid_oid'
	| 'key_usage_empty'
	| 'name_constraints_empty'
	| 'path_length_requires_key_cert_sign'
	| 'policy_constraints_empty'
	| 'policy_mappings_any_policy'
	| 'policy_mappings_empty'
	| 'reserved_policy_qualifier_oid';

/** Throws a {@link ResultError} for an extension encoder input-validation failure. */
export function throwExtensionEncoderError(
	code: ExtensionEncoderErrorCode,
	message: string,
): never {
	throwMicro509Error(code, message);
}
