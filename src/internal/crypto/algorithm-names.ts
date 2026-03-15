/**
 * Human-readable algorithm labels for parsed OIDs.
 *
 * Shared by certificate, revocation, and PKCS parse surfaces so callers can
 * display meaningful algorithm names without memorizing dotted-decimal OIDs.
 *
 * @module
 */

import { OIDS } from '#micro509/internal/asn1/oids.ts';
import { parseRsaPssParameters } from './rsa-pss.ts';

/** Convert a hash or message-digest OID into a human-readable name. */
export function describeHashAlgorithm(oid: string): string {
	switch (oid) {
		case OIDS.sha1:
			return 'SHA-1';
		case OIDS.sha256:
			return 'SHA-256';
		case OIDS.sha384:
			return 'SHA-384';
		case OIDS.sha512:
			return 'SHA-512';
		default:
			return `Unknown (${oid})`;
	}
}

/** Convert a signature AlgorithmIdentifier into a human-readable name. */
export function describeSignatureAlgorithm(
	oid: string,
	parametersDer: Uint8Array | undefined,
): string {
	switch (oid) {
		case OIDS.sha256WithRSAEncryption:
			return 'RSA PKCS#1 v1.5 with SHA-256';
		case OIDS.sha384WithRSAEncryption:
			return 'RSA PKCS#1 v1.5 with SHA-384';
		case OIDS.sha512WithRSAEncryption:
			return 'RSA PKCS#1 v1.5 with SHA-512';
		case OIDS.rsassaPss: {
			const parsed = parseRsaPssParameters(parametersDer);
			return parsed.ok ? `RSA-PSS with ${parsed.value.hash}` : 'RSA-PSS';
		}
		case OIDS.ecdsaWithSHA256:
			return 'ECDSA with SHA-256';
		case OIDS.ecdsaWithSHA384:
			return 'ECDSA with SHA-384';
		case OIDS.ecdsaWithSHA512:
			return 'ECDSA with SHA-512';
		case OIDS.ed25519:
			return 'Ed25519';
		default:
			return `Unknown (${oid})`;
	}
}

/** Convert a SubjectPublicKeyInfo algorithm identifier into a human-readable name. */
export function describePublicKeyAlgorithm(oid: string, parametersOid: string | undefined): string {
	switch (oid) {
		case OIDS.rsaEncryption:
			return 'RSA';
		case OIDS.rsassaPss:
			return 'RSA-PSS';
		case OIDS.ecPublicKey:
			switch (parametersOid) {
				case OIDS.prime256v1:
					return 'EC P-256';
				case OIDS.secp384r1:
					return 'EC P-384';
				case OIDS.secp521r1:
					return 'EC P-521';
				default:
					return 'EC';
			}
		case OIDS.ed25519:
			return 'Ed25519';
		default:
			return `Unknown (${oid})`;
	}
}
