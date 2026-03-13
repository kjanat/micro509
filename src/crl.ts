import {
	childrenOf,
	decodeIntegerNumber,
	decodeObjectIdentifier,
	decodeString,
	extractBitStringValue,
	parseTime,
	requireElement,
	toHex,
} from './asn1.ts';
import type { Micro509Error } from './core/result.ts';
import {
	bitString,
	bool,
	concatBytes,
	DEFAULT_MAX_DER_DEPTH,
	type DerElement,
	explicitContext,
	generalizedTime,
	implicitConstructedContext,
	implicitPrimitiveContext,
	integer,
	integerFromNumber,
	objectIdentifier,
	octetString,
	readElement,
	readRootElement,
	readSequenceChildren,
	sequence,
	time,
	tlv,
} from './der.ts';
import {
	encodeDistributionPointReasonFlagsContent,
	parseDistributionPointReasonFlagsContent,
} from './extension-bits.ts';
import {
	type DistributionPoint,
	type DistributionPointReason,
	encodeCrlDistributionPoints,
	encodeSubjectAltName,
	type GeneralName,
	type IssuingDistributionPoint,
} from './extensions.ts';
import { sha1 } from './hash.ts';
import { decodeIpAddress } from './ip.ts';
import { exportSpkiDer } from './keys.ts';
import {
	encodeName,
	encodeRelativeDistinguishedName,
	type NameFieldKey,
	type NameInput,
	nameFieldKeyFromOid,
} from './name.ts';
import { OIDS } from './oids.ts';
import {
	type ParsedCertificate,
	type ParsedDistributionPoint,
	type ParsedDistributionPointName,
	type ParsedIssuingDistributionPoint,
	type ParsedNameAttribute,
	type ParsedRelativeDistinguishedName,
	parseCertificateDer,
	parseCertificatePem,
} from './parse.ts';
import { base64Encode, pemDecode, pemEncode } from './pem.ts';
import { verifySignedData } from './sig-verify.ts';
import { encodeAlgorithmIdentifier, getSignatureAlgorithm, signBytes } from './signing.ts';

export interface RevokedCertificateInput {
	readonly serialNumber: Uint8Array;
	readonly revocationDate?: Date;
	readonly reasonCode?: RevocationReason;
	readonly invalidityDate?: Date;
}

export type RevocationReason =
	| 'unspecified'
	| 'keyCompromise'
	| 'cACompromise'
	| 'affiliationChanged'
	| 'superseded'
	| 'cessationOfOperation'
	| 'certificateHold'
	| 'removeFromCRL'
	| 'privilegeWithdrawn'
	| 'aACompromise';

export interface CreateCertificateRevocationListInput {
	readonly issuer: NameInput;
	readonly signerPrivateKey: CryptoKey;
	readonly issuerPublicKey?: CryptoKey;
	readonly thisUpdate?: Date;
	readonly nextUpdate?: Date;
	readonly revokedCertificates?: readonly RevokedCertificateInput[];
	readonly crlNumber?: number;
	readonly baseCrlNumber?: number;
	readonly issuingDistributionPoint?: IssuingDistributionPoint;
	readonly freshestCrlDistributionPoints?: readonly DistributionPoint[];
}

export interface CertificateRevocationListMaterial {
	readonly der: Uint8Array;
	readonly pem: string;
	readonly base64: string;
}

export interface ParsedRevokedCertificate {
	readonly serialNumberHex: string;
	readonly revocationDate: Date;
	readonly reasonCode?: RevocationReason;
	readonly invalidityDate?: Date;
	readonly certificateIssuer?: readonly GeneralName[];
}

export interface ParsedCertificateRevocationList {
	readonly version: number;
	readonly tbsCertListDer: Uint8Array;
	readonly signatureValue: Uint8Array;
	readonly issuer: {
		readonly derHex: string;
		readonly commonName?: string;
	};
	readonly thisUpdate: Date;
	readonly nextUpdate?: Date;
	readonly signatureAlgorithmOid: string;
	readonly issuerPublicKeyAlgorithmOid?: string;
	readonly issuerPublicKeyParametersOid?: string;
	readonly authorityKeyIdentifier?: string;
	readonly crlNumber?: number;
	readonly baseCrlNumber?: number;
	readonly issuingDistributionPoint?: ParsedIssuingDistributionPoint;
	readonly freshestCrlDistributionPoints?: readonly ParsedDistributionPoint[];
	readonly revokedCertificates: readonly ParsedRevokedCertificate[];
}

const REVOCATION_REASON_CODES: Record<RevocationReason, number> = {
	unspecified: 0,
	keyCompromise: 1,
	cACompromise: 2,
	affiliationChanged: 3,
	superseded: 4,
	cessationOfOperation: 5,
	certificateHold: 6,
	removeFromCRL: 8,
	privilegeWithdrawn: 9,
	aACompromise: 10,
};

export type CrlSource = string | Uint8Array | ParsedCertificateRevocationList;
export type CrlCertificateSource = string | Uint8Array | ParsedCertificate;

export interface VerifyCertificateRevocationListFailure extends Micro509Error<'signature_invalid'> {
	readonly ok: false;
}

interface VerifyCertificateRevocationListFailureResult {
	readonly ok: false;
	readonly error: VerifyCertificateRevocationListFailure;
	readonly code: 'signature_invalid';
	readonly message: string;
}

export type VerifyCertificateRevocationListResult =
	| { readonly ok: true; readonly value: ParsedCertificateRevocationList }
	| VerifyCertificateRevocationListFailureResult;

export interface ValidateCertificateRevocationListInput {
	readonly crl: CrlSource;
	readonly issuerCertificate: CrlCertificateSource;
	readonly at?: Date;
	readonly clockSkewMs?: number;
}

export interface ValidateCertificateRevocationListFailure
	extends Micro509Error<
		'signature_invalid' | 'issuer_mismatch' | 'stale_crl' | 'crl_sign_not_permitted'
	> {
	readonly ok: false;
}

interface ValidateCertificateRevocationListFailureResult {
	readonly ok: false;
	readonly error: ValidateCertificateRevocationListFailure;
	readonly code: 'signature_invalid' | 'issuer_mismatch' | 'stale_crl' | 'crl_sign_not_permitted';
	readonly message: string;
}

export type ValidateCertificateRevocationListResult =
	| { readonly ok: true; readonly value: ParsedCertificateRevocationList }
	| ValidateCertificateRevocationListFailureResult;

export interface CheckCertificateRevocationAgainstCrlInput {
	readonly certificate: CrlCertificateSource;
	readonly issuerCertificate: CrlCertificateSource;
	readonly crl: CrlSource;
	readonly deltaCrl?: CrlSource;
	readonly at?: Date;
	readonly clockSkewMs?: number;
}

export type CheckCertificateRevocationAgainstCrlErrorCode =
	| 'signature_invalid'
	| 'issuer_mismatch'
	| 'stale_crl'
	| 'crl_sign_not_permitted'
	| 'non_applicable';

export type CrlApplicabilityFailureReason =
	| 'certificate_scope_mismatch'
	| 'delta_crl_incompatible'
	| 'delta_crl_unsupported'
	| 'distribution_point_mismatch'
	| 'indirect_crl_unsupported'
	| 'issuer_mismatch'
	| 'reasons_mismatch';

type RevokedCertificateLookupResult =
	| {
			readonly ok: true;
			readonly entry?: ParsedRevokedCertificate;
	  }
	| CheckCertificateRevocationAgainstCrlFailureResult;

export interface CheckCertificateRevocationAgainstCrlFailureDetails {
	readonly reason?: CrlApplicabilityFailureReason;
}

export interface CheckCertificateRevocationAgainstCrlFailure
	extends Micro509Error<
		CheckCertificateRevocationAgainstCrlErrorCode,
		CheckCertificateRevocationAgainstCrlFailureDetails
	> {
	readonly ok: false;
}

export interface CheckCertificateRevocationAgainstCrlGoodValue {
	readonly status: 'good';
	readonly crl: ParsedCertificateRevocationList;
}

export interface CheckCertificateRevocationAgainstCrlRevokedValue {
	readonly status: 'revoked';
	readonly crl: ParsedCertificateRevocationList;
	readonly revocationDate: Date;
	readonly reasonCode?: RevocationReason;
}

export type CheckCertificateRevocationAgainstCrlValue =
	| CheckCertificateRevocationAgainstCrlGoodValue
	| CheckCertificateRevocationAgainstCrlRevokedValue;

interface CheckCertificateRevocationAgainstCrlFailureResult {
	readonly ok: false;
	readonly error: CheckCertificateRevocationAgainstCrlFailure;
	readonly code: CheckCertificateRevocationAgainstCrlErrorCode;
	readonly message: string;
	readonly details?: CheckCertificateRevocationAgainstCrlFailureDetails;
}

export type CheckCertificateRevocationAgainstCrlResult =
	| { readonly ok: true; readonly value: CheckCertificateRevocationAgainstCrlValue }
	| CheckCertificateRevocationAgainstCrlFailureResult;

export async function createCertificateRevocationList(
	input: CreateCertificateRevocationListInput,
): Promise<CertificateRevocationListMaterial> {
	const signatureAlgorithm = getSignatureAlgorithm(input.signerPrivateKey);
	const thisUpdate = input.thisUpdate ?? new Date();
	const nextUpdate = input.nextUpdate;
	const extensions = await buildCrlExtensions(
		input.issuerPublicKey,
		input.crlNumber,
		input.baseCrlNumber,
		input.issuingDistributionPoint,
		input.freshestCrlDistributionPoints,
	);
	const revoked = input.revokedCertificates ?? [];
	const revokedSequence =
		revoked.length === 0
			? []
			: [sequence(revoked.map((entry) => createRevokedCertificate(entry, thisUpdate)))];
	const tbsCertList = sequence([
		integerFromNumber(1),
		encodeAlgorithmIdentifier(signatureAlgorithm),
		encodeName(input.issuer),
		time(thisUpdate),
		...(nextUpdate === undefined ? [] : [time(nextUpdate)]),
		...revokedSequence,
		...(extensions.length === 0 ? [] : [explicitContext(0, sequence(extensions))]),
	]);
	const signatureValue = await signBytes(input.signerPrivateKey, signatureAlgorithm, tbsCertList);
	const der = sequence([
		tbsCertList,
		encodeAlgorithmIdentifier(signatureAlgorithm),
		bitString(signatureValue),
	]);
	return {
		der,
		pem: pemEncode('X509 CRL', der),
		base64: base64Encode(der),
	};
}

export function parseCertificateRevocationListDer(
	der: Uint8Array,
): ParsedCertificateRevocationList {
	const top = readSequenceChildren(der, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	const tbsCertList = requireElement(top[0], 'TBSCertList');
	const signatureAlgorithm = requireElement(top[1], 'signatureAlgorithm');
	const signatureValue = requireElement(top[2], 'signatureValue');
	const tbsChildren = childrenOf(der, tbsCertList);
	let index = 0;
	let version = 1;
	if (tbsChildren[index]?.tag === 0x02) {
		version = decodeIntegerNumber(requireElement(tbsChildren[index], 'version').value) + 1;
		index += 1;
	}
	index += 1; // signature algorithm in TBS
	const issuer = requireElement(tbsChildren[index], 'issuer');
	const thisUpdate = requireElement(tbsChildren[index + 1], 'thisUpdate');
	let cursor = index + 2;
	const maybeNextUpdate = tbsChildren[cursor];
	const nextUpdate =
		maybeNextUpdate !== undefined && (maybeNextUpdate.tag === 0x17 || maybeNextUpdate.tag === 0x18)
			? parseTime(maybeNextUpdate)
			: undefined;
	if (nextUpdate !== undefined) {
		cursor += 1;
	}
	let revokedCertificates: readonly ParsedRevokedCertificate[] = [];
	const maybeRevoked = tbsChildren[cursor];
	if (maybeRevoked?.tag === 0x30) {
		revokedCertificates = childrenOf(der, maybeRevoked).map((entry) => {
			const entryDer = der.slice(entry.start - entry.headerLength, entry.end);
			const parts = readSequenceChildren(entryDer);
			const entryExtensions = parts[2];
			const parsedEntryExtensions = parseRevokedCertificateExtensions(entryDer, entryExtensions);
			return {
				serialNumberHex: toHex(requireElement(parts[0], 'revoked serialNumber').value),
				revocationDate: parseTime(requireElement(parts[1], 'revocationDate')),
				...(parsedEntryExtensions.reasonCode === undefined
					? {}
					: { reasonCode: parsedEntryExtensions.reasonCode }),
				...(parsedEntryExtensions.invalidityDate === undefined
					? {}
					: { invalidityDate: parsedEntryExtensions.invalidityDate }),
				...(parsedEntryExtensions.certificateIssuer === undefined
					? {}
					: { certificateIssuer: parsedEntryExtensions.certificateIssuer }),
			};
		});
		cursor += 1;
	}
	let authorityKeyIdentifier: string | undefined;
	let crlNumber: number | undefined;
	let baseCrlNumber: number | undefined;
	let issuingDistributionPoint: ParsedIssuingDistributionPoint | undefined;
	let freshestCrlDistributionPoints: readonly ParsedDistributionPoint[] | undefined;
	const maybeExtensions = tbsChildren[cursor];
	if (maybeExtensions?.tag === 0xa0) {
		const extensionSequence = requireElement(childrenOf(der, maybeExtensions)[0], 'crl extensions');
		for (const extension of childrenOf(der, extensionSequence)) {
			const parts = childrenOf(der, extension);
			const oid = decodeObjectIdentifier(requireElement(parts[0], 'extension OID').value);
			const valueElement = requireElement(parts[parts.length - 1], 'extension value');
			if (oid === OIDS.authorityKeyIdentifier) {
				authorityKeyIdentifier = parseAuthorityKeyIdentifier(valueElement.value);
			}
			if (oid === OIDS.cRLNumber) {
				crlNumber = decodeIntegerNumber(readElement(valueElement.value).value);
			}
			if (oid === OIDS.deltaCRLIndicator) {
				baseCrlNumber = decodeIntegerNumber(readElement(valueElement.value).value);
			}
			if (oid === OIDS.issuingDistributionPoint) {
				issuingDistributionPoint = parseIssuingDistributionPoint(valueElement.value);
			}
			if (oid === OIDS.freshestCRL) {
				freshestCrlDistributionPoints = parseDistributionPoints(valueElement.value);
			}
		}
	}
	return {
		version,
		tbsCertListDer: der.slice(tbsCertList.start - tbsCertList.headerLength, tbsCertList.end),
		signatureValue: extractBitStringValue(signatureValue),
		issuer: parseIssuer(der, issuer),
		thisUpdate: parseTime(thisUpdate),
		...(nextUpdate === undefined ? {} : { nextUpdate }),
		signatureAlgorithmOid: parseAlgorithmIdentifier(der, signatureAlgorithm).oid,
		...(authorityKeyIdentifier === undefined ? {} : { authorityKeyIdentifier }),
		...(crlNumber === undefined ? {} : { crlNumber }),
		...(baseCrlNumber === undefined ? {} : { baseCrlNumber }),
		...(issuingDistributionPoint === undefined ? {} : { issuingDistributionPoint }),
		...(freshestCrlDistributionPoints === undefined ? {} : { freshestCrlDistributionPoints }),
		revokedCertificates,
	};
}

export function parseCertificateRevocationListPem(pem: string): ParsedCertificateRevocationList {
	return parseCertificateRevocationListDer(pemDecode('X509 CRL', pem));
}

export async function verifyCertificateRevocationList(
	crl: string | Uint8Array,
	issuerCertificate: string | Uint8Array,
): Promise<VerifyCertificateRevocationListResult> {
	const parsedCrl =
		typeof crl === 'string'
			? parseCertificateRevocationListPem(crl)
			: parseCertificateRevocationListDer(new Uint8Array(crl));
	const issuer =
		typeof issuerCertificate === 'string'
			? parseIssuerCertificatePem(issuerCertificate)
			: parseIssuerCertificateDer(new Uint8Array(issuerCertificate));
	const verified = await verifySignedData(
		parsedCrl.signatureAlgorithmOid,
		issuer.publicKeyAlgorithmOid,
		issuer.publicKeyParametersOid,
		issuer.subjectPublicKeyInfoDer,
		parsedCrl.signatureValue,
		parsedCrl.tbsCertListDer,
	);
	return verified
		? { ok: true, value: parsedCrl }
		: verifyCertificateRevocationListFailureResult(
				'signature_invalid',
				'certificate revocation list signature does not verify',
			);
}

export async function validateCertificateRevocationList(
	input: ValidateCertificateRevocationListInput,
): Promise<ValidateCertificateRevocationListResult> {
	const parsedCrl = normalizeCrl(input.crl);
	const issuer = normalizeCrlCertificate(input.issuerCertificate);
	if (parsedCrl.issuer.derHex !== issuer.subject.derHex) {
		return validateCertificateRevocationListFailureResult(
			'issuer_mismatch',
			'CRL issuer name does not match certificate subject',
		);
	}
	if (
		parsedCrl.authorityKeyIdentifier !== undefined &&
		issuer.subjectKeyIdentifier !== undefined &&
		parsedCrl.authorityKeyIdentifier !== issuer.subjectKeyIdentifier
	) {
		return validateCertificateRevocationListFailureResult(
			'issuer_mismatch',
			'CRL authority key identifier does not match issuer subject key identifier',
		);
	}
	if (issuer.keyUsage !== undefined && !issuer.keyUsage.includes('cRLSign')) {
		return validateCertificateRevocationListFailureResult(
			'crl_sign_not_permitted',
			'issuer certificate key usage does not permit CRL signing',
		);
	}
	const verified = await verifySignedData(
		parsedCrl.signatureAlgorithmOid,
		issuer.publicKeyAlgorithmOid,
		issuer.publicKeyParametersOid,
		issuer.subjectPublicKeyInfoDer,
		parsedCrl.signatureValue,
		parsedCrl.tbsCertListDer,
	);
	if (!verified) {
		return validateCertificateRevocationListFailureResult(
			'signature_invalid',
			'certificate revocation list signature does not verify',
		);
	}
	const at = input.at ?? new Date();
	const skew = input.clockSkewMs ?? 0;
	if (
		parsedCrl.thisUpdate.getTime() - skew > at.getTime() ||
		(parsedCrl.nextUpdate !== undefined && parsedCrl.nextUpdate.getTime() + skew < at.getTime())
	) {
		return validateCertificateRevocationListFailureResult(
			'stale_crl',
			'CRL is not valid at requested time',
		);
	}
	return { ok: true, value: parsedCrl };
}

export async function checkCertificateRevocationAgainstCrl(
	input: CheckCertificateRevocationAgainstCrlInput,
): Promise<CheckCertificateRevocationAgainstCrlResult> {
	const certificate = normalizeCrlCertificate(input.certificate);
	const validated = await validateCertificateRevocationList({
		crl: input.crl,
		issuerCertificate: input.issuerCertificate,
		...(input.at === undefined ? {} : { at: input.at }),
		...(input.clockSkewMs === undefined ? {} : { clockSkewMs: input.clockSkewMs }),
	});
	if (!validated.ok) {
		return checkCertificateRevocationAgainstCrlFailureResult(validated.code, validated.message);
	}
	let validatedDelta: ParsedCertificateRevocationList | undefined;
	if (input.deltaCrl !== undefined) {
		const deltaValidation = await validateCertificateRevocationList({
			crl: input.deltaCrl,
			issuerCertificate: input.issuerCertificate,
			...(input.at === undefined ? {} : { at: input.at }),
			...(input.clockSkewMs === undefined ? {} : { clockSkewMs: input.clockSkewMs }),
		});
		if (!deltaValidation.ok) {
			return checkCertificateRevocationAgainstCrlFailureResult(
				deltaValidation.code,
				deltaValidation.message,
			);
		}
		const compatibilityFailure = checkDeltaCrlCompatibility(validated.value, deltaValidation.value);
		if (compatibilityFailure !== undefined) {
			return compatibilityFailure;
		}
		validatedDelta = deltaValidation.value;
	}
	const applicabilityFailure = checkCrlApplicability(certificate, validated.value);
	if (applicabilityFailure !== undefined) {
		return applicabilityFailure;
	}
	if (validatedDelta !== undefined) {
		const deltaApplicabilityFailure = checkCrlApplicability(certificate, validatedDelta, true);
		if (deltaApplicabilityFailure !== undefined) {
			return deltaApplicabilityFailure;
		}
	}
	const completeRevoked = findRevokedCertificateEntry(certificate, validated.value);
	if (!completeRevoked.ok) {
		return completeRevoked;
	}
	let deltaRevoked: ParsedRevokedCertificate | undefined;
	if (validatedDelta !== undefined) {
		const deltaLookup = findRevokedCertificateEntry(certificate, validatedDelta);
		if (!deltaLookup.ok) {
			return deltaLookup;
		}
		deltaRevoked = deltaLookup.entry;
	}
	return resolveCertificateRevocationStatus(
		certificate,
		input.at ?? new Date(),
		validated.value,
		completeRevoked.entry,
		deltaRevoked,
	);
}

function verifyCertificateRevocationListFailureResult(
	code: 'signature_invalid',
	message: string,
): VerifyCertificateRevocationListFailureResult {
	const error: VerifyCertificateRevocationListFailure = { ok: false, code, message };
	return { ok: false, error, code, message };
}

function validateCertificateRevocationListFailureResult(
	code: ValidateCertificateRevocationListFailureResult['code'],
	message: string,
): ValidateCertificateRevocationListFailureResult {
	const error: ValidateCertificateRevocationListFailure = { ok: false, code, message };
	return { ok: false, error, code, message };
}

function checkCertificateRevocationAgainstCrlFailureResult(
	code: CheckCertificateRevocationAgainstCrlErrorCode,
	message: string,
	details?: CheckCertificateRevocationAgainstCrlFailureDetails,
): CheckCertificateRevocationAgainstCrlFailureResult {
	const error: CheckCertificateRevocationAgainstCrlFailure = {
		ok: false,
		code,
		message,
		...(details === undefined ? {} : { details }),
	};
	return {
		ok: false,
		error,
		code,
		message,
		...(details === undefined ? {} : { details }),
	};
}

function checkCertificateRevocationAgainstCrlSuccess(
	value: CheckCertificateRevocationAgainstCrlValue,
): CheckCertificateRevocationAgainstCrlResult {
	return { ok: true, value };
}

export function isCertificateRevoked(
	certificateSerialNumber: Uint8Array | string,
	crl: ParsedCertificateRevocationList,
): boolean {
	const serialNumberHex =
		typeof certificateSerialNumber === 'string'
			? normalizeHex(certificateSerialNumber)
			: toHex(certificateSerialNumber);
	return crl.revokedCertificates.some(
		(entry) => normalizeHex(entry.serialNumberHex) === serialNumberHex,
	);
}

function findRevokedCertificateEntry(
	certificate: ParsedCertificate,
	crl: ParsedCertificateRevocationList,
): RevokedCertificateLookupResult {
	const serialNumberHex = normalizeHex(certificate.serialNumberHex);
	let effectiveIssuer: readonly GeneralName[] | undefined;
	let sawUnsupportedIssuer = false;
	for (const entry of crl.revokedCertificates) {
		if (entry.certificateIssuer !== undefined) {
			effectiveIssuer = entry.certificateIssuer;
		}
		if (normalizeHex(entry.serialNumberHex) !== serialNumberHex) {
			continue;
		}
		const issuerMatch = matchesRevokedEntryIssuer(certificate, crl, effectiveIssuer);
		if (issuerMatch === 'match') {
			return { ok: true, entry };
		}
		if (issuerMatch === 'unsupported') {
			sawUnsupportedIssuer = true;
		}
	}
	if (sawUnsupportedIssuer) {
		return nonApplicable(
			'indirect_crl_unsupported',
			'indirect CRL entry certificateIssuer must include a directoryName',
		);
	}
	return { ok: true };
}

function checkCrlApplicability(
	certificate: ParsedCertificate,
	crl: ParsedCertificateRevocationList,
	allowDeltaCrl = false,
): CheckCertificateRevocationAgainstCrlFailureResult | undefined {
	if (!allowDeltaCrl && crl.baseCrlNumber !== undefined) {
		return nonApplicable(
			'delta_crl_unsupported',
			'delta CRLs are not applicable until delta merge support is implemented',
		);
	}
	const issuingDistributionPoint = crl.issuingDistributionPoint;
	const isIndirectCrl = issuingDistributionPoint?.indirectCrl === true;
	if (!isIndirectCrl && certificate.issuer.derHex !== crl.issuer.derHex) {
		return nonApplicable(
			'issuer_mismatch',
			'CRL issuer does not match certificate issuer for direct CRL processing',
		);
	}
	if (issuingDistributionPoint?.onlyContainsAttributeCerts === true) {
		return nonApplicable(
			'certificate_scope_mismatch',
			'attribute-certificate-only CRLs are not applicable to public-key certificates',
		);
	}
	const isCaCertificate = certificate.basicConstraints?.ca === true;
	if (issuingDistributionPoint?.onlyContainsUserCerts === true && isCaCertificate) {
		return nonApplicable(
			'certificate_scope_mismatch',
			'CRL only applies to end-entity certificates',
		);
	}
	if (issuingDistributionPoint?.onlyContainsCACerts === true && !isCaCertificate) {
		return nonApplicable('certificate_scope_mismatch', 'CRL only applies to CA certificates');
	}
	const distributionPoints = certificate.crlDistributionPoints ?? [];
	if (distributionPoints.length === 0) {
		if (issuingDistributionPoint?.distributionPoint !== undefined) {
			return nonApplicable(
				'distribution_point_mismatch',
				'certificates without CRL distribution points only accept full-scope CRLs',
			);
		}
		if (isIndirectCrl && certificate.issuer.derHex !== crl.issuer.derHex) {
			return nonApplicable(
				'issuer_mismatch',
				'indirect CRLs for alternate certificate issuers require matching cRLIssuer distribution points',
			);
		}
		return undefined;
	}
	let sawIndirectDistributionPoint = false;
	let sawDistributionMismatch = false;
	let sawIndirectIssuerMismatch = false;
	let sawIndirectIssuerUnsupported = false;
	let sawReasonsMismatch = false;
	for (const distributionPoint of distributionPoints) {
		if (!isIndirectCrl && distributionPoint.crlIssuer !== undefined) {
			sawIndirectDistributionPoint = true;
			continue;
		}
		if (isIndirectCrl) {
			if (
				certificate.issuer.derHex !== crl.issuer.derHex ||
				distributionPoint.crlIssuer !== undefined
			) {
				const issuerMatch = matchesIndirectCrlIssuer(distributionPoint.crlIssuer, crl);
				if (issuerMatch === 'unsupported') {
					sawIndirectIssuerUnsupported = true;
					continue;
				}
				if (!issuerMatch) {
					sawIndirectIssuerMismatch = true;
					continue;
				}
			}
		}
		if (
			!matchesDistributionPointName(
				distributionPoint.distributionPoint,
				issuingDistributionPoint?.distributionPoint,
			)
		) {
			sawDistributionMismatch = true;
			continue;
		}
		if (
			!hasOverlappingReasons(distributionPoint.reasons, issuingDistributionPoint?.onlySomeReasons)
		) {
			sawReasonsMismatch = true;
			continue;
		}
		return undefined;
	}
	if (sawReasonsMismatch) {
		return nonApplicable(
			'reasons_mismatch',
			'certificate distribution point reasons do not overlap the CRL reason scope',
		);
	}
	if (sawIndirectIssuerUnsupported) {
		return nonApplicable(
			'indirect_crl_unsupported',
			'indirect CRL distribution points must identify the CRL issuer with directoryName',
		);
	}
	if (sawIndirectIssuerMismatch) {
		return nonApplicable(
			'issuer_mismatch',
			'certificate distribution points do not authorize this indirect CRL issuer',
		);
	}
	if (sawDistributionMismatch) {
		return nonApplicable(
			'distribution_point_mismatch',
			'certificate distribution points do not match the CRL issuing distribution point',
		);
	}
	if (sawIndirectDistributionPoint) {
		return nonApplicable(
			'indirect_crl_unsupported',
			'certificate distribution points that name alternate CRL issuers are not supported yet',
		);
	}
	return nonApplicable(
		'distribution_point_mismatch',
		'certificate distribution points do not match the CRL scope',
	);
}

function checkDeltaCrlCompatibility(
	completeCrl: ParsedCertificateRevocationList,
	deltaCrl: ParsedCertificateRevocationList,
): CheckCertificateRevocationAgainstCrlFailureResult | undefined {
	if (completeCrl.baseCrlNumber !== undefined) {
		return nonApplicable(
			'delta_crl_incompatible',
			'complete CRL input must not itself be a delta CRL',
		);
	}
	if (deltaCrl.baseCrlNumber === undefined) {
		return nonApplicable(
			'delta_crl_incompatible',
			'delta CRL input must include a delta CRL indicator',
		);
	}
	if (normalizeHex(completeCrl.issuer.derHex) !== normalizeHex(deltaCrl.issuer.derHex)) {
		return nonApplicable(
			'delta_crl_incompatible',
			'complete and delta CRLs must share the same issuer',
		);
	}
	if (completeCrl.authorityKeyIdentifier !== deltaCrl.authorityKeyIdentifier) {
		return nonApplicable(
			'delta_crl_incompatible',
			'complete and delta CRLs must share the same authority key identifier',
		);
	}
	if (
		!sameIssuingDistributionPoint(
			completeCrl.issuingDistributionPoint,
			deltaCrl.issuingDistributionPoint,
		)
	) {
		return nonApplicable(
			'delta_crl_incompatible',
			'complete and delta CRLs must share the same issuing distribution point scope',
		);
	}
	if (completeCrl.crlNumber === undefined || deltaCrl.crlNumber === undefined) {
		return nonApplicable(
			'delta_crl_incompatible',
			'complete and delta CRLs must both carry CRL numbers for delta processing',
		);
	}
	if (completeCrl.crlNumber < deltaCrl.baseCrlNumber) {
		return nonApplicable(
			'delta_crl_incompatible',
			'delta CRL base number must not exceed the complete CRL number',
		);
	}
	if (completeCrl.crlNumber >= deltaCrl.crlNumber) {
		return nonApplicable(
			'delta_crl_incompatible',
			'delta CRL number must be newer than the complete CRL number',
		);
	}
	return undefined;
}

function matchesIndirectCrlIssuer(
	crlIssuerNames: readonly GeneralName[] | undefined,
	crl: ParsedCertificateRevocationList,
): boolean | 'unsupported' {
	if (crlIssuerNames === undefined) {
		return false;
	}
	let sawUnsupportedName = false;
	for (const generalName of crlIssuerNames) {
		if (generalName.type === 'directoryName') {
			if (normalizeHex(generalName.derHex) === normalizeHex(crl.issuer.derHex)) {
				return true;
			}
			continue;
		}
		sawUnsupportedName = true;
	}
	return sawUnsupportedName ? 'unsupported' : false;
}

function matchesRevokedEntryIssuer(
	certificate: ParsedCertificate,
	crl: ParsedCertificateRevocationList,
	effectiveIssuer: readonly GeneralName[] | undefined,
): 'match' | 'mismatch' | 'unsupported' {
	if (effectiveIssuer === undefined) {
		return normalizeHex(certificate.issuer.derHex) === normalizeHex(crl.issuer.derHex)
			? 'match'
			: 'mismatch';
	}
	let sawUnsupportedName = false;
	for (const generalName of effectiveIssuer) {
		if (generalName.type === 'directoryName') {
			if (normalizeHex(generalName.derHex) === normalizeHex(certificate.issuer.derHex)) {
				return 'match';
			}
			continue;
		}
		sawUnsupportedName = true;
	}
	return sawUnsupportedName ? 'unsupported' : 'mismatch';
}

function nonApplicable(
	reason: CrlApplicabilityFailureReason,
	message: string,
): CheckCertificateRevocationAgainstCrlFailureResult {
	return checkCertificateRevocationAgainstCrlFailureResult('non_applicable', message, { reason });
}

function resolveCertificateRevocationStatus(
	certificate: ParsedCertificate,
	at: Date,
	completeCrl: ParsedCertificateRevocationList,
	completeEntry: ParsedRevokedCertificate | undefined,
	deltaEntry: ParsedRevokedCertificate | undefined,
): CheckCertificateRevocationAgainstCrlResult {
	if (deltaEntry !== undefined) {
		if (deltaEntry.reasonCode === 'removeFromCRL') {
			if (
				completeEntry?.reasonCode === 'certificateHold' ||
				certificate.notAfter.getTime() < at.getTime()
			) {
				return checkCertificateRevocationAgainstCrlSuccess({
					status: 'good',
					crl: completeCrl,
				});
			}
		} else {
			return checkCertificateRevocationAgainstCrlSuccess({
				status: 'revoked',
				crl: completeCrl,
				revocationDate: deltaEntry.revocationDate,
				...(deltaEntry.reasonCode === undefined ? {} : { reasonCode: deltaEntry.reasonCode }),
			});
		}
	}
	if (completeEntry === undefined) {
		return checkCertificateRevocationAgainstCrlSuccess({ status: 'good', crl: completeCrl });
	}
	return checkCertificateRevocationAgainstCrlSuccess({
		status: 'revoked',
		crl: completeCrl,
		revocationDate: completeEntry.revocationDate,
		...(completeEntry.reasonCode === undefined ? {} : { reasonCode: completeEntry.reasonCode }),
	});
}

function matchesDistributionPointName(
	certificatePoint: ParsedDistributionPointName | undefined,
	crlPoint: ParsedDistributionPointName | undefined,
): boolean {
	if (crlPoint === undefined) {
		return true;
	}
	if (certificatePoint === undefined) {
		return false;
	}
	if (certificatePoint.fullName !== undefined || crlPoint.fullName !== undefined) {
		if (certificatePoint.fullName === undefined || crlPoint.fullName === undefined) {
			return false;
		}
		return certificatePoint.fullName.some(
			(leftName) =>
				crlPoint.fullName?.some((rightName) => compareGeneralNames(leftName, rightName)) === true,
		);
	}
	if (certificatePoint.relativeName === undefined || crlPoint.relativeName === undefined) {
		return false;
	}
	return compareRelativeDistinguishedNames(certificatePoint.relativeName, crlPoint.relativeName);
}

function sameIssuingDistributionPoint(
	left: ParsedIssuingDistributionPoint | undefined,
	right: ParsedIssuingDistributionPoint | undefined,
): boolean {
	if (left === undefined || right === undefined) {
		return left === right;
	}
	return (
		sameDistributionPointName(left.distributionPoint, right.distributionPoint) &&
		(left.onlyContainsUserCerts === true) === (right.onlyContainsUserCerts === true) &&
		(left.onlyContainsCACerts === true) === (right.onlyContainsCACerts === true) &&
		(left.indirectCrl === true) === (right.indirectCrl === true) &&
		(left.onlyContainsAttributeCerts === true) === (right.onlyContainsAttributeCerts === true) &&
		sameReasonSet(left.onlySomeReasons, right.onlySomeReasons)
	);
}

function sameDistributionPointName(
	left: ParsedDistributionPointName | undefined,
	right: ParsedDistributionPointName | undefined,
): boolean {
	if (left === undefined || right === undefined) {
		return left === right;
	}
	if (left.fullName !== undefined || right.fullName !== undefined) {
		if (left.fullName === undefined || right.fullName === undefined) {
			return false;
		}
		return sameGeneralNameSet(left.fullName, right.fullName);
	}
	if (left.relativeName === undefined || right.relativeName === undefined) {
		return false;
	}
	return compareRelativeDistinguishedNames(left.relativeName, right.relativeName);
}

function sameGeneralNameSet(left: readonly GeneralName[], right: readonly GeneralName[]): boolean {
	if (left.length !== right.length) {
		return false;
	}
	const matched = new Array(right.length).fill(false);
	for (const leftName of left) {
		let found = false;
		for (let index = 0; index < right.length; index += 1) {
			const rightName = right[index];
			if (rightName === undefined || matched[index]) {
				continue;
			}
			if (!compareGeneralNames(leftName, rightName)) {
				continue;
			}
			matched[index] = true;
			found = true;
			break;
		}
		if (!found) {
			return false;
		}
	}
	return true;
}

function sameReasonSet(
	left: readonly DistributionPointReason[] | undefined,
	right: readonly DistributionPointReason[] | undefined,
): boolean {
	if (left === undefined || right === undefined) {
		return left === right;
	}
	if (left.length !== right.length) {
		return false;
	}
	return left.every((reason) => right.includes(reason));
}

function hasOverlappingReasons(
	certificateReasons: readonly DistributionPointReason[] | undefined,
	crlReasons: readonly DistributionPointReason[] | undefined,
): boolean {
	if (certificateReasons === undefined || crlReasons === undefined) {
		return true;
	}
	return certificateReasons.some((reason) => crlReasons.includes(reason));
}

function compareGeneralNames(left: GeneralName, right: GeneralName): boolean {
	if (left.type === 'dns' && right.type === 'dns') {
		return left.value === right.value;
	}
	if (left.type === 'email' && right.type === 'email') {
		return left.value === right.value;
	}
	if (left.type === 'ip' && right.type === 'ip') {
		return left.value === right.value;
	}
	if (left.type === 'uri' && right.type === 'uri') {
		return left.value === right.value;
	}
	if (left.type === 'directoryName' && right.type === 'directoryName') {
		return normalizeHex(left.derHex) === normalizeHex(right.derHex);
	}
	if (left.type === 'unknown' && right.type === 'unknown') {
		return left.tag === right.tag && bytesEqual(left.value, right.value);
	}
	return false;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
	if (left.length !== right.length) {
		return false;
	}
	for (let index = 0; index < left.length; index += 1) {
		if (left[index] !== right[index]) {
			return false;
		}
	}
	return true;
}

function compareRelativeDistinguishedNames(
	left: ParsedRelativeDistinguishedName,
	right: ParsedRelativeDistinguishedName,
): boolean {
	if (left.attributes.length !== right.attributes.length) {
		return false;
	}
	const matched = new Array(right.attributes.length).fill(false);
	for (const leftAttribute of left.attributes) {
		let found = false;
		for (let index = 0; index < right.attributes.length; index += 1) {
			const rightAttribute = right.attributes[index];
			if (rightAttribute === undefined || matched[index]) {
				continue;
			}
			if (!compareNameAttributeValue(leftAttribute, rightAttribute)) {
				continue;
			}
			matched[index] = true;
			found = true;
			break;
		}
		if (!found) {
			return false;
		}
	}
	return true;
}

function compareNameAttributeValue(left: ParsedNameAttribute, right: ParsedNameAttribute): boolean {
	if (left.oid !== right.oid) {
		return false;
	}
	if (isDirectoryStringTag(left.valueTag) && isDirectoryStringTag(right.valueTag)) {
		const preparedLeft = prepareNameCompareString(left.value);
		const preparedRight = prepareNameCompareString(right.value);
		if (preparedLeft === undefined || preparedRight === undefined) {
			return false;
		}
		return preparedLeft === preparedRight;
	}
	return left.valueTag === right.valueTag && left.value === right.value;
}

function isDirectoryStringTag(tag: number): boolean {
	return tag === 0x0c || tag === 0x13;
}

function prepareNameCompareString(value: string): string | undefined {
	const normalized = value.normalize('NFKC');
	if (/[^\P{Cc}\t\n\r]/u.test(normalized)) {
		return undefined;
	}
	return normalized.toLowerCase().trim().replace(/\s+/gu, ' ');
}

async function buildCrlExtensions(
	issuerPublicKey: CryptoKey | undefined,
	crlNumber: number | undefined,
	baseCrlNumber?: number,
	issuingDistributionPoint?: IssuingDistributionPoint,
	freshestCrlDistributionPoints?: readonly DistributionPoint[],
): Promise<Uint8Array[]> {
	const extensions: Uint8Array[] = [];
	if (issuerPublicKey !== undefined) {
		const spki = await exportSpkiDer(issuerPublicKey);
		extensions.push(
			encodeExtension(
				OIDS.authorityKeyIdentifier,
				sequence([implicitPrimitiveContext(0, buildSubjectKeyIdentifier(spki))]),
			),
		);
	}
	if (crlNumber !== undefined) {
		extensions.push(encodeExtension(OIDS.cRLNumber, integerFromNumber(crlNumber)));
	}
	if (baseCrlNumber !== undefined) {
		extensions.push(
			encodeExtension(OIDS.deltaCRLIndicator, integerFromNumber(baseCrlNumber), true),
		);
	}
	if (issuingDistributionPoint !== undefined) {
		extensions.push(
			encodeExtension(
				OIDS.issuingDistributionPoint,
				encodeIssuingDistributionPoint(issuingDistributionPoint),
				true,
			),
		);
	}
	if (freshestCrlDistributionPoints !== undefined && freshestCrlDistributionPoints.length > 0) {
		extensions.push(
			encodeExtension(OIDS.freshestCRL, encodeCrlDistributionPoints(freshestCrlDistributionPoints)),
		);
	}
	return extensions;
}

function createRevokedCertificate(entry: RevokedCertificateInput, thisUpdate: Date): Uint8Array {
	const extensions = buildRevokedCertificateExtensions(entry);
	return sequence([
		integer(entry.serialNumber),
		time(entry.revocationDate ?? thisUpdate),
		...(extensions.length === 0 ? [] : [sequence(extensions)]),
	]);
}

function buildRevokedCertificateExtensions(entry: RevokedCertificateInput): Uint8Array[] {
	const extensions: Uint8Array[] = [];
	if (entry.reasonCode !== undefined) {
		extensions.push(
			encodeExtension(
				OIDS.cRLReason,
				tlv(0x0a, Uint8Array.of(REVOCATION_REASON_CODES[entry.reasonCode])),
			),
		);
	}
	if (entry.invalidityDate !== undefined) {
		extensions.push(encodeExtension(OIDS.invalidityDate, generalizedTime(entry.invalidityDate)));
	}
	return extensions;
}

function parseRevokedCertificateExtensions(
	entryDer: Uint8Array | undefined,
	element: DerElement | undefined,
): {
	readonly reasonCode?: RevocationReason;
	readonly invalidityDate?: Date;
	readonly certificateIssuer?: readonly GeneralName[];
} {
	if (entryDer === undefined || element === undefined) {
		return {};
	}
	let reasonCode: RevocationReason | undefined;
	let invalidityDate: Date | undefined;
	let certificateIssuer: readonly GeneralName[] | undefined;
	for (const extension of childrenOf(entryDer, element)) {
		const parts = childrenOf(entryDer, extension);
		const oid = decodeObjectIdentifier(
			requireElement(parts[0], 'revoked certificate extension OID').value,
		);
		const valueElement = requireElement(
			parts[parts.length - 1],
			'revoked certificate extension value',
		);
		if (oid === OIDS.cRLReason) {
			reasonCode = revocationReasonFromCode(readElement(valueElement.value).value[0]);
		}
		if (oid === OIDS.invalidityDate) {
			invalidityDate = parseTime(readElement(valueElement.value));
		}
		if (oid === OIDS.certificateIssuer) {
			certificateIssuer = childrenOf(
				valueElement.value,
				readRootElement(valueElement.value, { maxDepth: DEFAULT_MAX_DER_DEPTH }),
			).map((name) => parseGeneralName(name));
		}
	}
	return {
		...(reasonCode === undefined ? {} : { reasonCode }),
		...(invalidityDate === undefined ? {} : { invalidityDate }),
		...(certificateIssuer === undefined ? {} : { certificateIssuer }),
	};
}

function parseIssuingDistributionPoint(valueDer: Uint8Array): ParsedIssuingDistributionPoint {
	const sequenceElement = readRootElement(valueDer, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	let distributionPoint: ParsedDistributionPointName | undefined;
	let onlyContainsUserCerts: boolean | undefined;
	let onlyContainsCACerts: boolean | undefined;
	let onlySomeReasons: readonly DistributionPointReason[] | undefined;
	let indirectCrl: boolean | undefined;
	let onlyContainsAttributeCerts: boolean | undefined;
	for (const child of childrenOf(valueDer, sequenceElement)) {
		if (child.tag === 0xa0) {
			const parsedDistributionPoint = parseDistributionPointName(valueDer, child);
			if (parsedDistributionPoint !== undefined) {
				distributionPoint = parsedDistributionPoint;
			}
		} else if (child.tag === 0x81) {
			onlyContainsUserCerts = parseImplicitBoolean(child);
		} else if (child.tag === 0x82) {
			onlyContainsCACerts = parseImplicitBoolean(child);
		} else if (child.tag === 0x83) {
			onlySomeReasons = parseDistributionPointReasonFlagsContent(child.value);
		} else if (child.tag === 0x84) {
			indirectCrl = parseImplicitBoolean(child);
		} else if (child.tag === 0x85) {
			onlyContainsAttributeCerts = parseImplicitBoolean(child);
		}
	}
	return {
		...(distributionPoint === undefined ? {} : { distributionPoint }),
		...(onlyContainsUserCerts === undefined ? {} : { onlyContainsUserCerts }),
		...(onlyContainsCACerts === undefined ? {} : { onlyContainsCACerts }),
		...(onlySomeReasons === undefined ? {} : { onlySomeReasons }),
		...(indirectCrl === undefined ? {} : { indirectCrl }),
		...(onlyContainsAttributeCerts === undefined ? {} : { onlyContainsAttributeCerts }),
	};
}

function parseDistributionPoints(valueDer: Uint8Array): readonly ParsedDistributionPoint[] {
	const sequenceElement = readRootElement(valueDer, { maxDepth: DEFAULT_MAX_DER_DEPTH });
	return childrenOf(valueDer, sequenceElement).map((distributionPoint) =>
		parseDistributionPoint(valueDer, distributionPoint),
	);
}

function parseDistributionPointName(
	valueDer: Uint8Array,
	element: DerElement,
): ParsedDistributionPointName | undefined {
	const distributionPointName = requireElement(
		childrenOf(valueDer, element)[0],
		'distributionPointName',
	);
	if (distributionPointName.tag === 0xa0) {
		return {
			fullName: childrenOf(valueDer, distributionPointName).map((name) => parseGeneralName(name)),
		};
	}
	if (distributionPointName.tag === 0xa1) {
		const relativeName = parseRelativeName(valueDer, distributionPointName);
		return { relativeName };
	}
	return undefined;
}

function parseDistributionPoint(
	valueDer: Uint8Array,
	element: DerElement,
): ParsedDistributionPoint {
	let distributionPoint: ParsedDistributionPointName | undefined;
	let reasons: readonly DistributionPointReason[] | undefined;
	let crlIssuer: readonly GeneralName[] | undefined;
	for (const child of childrenOf(valueDer, element)) {
		if (child.tag === 0xa0) {
			const parsedDistributionPoint = parseDistributionPointName(valueDer, child);
			if (parsedDistributionPoint !== undefined) {
				distributionPoint = parsedDistributionPoint;
			}
		} else if (child.tag === 0x81) {
			reasons = parseDistributionPointReasonFlagsContent(child.value);
		} else if (child.tag === 0xa2) {
			crlIssuer = childrenOf(valueDer, child).map((name) => parseGeneralName(name));
		}
	}
	return {
		...(distributionPoint === undefined ? {} : { distributionPoint }),
		...(reasons === undefined ? {} : { reasons }),
		...(crlIssuer === undefined ? {} : { crlIssuer }),
	};
}

function parseGeneralName(element: DerElement): GeneralName {
	switch (element.tag) {
		case 0x81:
			return { type: 'email' as const, value: textDecoder.decode(element.value) };
		case 0x82:
			return { type: 'dns' as const, value: textDecoder.decode(element.value) };
		case 0x86:
			return { type: 'uri' as const, value: textDecoder.decode(element.value) };
		case 0x87:
			return { type: 'ip' as const, value: decodeIpAddress(element.value) };
		case 0xa4:
			return {
				type: 'directoryName' as const,
				derHex: toHex(rebuildDirectoryNameFromImplicit(element)),
			};
		default:
			return { type: 'unknown' as const, tag: element.tag, value: new Uint8Array(element.value) };
	}
}

function parseRelativeName(
	valueDer: Uint8Array,
	element: DerElement,
): ParsedRelativeDistinguishedName {
	const attributes: ParsedNameAttribute[] = [];
	const values: Partial<Record<NameFieldKey, string>> = {};
	for (const attributeSequence of childrenOf(valueDer, element)) {
		const parts = childrenOf(valueDer, attributeSequence);
		const oid = decodeObjectIdentifier(requireElement(parts[0], 'name OID').value);
		const valueElement = requireElement(parts[1], 'name value');
		const fieldKey = nameFieldKeyFromOid(oid);
		const fieldValue = decodeNameValue(valueElement);
		const attribute: ParsedNameAttribute =
			fieldKey === undefined
				? { oid, valueTag: valueElement.tag, value: fieldValue }
				: { oid, key: fieldKey, valueTag: valueElement.tag, value: fieldValue };
		attributes.push(attribute);
		if (fieldKey !== undefined && values[fieldKey] === undefined) {
			values[fieldKey] = fieldValue;
		}
	}
	return {
		derHex: toHex(valueDer.slice(element.start - element.headerLength, element.end)),
		attributes,
		values,
	};
}

function decodeNameValue(element: DerElement): string {
	return decodeString(element.tag, element.value);
}

function parseImplicitBoolean(element: DerElement): boolean {
	return (element.value[0] ?? 0) !== 0;
}

function encodeIssuingDistributionPoint(value: IssuingDistributionPoint): Uint8Array {
	const certificateScopeFlags = [
		value.onlyContainsUserCerts === true,
		value.onlyContainsCACerts === true,
		value.onlyContainsAttributeCerts === true,
	].filter(Boolean).length;
	if (certificateScopeFlags > 1) {
		throw new Error(
			'IssuingDistributionPoint can assert at most one of user, CA, or attribute cert scope',
		);
	}
	const fields: Uint8Array[] = [];
	if (value.distributionPoint !== undefined) {
		fields.push(
			implicitConstructedContext(0, encodeDistributionPointName(value.distributionPoint)),
		);
	}
	if (value.onlyContainsUserCerts) {
		fields.push(implicitPrimitiveContext(1, Uint8Array.of(0xff)));
	}
	if (value.onlyContainsCACerts) {
		fields.push(implicitPrimitiveContext(2, Uint8Array.of(0xff)));
	}
	if (value.onlySomeReasons !== undefined && value.onlySomeReasons.length > 0) {
		fields.push(
			implicitPrimitiveContext(3, encodeDistributionPointReasonFlagsContent(value.onlySomeReasons)),
		);
	}
	if (value.indirectCrl) {
		fields.push(implicitPrimitiveContext(4, Uint8Array.of(0xff)));
	}
	if (value.onlyContainsAttributeCerts) {
		fields.push(implicitPrimitiveContext(5, Uint8Array.of(0xff)));
	}
	return sequence(fields);
}

function encodeDistributionPointName(
	value: IssuingDistributionPoint['distributionPoint'],
): Uint8Array {
	if (value === undefined) {
		throw new Error('IssuingDistributionPoint distributionPoint is required');
	}
	if (value.fullName !== undefined && value.relativeName !== undefined) {
		throw new Error('DistributionPointName cannot contain both fullName and relativeName');
	}
	if (value.fullName !== undefined) {
		if (value.fullName.length === 0) {
			throw new Error('DistributionPointName fullName must not be empty');
		}
		return implicitConstructedContext(0, concatGeneralNames(value.fullName));
	}
	if (value.relativeName !== undefined) {
		const relativeName = encodeRelativeDistinguishedName(value.relativeName);
		const relativeNameElement = readElement(relativeName);
		return implicitConstructedContext(
			1,
			relativeName.slice(relativeNameElement.start, relativeNameElement.end),
		);
	}
	throw new Error('DistributionPointName must contain fullName or relativeName');
}

function concatGeneralNames(names: readonly GeneralName[]): Uint8Array {
	return concatBytes(names.map((name) => encodeSubjectAltName(name)));
}

function rebuildDirectoryNameFromImplicit(element: DerElement): Uint8Array {
	return tlv(0x30, element.value);
}

function encodeExtension(oid: string, value: Uint8Array, critical = false): Uint8Array {
	return sequence([objectIdentifier(oid), ...(critical ? [bool(true)] : []), octetString(value)]);
}

function buildSubjectKeyIdentifier(spki: Uint8Array): Uint8Array {
	const top = readSequenceChildren(spki);
	const keyBitString = top[1];
	if (keyBitString === undefined || keyBitString.tag !== 0x03) {
		throw new Error('SPKI missing subject public key bit string');
	}
	return sha1(keyBitString.value.slice(1));
}

function parseIssuer(
	source: Uint8Array,
	element: DerElement,
): { readonly derHex: string; readonly commonName?: string } {
	let commonName: string | undefined;
	for (const setElement of childrenOf(source, element)) {
		const attribute = requireElement(childrenOf(source, setElement)[0], 'issuer attribute');
		const parts = childrenOf(source, attribute);
		const oid = decodeObjectIdentifier(requireElement(parts[0], 'issuer attribute OID').value);
		if (oid === OIDS.commonName) {
			commonName = textDecoder.decode(requireElement(parts[1], 'issuer attribute value').value);
		}
	}
	return {
		derHex: toHex(source.slice(element.start - element.headerLength, element.end)),
		...(commonName === undefined ? {} : { commonName }),
	};
}

function parseAuthorityKeyIdentifier(bytes: Uint8Array): string | undefined {
	const sequenceElement = readRootElement(bytes, {
		maxDepth: DEFAULT_MAX_DER_DEPTH,
		allowOpaqueConstructedTags: [0xa1, 0xa2],
	});
	for (const child of childrenOf(bytes, sequenceElement)) {
		if (child.tag === 0x80) {
			return toHex(child.value);
		}
		if (child.tag === 0xa0) {
			const keyIdentifier = readRootElement(child.value, { maxDepth: DEFAULT_MAX_DER_DEPTH });
			if (keyIdentifier.tag === 0x04) {
				return toHex(keyIdentifier.value);
			}
		}
	}
	return undefined;
}

function parseAlgorithmIdentifier(
	source: Uint8Array,
	element: DerElement,
): { readonly oid: string } {
	const children = childrenOf(source, element);
	const oid = requireElement(children[0], 'algorithm OID');
	return { oid: decodeObjectIdentifier(oid.value) };
}

function normalizeHex(value: string): string {
	return value.replace(/^0+/, '').toLowerCase();
}

function revocationReasonFromCode(code: number | undefined): RevocationReason | undefined {
	switch (code) {
		case 0:
			return 'unspecified';
		case 1:
			return 'keyCompromise';
		case 2:
			return 'cACompromise';
		case 3:
			return 'affiliationChanged';
		case 4:
			return 'superseded';
		case 5:
			return 'cessationOfOperation';
		case 6:
			return 'certificateHold';
		case 8:
			return 'removeFromCRL';
		case 9:
			return 'privilegeWithdrawn';
		case 10:
			return 'aACompromise';
	}
	return undefined;
}

function parseIssuerCertificateDer(der: Uint8Array): ParsedCertificate {
	return parseCertificateDer(der);
}

function parseIssuerCertificatePem(pem: string): ParsedCertificate {
	return parseCertificatePem(pem);
}

function normalizeCrl(source: CrlSource): ParsedCertificateRevocationList {
	if (typeof source === 'string') {
		return parseCertificateRevocationListPem(source);
	}
	if (source instanceof Uint8Array) {
		return parseCertificateRevocationListDer(new Uint8Array(source));
	}
	return source;
}

function normalizeCrlCertificate(source: CrlCertificateSource): ParsedCertificate {
	if (typeof source === 'string') {
		return parseCertificatePem(source);
	}
	if (source instanceof Uint8Array) {
		return parseCertificateDer(new Uint8Array(source));
	}
	return source;
}

const textDecoder = new TextDecoder();
