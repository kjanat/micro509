/**
 * Canonical revocation domain surface.
 * Owns CRL, OCSP, and revocation orchestration APIs.
 * @module
 */

export type * from './crl.ts';
export {
	checkCertificateRevocationAgainstCrl,
	createCertificateRevocationList,
	isCertificateRevoked,
	parseCertificateRevocationListDer,
	parseCertificateRevocationListPem,
	validateCertificateRevocationList,
	verifyCertificateRevocationList,
} from './crl.ts';

export type * from './ocsp.ts';
export {
	createOcspRequest,
	createOcspResponse,
	parseOcspRequestDer,
	parseOcspRequestPem,
	parseOcspResponseDer,
	parseOcspResponsePem,
	validateOcspResponse,
	verifyOcspResponse,
} from './ocsp.ts';

export type * from './revocation.ts';
export {
	checkCertificateRevocation,
	getCertificateOcspResponderUris,
	resolveOcspResponderCandidates,
} from './revocation.ts';
