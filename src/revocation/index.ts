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
	parseCertificateRevocationListDerOrThrow,
	parseCertificateRevocationListPem,
	parseCertificateRevocationListPemOrThrow,
	validateCertificateRevocationList,
	verifyCertificateRevocationListSignature,
} from './crl.ts';

export type * from './ocsp.ts';
export {
	createOcspRequest,
	createOcspResponse,
	hasOcspNoCheckExtension,
	parseOcspRequestDer,
	parseOcspRequestDerOrThrow,
	parseOcspRequestPem,
	parseOcspRequestPemOrThrow,
	parseOcspResponseDer,
	parseOcspResponseDerOrThrow,
	parseOcspResponsePem,
	parseOcspResponsePemOrThrow,
	validateOcspResponse,
	verifyOcspResponseSignature,
} from './ocsp.ts';

export type * from './revocation.ts';
export {
	checkCertificateRevocation,
	getCertificateOcspResponderUris,
	resolveOcspResponderCandidates,
} from './revocation.ts';

export type * from './chain.ts';
export { checkChainRevocation } from './chain.ts';
