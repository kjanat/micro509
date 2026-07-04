/**
 * PKCS container APIs: PFX/PKCS#12 and PKCS#7/CMS.
 *
 * Owns PFX archive creation and parsing, PKCS#7 certificate bags and SignedData,
 * and PKCS#12 MAC integrity helpers.
 *
 * @module
 */

// — pfx.ts ————————————————————————————————————————————
// Re-exports owned by pfx but sourced from internal (PBES2 encryption options)
export type {
	CreatePfxErrorCode,
	CreatePfxFailure,
	CreatePfxInput,
	CreatePfxResult,
	ParsedPfx,
	ParsedPfxAttribute,
	ParsedPfxBag,
	ParsedPfxBagAttributes,
	ParsePfxErrorCode,
	ParsePfxFailure,
	ParsePfxOptions,
	ParsePfxResult,
	PfxBagAttributesInput,
	PfxCertificateBagInput,
	PfxCertificateSource,
	PfxEncryptionOptions,
	PfxMaterial,
	PfxPrivateKeyBagInput,
	PfxPrivateKeySource,
} from './pfx.ts';
export { createPfx, parsePfxDer, parsePfxPem } from './pfx.ts';

// — pkcs7.ts ——————————————————————————————————————————
export type {
	CreatePkcs7CertBagErrorCode,
	CreatePkcs7CertBagFailure,
	CreatePkcs7CertBagResult,
	CreatePkcs7SignedDataErrorCode,
	CreatePkcs7SignedDataFailure,
	CreatePkcs7SignedDataInput,
	CreatePkcs7SignedDataResult,
	ParsedPkcs7SignedData,
	ParsedPkcs7SignerInfo,
	ParsePkcs7CertBagResult,
	ParsePkcs7ErrorCode,
	ParsePkcs7Failure,
	ParsePkcs7SignedDataResult,
	Pkcs7CertBagMaterial,
	Pkcs7CertificateSource,
	Pkcs7SignedDataMaterial,
	Pkcs7Signer,
	VerifyPkcs7SignedDataFailure,
	VerifyPkcs7SignedDataResult,
} from './pkcs7.ts';
export {
	createPkcs7CertBag,
	createPkcs7SignedData,
	parsePkcs7CertBagDer,
	parsePkcs7CertBagPem,
	parsePkcs7SignedDataDer,
	parsePkcs7SignedDataPem,
	verifyPkcs7SignedData,
} from './pkcs7.ts';

// — pkcs12-mac.ts —————————————————————————————————————
export type {
	ParsedPkcs12MacData,
	ParsePkcs12MacDataErrorCode,
	ParsePkcs12MacDataFailure,
	ParsePkcs12MacDataResult,
	Pkcs12MacOptions,
} from './pkcs12-mac.ts';
export {
	createPkcs12MacData,
	parsePkcs12MacData,
	parsePkcs12MacDataOrThrow,
} from './pkcs12-mac.ts';
