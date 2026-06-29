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
	CreatePfxInput,
	ParsedPfx,
	ParsedPfxAttribute,
	ParsedPfxBag,
	ParsedPfxBagAttributes,
	ParsePfxErrorCode,
	ParsePfxFailure,
	ParsePfxOptions,
	ParsePfxResult,
	Pbes2EncryptionOptions,
	Pbes2EncryptionScheme,
	Pbes2Prf,
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
	CreatePkcs7SignedDataInput,
	ParsedPkcs7SignedData,
	ParsedPkcs7SignerInfo,
	ParsePkcs7CertBagResult,
	ParsePkcs7ErrorCode,
	ParsePkcs7Failure,
	ParsePkcs7SignedDataResult,
	Pkcs7CertBag,
	Pkcs7CertificateSource,
	Pkcs7SignedDataMaterial,
	Pkcs7Signer,
	VerifyPkcs7SignedDataFailure,
	VerifyPkcs7SignedDataResult,
} from './pkcs7.ts';
export {
	createPkcs7CertBagDer,
	createPkcs7CertBagPem,
	createPkcs7SignedDataDer,
	createPkcs7SignedDataPem,
	parsePkcs7CertBagDer,
	parsePkcs7CertBagPem,
	parsePkcs7SignedDataDer,
	parsePkcs7SignedDataPem,
	verifyPkcs7SignedData,
} from './pkcs7.ts';

// — pkcs12-mac.ts —————————————————————————————————————
export type { ParsedPkcs12MacData, Pkcs12MacOptions } from './pkcs12-mac.ts';
export { createPkcs12MacData, parsePkcs12MacData } from './pkcs12-mac.ts';
