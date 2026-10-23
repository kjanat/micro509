/**
 * Canonical detached-signature crypto surface.
 * Owns raw sign/verify primitives and ECDSA signature encoding conversion.
 *
 * @module micro509/crypto
 */

export type {
	SignatureProfileInput,
	SignDataResult,
	VerifySignatureConfigFailure,
	VerifySignatureInput,
	VerifySignatureLimitFailure,
	VerifySignatureResult,
	VerifySignatureWithKeyInput,
	VerifySignedDataFailure,
	VerifySignedDataResult,
	VerifySignedDataSuccess,
} from '#micro509/crypto/crypto';
export {
	ecdsaSignatureDerToRaw,
	ecdsaSignatureRawToDer,
	signData,
	verifySignature,
	verifySignatureWithKey,
} from '#micro509/crypto/crypto';
