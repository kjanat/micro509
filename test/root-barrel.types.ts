import type {
	CreateCertificateErrorCode,
	CreateCertificateInput,
	CreateOcspCertStatusInput,
	CreatePfxInput,
	CreateSelfSignedCertificateBase,
	CreateSelfSignedCertificateInput,
	CrlEncoderErrorCode,
	ExtensionEncoderErrorCode,
	KeyAlgorithmInput,
	KeyPairMaterial,
	NameEncoderErrorCode,
	ParsedIssuingDistributionPointScope,
	Result,
	VerifyCertificateChainInput,
} from '#micro509';
import type { SignatureProfileInput } from '#micro509/internal/crypto/signing';
import type { ParsedPkcs12MacData } from '#micro509/pkcs';

type Assert<Condition extends true> = Condition;
type IsAssignable<Source, Target> = [Source] extends [Target] ? true : false;
type IsNotAssignable<Source, Target> = [Source] extends [Target] ? false : true;

type RootPkcs12MacData = ParsedPkcs12MacData;
type RootSignatureProfileInput = SignatureProfileInput;

function assertRootTypes(_input: {
	readonly certificate?: CreateCertificateInput;
	readonly pfx?: CreatePfxInput;
	readonly verify?: VerifyCertificateChainInput;
	readonly result?: Result<string, number>;
	readonly pkcs12?: RootPkcs12MacData;
	readonly signature?: RootSignatureProfileInput;
	readonly certificateError?: CreateCertificateErrorCode;
	readonly extensionError?: ExtensionEncoderErrorCode;
	readonly nameError?: NameEncoderErrorCode;
	readonly crlError?: CrlEncoderErrorCode;
	readonly selfSignedExistingKeyPair?: Assert<
		IsAssignable<
			CreateSelfSignedCertificateBase & { readonly keyPair: KeyPairMaterial },
			CreateSelfSignedCertificateInput
		>
	>;
	readonly selfSignedGeneratedKeyPair?: Assert<
		IsAssignable<
			CreateSelfSignedCertificateBase & { readonly algorithm: KeyAlgorithmInput },
			CreateSelfSignedCertificateInput
		>
	>;
	readonly selfSignedRejectsBothKeySources?: Assert<
		IsNotAssignable<
			CreateSelfSignedCertificateBase & {
				readonly keyPair: KeyPairMaterial;
				readonly algorithm: KeyAlgorithmInput;
			},
			CreateSelfSignedCertificateInput
		>
	>;
	readonly issuingDistributionPointAcceptsOneScope?: Assert<
		IsAssignable<{ readonly onlyContainsUserCerts: true }, ParsedIssuingDistributionPointScope>
	>;
	readonly issuingDistributionPointRejectsConflictingScopes?: Assert<
		IsNotAssignable<
			{
				readonly onlyContainsUserCerts: true;
				readonly onlyContainsCACerts: true;
			},
			ParsedIssuingDistributionPointScope
		>
	>;
	readonly ocspAcceptsRevocationFieldsForRevoked?: Assert<
		IsAssignable<
			{
				readonly certStatus: 'revoked';
				readonly revokedAt: Date;
				readonly revocationReasonCode: number;
			},
			CreateOcspCertStatusInput
		>
	>;
	readonly ocspRejectsRevocationFieldsForGood?: Assert<
		IsNotAssignable<
			{
				readonly certStatus: 'good';
				readonly revokedAt: Date;
				readonly revocationReasonCode: number;
			},
			CreateOcspCertStatusInput
		>
	>;
	readonly ocspRejectsRevocationFieldsForUnknown?: Assert<
		IsNotAssignable<
			{
				readonly certStatus: 'unknown';
				readonly revokedAt: Date;
				readonly revocationReasonCode: number;
			},
			CreateOcspCertStatusInput
		>
	>;
}): void {}

assertRootTypes({
	certificateError: 'validity_not_after_before_not_before',
	extensionError: 'key_usage_empty',
	nameError: 'invalid_country_code',
	crlError: 'distribution_point_full_name_empty',
	selfSignedExistingKeyPair: true,
	selfSignedGeneratedKeyPair: true,
	selfSignedRejectsBothKeySources: true,
	issuingDistributionPointAcceptsOneScope: true,
	issuingDistributionPointRejectsConflictingScopes: true,
	ocspAcceptsRevocationFieldsForRevoked: true,
	ocspRejectsRevocationFieldsForGood: true,
	ocspRejectsRevocationFieldsForUnknown: true,
});
