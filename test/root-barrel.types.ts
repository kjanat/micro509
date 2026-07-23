import type {
	CreateCertificateErrorCode,
	CreateCertificateInput,
	CreatePfxInput,
	CrlEncoderErrorCode,
	ExtensionEncoderErrorCode,
	NameEncoderErrorCode,
	Result,
	VerifyCertificateChainInput,
} from '#micro509';
import type { SignatureProfileInput } from '#micro509/internal/crypto/signing';
import type { ParsedPkcs12MacData } from '#micro509/pkcs';

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
}): void {}

assertRootTypes({
	certificateError: 'validity_not_after_before_not_before',
	extensionError: 'key_usage_empty',
	nameError: 'invalid_country_code',
	crlError: 'distribution_point_name_conflict',
});
