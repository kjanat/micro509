import type {
	CreateCertificateInput,
	CreatePfxInput,
	Result,
	VerifyCertificateChainInput,
} from '#micro509';

// @ts-expect-error PKCS#12 MAC stays off the workflow-first root import.
type RootPkcs12MacData = import('#micro509').ParsedPkcs12MacData;

// @ts-expect-error Signature profile tuning stays owned by x509.
type RootSignatureProfileInput = import('#micro509').SignatureProfileInput;

function assertRootTypes(_input: {
	readonly certificate?: CreateCertificateInput;
	readonly pfx?: CreatePfxInput;
	readonly verify?: VerifyCertificateChainInput;
	readonly result?: Result<string, number>;
	readonly pkcs12?: RootPkcs12MacData;
	readonly signature?: RootSignatureProfileInput;
}): void {}

assertRootTypes({});
