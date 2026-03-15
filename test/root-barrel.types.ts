import type {
	CreateCertificateInput,
	CreatePfxInput,
	Result,
	VerifyCertificateChainInput,
} from 'micro509';
import type { ParsedPkcs12MacData } from 'micro509/pkcs';
import type { SignatureProfileInput } from '#micro509/internal/crypto/signing.ts';

type RootPkcs12MacData = ParsedPkcs12MacData;
type RootSignatureProfileInput = SignatureProfileInput;

function assertRootTypes(_input: {
	readonly certificate?: CreateCertificateInput;
	readonly pfx?: CreatePfxInput;
	readonly verify?: VerifyCertificateChainInput;
	readonly result?: Result<string, number>;
	readonly pkcs12?: RootPkcs12MacData;
	readonly signature?: RootSignatureProfileInput;
}): void {}

assertRootTypes({});
