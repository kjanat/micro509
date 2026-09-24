import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { arg, CLIError, cli, command } from 'dreamcli';

const W3C_SPECS = {
	'webcrypto-editors-draft': {
		url: 'https://w3c.github.io/webcrypto/',
		file: 'WebCryptoAPI/w3c-webcrypto-editors-draft.txt',
	},
	'webcrypto-tr': {
		url: 'https://www.w3.org/TR/webcrypto-2/',
		file: 'WebCryptoAPI/W3C-TR-webcrypto-current.txt',
	},
	'webcrypto-rec-2017': {
		url: 'https://www.w3.org/TR/2017/REC-WebCryptoAPI-20170126/',
		file: 'WebCryptoAPI/W3C-REC-WebCryptoAPI-20170126.txt',
	},
	webidl: {
		url: 'https://webidl.spec.whatwg.org/',
		file: 'WebIDL/webidl.txt',
	},
} as const satisfies Record<string, { readonly url: string; readonly file: string }>;

const W3C_NAMES = [
	'webcrypto-editors-draft',
	'webcrypto-tr',
	'webcrypto-rec-2017',
	'webidl',
] as const satisfies readonly (keyof typeof W3C_SPECS)[];

const ITU_ITEM = /^T-REC-(X\.\d+)-\d{6}-[A-Z]!\w*!PDF-E$/;

function tool(name: string, code: string, suggest: string): string {
	const found = Bun.which(name);
	if (found === null) throw new CLIError(`${name} not found on PATH`, { code, suggest });
	return found;
}

async function run(
	argv: readonly string[],
	stdin: Uint8Array | undefined,
	code: string,
): Promise<string> {
	const child = Bun.spawn([...argv], { stdin: stdin ?? 'ignore', stdout: 'pipe', stderr: 'pipe' });
	const [output, errors, exitCode] = await Promise.all([
		new Response(child.stdout).text(),
		new Response(child.stderr).text(),
		child.exited,
	]);
	if (exitCode !== 0) {
		throw new CLIError(
			`${path.basename(argv[0] ?? '')} exited with ${exitCode}: ${errors.trim()}`,
			{
				code,
			},
		);
	}
	return output;
}

const rfc = command('rfc')
	.description('Refresh a vendored RFC text file from the RFC Editor')
	.arg('number', arg.number().int().min(1).env('RFC').describe('RFC number, e.g. 822'))
	.action(async ({ args, out }) => {
		const url = `https://www.rfc-editor.org/rfc/rfc${args.number}.txt`;
		out.status(`fetching ${url}`);
		const response = await fetch(url);
		if (!response.ok) {
			throw new CLIError(`rfc${args.number}: ${response.status} ${response.statusText}`, {
				code: 'RFC_FETCH_FAILED',
				suggest: 'Check the number against https://www.rfc-editor.org/',
			});
		}
		const destination = `docs/rfc/rfc${args.number}.txt`;
		await Bun.write(destination, await response.bytes());
		out.log(destination);
	});

const itu = command('itu')
	.description('Download an ITU-T Recommendation PDF and vendor it as layout text')
	.arg(
		'id',
		arg
			.string()
			.pattern(ITU_ITEM)
			.env('ITU')
			.describe('ITU item id, e.g. T-REC-X.509-201910-I!!PDF-E or T-REC-X.509-202110-I!Cor1!PDF-E'),
	)
	.action(async ({ args, out }) => {
		const recommendation = ITU_ITEM.exec(args.id)?.[1];
		if (recommendation === undefined) {
			throw new CLIError(`not an ITU item id: ${args.id}`, { code: 'ITU_ID_INVALID' });
		}
		const pdftotext = tool(
			'pdftotext',
			'ITU_CONVERTER_MISSING',
			'Install poppler, which provides pdftotext',
		);
		const url = `https://www.itu.int/rec/dologin.asp?lang=e&id=${args.id}&type=items`;
		out.status(`fetching ${url}`);
		const response = await fetch(url);
		const bytes = await response.bytes();
		if (!response.ok || new TextDecoder().decode(bytes.subarray(0, 5)) !== '%PDF-') {
			throw new CLIError(
				`${args.id}: ${response.status} ${response.headers.get('content-type') ?? ''}`,
				{
					code: 'ITU_FETCH_FAILED',
					suggest: `Find the item id on https://www.itu.int/rec/T-REC-${recommendation}`,
				},
			);
		}
		const scratch = mkdtempSync(path.join(tmpdir(), 'itu-'));
		try {
			const pdf = path.join(scratch, 'item.pdf');
			await Bun.write(pdf, bytes);
			const directory = path.join('docs', 'itu', recommendation);
			mkdirSync(directory, { recursive: true });
			const destination = path.join(directory, `${args.id}.txt`);
			await run(
				[pdftotext, '-layout', '-enc', 'UTF-8', pdf, destination],
				undefined,
				'ITU_CONVERT_FAILED',
			);
			out.log(destination);
		} finally {
			rmSync(scratch, { recursive: true, force: true });
		}
	});

const w3c = command('w3c')
	.description('Refresh a vendored W3C or WHATWG specification as plain text')
	.arg('spec', arg.enum(W3C_NAMES).env('W3C_SPEC').describe('Specification to fetch'))
	.action(async ({ args, out }) => {
		const spec = W3C_SPECS[args.spec];
		const w3m = tool('w3m', 'W3C_CONVERTER_MISSING', 'Install w3m, which renders the HTML to text');
		out.status(`fetching ${spec.url}`);
		const response = await fetch(spec.url);
		if (!response.ok) {
			throw new CLIError(`${args.spec}: ${response.status} ${response.statusText}`, {
				code: 'W3C_FETCH_FAILED',
				suggest: `Check ${spec.url}`,
			});
		}
		const text = await run(
			[w3m, '-T', 'text/html', '-I', 'UTF-8', '-O', 'UTF-8', '-cols', '80', '-dump'],
			await response.bytes(),
			'W3C_CONVERT_FAILED',
		);
		const destination = `docs/w3c/${spec.file}`;
		await Bun.write(destination, text);
		out.log(destination);
	});

cli('fetch-spec')
	.description('Vendor standards text into docs/')
	.command(rfc)
	.command(itu)
	.command(w3c)
	.run();
