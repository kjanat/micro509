import { existsSync, mkdirSync, mkdtempSync, renameSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { Out } from 'dreamcli';
import { arg, CLIError, cli, command } from 'dreamcli';
import { licenseLinks, provenance } from './spec/w3c.ts';

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

const PANDOC = { repository: 'jgm/pandoc', version: '3.11' } as const;

const PANDOC_ASSETS = new Map([
	['linux-x64', 'linux-amd64.tar.gz'],
	['linux-arm64', 'linux-arm64.tar.gz'],
	['darwin-arm64', 'arm64-macOS.zip'],
	['darwin-x64', 'x86_64-macOS.zip'],
	['win32-x64', 'windows-x86_64.zip'],
]);

const PANDOC_CACHE = path.join('node_modules', '.cache', 'pandoc', PANDOC.version);

const ITU_CONVERTER = path.join(import.meta.dir, 'spec', 'itu.lua');

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

function startsWith(bytes: Uint8Array, prefix: readonly number[]): boolean {
	return prefix.every((byte, index) => bytes[index] === byte);
}

async function retry(argv: readonly string[], code: string, out: Out): Promise<string> {
	let delay = 2;
	for (let attempt = 1; ; attempt += 1) {
		try {
			return await run(argv, undefined, code);
		} catch (error) {
			if (attempt === 4) throw error;
			const reason = error instanceof Error ? error.message : String(error);
			out.warn(
				`GitHub release request failed (${reason}); retrying in ${delay}s (attempt ${attempt + 1}/4)`,
			);
			await Bun.sleep(delay * 1000);
			delay *= 2;
		}
	}
}

function releaseOf(json: string): { readonly tag: string; readonly url: string } | undefined {
	const value: unknown = JSON.parse(json);
	if (typeof value !== 'object' || value === null) return undefined;
	const tag: unknown = Reflect.get(value, 'tagName');
	const url: unknown = Reflect.get(value, 'url');
	return typeof tag === 'string' && typeof url === 'string' ? { tag, url } : undefined;
}

function cachedPandoc(): string | undefined {
	if (!existsSync(PANDOC_CACHE)) return undefined;
	for (const pattern of ['*/bin/pandoc', '*/pandoc.exe']) {
		for (const binary of new Bun.Glob(pattern).scanSync({ cwd: PANDOC_CACHE })) {
			return path.join(PANDOC_CACHE, binary);
		}
	}
	return undefined;
}

async function pandoc(out: Out): Promise<string> {
	const cached = cachedPandoc();
	if (cached !== undefined) return cached;
	const suffix = PANDOC_ASSETS.get(`${process.platform}-${process.arch}`);
	if (suffix === undefined) {
		throw new CLIError(
			`no pandoc ${PANDOC.version} build for ${process.platform}-${process.arch}`,
			{
				code: 'PANDOC_UNSUPPORTED_PLATFORM',
			},
		);
	}
	const gh = tool(
		'gh',
		'PANDOC_GH_MISSING',
		'Install the GitHub CLI, which downloads and verifies pandoc',
	);
	const release = releaseOf(
		await retry(
			[gh, 'release', 'view', '--repo', PANDOC.repository, '--json', 'tagName,url'],
			'PANDOC_RELEASE_FAILED',
			out,
		),
	);
	if (release !== undefined && release.tag !== PANDOC.version) {
		out.warn(
			`pandoc ${PANDOC.version} is not the latest release ${release.tag}; see ${release.url}`,
		);
	}
	const asset = `pandoc-${PANDOC.version}-${suffix}`;
	const scratch = mkdtempSync(path.join(tmpdir(), 'pandoc-'));
	try {
		const archive = path.join(scratch, asset);
		out.status(`downloading ${PANDOC.repository} ${asset}`);
		await retry(
			[
				gh,
				'release',
				'download',
				PANDOC.version,
				'--repo',
				PANDOC.repository,
				'--pattern',
				asset,
				'--output',
				archive,
				'--clobber',
			],
			'PANDOC_DOWNLOAD_FAILED',
			out,
		);
		await retry(
			[gh, 'release', 'verify-asset', PANDOC.version, archive, '--repo', PANDOC.repository],
			'PANDOC_UNVERIFIED',
			out,
		);
		const staging = `${PANDOC_CACHE}.partial`;
		rmSync(staging, { recursive: true, force: true });
		mkdirSync(staging, { recursive: true });
		const extract = asset.endsWith('.zip')
			? [tool('unzip', 'PANDOC_UNZIP_MISSING', 'Install unzip'), '-q', archive, '-d', staging]
			: [tool('tar', 'PANDOC_TAR_MISSING', 'Install tar'), '-xzf', archive, '-C', staging];
		await run(extract, undefined, 'PANDOC_EXTRACT_FAILED');
		renameSync(staging, PANDOC_CACHE);
	} finally {
		rmSync(scratch, { recursive: true, force: true });
	}
	const installed = cachedPandoc();
	if (installed === undefined) {
		throw new CLIError(`${asset} holds no pandoc binary`, { code: 'PANDOC_EXTRACT_FAILED' });
	}
	return installed;
}

async function fetchItuItem(id: string, out: Out): Promise<Uint8Array | undefined> {
	const url = `https://www.itu.int/rec/dologin.asp?lang=e&id=${id}&type=items`;
	out.status(`fetching ${url}`);
	const response = await fetch(url);
	return response.ok ? await response.bytes() : undefined;
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
	.description('Vendor an ITU-T Recommendation as text, from its Word item when ITU publishes one')
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
		const wordId = args.id.replace(/!PDF-E$/, '!MSW-E');
		const directory = path.join('docs', 'itu', recommendation);
		mkdirSync(directory, { recursive: true });
		const scratch = mkdtempSync(path.join(tmpdir(), 'itu-'));
		try {
			const word = await fetchItuItem(wordId, out);
			if (word !== undefined && startsWith(word, [0x50, 0x4b, 0x03, 0x04])) {
				const docx = path.join(scratch, 'item.docx');
				await Bun.write(docx, word);
				const destination = path.join(directory, `${wordId}.txt`);
				await run(
					[await pandoc(out), 'lua', ITU_CONVERTER, docx, destination],
					undefined,
					'ITU_CONVERT_FAILED',
				);
				rmSync(path.join(directory, `${args.id}.txt`), { force: true });
				out.log(destination);
				return;
			}
			const pdftotext = tool(
				'pdftotext',
				'ITU_CONVERTER_MISSING',
				'Install poppler, which provides pdftotext',
			);
			const bytes = await fetchItuItem(args.id, out);
			if (bytes === undefined || !startsWith(bytes, [0x25, 0x50, 0x44, 0x46, 0x2d])) {
				throw new CLIError(`${args.id}: neither a Word document nor a PDF`, {
					code: 'ITU_FETCH_FAILED',
					suggest: `Find the item id on https://www.itu.int/rec/T-REC-${recommendation}`,
				});
			}
			const pdf = path.join(scratch, 'item.pdf');
			await Bun.write(pdf, bytes);
			const destination = path.join(directory, `${args.id}.txt`);
			await run(
				[pdftotext, '-layout', '-enc', 'UTF-8', pdf, destination],
				undefined,
				'ITU_CONVERT_FAILED',
			);
			rmSync(path.join(directory, `${wordId}.txt`), { force: true });
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
		const html = await response.bytes();
		const licenses = licenseLinks(new TextDecoder().decode(html), response.url);
		if (licenses.length === 0) {
			throw new CLIError(`${args.spec}: no license link found in ${spec.url}`, {
				code: 'W3C_LICENSE_MISSING',
				suggest: 'Vendor only text whose license the page links',
			});
		}
		const text = await run(
			[w3m, '-T', 'text/html', '-I', 'UTF-8', '-O', 'UTF-8', '-cols', '80', '-dump'],
			html,
			'W3C_CONVERT_FAILED',
		);
		const destination = `docs/w3c/${spec.file}`;
		await Bun.write(destination, `${text.trimEnd()}\n${provenance(spec.url, licenses)}`);
		out.log(destination);
	});

cli('fetch-spec')
	.description('Vendor standards text into docs/')
	.command(rfc)
	.command(itu)
	.command(w3c)
	.run();
