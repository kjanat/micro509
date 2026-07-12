#!/usr/bin/env bun
/**
 * Typechecks and lints every `<LiveCode>` example in the authored site pages,
 * so broken examples fail the build instead of failing in a visitor's browser.
 *
 * Each ` ```ts ` block inside a `<LiveCode>` tag is extracted into
 * `site/.vitepress/cache/livecode-check/` as a standalone module. The
 * generated project maps the bare `micro509` specifiers onto `src/`, so
 * examples typecheck against the exact sources they will run against once the
 * site co-hosts the built library — API drift in a snippet is a type error.
 *
 * Checks:
 * - `tsc --noEmit` over the generated project (strict, browser lib)
 * - `biome lint` over the generated files
 * - with `--run`, additionally executes every block under Bun with imports
 *   rewritten to `src/` and fails on any runtime error (slow: real keygen)
 *
 * @module
 */
import pkg from '#pkg' with { type: 'json' };
import { mkdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

const root = path.resolve(import.meta.dir, '..');
const outDir = path.join(root, 'site/.vitepress/cache/livecode-check');
const runMode = process.argv.includes('--run');

/** Authored site pages; `site/api/**` is generated from source jsdoc. */
const PAGE_GLOB = new Bun.Glob('site/**/*.md');
const EXCLUDED = [/^site\/api\//, /^site\/\.vitepress\//];

/** `<LiveCode ...>` wrapping a ts fence; captures the snippet source. */
const LIVECODE_BLOCK = /<LiveCode[^>]*>\s*\n\n```ts\n([\s\S]*?)```/g;

interface Snippet {
	/** Repo-relative markdown page the block came from. */
	readonly page: string;
	/** Zero-based block index within the page. */
	readonly index: number;
	/** Raw TypeScript source of the block. */
	readonly source: string;
	/** Generated file path for this block. */
	readonly file: string;
}

async function collectSnippets(): Promise<readonly Snippet[]> {
	const snippets: Snippet[] = [];
	for await (const page of PAGE_GLOB.scan({ cwd: root })) {
		if (EXCLUDED.some((pattern) => pattern.test(page))) continue;
		const text = await Bun.file(path.join(root, page)).text();
		const slug = page
			.replace(/^site\//, '')
			.replace(/\.md$/, '')
			.replaceAll('/', '__');
		let index = 0;
		for (const match of text.matchAll(LIVECODE_BLOCK)) {
			const source = match[1] ?? '';
			snippets.push({
				page,
				index,
				source,
				file: path.join(outDir, `${slug}-${index}.ts`),
			});
			index += 1;
		}
	}
	return snippets;
}

/** Emit one module per snippet plus a tsconfig mapping `micro509` onto src/. */
async function emitProject(snippets: readonly Snippet[]): Promise<void> {
	await rm(outDir, { recursive: true, force: true });
	await mkdir(outDir, { recursive: true });
	await Promise.all(
		snippets.map((snippet) =>
			writeFile(
				snippet.file,
				`// Generated from ${snippet.page} — do not edit.\n${snippet.source}`,
			),
		),
	);
	const tsconfig = {
		compilerOptions: {
			strict: true,
			noEmit: true,
			target: 'ESNext',
			module: 'ESNext',
			moduleResolution: 'bundler',
			// Examples run in the browser: DOM globals, no Bun/Node types.
			lib: ['ESNext', 'DOM', 'DOM.Iterable'],
			types: [],
			skipLibCheck: true,
			paths: {
				[pkg.name]: [path.join(root, 'src/index.ts')],
				[`${pkg.name}/*`]: [path.join(root, 'src/*/index.ts')],
			},
		},
		include: ['./*.ts'],
	};
	await writeFile(path.join(outDir, 'tsconfig.json'), JSON.stringify(tsconfig, null, '\t'));
}

/** Spawn a checked step, echoing output; returns success. */
function step(label: string, cmd: readonly string[]): boolean {
	const result = Bun.spawnSync([...cmd], { cwd: root, stdout: 'inherit', stderr: 'inherit' });
	const ok = result.exitCode === 0;
	console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}`);
	return ok;
}

/** Execute one snippet under Bun with `micro509` imports rewritten to src/. */
async function runSnippet(snippet: Snippet): Promise<boolean> {
	const runnable = snippet.source
		.replaceAll(`'${pkg.name}'`, `'${path.join(root, 'src/index.ts')}'`)
		.replaceAll(new RegExp(`'${pkg.name}/(\\w+)'`, 'g'), `'${path.join(root, 'src')}/$1/index.ts'`);
	const file = snippet.file.replace(/\.ts$/, '.run.ts');
	await writeFile(file, runnable);
	const result = Bun.spawnSync(['bun', file], { cwd: root, stdout: 'pipe', stderr: 'pipe' });
	const ok = result.exitCode === 0;
	console.log(`${ok ? 'ok  ' : 'FAIL'} run ${snippet.page}#${snippet.index}`);
	if (!ok) console.error(result.stderr.toString());
	return ok;
}

const snippets = await collectSnippets();
if (snippets.length === 0) {
	console.error('No <LiveCode> blocks found — extraction is broken, refusing to pass.');
	process.exit(1);
}
await emitProject(snippets);
console.log(
	`Checking ${snippets.length} LiveCode blocks from ${new Set(snippets.map((s) => s.page)).size} pages`,
);

let ok = step('tsc', ['bunx', 'tsc', '--noEmit', '-p', path.join(outDir, 'tsconfig.json')]);
ok = step('biome lint', ['bunx', 'biome', 'lint', '--vcs-use-ignore-file=false', outDir]) && ok;

if (runMode) {
	for (const snippet of snippets) {
		ok = (await runSnippet(snippet)) && ok;
	}
}

process.exit(ok ? 0 : 1);
