/**
 * VitePress plugin: the runnable examples in the docs are code, so compile them.
 *
 * Every fenced block the `block` pattern matches is extracted into a standalone
 * module under `outDir`, given a tsconfig that maps the library's bare specifier
 * onto its sources, and put through `tsc` and `biome`. An example that no longer
 * compiles against the code it demonstrates is API drift, and it is caught here
 * rather than in a reader's browser.
 *
 * A failure fails `vitepress build`. It does not fail `vitepress dev`: an example
 * is broken for as long as it takes to write it, and a dev server that refuses to
 * render while you type is a dev server you turn off. Dev warns, and the build is
 * the gate.
 *
 * Which pages hold examples is an argument. This does not glob for them, so it
 * cannot drift out of step with what the site actually serves — a generated API
 * page or an archived version's page is not an authored example, and only the
 * caller knows which is which.
 *
 * @module
 */
import proc from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import type { Plugin } from 'vitepress';

export interface DocExamplesOptions {
	/** Directory the checks run from — where `tsc` and `biome` resolve config. */
	readonly root: string;
	/** Pages to extract examples from, absolute. */
	readonly pages: readonly string[];
	/** Where the extracted modules are written; wiped on each run. */
	readonly outDir: string;
	/** Captures one example's source in its first group. */
	readonly block: RegExp;
	/** Bare specifiers an example may import, mapped onto source files. */
	readonly paths: Readonly<Record<string, readonly string[]>>;
}

export interface Failure {
	readonly check: string;
	readonly output: string;
}

export interface ExamplesResult {
	readonly examples: number;
	readonly pages: number;
	readonly failures: readonly Failure[];
}

interface Example {
	readonly page: string;
	readonly index: number;
	readonly source: string;
	readonly file: string;
}

function extract(options: DocExamplesOptions): readonly Example[] {
	const examples: Example[] = [];
	for (const page of options.pages) {
		const text = fs.readFileSync(page, 'utf8');
		const slug = path.relative(options.root, page).replace(/\.md$/, '').replaceAll(/[/\\]/g, '__');
		let index = 0;
		for (const match of text.matchAll(options.block)) {
			examples.push({
				page,
				index,
				source: match[1] ?? '',
				file: path.join(options.outDir, `${slug}-${index}.ts`),
			});
			index += 1;
		}
	}
	return examples;
}

function emit(examples: readonly Example[], options: DocExamplesOptions): void {
	fs.rmSync(options.outDir, { recursive: true, force: true });
	fs.mkdirSync(options.outDir, { recursive: true });

	for (const example of examples) {
		const from = path.relative(options.root, example.page);
		fs.writeFileSync(example.file, `// Generated from ${from} — do not edit.\n${example.source}`);
	}

	const tsconfig = {
		compilerOptions: {
			strict: true,
			noEmit: true,
			target: 'ESNext',
			module: 'ESNext',
			moduleResolution: 'bundler',
			lib: ['ESNext', 'DOM', 'DOM.Iterable'],
			types: [],
			skipLibCheck: true,
			paths: options.paths,
		},
		include: ['./*.ts'],
	};
	fs.writeFileSync(
		path.join(options.outDir, 'tsconfig.json'),
		JSON.stringify(tsconfig, null, '\t'),
	);
}

function run(check: string, cmd: readonly string[], root: string): Failure | undefined {
	const result = proc.spawnSync(cmd[0] ?? '', cmd.slice(1), { cwd: root, encoding: 'utf8' });
	if (result.status === 0) return undefined;
	return { check, output: `${result.stdout ?? ''}${result.stderr ?? ''}`.trim() };
}

/**
 * Extract every example and check it. Never throws: the caller decides what a
 * failure means, which is the whole difference between the dev server and the build.
 */
export function checkDocExamples(options: DocExamplesOptions): ExamplesResult {
	const examples = extract(options);
	const pages = new Set(examples.map((example) => example.page)).size;

	if (examples.length === 0) {
		return {
			examples: 0,
			pages: 0,
			failures: [
				{ check: 'extract', output: 'No examples found — the block pattern matches nothing.' },
			],
		};
	}

	emit(examples, options);
	const failures = [
		run(
			'tsc',
			['bunx', 'tsc', '--noEmit', '-p', path.join(options.outDir, 'tsconfig.json')],
			options.root,
		),
		run(
			'biome',
			['bunx', '@biomejs/biome', 'lint', '--vcs-use-ignore-file=false', options.outDir],
			options.root,
		),
	].filter((failure) => failure !== undefined);

	return { examples: examples.length, pages, failures };
}

/** Fails `vitepress build`; warns, and keeps serving, under `vitepress dev`. */
export function docExamplesPlugin(options: DocExamplesOptions): Plugin {
	let isBuild = false;

	const check = (): ExamplesResult => {
		const result = checkDocExamples(options);
		const summary = `${result.examples} examples in ${result.pages} pages`;
		if (result.failures.length === 0) console.log(`[examples] ${summary}: ok`);
		return result;
	};

	const report = (result: ExamplesResult): string =>
		result.failures.map((failure) => `[examples] ${failure.check}\n${failure.output}`).join('\n\n');

	return {
		name: 'vitepress-doc-examples',
		configResolved(config) {
			isBuild = config.command === 'build';
		},
		buildStart() {
			if (!isBuild) return;
			const result = check();
			if (result.failures.length > 0) this.error(report(result));
		},
		configureServer(server) {
			const watched = new Set(options.pages);
			const recheck = (file: string): void => {
				if (!watched.has(file)) return;
				const result = check();
				if (result.failures.length > 0) server.config.logger.warn(report(result));
			};
			server.watcher.on('change', recheck);
			recheck([...watched][0] ?? '');
		},
	};
}
