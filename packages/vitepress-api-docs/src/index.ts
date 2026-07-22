/**
 * VitePress plugin: an API reference generated from a source tree's jsdoc.
 *
 * Given a tree, the entrypoints to document and the name to document them under,
 * writes reference pages into `outDir`:
 *   - `<module>.md` per-module pages (sidebar-visible)
 *   - `index.md`    the overview landing page
 *
 * Every exported symbol is a `##` section on its module page, anchored so
 * `{@link}` references resolve to it. There are no per-symbol pages: they
 * duplicate the module page's content and cost the consuming site 3 build
 * artifacts each (html + 2 route chunks), which is what a site documenting many
 * versions at once cannot afford.
 *
 * Nothing about the host project is assumed — not its manifest filenames, not
 * where its sources live, not what it is called. The caller reads its own
 * manifests and passes the results; a release that shipped under a different
 * name is therefore documented under that name.
 *
 * The extractor (`deno doc`) runs as a subprocess, which is not a preference:
 * `@deno/doc`'s npm build loads its wasm through `Deno.readFile` and throws
 * "Loading local files are not supported in this environment" under both Node
 * and Bun (checked against 0.202.0). It is a Deno program, so it is run as one —
 * the `deno` binary is a declared dependency of this package.
 *
 * @module
 */

import proc from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import type { ApiModule, RenderOptions } from '@micro509/doc-render';
import { renderModulePages, renderOverview } from '@micro509/doc-render';
import type { Plugin } from 'vitepress';

/** One API reference: sources in, markdown pages out. */
export interface ApiDocsTarget {
	/** Tree the entrypoints are relative to; the extractor runs here. */
	readonly root: string;
	/** Directory the `.md` pages are written to; wiped first. */
	readonly outDir: string;
	/** What this tree is called — headings, and the extractor's `--name`. */
	readonly name: string;
	/** Source files to document, relative to `root`. */
	readonly entrypoints: readonly string[];
	/**
	 * Import map the extractor resolves the tree's specifiers with, relative to
	 * `root`. Omit when the sources need none. `importmapify`
	 * writes one from a package.json `imports` map.
	 */
	readonly importMap?: string | undefined;
	/** URL space the pages will be served under. Default `/api/`. */
	readonly apiBase?: string;
}

/** The shape `deno doc --json` promises: modules keyed by URL, each with symbols. */
function isModuleGraph(value: unknown): value is { readonly nodes: Record<string, ApiModule> } {
	if (typeof value !== 'object' || value === null || !('nodes' in value)) return false;
	const { nodes } = value;
	// An array is an object whose `every` is vacuously true: `nodes: []` would
	// pass, and document nothing, in a build that reported success.
	if (typeof nodes !== 'object' || nodes === null || Array.isArray(nodes)) return false;
	return Object.values(nodes).every(
		(module) =>
			typeof module === 'object' &&
			module !== null &&
			'symbols' in module &&
			Array.isArray(module.symbols),
	);
}

/** Extract the doc-node graph for a tree's entrypoints. */
function loadNodes(target: ApiDocsTarget): Record<string, ApiModule> {
	const importMap = target.importMap === undefined ? [] : ['--import-map', target.importMap];
	const nodes: Record<string, ApiModule> = {};
	for (const entrypoint of target.entrypoints) {
		const raw = proc.execFileSync(
			'deno',
			['doc', '--no-npm', ...importMap, '--json', `--name=${target.name}`, entrypoint],
			{ cwd: target.root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
		);

		const parsed: unknown = JSON.parse(raw);
		if (!isModuleGraph(parsed)) {
			throw new Error(
				`[api-docs] deno doc did not return a module graph for ${entrypoint} (${target.root})`,
			);
		}
		Object.assign(nodes, parsed.nodes);
	}
	return nodes;
}

/** A generated page states its own title, so a sidebar can read it off the page. */
function withTitle(title: string, markdown: string): string {
	// Quoted: a title carrying `:` or `#` is not a plain YAML scalar.
	return `---\ntitle: ${JSON.stringify(title)}\n---\n\n${markdown}\n`;
}

/** Regenerate one API reference from one source tree. */
export function generateApiDocs(target: ApiDocsTarget): void {
	const render: RenderOptions = { packageName: target.name, apiBase: target.apiBase ?? '/api/' };
	const nodes = loadNodes(target);
	const { pages } = renderModulePages(nodes, render);

	// Wipe first: a module dropped from the entrypoints would otherwise linger as
	// an orphan route — a page nobody links to, that crawlers still find.
	fs.rmSync(target.outDir, { recursive: true, force: true });
	fs.mkdirSync(target.outDir, { recursive: true });

	for (const page of pages) {
		fs.writeFileSync(
			path.join(target.outDir, `${page.pkg}.md`),
			withTitle(page.pkg === 'root' ? target.name : `${target.name}/${page.pkg}`, page.markdown),
		);
	}
	fs.writeFileSync(
		path.join(target.outDir, 'index.md'),
		withTitle('Overview', renderOverview(nodes, render)),
	);
}

/**
 * Dev-server half: re-run `regenerate` (debounced) when the watched sources
 * change, then reload the page.
 *
 * Takes the regeneration as a callback rather than a second copy of the target,
 * so the pages a `vitepress dev` serves are produced by exactly the call that
 * produced them at config load.
 */
export function apiDocsPlugin(options: {
	/** Directory whose `.ts` files trigger a regeneration. */
	readonly watchDir: string;
	readonly regenerate: () => void;
}): Plugin {
	let timer: ReturnType<typeof setTimeout> | undefined;

	// `startsWith` would also match a sibling: `src-other/x.ts` starts with `src`.
	const watched = (file: string): boolean => {
		const rel = path.relative(options.watchDir, file);
		return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
	};

	return {
		name: 'vitepress-api-docs',
		configureServer(server) {
			server.watcher.add(path.join(options.watchDir, '**/*.ts'));
			server.watcher.on('change', (file) => {
				if (!watched(file)) return;
				clearTimeout(timer);
				timer = setTimeout(() => {
					options.regenerate();
					server.ws.send({ type: 'full-reload' });
				}, 200);
			});
		},
	};
}
