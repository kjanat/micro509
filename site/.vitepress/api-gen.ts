/**
 * VitePress API docs generator + HMR plugin.
 *
 * Runs `deno doc --json` once, renders the shared markdown, and writes:
 *   - `site/api/<pkg>.md`          per-module reference pages (sidebar-visible)
 *   - `site/api/index.md`          API overview landing page
 *   - `site/api/<bucket>/<name>.md` one real page per exported symbol
 *     (fn/type/var buckets), unadvertised deep-link targets for `{@link}`
 *
 * Symbol pages are emitted as real `.md` files rather than a `[bucket]/[symbol]`
 * dynamic route: VitePress ships a content-stripped "lean" chunk for dynamic
 * routes and wipes the injected body on client hydration, so those pages render
 * blank after load. Real pages hydrate correctly.
 *
 * The plugin regenerates on any `src/**\/*.ts` change (debounced) and triggers a
 * reload — a fast doc refresh in `site:dev` without a full site restart.
 *
 * NOTE: shells `deno doc`, so the environment running the build needs `deno`
 * (and `bun` for the import map). Fine for local dev; production/CF builds must
 * provide deno or precompute the pages.
 */
import proc from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import type { Plugin } from 'vitepress';
import type { ApiModule } from '../../scripts/render-doc.shared.ts';
import {
	publicEntrypoints,
	renderModulePages,
	renderOverview,
	renderSymbolPages,
} from '../../scripts/render-doc.shared.ts';
const repoRoot = path.resolve(import.meta.dirname, '..', '..');
const apiDir = path.join(repoRoot, 'site/api');
const srcDir = path.join(repoRoot, 'src');

/** Directories under `site/api/` that hold generated per-symbol pages. */
const SYMBOL_BUCKETS = ['fn', 'type', 'var'] as const;

function loadNodes(): Record<string, ApiModule> {
	proc.execFileSync('bun', ['scripts/gen-deno-importmap.bun.ts'], { cwd: repoRoot });
	const raw = proc.execFileSync(
		'deno',
		[
			'doc',
			'--no-npm',
			'--import-map',
			'deno.import_map.json',
			'--json',
			'--name=micro509',
			...publicEntrypoints,
		],
		{ cwd: repoRoot, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
	);
	return (JSON.parse(raw) as { nodes: Record<string, ApiModule> }).nodes;
}

/** Full regeneration: module pages, overview, and one real page per symbol. */
export function generateApiDocs(): void {
	const nodes = loadNodes();
	const { pages } = renderModulePages(nodes);
	fs.mkdirSync(apiDir, { recursive: true });

	for (const p of pages) fs.writeFileSync(path.join(apiDir, `${p.pkg}.md`), `${p.markdown}\n`);
	fs.writeFileSync(path.join(apiDir, 'index.md'), `${renderOverview(nodes)}\n`);

	// Clear stale bucket dirs so removed symbols don't leave orphan pages, then
	// write each symbol as a real `site/api/<bucket>/<name>.md` page.
	for (const bucket of SYMBOL_BUCKETS)
		fs.rmSync(path.join(apiDir, bucket), { recursive: true, force: true });
	for (const s of renderSymbolPages(nodes)) {
		const dir = path.join(apiDir, s.bucket);
		fs.mkdirSync(dir, { recursive: true });
		fs.writeFileSync(path.join(dir, `${s.name}.md`), `${s.markdown}\n`);
	}
}

export function apiDocsPlugin(): Plugin {
	let timer: ReturnType<typeof setTimeout> | undefined;
	return {
		name: 'micro509:api-docs',
		configureServer(server) {
			server.watcher.add(path.join(srcDir, '**/*.ts'));
			server.watcher.on('change', (file) => {
				if (!file.startsWith(srcDir)) return;
				clearTimeout(timer);
				timer = setTimeout(() => {
					generateApiDocs();
					server.ws.send({ type: 'full-reload' });
				}, 200);
			});
		},
	};
}
