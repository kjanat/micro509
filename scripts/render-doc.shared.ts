/**
 * Shared renderer: deno-doc node graph -> cross-linked markdown.
 *
 * Runtime-agnostic and side-effect-free — no I/O, no data fetching. Both entry
 * scripts feed it the same node graph and print the result:
 *   - `render-doc.bun.ts` (bun) sources it from the `deno doc --json` CLI.
 *   - `render-doc.deno.ts` (deno) sources it from `@deno/doc`'s
 *     `doc()` API, which returns byte-identical nodes at runtime.
 *
 * Types come from `@deno/doc` (installed as `npm:@jsr/deno__doc`), imported
 * type-only so they resolve under tsgo/bun/deno and erase at runtime. The one
 * place its types diverge from the wasm's actual output is the module doc field:
 * declared `moduleDoc`, emitted `module_doc`. `ApiModule` bridges that.
 *
 * Coverage: the full `TsTypeDef` grammar micro509's public surface uses (every
 * unhandled node falls back to its `.repr` source-text — never wrong, only
 * un-linked), plus `function` and `typeAlias` declarations and all JSDoc tags
 * the codebase emits. Still to add for fuller API coverage:
 * `interface`/`class`/`variable`/`enum` declarations, overload sets
 * (`declarations[1..]`), and a vitepress-shaped sidebar emitter.
 *
 * @module
 */

import type {
	Symbol as DocSymbol,
	Document,
	JsDoc,
	JsDocTag,
	ParamDef,
	TsTypeDef,
	TsTypeParamDef,
} from '@deno/doc';

import jsr from '#jsr' with { type: 'json' };

/** `doc()`/`deno doc --json` emit `module_doc`; @deno/doc's types call it
 * `moduleDoc`. Bridge that single divergence — everything else is faithfully
 * typed, so `Record<string, Document>` is assignable with no cast. */
export type ApiModule = Document & { readonly module_doc?: JsDoc };

/** Public entrypoints = jsr.json's `exports` — tsdown's materialized entry list
 * (its `build:done` hook writes them from `entries`), pointing straight at the source `.ts` files.
 * Skip `.` (the root barrel re-exports the 7 packages and would duplicate every symbol). */
export const publicEntrypoints: readonly string[] = Object.entries(jsr.exports)
	.filter(([subpath]) => subpath !== '.')
	.map(([, source]) => source.replace(/^\.\//, ''))
	.sort();

/** link registry: symbol name -> its page bucket. Populated per render pass. */
const symbolBucket = new Map<string, string>();

/** Bucket per declaration kind. This namespaces per-symbol page URLs so that
 * `Type`/`factory` pairs (ErrorResult vs errorResult) and symbol-vs-module names
 * (Result vs the `result` module page) don't collide — VitePress folds route
 * paths case-insensitively, so distinct buckets are what keep them apart. */
function bucketOf(kind: string): string {
	if (kind === 'function') return 'fn';
	if (kind === 'variable') return 'var';
	return 'type';
}

/** Per-symbol page at `/api/<bucket>/<name>` (a `[bucket]/[symbol]` dynamic route).
 * The `<bucket>/` segment keeps `Type`/`factory` pairs (ErrorResult vs errorResult) and
 * symbol-vs-module names on case-insensitively-distinct URLs.
 * VitePress folds route paths case-insensitively. */
function symbolUrl(name: string): string {
	return `/api/${symbolBucket.get(name) ?? 'type'}/${name}`;
}

function link(name: string): string {
	if (symbolBucket.has(name)) return `[\`${name}\`](${symbolUrl(name)})`;
	return `\`${name}\``;
}

/** Narrow a tag list to one kind without a cast (filter doesn't narrow unions). */
function tagsOfKind<K extends JsDocTag['kind']>(
	tags: readonly JsDocTag[],
	kind: K,
): Extract<JsDocTag, { kind: K }>[] {
	return tags.filter((tag): tag is Extract<JsDocTag, { kind: K }> => tag.kind === kind);
}

/** @deno/doc's `JsDocTag` union omits `see`/`example` even though the wasm emits
 * them, so tagsOfKind can't reach them. Match by name and read `doc` defensively. */
function tagsByName(tags: readonly JsDocTag[], kind: string): { doc?: string }[] {
	return tags.filter((tag): tag is JsDocTag & { doc?: string } => String(tag.kind) === kind);
}

/** ParamDef is a union (identifier, rest, object pattern, ...); only some members
 * carry name/optional/tsType. Read them uniformly without a cast. */
function paramInfo(p: ParamDef): {
	name: string;
	optional: boolean;
	tsType: TsTypeDef | undefined;
} {
	return {
		name: 'name' in p ? p.name : '_',
		optional: 'optional' in p && p.optional === true,
		tsType: 'tsType' in p ? p.tsType : undefined,
	};
}

/* TsTypeDef -> markdown, recursive. Each case narrows on `kind`. */
function renderType(t: TsTypeDef | undefined): string {
	if (!t) return '`unknown`';
	switch (t.kind) {
		case 'keyword':
			return `\`${t.repr}\``;
		case 'literal':
			return `\`${t.repr}\``;
		case 'typeRef': {
			const v = t.value;
			const head = v.resolution?.kind === 'typeParam' ? `\`${v.typeName}\`` : link(v.typeName);
			if (!v.typeParams?.length) return head;
			return `${head}\\<${v.typeParams.map(renderType).join(', ')}>`;
		}
		case 'array':
			return `${renderType(t.value)}\`[]\``;
		case 'union':
			return t.value.map(renderType).join(' \\| ');
		case 'intersection':
			return t.value.map(renderType).join(' & ');
		case 'parenthesized':
			return `(${renderType(t.value)})`;
		case 'typeOperator':
			return `\`${t.value.operator}\` ${renderType(t.value.tsType)}`;
		case 'tuple':
			return `\\[${t.value.map(renderType).join(', ')}]`;
		case 'typeQuery':
			return `\`typeof\` ${link(t.value)}`;
		case 'indexedAccess':
			return `${renderType(t.value.objType)}\\[${renderType(t.value.indexType)}]`;
		case 'typeLiteral': {
			const props = t.value.properties ?? [];
			if (!props.length) return '`{}`';
			const body = props
				.map((p) => {
					const ro = p.readonly ? '`readonly` ' : '';
					const opt = p.optional ? '?' : '';
					return `  ${ro}\`${p.name}${opt}\`: ${renderType(p.tsType)}`;
				})
				.join(';\n');
			return `{\n${body}\n}`;
		}
		case 'fnOrConstructor': {
			const params = t.value.params
				.map((p) => {
					const { name, tsType } = paramInfo(p);
					return `\`${name}\`: ${renderType(tsType)}`;
				})
				.join(', ');
			return `(${params}) => ${renderType(t.value.tsType)}`;
		}
		default:
			// safety net: every node carries source-text in `repr`
			return `\`${t.repr}\``;
	}
}

/** One {@link}/{@linkcode}/{@linkplain}. Supports `target | label`, bare URLs,
 * `[module]`/`[module].symbol` module refs, and dotted symbol paths. `linkcode`
 * renders the visible text in monospace (per deno's inline-link semantics). */
function renderInlineLink(code: boolean, target: string, label?: string): string {
	const text = label ?? target.replace(/^\[|\]$/g, '');
	const shown = code ? `\`${text}\`` : text;
	if (/^https?:\/\//.test(target)) return `[${shown}](${target})`;
	if (target.startsWith('[')) return shown; // module ref — no page anchor in flat output yet
	const anchor = target.split('.')[0] ?? target;
	if (anchor && symbolBucket.has(anchor)) return `[${shown}](${symbolUrl(anchor)})`;
	return shown;
}

function resolveInlineLinks(text: string): string {
	return text.replace(
		/\{@(link|linkcode|linkplain)\s+([^}]+)\}/g,
		(_m, kind: string, inner: string) => {
			// Label is separated from the target by `|` (TSDoc) or whitespace (JSDoc).
			const trimmed = inner.trim();
			const bar = trimmed.indexOf('|');
			let target: string;
			let label: string | undefined;
			if (bar !== -1) {
				target = trimmed.slice(0, bar).trim();
				label = trimmed.slice(bar + 1).trim();
			} else {
				const sp = trimmed.search(/\s/);
				target = sp === -1 ? trimmed : trimmed.slice(0, sp);
				label = sp === -1 ? undefined : trimmed.slice(sp + 1).trim();
			}
			return renderInlineLink(kind === 'linkcode', target, label);
		},
	);
}

/** Keep multi-line doc content inside a `- ` list item: indent continuation lines
 * so blank lines / hard breaks don't float the tail out of the list. */
function bulletBody(doc: string): string {
	return resolveInlineLinks(doc).replace(/\n/g, '\n  ');
}

/** Strip links/backticks/escapes back to plain source text — for ```ts fences,
 * where markdown doesn't render and `[x](#y)` / `\<` would appear literally. */
function plain(s: string): string {
	return s
		.replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
		.replace(/`/g, '')
		.replace(/\\([<>|[\]])/g, '$1');
}

function renderDescription(js: JsDoc | undefined): string {
	return js?.doc ? resolveInlineLinks(js.doc) : '';
}

/** Non-param tag blocks: returns, throws, see, examples, surfaced defaults. */
function renderTagBlocks(js: JsDoc | undefined): string {
	const tags = js?.tags ?? [];
	return [
		...renderReturnTags(tags),
		...renderThrowsTags(tags),
		...renderSeeTags(tags),
		...renderUnsupportedTags(tags),
		...renderExampleTags(tags),
	]
		.join('\n')
		.trimEnd();
}

function renderReturnTags(tags: readonly JsDocTag[]): string[] {
	const out: string[] = [];
	for (const r of tagsOfKind(tags, 'return')) {
		if (r.doc) out.push(`**Returns** — ${resolveInlineLinks(r.doc)}`, '');
	}
	return out;
}

function renderThrowsTags(tags: readonly JsDocTag[]): string[] {
	const throws = tagsOfKind(tags, 'throws');
	if (!throws.length) return [];
	const out = ['**Throws**'];
	for (const t of throws) {
		const ty = t.tsType ? `${renderType(t.tsType)} — ` : '';
		out.push(`- ${ty}${bulletBody(t.doc ?? '')}`);
	}
	return [...out, ''];
}

function renderSeeTags(tags: readonly JsDocTag[]): string[] {
	const see = tagsByName(tags, 'see');
	if (!see.length) return [];
	return ['**See also**', ...see.map((s) => `- ${bulletBody(s.doc ?? '')}`), ''];
}

function renderUnsupportedTags(tags: readonly JsDocTag[]): string[] {
	const out: string[] = [];
	for (const u of tagsOfKind(tags, 'unsupported')) {
		if (u.value) out.push(resolveInlineLinks(u.value), '');
	}
	return out;
}

function renderExampleTags(tags: readonly JsDocTag[]): string[] {
	const examples = tagsByName(tags, 'example');
	if (!examples.length) return [];
	const out = ['**Examples**', ''];
	for (const e of examples) if (e.doc) out.push(e.doc.trimEnd(), '');
	return out;
}

/** module_doc: description + tag blocks, no params. */
function renderModuleDoc(js: JsDoc | undefined): string {
	return [renderDescription(js), renderTagBlocks(js)].filter(Boolean).join('\n\n');
}

function renderTypeParams(tps: readonly TsTypeParamDef[] | undefined): string {
	if (!tps?.length) return '';
	const inner = tps
		.map((tp) => (tp.constraint ? `${tp.name} extends ${renderType(tp.constraint)}` : tp.name))
		.join(', ');
	return `\\<${inner}>`;
}

/** Parameters list — links live here (not in the fenced signature), merging the declared param types with their @param docs. */
function renderParams(defParams: readonly ParamDef[], js: JsDoc | undefined): string {
	if (!defParams.length) return '';
	const docs = new Map<string, string>();
	for (const tag of tagsOfKind(js?.tags ?? [], 'param')) docs.set(tag.name, tag.doc ?? '');

	const lines = ['**Parameters**'];
	for (const p of defParams) {
		const { name, optional, tsType } = paramInfo(p);
		const doc = docs.get(name);
		const label = `\`${name}${optional ? '?' : ''}\``;
		lines.push(`- ${label}: ${renderType(tsType)}${doc ? ` — ${bulletBody(doc)}` : ''}`);
	}
	return lines.join('\n');
}

type SymbolDeclaration = DocSymbol['declarations'][number];

function renderFunctionSymbol(
	sym: DocSymbol,
	d: Extract<SymbolDeclaration, { readonly kind: 'function' }>,
): string[] {
	const tp = plain(renderTypeParams(d.def.typeParams));
	const sigParams = d.def.params
		.map((p) => {
			const { name, optional, tsType } = paramInfo(p);
			return `\t${name}${optional ? '?' : ''}: ${plain(renderType(tsType))}`;
		})
		.join(',\n');
	const head = `function ${sym.name}${tp}`;
	const ret = plain(renderType(d.def.returnType));
	const out = [
		'```ts',
		sigParams ? `${head}(\n${sigParams},\n): ${ret}` : `${head}(): ${ret}`,
		'```',
		'',
	];
	const params = renderParams(d.def.params, d.jsDoc);
	if (params) out.push(params, '');
	return out;
}

function renderTypeAliasSymbol(
	sym: DocSymbol,
	d: Extract<SymbolDeclaration, { readonly kind: 'typeAlias' }>,
): string[] {
	const tp = plain(renderTypeParams(d.def.typeParams));
	return ['```ts', `type ${sym.name}${tp} = ${plain(renderType(d.def.tsType))}`, '```', ''];
}

function renderInterfaceSignature(
	sym: DocSymbol,
	d: Extract<SymbolDeclaration, { readonly kind: 'interface' }>,
): string[] {
	const tp = plain(renderTypeParams(d.def.typeParams));
	const ext = d.def.extends?.length
		? ` extends ${d.def.extends.map((e) => plain(renderType(e))).join(', ')}`
		: '';
	const members: string[] = [];
	for (const p of d.def.properties ?? []) {
		const ro = p.readonly ? 'readonly ' : '';
		members.push(`\t${ro}${p.name}${p.optional ? '?' : ''}: ${plain(renderType(p.tsType))};`);
	}
	for (const m of d.def.methods ?? []) {
		const mp = m.params
			.map((p) => {
				const { name, optional, tsType } = paramInfo(p);
				return `${name}${optional ? '?' : ''}: ${plain(renderType(tsType))}`;
			})
			.join(', ');
		members.push(`\t${m.name}${m.optional ? '?' : ''}(${mp}): ${plain(renderType(m.returnType))};`);
	}
	const body = members.length ? ` {\n${members.join('\n')}\n}` : '';
	return ['```ts', `interface ${sym.name}${tp}${ext}${body}`, '```', ''];
}

function renderInterfaceProperties(
	d: Extract<SymbolDeclaration, { readonly kind: 'interface' }>,
): string[] {
	const props = d.def.properties ?? [];
	if (!props.length) return [];
	const lines = ['**Properties**'];
	for (const p of props) {
		const ro = p.readonly ? '`readonly` ' : '';
		const label = `\`${p.name}${p.optional ? '?' : ''}\``;
		const pdoc = p.jsDoc?.doc ? ` — ${bulletBody(p.jsDoc.doc)}` : '';
		lines.push(`- ${ro}${label}: ${renderType(p.tsType)}${pdoc}`);
	}
	return [lines.join('\n'), ''];
}

function renderInterfaceSymbol(
	sym: DocSymbol,
	d: Extract<SymbolDeclaration, { readonly kind: 'interface' }>,
): string[] {
	return [...renderInterfaceSignature(sym, d), ...renderInterfaceProperties(d)];
}

function renderVariableSymbol(
	sym: DocSymbol,
	d: Extract<SymbolDeclaration, { readonly kind: 'variable' }>,
): string[] {
	return ['```ts', `${d.def.kind} ${sym.name}: ${plain(renderType(d.def.tsType))}`, '```', ''];
}

function renderSymbol(sym: DocSymbol, level = 3): string {
	const d = sym.declarations[0];
	if (!d) return '';
	const out: string[] = [`${'#'.repeat(level)} \`${sym.name}\``, ''];

	const description = renderDescription(d.jsDoc);
	if (description) out.push(description, '');

	if (d.kind === 'function') {
		out.push(...renderFunctionSymbol(sym, d));
	} else if (d.kind === 'typeAlias') {
		out.push(...renderTypeAliasSymbol(sym, d));
	} else if (d.kind === 'interface') {
		out.push(...renderInterfaceSymbol(sym, d));
	} else if (d.kind === 'variable') {
		out.push(...renderVariableSymbol(sym, d));
	} else {
		out.push(`_(kind: ${d.kind} — renderer not yet extended)_`, '');
	}

	const tail = renderTagBlocks(d.jsDoc);
	if (tail) out.push(tail, '');
	return out.join('\n');
}

function pkgOf(url: string): string {
	return url.replace(/^.*\/src\//, '').replace(/\/index\.ts$/, '');
}

/** Register every symbol's page bucket so `{@link}`/typeRef links resolve. */
function registerSymbols(nodes: Record<string, ApiModule>): void {
	symbolBucket.clear();
	for (const mod of Object.values(nodes)) {
		for (const s of mod.symbols) {
			const kind = s.declarations[0]?.kind ?? 'type';
			symbolBucket.set(s.name, bucketOf(kind));
		}
	}
}

/**
 * Render a `{ url -> ApiModule }` node graph to a single markdown string.
 * With `filters` non-empty, only the named symbols are emitted. Used by the
 * stdout preview scripts; the site uses the page emitters below.
 */
export function renderDocuments(
	nodes: Record<string, ApiModule>,
	filters: ReadonlySet<string> = new Set(),
): string {
	registerSymbols(nodes);
	const out: string[] = [];
	for (const [url, mod] of Object.entries(nodes)) {
		const symbols = filters.size ? mod.symbols.filter((s) => filters.has(s.name)) : mod.symbols;
		if (!symbols.length) continue;

		out.push(`## \`micro509/${pkgOf(url)}\`\n`);
		const moduleDoc = renderModuleDoc(mod.module_doc);
		if (moduleDoc) out.push(`${moduleDoc}\n`);

		for (const sym of symbols) out.push(renderSymbol(sym, 3), '\n---\n');
	}
	return out.join('\n');
}

export type ApiModulePage = { pkg: string; markdown: string };

/** Per-module reference pages (sidebar-visible). Symbols are `##` sections. */
export function renderModulePages(nodes: Record<string, ApiModule>): {
	pages: ApiModulePage[];
	sidebar: { text: string; link: string }[];
} {
	registerSymbols(nodes);
	const pages: ApiModulePage[] = [];
	for (const [url, mod] of Object.entries(nodes)) {
		if (!mod.symbols.length) continue;
		const pkg = pkgOf(url);
		const out = [`# \`micro509/${pkg}\``, ''];
		const moduleDoc = renderModuleDoc(mod.module_doc);
		if (moduleDoc) out.push(moduleDoc, '');
		for (const sym of mod.symbols) out.push(renderSymbol(sym, 2), '');
		pages.push({ pkg, markdown: out.join('\n') });
	}
	pages.sort((a, b) => a.pkg.localeCompare(b.pkg));
	return { pages, sidebar: pages.map((p) => ({ text: p.pkg, link: `/api/${p.pkg}` })) };
}

export type ApiSymbolPage = { name: string; pkg: string; bucket: string; markdown: string };

/** Per-symbol pages — dynamic-route deep-link targets, not in the sidebar. */
export function renderSymbolPages(nodes: Record<string, ApiModule>): ApiSymbolPage[] {
	registerSymbols(nodes);
	const pages: ApiSymbolPage[] = [];
	for (const [url, mod] of Object.entries(nodes)) {
		const pkg = pkgOf(url);
		for (const sym of mod.symbols) {
			const bucket = symbolBucket.get(sym.name) ?? 'type';
			pages.push({ name: sym.name, pkg, bucket, markdown: renderSymbol(sym, 1) });
		}
	}
	return pages;
}

/** The single `/api/` landing page: modules with one-line descriptions. */
export function renderOverview(nodes: Record<string, ApiModule>): string {
	const out = ['# micro509 API Reference', ''];
	for (const [url, mod] of Object.entries(nodes)) {
		if (!mod.symbols.length) continue;
		const pkg = pkgOf(url);
		const desc = (mod.module_doc?.doc ?? '').split('\n')[0]?.trim();
		out.push(`- [\`micro509/${pkg}\`](/api/${pkg})${desc ? ` — ${desc}` : ''}`);
	}
	return out.join('\n');
}
