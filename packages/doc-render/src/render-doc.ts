/**
 * Renderer: deno-doc node graph -> cross-linked markdown.
 *
 * Runtime-agnostic and side-effect-free — no I/O, no data fetching, and no
 * knowledge of the project being documented. Everything project-shaped (the
 * package name in headings, the URL space the pages are served under, how a
 * module URL becomes a page slug) is a `RenderOptions` field, so the same
 * renderer serves any deno-doc graph.
 *
 * Types come from `@deno/doc` (installed as `npm:@jsr/deno__doc`), imported
 * type-only so they resolve under tsgo/bun/deno and erase at runtime. The one
 * place its types diverge from the wasm's actual output is the module doc field:
 * declared `moduleDoc`, emitted `module_doc`. `ApiModule` bridges that.
 *
 * Coverage: the `TsTypeDef` grammar a typical public surface uses (every
 * unhandled node falls back to its `.repr` source-text — never wrong, only
 * un-linked), plus `function`, `typeAlias`, `interface` and `variable`
 * declarations and the JSDoc tags they carry. Still to add for fuller coverage:
 * `class`/`enum` declarations and overload sets (`declarations[1..]`).
 *
 * @module
 */

import type {
	Document,
	JsDoc,
	JsDocTag,
	ParamDef,
	Symbol,
	TsTypeDef,
	TsTypeParamDef,
} from '@deno/doc';

/** `doc()`/`deno doc --json` emit `module_doc`; @deno/doc's types call it
 * `moduleDoc`. Bridge that single divergence — everything else is faithfully
 * typed, so `Record<string, Document>` is assignable with no cast. */
export type ApiModule = Document & { readonly module_doc?: JsDoc };

/** How the rendered markdown addresses the project it documents. */
export interface RenderOptions {
	/** Package name shown in headings and module titles, e.g. `micro509/x509`. */
	readonly packageName: string;
	/** URL space the module pages are served under. Default `/api/`. */
	readonly apiBase?: string;
	/**
	 * Module URL -> page slug. Default: the path between `/src/` and a trailing
	 * `/index.ts`, which is the shape a `src/<module>/index.ts` layout produces.
	 */
	readonly slugOf?: (url: string) => string;
}

/** Resolved options — defaults applied once per render pass. */
interface Renderer {
	readonly packageName: string;
	readonly apiBase: string;
	readonly slugOf: (url: string) => string;
}

function defaultSlug(url: string): string {
	return url.replace(/^.*\/src\//, '').replace(/\/index\.ts$/, '');
}

function resolve(options: RenderOptions): Renderer {
	return {
		packageName: options.packageName,
		apiBase: options.apiBase ?? '/api/',
		slugOf: options.slugOf ?? defaultSlug,
	};
}

/** The `exports` map of a jsr.json / deno.json — the only field entrypoints need. */
export interface ExportsManifest {
	readonly exports: Readonly<Record<string, string>>;
}

/**
 * Public entrypoints = the manifest's `exports`, pointing at source files.
 * The `.` barrel is skipped: it re-exports the other subpaths and would
 * duplicate every symbol.
 *
 * Taken as a parameter rather than read from disk, so a past release's
 * entrypoints can be resolved from that release's manifest.
 */
export function entrypointsOf(manifest: ExportsManifest): readonly string[] {
	return Object.entries(manifest.exports)
		.filter(([subpath]) => subpath !== '.')
		.map(([, source]) => source.replace(/^\.\//, ''))
		.sort();
}

/** Where a symbol lives: which module page, under which anchor bucket. */
interface SymbolSite {
	/** Module page slug, e.g. `x509` for `/api/x509`. */
	readonly pkg: string;
	/** Anchor namespace for the declaration kind. */
	readonly bucket: string;
}

/** link registry: symbol name -> its module page + anchor. Populated per render pass. */
const symbolIndex = new Map<string, SymbolSite>();

/** Options of the pass in flight; set by `registerSymbols`, read by the link helpers. */
let renderer: Renderer = resolve({ packageName: '' });

/** Bucket per declaration kind. It namespaces the heading anchor so that
 * `Type`/`factory` pairs (ErrorResult vs errorResult) don't collide once anchors
 * are lowercased: `#fn-errorresult` vs `#type-errorresult`. */
function bucketOf(kind: string): string {
	if (kind === 'function') return 'fn';
	if (kind === 'variable') return 'var';
	return 'type';
}

/**
 * The heading anchor a symbol renders under, e.g. `fn-parsecertificate`.
 *
 * Lowercase, because VitePress lowercases the hash of every internal link it
 * rewrites while leaving an explicit `{#id}` anchor's case alone — a mixed-case
 * anchor produces a link that matches no element. The bucket prefix (not the
 * casing) is what keeps `errorResult` and `ErrorResult` apart.
 */
function symbolAnchor(name: string, bucket: string): string {
	return `${bucket}-${name}`.toLowerCase();
}

function parameterAnchorSegment(value: string): string {
	const hex = Array.from(new TextEncoder().encode(value), (byte) =>
		byte.toString(16).padStart(2, '0'),
	).join('');
	return `x${hex}`;
}

function parameterAnchor(pkg: string, symbolName: string, parameterName: string): string {
	return `fn-${parameterAnchorSegment(pkg)}-${parameterAnchorSegment(symbolName)}-param-${parameterAnchorSegment(parameterName)}`;
}

/**
 * Deep-link target for a symbol: its section on the owning module page.
 *
 * Symbols are documented in full on the module page, so a link points at that
 * section rather than at a standalone page — a page per symbol would duplicate
 * the content, and cost the consumer a build artifact (or three) each.
 */
function symbolUrl(name: string): string {
	const site = symbolIndex.get(name);
	if (site === undefined) return `${renderer.apiBase}#${name}`;
	return `${renderer.apiBase}${site.pkg}#${symbolAnchor(name, site.bucket)}`;
}

function link(name: string): string {
	if (symbolIndex.has(name)) return `[\`${name}\`](${symbolUrl(name)})`;
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
	name: string | undefined;
	optional: boolean;
	tsType: TsTypeDef | undefined;
} {
	if (p.kind === 'assign' || p.kind === 'rest') {
		const nested = paramInfo(p.kind === 'assign' ? p.left : p.arg);
		return { ...nested, tsType: p.tsType ?? nested.tsType };
	}
	return {
		name: 'name' in p ? p.name : undefined,
		optional: 'optional' in p && p.optional === true,
		tsType: 'tsType' in p ? p.tsType : undefined,
	};
}

interface InlineLinkContext {
	readonly parameters: ReadonlyMap<string, string>;
}

function functionLinkContext(
	pkg: string,
	symbolName: string,
	params: readonly ParamDef[],
): InlineLinkContext {
	const parameters = new Map<string, string>();
	for (const param of params) {
		const { name } = paramInfo(param);
		if (name === undefined) continue;
		const anchor = parameterAnchor(pkg, symbolName, name);
		parameters.set(name, `#${anchor}`);
	}
	return { parameters };
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
					return `\`${name ?? '_'}\`: ${renderType(tsType)}`;
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
function renderInlineLink(
	code: boolean,
	target: string,
	label?: string,
	context?: InlineLinkContext,
): string {
	const text = label ?? target.replace(/^\[|\]$/g, '');
	const shown = code ? `\`${text}\`` : text;
	if (/^https?:\/\//.test(target)) return `[${shown}](${target})`;
	if (target.startsWith('[')) return shown; // module ref — no page anchor in flat output yet
	const localName = target.split(/[.[]/, 1)[0];
	const localUrl = localName === undefined ? undefined : context?.parameters.get(localName);
	if (localUrl !== undefined) return `[${shown}](${localUrl})`;
	const symbol = target.split('.')[0] ?? target;
	if (symbol && symbolIndex.has(symbol)) return `[${shown}](${symbolUrl(symbol)})`;
	return shown;
}

function resolveInlineLinks(text: string, context?: InlineLinkContext): string {
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
			return renderInlineLink(kind === 'linkcode', target, label, context);
		},
	);
}

/** Keep multi-line doc content inside a `- ` list item: indent continuation lines
 * so blank lines / hard breaks don't float the tail out of the list. */
function bulletBody(doc: string, context?: InlineLinkContext): string {
	return resolveInlineLinks(doc, context).replace(/\n/g, '\n  ');
}

/** Strip links/backticks/escapes back to plain source text — for ```ts fences,
 * where markdown doesn't render and `[x](#y)` / `\<` would appear literally. */
function plain(s: string): string {
	// The label and target classes exclude their own opening delimiter: with
	// `[^\]]*`, a run of `[` makes every start position rescan the rest of the
	// string (polynomial backtracking).
	return s
		.replace(/\[([^[\]]*)\]\(([^()]*)\)/g, '$1')
		.replace(/`/g, '')
		.replace(/\\([<>|[\]])/g, '$1');
}

function renderDescription(js: JsDoc | undefined, context?: InlineLinkContext): string {
	return js?.doc ? resolveInlineLinks(js.doc, context) : '';
}

/** Non-param tag blocks: returns, throws, see, examples, surfaced defaults. */
function renderTagBlocks(js: JsDoc | undefined, context?: InlineLinkContext): string {
	const tags = js?.tags ?? [];
	return [
		...renderReturnTags(tags, context),
		...renderThrowsTags(tags, context),
		...renderSeeTags(tags, context),
		...renderUnsupportedTags(tags, context),
		...renderExampleTags(tags),
	]
		.join('\n')
		.trimEnd();
}

function renderReturnTags(tags: readonly JsDocTag[], context?: InlineLinkContext): string[] {
	const out: string[] = [];
	for (const r of tagsOfKind(tags, 'return')) {
		if (r.doc) out.push(`**Returns** — ${resolveInlineLinks(r.doc, context)}`, '');
	}
	return out;
}

function renderThrowsTags(tags: readonly JsDocTag[], context?: InlineLinkContext): string[] {
	const throws = tagsOfKind(tags, 'throws');
	if (!throws.length) return [];
	const out = ['**Throws**'];
	for (const t of throws) {
		const ty = t.tsType ? `${renderType(t.tsType)} — ` : '';
		out.push(`- ${ty}${bulletBody(t.doc ?? '', context)}`);
	}
	return [...out, ''];
}

function renderSeeTags(tags: readonly JsDocTag[], context?: InlineLinkContext): string[] {
	const see = tagsByName(tags, 'see');
	if (!see.length) return [];
	return ['**See also**', ...see.map((s) => `- ${bulletBody(s.doc ?? '', context)}`), ''];
}

function renderUnsupportedTags(tags: readonly JsDocTag[], context?: InlineLinkContext): string[] {
	const out: string[] = [];
	for (const u of tagsOfKind(tags, 'unsupported')) {
		if (u.value) out.push(resolveInlineLinks(u.value, context), '');
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
function renderParams(
	pkg: string,
	symbolName: string,
	defParams: readonly ParamDef[],
	js: JsDoc | undefined,
	context: InlineLinkContext,
): string {
	if (!defParams.length) return '';
	const docs = new Map<string, string>();
	for (const tag of tagsOfKind(js?.tags ?? [], 'param')) docs.set(tag.name, tag.doc ?? '');

	const lines = ['**Parameters**'];
	for (const p of defParams) {
		const { name, optional, tsType } = paramInfo(p);
		const displayName = name ?? '_';
		const doc = docs.get(displayName);
		const label = `\`${displayName}${optional ? '?' : ''}\``;
		const anchor =
			name === undefined ? '' : `<span id="${parameterAnchor(pkg, symbolName, name)}"></span>`;
		lines.push(
			`- ${anchor}${label}: ${renderType(tsType)}${doc ? ` — ${bulletBody(doc, context)}` : ''}`,
		);
	}
	return lines.join('\n');
}

type SymbolDeclaration = Symbol['declarations'][number];

/** Renders a function signature and its parameter documentation as Markdown. */
function renderFunctionSymbol(
	pkg: string,
	sym: Symbol,
	d: Extract<SymbolDeclaration, { readonly kind: 'function' }>,
	context: InlineLinkContext,
): string[] {
	const tp = plain(renderTypeParams(d.def.typeParams));
	const sigParams = d.def.params
		.map((p) => {
			const { name, optional, tsType } = paramInfo(p);
			return `\t${name ?? '_'}${optional ? '?' : ''}: ${plain(renderType(tsType))}`;
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
	const params = renderParams(pkg, sym.name, d.def.params, d.jsDoc, context);
	if (params) out.push(params, '');
	return out;
}

function renderTypeAliasSymbol(
	sym: Symbol,
	d: Extract<SymbolDeclaration, { readonly kind: 'typeAlias' }>,
): string[] {
	const tp = plain(renderTypeParams(d.def.typeParams));
	return ['```ts', `type ${sym.name}${tp} = ${plain(renderType(d.def.tsType))}`, '```', ''];
}

/** Renders an interface declaration, including an inline body for empty interfaces. */
function renderInterfaceSignature(
	sym: Symbol,
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
				return `${name ?? '_'}${optional ? '?' : ''}: ${plain(renderType(tsType))}`;
			})
			.join(', ');
		members.push(`\t${m.name}${m.optional ? '?' : ''}(${mp}): ${plain(renderType(m.returnType))};`);
	}
	const body = members.length ? ` {\n${members.join('\n')}\n}` : ' {}';
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
	sym: Symbol,
	d: Extract<SymbolDeclaration, { readonly kind: 'interface' }>,
): string[] {
	return [...renderInterfaceSignature(sym, d), ...renderInterfaceProperties(d)];
}

function renderVariableSymbol(
	sym: Symbol,
	d: Extract<SymbolDeclaration, { readonly kind: 'variable' }>,
): string[] {
	return ['```ts', `${d.def.kind} ${sym.name}: ${plain(renderType(d.def.tsType))}`, '```', ''];
}

function renderSymbol(pkg: string, sym: Symbol, level = 3): string {
	const d = sym.declarations[0];
	if (!d) return '';
	// Explicit `{#id}` anchor (VitePress custom-anchor syntax): the slugified
	// default folds case, which would collide `errorResult` with `ErrorResult`
	// and silently renumber one of them (`#errorresult-1`). `symbolUrl` links here.
	const site = symbolIndex.get(sym.name);
	const anchor = site === undefined ? undefined : symbolAnchor(sym.name, site.bucket);
	const heading = `${'#'.repeat(level)} \`${sym.name}\``;
	const out: string[] = [anchor === undefined ? heading : `${heading} {#${anchor}}`, ''];

	const context =
		d.kind === 'function' ? functionLinkContext(pkg, sym.name, d.def.params) : undefined;
	const description = renderDescription(d.jsDoc, context);
	if (description) out.push(description, '');

	if (d.kind === 'function') {
		out.push(
			...renderFunctionSymbol(pkg, sym, d, functionLinkContext(pkg, sym.name, d.def.params)),
		);
	} else if (d.kind === 'typeAlias') {
		out.push(...renderTypeAliasSymbol(sym, d));
	} else if (d.kind === 'interface') {
		out.push(...renderInterfaceSymbol(sym, d));
	} else if (d.kind === 'variable') {
		out.push(...renderVariableSymbol(sym, d));
	} else {
		out.push(`_(kind: ${d.kind} — renderer not yet extended)_`, '');
	}

	const tail = renderTagBlocks(d.jsDoc, context);
	if (tail) out.push(tail, '');
	return out.join('\n');
}

/**
 * Open a render pass: resolve the options and index every symbol's module page
 * and anchor, so `{@link}` and typeRef links can resolve while rendering.
 */
function beginPass(nodes: Record<string, ApiModule>, options: RenderOptions): void {
	renderer = resolve(options);
	symbolIndex.clear();
	for (const [url, mod] of Object.entries(nodes)) {
		const pkg = renderer.slugOf(url);
		for (const s of mod.symbols) {
			const kind = s.declarations[0]?.kind ?? 'type';
			symbolIndex.set(s.name, { pkg, bucket: bucketOf(kind) });
		}
	}
}

/**
 * Render a `{ url -> ApiModule }` node graph to a single markdown string.
 * With `filters` non-empty, only the named symbols are emitted — a flat dump for
 * previewing on stdout; the page emitters below are what a docs site consumes.
 */
export function renderDocuments(
	nodes: Record<string, ApiModule>,
	options: RenderOptions,
	filters: ReadonlySet<string> = new Set(),
): string {
	beginPass(nodes, options);
	const out: string[] = [];
	for (const [url, mod] of Object.entries(nodes)) {
		const symbols = filters.size ? mod.symbols.filter((s) => filters.has(s.name)) : mod.symbols;
		if (!symbols.length) continue;

		out.push(`## \`${renderer.packageName}/${renderer.slugOf(url)}\`\n`);
		const moduleDoc = renderModuleDoc(mod.module_doc);
		if (moduleDoc) out.push(`${moduleDoc}\n`);

		for (const sym of symbols) out.push(renderSymbol(renderer.slugOf(url), sym, 3), '\n---\n');
	}
	return out.join('\n');
}

export type ApiModulePage = { pkg: string; markdown: string };

/** Per-module reference pages (sidebar-visible). Symbols are `##` sections. */
export function renderModulePages(
	nodes: Record<string, ApiModule>,
	options: RenderOptions,
): {
	pages: ApiModulePage[];
	sidebar: { text: string; link: string }[];
} {
	beginPass(nodes, options);
	const pages: ApiModulePage[] = [];
	for (const [url, mod] of Object.entries(nodes)) {
		if (!mod.symbols.length) continue;
		const pkg = renderer.slugOf(url);
		const out = [`# \`${renderer.packageName}/${pkg}\``, ''];
		const moduleDoc = renderModuleDoc(mod.module_doc);
		if (moduleDoc) out.push(moduleDoc, '');
		for (const sym of mod.symbols) out.push(renderSymbol(pkg, sym, 2), '');
		pages.push({ pkg, markdown: out.join('\n') });
	}
	pages.sort((a, b) => a.pkg.localeCompare(b.pkg));
	return {
		pages,
		sidebar: pages.map((page) => ({
			text: page.pkg,
			link: `${renderer.apiBase}${page.pkg}`,
		})),
	};
}

/** The API landing page: every module with its one-line description. */
export function renderOverview(nodes: Record<string, ApiModule>, options: RenderOptions): string {
	beginPass(nodes, options);
	const out = [`# ${renderer.packageName} API Reference`, ''];
	for (const [url, mod] of Object.entries(nodes)) {
		if (!mod.symbols.length) continue;
		const pkg = renderer.slugOf(url);
		const desc = (mod.module_doc?.doc ?? '').split('\n')[0]?.trim();
		out.push(
			`- [\`${renderer.packageName}/${pkg}\`](${renderer.apiBase}${pkg})${desc ? ` — ${desc}` : ''}`,
		);
	}
	return out.join('\n');
}
