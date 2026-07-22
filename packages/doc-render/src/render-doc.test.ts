import { describe, expect, it } from 'bun:test';
import type { ApiModule } from './render-doc.ts';
import { entrypointsOf, renderModulePages, renderOverview } from './render-doc.ts';

const location = {
	filename: 'file:///workspace/src/example/index.ts',
	line: 1,
	col: 0,
	byteIndex: 0,
};

const modules = {
	'file:///workspace/src/example/index.ts': {
		symbols: [
			{
				name: 'walk',
				declarations: [
					{
						location,
						declarationKind: 'export',
						kind: 'function',
						jsDoc: {
							doc: 'Uses {@linkcode options | allowOpaqueConstructedTags}, {@linkcode options.allowOpaqueConstructedTags}, {@linkcode $options}, {@linkcode café}, or {@linkcode _}. Related: {@linkcode walk}.',
							tags: [
								{
									kind: 'throws',
									doc: 'if nesting exceeds {@linkcode maxDepth}.',
								},
							],
						},
						def: {
							params: [
								{
									kind: 'assign',
									left: {
										kind: 'identifier',
										name: 'maxDepth',
										optional: false,
										tsType: { kind: 'keyword', repr: 'number', value: 'number' },
									},
									right: 'DEFAULT_MAX_DEPTH',
								},
								{
									kind: 'identifier',
									name: 'options',
									optional: true,
									tsType: { kind: 'keyword', repr: 'object', value: 'object' },
								},
								{
									kind: 'identifier',
									name: '$options',
									optional: false,
									tsType: { kind: 'keyword', repr: 'object', value: 'object' },
								},
								{
									kind: 'identifier',
									name: 'café',
									optional: false,
									tsType: { kind: 'keyword', repr: 'string', value: 'string' },
								},
								{
									kind: 'rest',
									arg: {
										kind: 'identifier',
										name: 'args',
										optional: false,
									},
									tsType: {
										kind: 'array',
										value: { kind: 'keyword', repr: 'string', value: 'string' },
									},
								},
								{
									kind: 'identifier',
									name: '_',
									optional: false,
									tsType: { kind: 'keyword', repr: 'boolean', value: 'boolean' },
								},
							],
							returnType: { kind: 'keyword', repr: 'void', value: 'void' },
							hasBody: true,
						},
					},
				],
			},
		],
	},
} satisfies Record<string, ApiModule>;

describe('renderModulePages inline links', () => {
	it('links function parameters and their property paths to parameter anchors', () => {
		const result = renderModulePages(modules, { packageName: 'example' });
		const markdown = result.pages[0]?.markdown ?? '';
		const prefix = 'fn-x6578616d706c65-x77616c6b-param-';
		const optionsUrl = `#${prefix}x6f7074696f6e73`;

		expect(markdown).toContain(
			`[\`allowOpaqueConstructedTags\`](${optionsUrl}), [\`options.allowOpaqueConstructedTags\`](${optionsUrl})`,
		);
		expect(markdown).toContain(`[\`maxDepth\`](#${prefix}x6d61784465707468)`);
		expect(markdown).toContain(`<span id="${prefix}x6d61784465707468"></span>\`maxDepth\``);
		expect(markdown).toContain(`[\`$options\`](#${prefix}x246f7074696f6e73)`);
		expect(markdown).toContain(`<span id="${prefix}x246f7074696f6e73"></span>\`$options\``);
		expect(markdown).toContain(`[\`café\`](#${prefix}x636166c3a9)`);
		expect(markdown).toContain(`<span id="${prefix}x636166c3a9"></span>\`café\``);
		expect(markdown).toContain(`[\`_\`](#${prefix}x5f)`);
		expect(markdown).toContain(`<span id="${prefix}x5f"></span>\`_\``);
		expect(markdown).toContain('\tmaxDepth: number');
		expect(markdown).not.toContain('\t_: number');
		expect(markdown).toContain('\targs: string[]');
		expect(markdown).not.toContain('\targs: unknown');
	});

	it('namespaces parameter anchors by module', () => {
		const duplicateModules = {
			...modules,
			'file:///workspace/src/other/index.ts': modules['file:///workspace/src/example/index.ts'],
		} satisfies Record<string, ApiModule>;
		const result = renderModulePages(duplicateModules, { packageName: 'example' });
		const example = result.pages.find((page) => page.pkg === 'example')?.markdown ?? '';
		const other = result.pages.find((page) => page.pkg === 'other')?.markdown ?? '';

		expect(example).toContain('id="fn-x6578616d706c65-x77616c6b-param-');
		expect(other).toContain('id="fn-x6f74686572-x77616c6b-param-');
		expect(example).not.toContain('id="fn-x6f74686572-');
		expect(other).not.toContain('id="fn-x6578616d706c65-');
		expect(example).toContain('[`walk`](/api/example#fn-walk)');
		expect(other).toContain('[`walk`](/api/other#fn-walk)');
	});
});

describe('root entrypoint', () => {
	it('includes and renders the package root without colliding with Overview', () => {
		expect(
			entrypointsOf({
				exports: { '.': './src/index.ts', './example': './src/example/index.ts' },
			}),
		).toEqual(['src/example/index.ts', 'src/index.ts']);

		const rootModules = {
			'file:///workspace/src/index.ts': {
				...modules['file:///workspace/src/example/index.ts'],
				module_doc: { doc: 'Stable root import.\\\nMore detail.' },
			},
			...modules,
		} satisfies Record<string, ApiModule>;
		const result = renderModulePages(rootModules, { packageName: 'example' });
		const root = result.pages[0];

		expect(root?.pkg).toBe('root');
		expect(root?.markdown).toStartWith('# `example`');
		expect(root?.markdown).toContain('[`walk`](/api/example#fn-walk)');
		expect(result.sidebar[0]).toEqual({ text: 'example', link: '/api/root' });
		expect(renderOverview(rootModules, { packageName: 'example' })).toContain(
			'- [`example`](/api/root) — Stable root import.',
		);
		expect(renderOverview(rootModules, { packageName: 'example' })).not.toContain(
			'Stable root import.\\',
		);
	});

	it('keeps root identity independent from its route slug', () => {
		const rootModules = {
			...modules,
			'file:///workspace/src/index.ts': modules['file:///workspace/src/example/index.ts'],
		} satisfies Record<string, ApiModule>;
		const result = renderModulePages(rootModules, {
			packageName: 'example',
			slugOf: (url) => (url.endsWith('/src/index.ts') ? 'package-entry' : 'example'),
		});
		const root = result.pages[0];

		expect(root?.pkg).toBe('package-entry');
		expect(root?.markdown).toStartWith('# `example`');
		expect(result.sidebar[0]).toEqual({ text: 'example', link: '/api/package-entry' });
	});

	it('rejects colliding page slugs before output', () => {
		const collidingModules = {
			'file:///workspace/src/index.ts': modules['file:///workspace/src/example/index.ts'],
			'file:///workspace/src/root/index.ts': modules['file:///workspace/src/example/index.ts'],
		} satisfies Record<string, ApiModule>;

		expect(() => renderModulePages(collidingModules, { packageName: 'example' })).toThrow(
			'API page slug collision',
		);
	});

	it('reserves the Overview route', () => {
		const rootModules = {
			'file:///workspace/src/index.ts': modules['file:///workspace/src/example/index.ts'],
		} satisfies Record<string, ApiModule>;

		expect(() =>
			renderModulePages(rootModules, {
				packageName: 'example',
				slugOf: () => 'index',
			}),
		).toThrow('API page slug "index" is reserved for Overview');
	});
});

describe('reference anchors', () => {
	it('uses concrete declaration kinds for re-export references', () => {
		const referenceModules = {
			'file:///workspace/src/index.ts': {
				symbols: [
					{
						name: 'NamePair',
						declarations: [{ location, declarationKind: 'export', kind: 'interface', def: {} }],
					},
					{
						name: 'namePair',
						declarations: [
							{
								location,
								declarationKind: 'export',
								kind: 'function',
								def: {
									params: [],
									returnType: { kind: 'keyword', repr: 'void', value: 'void' },
									hasBody: true,
								},
							},
						],
					},
				],
			},
			'file:///workspace/src/domain/index.ts': {
				symbols: [
					{
						name: 'NamePair',
						declarations: [
							{
								location,
								declarationKind: 'export',
								kind: 'reference',
								reference_def: { target: location },
							},
						],
					},
					{
						name: 'namePair',
						declarations: [
							{
								location,
								declarationKind: 'export',
								kind: 'reference',
								jsDoc: { doc: 'Returns {@linkcode NamePair}.' },
								reference_def: { target: location },
							},
						],
					},
				],
			},
		} satisfies Record<string, ApiModule>;
		const result = renderModulePages(referenceModules, { packageName: 'example' });
		const domain = result.pages.find((page) => page.pkg === 'domain')?.markdown ?? '';

		expect(domain).toContain('## `NamePair` {#type-namepair}');
		expect(domain).toContain('## `namePair` {#fn-namepair}');
		expect(domain).toContain('[`NamePair`](/api/domain#type-namepair)');
	});
});
