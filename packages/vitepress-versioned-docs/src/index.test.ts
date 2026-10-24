import { describe, test } from 'bun:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { versionedDocs } from './index.ts';

const setup = () => {
	const root = mkdtempSync(path.join(os.tmpdir(), 'versioned-docs-target-'));
	const site = path.join(root, 'site');
	mkdirSync(path.join(site, 'guide'), { recursive: true });
	mkdirSync(path.join(site, 'api', 'fn'), { recursive: true });
	writeFileSync(path.join(site, 'index.md'), '# Home\n');
	writeFileSync(path.join(site, 'guide', 'index.md'), '# Guide\n');
	writeFileSync(path.join(site, 'api', 'fn', 'Name.md'), '# Name\n');
	writeFileSync(
		path.join(root, 'package.json'),
		JSON.stringify({
			version: '1.2.3',
			exports: { '.': './src/index.ts', './x509': './src/x509.ts' },
		}),
	);
	mkdirSync(path.join(root, 'src'), { recursive: true });
	return { root, site };
};

describe('single-target docs builds', () => {
	for (const channel of ['next', 'latest', 'archive', 'preview'] as const) {
		test(`${channel} uses only the checkout and publishes target metadata`, async () => {
			const { root, site } = setup();
			try {
				const outDir = path.join(root, 'dist');
				mkdirSync(outDir);
				let generated = 0;
				const docs = await versionedDocs({
					...(channel === 'archive'
						? { target: { channel, version: 'v1.2.3' } }
						: { target: { channel } }),
					repoRoot: root,
					siteRoot: 'site',
					versionsDir: path.join(site, 'versions'),
					cacheDir: path.join(root, 'cache'),
					devLabel: 'v1.2.3-dev',
					pages: ['site/guide', 'site/index.md'],
					sources: ['src', 'package.json'],
					releases: {
						index: 'http://127.0.0.1:1/packument',
						tag: (version) => `v${version}`,
						source: (tag) => `http://127.0.0.1:1/${tag}.tgz`,
						url: (tag) => `https://example.test/releases/${tag}`,
					},
					library: {
						name: 'micro509',
						moduleUrl: (version, subpath) => `https://cdn.test/${version.tag}/${subpath}`,
					},
					generateApi: ({ outDir: apiDir }) => {
						generated += 1;
						mkdirSync(apiDir, { recursive: true });
						writeFileSync(path.join(apiDir, 'index.md'), '# API\n');
					},
					fileGuardrail: 100,
				});
				assert.equal(generated, 1);
				const prefix = channel === 'next' ? 'next/' : channel === 'archive' ? 'v1.2.3/' : '';
				const expectedBase = prefix === '' ? '/' : `/${prefix}`;
				assert.equal(docs.base, expectedBase);
				assert.equal(docs.rewrites('site/guide/index.md'), 'guide/index.md');
				assert.deepEqual(
					docs.versions[0]?.sections.guide?.map((page) => page.slug),
					['index'],
				);
				const indexable = channel === 'latest';
				assert.equal(docs.head('guide/index.md').length, indexable ? 0 : 1);
				assert.equal(docs.isIndexable('guide/index.md'), indexable);
				assert.equal(docs.html('<head></head>', 'guide/index.md').includes('"imports"'), true);
				await Reflect.apply(docs.buildEnd, undefined, [{ outDir }]);
				const catalog = JSON.parse(readFileSync(path.join(outDir, 'versions.json'), 'utf8'));
				assert.equal(catalog.versions[0].base, expectedBase);
				assert.equal(catalog.versions[0].channel, channel === 'preview' ? 'latest' : channel);
				assert.ok('sections' in catalog.versions[0]);
				assert.equal(catalog.versions[0].sections.guide[0].slug, 'index');
				assert.equal(catalog.versions[0].sections.api[0].slug, 'fn/Name');
				const apiSidebar = docs.sidebar({
					api: [{ text: 'API Reference', slugs: ['index', 'root'] }],
				});
				assert.equal(JSON.stringify(apiSidebar).includes('fn/Name'), false);
				assert.equal(readFileSync(path.join(site, 'api', 'index.md'), 'utf8'), '# API\n');
			} finally {
				rmSync(root, { recursive: true, force: true });
			}
		});
	}

	test('latest and archive versions must match the checked-out manifest', async () => {
		const { root } = setup();
		try {
			await assert.rejects(
				versionedDocs({
					target: { channel: 'archive', version: 'v9.9.9' },
					repoRoot: root,
					siteRoot: 'site',
					versionsDir: path.join(root, 'versions'),
					cacheDir: path.join(root, 'cache'),
					devLabel: 'dev',
					pages: [],
					sources: [],
					releases: {
						index: 'http://127.0.0.1:1',
						tag: (value) => value,
						source: (value) => value,
						url: (value) => value,
					},
					library: { name: 'micro509', moduleUrl: () => '' },
					generateApi: () => undefined,
					fileGuardrail: 10,
				}),
				/does not match package version/,
			);
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});

	test('historical target materializes selected source pages and API into the site tree', async () => {
		const { root } = setup();
		try {
			const versionsDir = path.join(root, 'site', 'versions');
			mkdirSync(path.join(versionsDir, 'latest'), { recursive: true });
			writeFileSync(path.join(versionsDir, 'latest', 'stale.md'), '# Stale latest\n');
			mkdirSync(path.join(versionsDir, 'v1.1.0'), { recursive: true });
			writeFileSync(path.join(versionsDir, 'v1.1.0', 'stale.md'), '# Stale archive\n');
			const sourceRoot = path.join(root, 'historical');
			mkdirSync(path.join(sourceRoot, 'site', 'guide'), { recursive: true });
			mkdirSync(path.join(sourceRoot, 'src'), { recursive: true });
			writeFileSync(
				path.join(sourceRoot, 'package.json'),
				JSON.stringify({ version: '1.2.3', exports: { '.': './src/index.ts' } }),
			);
			writeFileSync(path.join(sourceRoot, 'site', 'guide', 'historical.md'), '# Historical\n');
			let generatedFrom = '';
			const docs = await versionedDocs({
				target: { channel: 'archive', version: 'v1.2.3', sourceRoot },
				repoRoot: root,
				siteRoot: 'site',
				versionsDir,
				cacheDir: path.join(root, 'cache'),
				devLabel: 'current-dev',
				pages: ['site/guide', 'site/index.md'],
				sources: ['src', 'package.json'],
				releases: {
					index: 'http://127.0.0.1:1/packument',
					tag: (value) => value,
					source: (value) => value,
					url: (value) => `https://example.test/releases/${value}`,
				},
				library: { name: 'micro509', moduleUrl: (version) => `https://cdn.test/${version.tag}` },
				generateApi: ({ root: apiSource, outDir }) => {
					generatedFrom = apiSource;
					mkdirSync(outDir, { recursive: true });
					writeFileSync(path.join(outDir, 'index.md'), '# Historical API\n');
				},
				fileGuardrail: 100,
			});
			const target = path.join(root, 'site', 'versions', 'v1.2.3');
			assert.equal(generatedFrom, sourceRoot);
			assert.equal(
				readFileSync(path.join(target, 'guide', 'historical.md'), 'utf8'),
				'# Historical\n',
			);
			assert.equal(
				readFileSync(path.join(target, 'api', 'index.md'), 'utf8'),
				'# Historical API\n',
			);
			assert.equal(
				docs.rewrites('site/versions/v1.2.3/guide/historical.md'),
				'guide/historical.md',
			);
			assert.deepEqual(
				docs.versions[0]?.sections.guide?.map((page) => page.slug),
				['historical'],
			);
			assert.deepEqual(docs.srcExclude, [
				'site/guide/**',
				'site/index.md',
				'site/api/**',
				'site/versions/latest/**',
				'site/versions/v1.1.0/**',
			]);
			assert.equal(docs.srcExclude.includes('site/versions/v1.2.3/**'), false);

			const next = await versionedDocs({
				target: { channel: 'next' },
				repoRoot: root,
				siteRoot: 'site',
				versionsDir,
				cacheDir: path.join(root, 'cache'),
				devLabel: 'current-dev',
				pages: ['site/guide', 'site/index.md'],
				sources: ['src', 'package.json'],
				releases: {
					index: 'http://127.0.0.1:1/packument',
					tag: (value) => value,
					source: (value) => value,
					url: (value) => value,
				},
				library: { name: 'micro509', moduleUrl: () => '' },
				generateApi: ({ outDir }) => mkdirSync(outDir, { recursive: true }),
				fileGuardrail: 100,
			});
			assert.deepEqual(next.srcExclude, ['site/versions/**']);
		} finally {
			rmSync(root, { recursive: true, force: true });
		}
	});
});
