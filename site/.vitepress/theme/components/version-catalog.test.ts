import { describe, expect, test } from 'bun:test';
import { hrefFor, mergeVersions, parseCatalog } from './version-catalog';

const catalog = {
	schemaVersion: 3,
	versions: [
		{
			label: 'v1.0.0',
			tag: 'v1.0.0',
			channel: 'latest',
			base: '/',
			releaseUrl: 'https://example.test/releases/v1.0.0',
			sections: {
				guide: [{ slug: 'index' }, { slug: 'getting-started' }],
			},
		},
		{
			label: 'v0.9.0',
			tag: 'v0.9.0',
			channel: 'archive',
			base: '/v0.9.0/',
			releaseUrl: null,
			sections: { guide: [{ slug: 'index' }] },
		},
	],
} as const;

describe('version catalog', () => {
	test('parses release entries and section inventory', () => {
		const entries = parseCatalog(catalog);
		expect(entries?.map((entry) => entry.prefix)).toEqual(['', 'v0.9.0/']);
		expect(entries?.[0]?.sections?.guide?.map((page) => page.slug)).toEqual([
			'index',
			'getting-started',
		]);
	});

	test('rejects incompatible schema versions and version bases', () => {
		expect(parseCatalog({ ...catalog, schemaVersion: 4 })).toBeUndefined();
		const invalidBase = {
			schemaVersion: 3,
			versions: [{ ...catalog.versions[0], base: '//elsewhere.test/' }],
		};
		expect(parseCatalog(invalidBase)).toBeUndefined();
	});

	test('keeps a same-prefix local preview label and PR link', () => {
		const entries = parseCatalog(catalog);
		if (entries === undefined) throw new Error('catalog parse failed');
		const merged = mergeVersions(entries, [
			{
				label: '#42',
				tag: 'v1.1.0-dev',
				prefix: '',
				labelUrl: 'https://example.test/pull/42',
			},
		]);
		expect(merged[0]?.label).toBe('#42');
		expect(merged[0]?.labelUrl).toBe('https://example.test/pull/42');
		expect(merged[0]?.sections).toEqual(entries[0]?.sections);
	});

	test('falls back to a section landing page when the version lacks the page', () => {
		const entries = parseCatalog(catalog);
		if (entries === undefined) throw new Error('catalog parse failed');
		const latest = entries[0];
		const archive = entries[1];
		if (latest === undefined || archive === undefined) throw new Error('catalog entries missing');
		expect(hrefFor(archive, 'guide/getting-started')).toBe('/v0.9.0/guide/');
		expect(hrefFor(latest, 'guide/getting-started')).toBe('/guide/getting-started');
	});

	test('preserves nested symbol fragments when switching versions', () => {
		const entries = parseCatalog(catalog);
		const latest = entries?.[0];
		if (latest === undefined) throw new Error('catalog entry missing');
		expect(hrefFor(latest, 'api/x509', '?view=full#type-certificate')).toBe(
			'/api/x509?view=full#type-certificate',
		);
	});
});
