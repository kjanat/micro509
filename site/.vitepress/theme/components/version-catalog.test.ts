import { describe, expect, test } from 'bun:test';
import type { VersionEntry } from './version-catalog';
import {
	hrefFor,
	mergeVersions,
	parseCatalog,
	versionForPath,
	versionKey,
} from './version-catalog';

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
				api: [{ slug: 'x509' }],
				guide: [{ slug: 'index' }, { slug: 'getting-started' }],
			},
		},
		{
			label: 'v0.9.0',
			tag: 'v0.9.0',
			channel: 'archive',
			base: '/v0.9.0/',
			releaseUrl: null,
			sections: { guide: [{ slug: 'certificates' }, { slug: 'getting-started' }] },
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

	test('parses preview identity and assigns the production origin to published entries', () => {
		const preview = parseCatalog({
			schemaVersion: 3,
			versions: [{ label: '#42', tag: '#42', channel: 'preview', base: '/', releaseUrl: null }],
		});
		expect(preview?.[0]).toMatchObject({ label: '#42', channel: 'preview', prefix: '' });
		const published = parseCatalog(catalog, 'https://docs.example.test');
		expect(published?.map((entry) => entry.origin)).toEqual([
			'https://docs.example.test',
			'https://docs.example.test',
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

	test('shows a local preview separately from the production root and next', () => {
		const entries = parseCatalog(catalog);
		if (entries === undefined) throw new Error('catalog parse failed');
		const published = [
			...entries,
			{ label: 'next', tag: 'v1.1.0-dev', channel: 'next' as const, prefix: 'next/' },
		].map((entry) => ({ ...entry, origin: 'https://docs.example.test' }));
		const merged = mergeVersions(published, [
			{
				label: '#42',
				tag: '#42',
				channel: 'preview',
				prefix: '',
				labelUrl: 'https://example.test/pull/42',
				sections: { guide: [{ slug: 'preview-only' }] },
			},
		]);
		expect(merged.map((entry) => entry.label)).toEqual(['#42', 'v1.0.0', 'v0.9.0', 'next']);
		expect(merged[0]?.label).toBe('#42');
		expect(merged[0]?.labelUrl).toBe('https://example.test/pull/42');
		expect(merged[0]?.sections?.guide).toEqual([{ slug: 'preview-only' }]);
		expect(merged[1]?.sections).toEqual(entries[0]?.sections);
	});

	test('links production versions to their own origin from a preview', () => {
		const entry = {
			label: 'next',
			prefix: 'next/',
			origin: 'https://docs.example.test',
			sections: { guide: [{ slug: 'getting-started' }] },
		};
		expect(hrefFor(entry, 'guide/getting-started', '?view=full#install')).toBe(
			'https://docs.example.test/next/guide/getting-started?view=full#install',
		);
		expect(hrefFor(entry, 'guide/preview-only', '?view=full#missing')).toBe(
			'https://docs.example.test/next/guide/getting-started?view=full',
		);
	});

	test('selects the local preview without confusing production prefixes or root entries', () => {
		const preview = { label: '#42', tag: '#42', channel: 'preview', prefix: '' } as const;
		const latest = { label: 'v1.0.0', tag: 'v1.0.0', channel: 'latest', prefix: '' } as const;
		const next = {
			label: 'next',
			channel: 'next',
			prefix: 'next/',
			origin: 'https://docs.example.test',
		} as const;
		expect(versionKey(preview)).not.toBe(versionKey(latest));
		const merged = mergeVersions([latest, next], [preview]);
		expect(merged.map((entry) => entry.label)).toEqual(['#42', 'v1.0.0', 'next']);
		expect(versionForPath(merged, '/guide/keys')).toEqual(preview);
		expect(versionForPath(merged, '/next/guide/keys')).toEqual(preview);
		expect(hrefFor(preview, 'guide/keys', '#import')).toBe('/guide/keys#import');
	});

	test('selects the longest local prefix on production pages', () => {
		const entries = parseCatalog(catalog);
		if (entries === undefined) throw new Error('catalog parse failed');
		expect(versionForPath(entries, '/guide/keys')?.label).toBe('v1.0.0');
		expect(versionForPath(entries, '/v0.9.0/guide/certificates')?.label).toBe('v0.9.0');
	});

	test('falls back to an existing guide page and drops the old fragment', () => {
		const entries = parseCatalog(catalog);
		if (entries === undefined) throw new Error('catalog parse failed');
		const latest = entries[0];
		const archive = entries[1];
		if (latest === undefined || archive === undefined) throw new Error('catalog entries missing');
		expect(hrefFor(archive, 'guide/nonexistent', '?view=full#old-page-symbol')).toBe(
			'/v0.9.0/guide/getting-started?view=full',
		);
		expect(hrefFor(latest, 'guide/getting-started')).toBe('/guide/getting-started');
	});

	test('prefers section index, then guide getting-started, then the first page', () => {
		const entry: VersionEntry = {
			label: 'next',
			prefix: 'next/',
			sections: {
				reference: [{ slug: 'index' }, { slug: 'standards' }],
				guide: [{ slug: 'certificates' }, { slug: 'getting-started' }],
				api: [{ slug: 'x509' }, { slug: 'verify' }],
			},
		};
		expect(hrefFor(entry, 'reference/missing')).toBe('/next/reference/');
		expect(hrefFor(entry, 'guide/missing')).toBe('/next/guide/getting-started');
		expect(hrefFor(entry, 'api/missing')).toBe('/next/api/x509');
	});

	test('falls back to the version root when the section is absent or empty', () => {
		const entry: VersionEntry = {
			label: 'v0.9.0',
			prefix: 'v0.9.0/',
			sections: { guide: [] },
		};
		expect(hrefFor(entry, 'guide/missing', '?view=full#old-anchor')).toBe('/v0.9.0/?view=full');
		expect(hrefFor(entry, 'reference/missing')).toBe('/v0.9.0/');
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
