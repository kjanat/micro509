export interface VersionEntry {
	readonly label: string;
	readonly prefix: string;
	readonly labelUrl?: string;
	readonly channel?: 'latest' | 'next' | 'archive';
	readonly tag?: string;
	readonly sections?: Readonly<Record<string, readonly { readonly slug: string }[]>>;
}

const RELEASE_TAG = /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/;
const PREVIEW_TAG = /^[A-Za-z0-9][A-Za-z0-9._#-]*$/;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isChannel(value: unknown): value is NonNullable<VersionEntry['channel']> {
	return value === 'latest' || value === 'next' || value === 'archive';
}

function validBase(
	channel: NonNullable<VersionEntry['channel']>,
	tag: string,
	base: string,
): boolean {
	switch (channel) {
		case 'latest':
			return base === '/' && RELEASE_TAG.test(tag);
		case 'next':
			return base === '/next/' && PREVIEW_TAG.test(tag);
		case 'archive':
			return base === `/${tag}/` && RELEASE_TAG.test(tag);
	}
}

function parseSections(value: unknown): VersionEntry['sections'] | false {
	if (value === undefined) return undefined;
	if (!isRecord(value)) return false;
	const sections: Record<string, readonly { readonly slug: string }[]> = {};
	for (const [section, pages] of Object.entries(value)) {
		if (!Array.isArray(pages)) return false;
		const slugs: { readonly slug: string }[] = [];
		for (const page of pages) {
			if (!isRecord(page) || typeof page.slug !== 'string') return false;
			slugs.push({ slug: page.slug });
		}
		sections[section] = slugs;
	}
	return sections;
}

function parseVersion(value: unknown): VersionEntry | undefined {
	if (!isRecord(value)) return undefined;
	const { label, tag, channel, base, releaseUrl } = value;
	if (
		typeof label !== 'string' ||
		typeof tag !== 'string' ||
		!isChannel(channel) ||
		typeof base !== 'string' ||
		!(releaseUrl === null || typeof releaseUrl === 'string') ||
		!validBase(channel, tag, base)
	)
		return undefined;
	const sections = parseSections(value.sections);
	if (sections === false) return undefined;
	return {
		label,
		prefix: base.slice(1),
		channel,
		tag,
		...(releaseUrl === null ? {} : { labelUrl: releaseUrl }),
		...(sections === undefined ? {} : { sections }),
	};
}

export function parseCatalog(value: unknown): readonly VersionEntry[] | undefined {
	if (!isRecord(value) || value.schemaVersion !== 3 || !Array.isArray(value.versions)) {
		return undefined;
	}
	const entries: VersionEntry[] = [];
	for (const item of value.versions) {
		const entry = parseVersion(item);
		if (entry === undefined) return undefined;
		entries.push(entry);
	}
	return entries;
}

export function mergeVersions(
	catalog: readonly VersionEntry[],
	embedded: readonly VersionEntry[],
): readonly VersionEntry[] {
	const byPrefix = new Map(catalog.map((entry) => [entry.prefix, entry]));
	const localOnly: VersionEntry[] = [];
	for (const local of embedded) {
		const catalogEntry = byPrefix.get(local.prefix);
		if (catalogEntry === undefined) {
			byPrefix.set(local.prefix, local);
			localOnly.push(local);
		} else if (catalogEntry.tag !== local.tag) {
			// A local preview at this app's base may not appear in the release catalog.
			byPrefix.set(local.prefix, {
				...catalogEntry,
				label: local.label,
				...(local.labelUrl === undefined ? {} : { labelUrl: local.labelUrl }),
			});
		} else if (local.labelUrl !== undefined) {
			byPrefix.set(local.prefix, { ...catalogEntry, labelUrl: local.labelUrl });
		}
	}
	return [...localOnly, ...catalog.map((entry) => byPrefix.get(entry.prefix) ?? entry)];
}

export function hrefFor(entry: VersionEntry, page: string, suffix = ''): string {
	if (entry.sections === undefined || page === '') return `/${entry.prefix}${page}${suffix}`;
	const [section, ...tail] = page.split('/');
	const slug = tail.join('/') || 'index';
	const pages = entry.sections[section];
	if (pages?.some((candidate) => candidate.slug === slug))
		return `/${entry.prefix}${page}${suffix}`;

	const fallback =
		pages?.find((candidate) => candidate.slug === 'index') ??
		(section === 'guide'
			? pages?.find((candidate) => candidate.slug === 'getting-started')
			: undefined) ??
		pages?.[0];
	const query = suffix.split('#', 1)[0] ?? '';
	if (fallback === undefined) return `/${entry.prefix}${query}`;
	if (fallback.slug === 'index') return `/${entry.prefix}${section}/${query}`;
	return `/${entry.prefix}${section}/${fallback.slug}${query}`;
}
