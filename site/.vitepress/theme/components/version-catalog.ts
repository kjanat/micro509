export interface VersionEntry {
	readonly label: string;
	readonly prefix: string;
	/** Set for versions hosted outside this app, such as production links in a PR preview. */
	readonly origin?: string;
	readonly labelUrl?: string;
	readonly channel?: 'latest' | 'next' | 'archive' | 'preview';
	readonly tag?: string;
	readonly sections?: Readonly<Record<string, readonly { readonly slug: string }[]>>;
}

const RELEASE_TAG = /^v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/;
const PREVIEW_TAG = /^[A-Za-z0-9][A-Za-z0-9._#-]*$/;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isChannel(value: unknown): value is NonNullable<VersionEntry['channel']> {
	return value === 'latest' || value === 'next' || value === 'archive' || value === 'preview';
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
		case 'preview':
			return base === '/' && (PREVIEW_TAG.test(tag) || /^#[1-9]\d*$/.test(tag));
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

export function parseCatalog(value: unknown, origin?: string): readonly VersionEntry[] | undefined {
	if (!isRecord(value) || value.schemaVersion !== 3 || !Array.isArray(value.versions)) {
		return undefined;
	}
	const entries: VersionEntry[] = [];
	for (const item of value.versions) {
		const entry = parseVersion(item);
		if (entry === undefined) return undefined;
		entries.push(origin === undefined ? entry : { ...entry, origin });
	}
	return entries;
}

/** A preview and production can both serve `/` on different origins. */
export function versionKey(entry: VersionEntry): string {
	return `${entry.origin ?? ''}|${entry.channel === 'preview' ? 'preview|' : ''}${entry.prefix}`;
}

/** External destinations never determine which local documentation page is being read. */
export function versionForPath(
	versions: readonly VersionEntry[],
	path: string,
): VersionEntry | undefined {
	return [...versions]
		.filter((entry) => entry.origin === undefined)
		.sort((a, b) => b.prefix.length - a.prefix.length)
		.find((entry) => path.startsWith(`/${entry.prefix}`));
}

export function mergeVersions(
	catalog: readonly VersionEntry[],
	embedded: readonly VersionEntry[],
): readonly VersionEntry[] {
	const byKey = new Map(catalog.map((entry) => [versionKey(entry), entry]));
	const localOnly: VersionEntry[] = [];
	for (const local of embedded) {
		const key = versionKey(local);
		const catalogEntry = byKey.get(key);
		if (catalogEntry === undefined) {
			byKey.set(key, local);
			localOnly.push(local);
		} else if (catalogEntry.tag !== local.tag) {
			// A local preview at this app's base may not appear in the release catalog.
			byKey.set(key, {
				...catalogEntry,
				label: local.label,
				...(local.labelUrl === undefined ? {} : { labelUrl: local.labelUrl }),
			});
		} else if (local.labelUrl !== undefined) {
			byKey.set(key, { ...catalogEntry, labelUrl: local.labelUrl });
		}
	}
	return [...localOnly, ...catalog.map((entry) => byKey.get(versionKey(entry)) ?? entry)];
}

export function hrefFor(entry: VersionEntry, page: string, suffix = ''): string {
	const base = `${entry.origin ?? ''}/${entry.prefix}`;
	if (entry.sections === undefined || page === '') return `${base}${page}${suffix}`;
	const [section, ...tail] = page.split('/');
	const slug = tail.join('/') || 'index';
	const pages = entry.sections[section];
	if (pages?.some((candidate) => candidate.slug === slug)) return `${base}${page}${suffix}`;

	const fallback =
		pages?.find((candidate) => candidate.slug === 'index') ??
		(section === 'guide'
			? pages?.find((candidate) => candidate.slug === 'getting-started')
			: undefined) ??
		pages?.[0];
	const query = suffix.split('#', 1)[0] ?? '';
	if (fallback === undefined) return `${base}${query}`;
	if (fallback.slug === 'index') return `${base}${section}/${query}`;
	return `${base}${section}/${fallback.slug}${query}`;
}
