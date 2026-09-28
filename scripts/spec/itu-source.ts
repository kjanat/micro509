/** Download item syntax, shared by fetching and identifier tests. */
export const ITU_ITEM = /^T-REC-([A-Z]\.\d+(?:\.\d+)?)-\d{4}(?:0[1-9]|1[0-2])-[A-Z]!\w*!PDF-E$/;

/** A bundled filename is not an edition. Only explicit cover evidence supplies one. */
export function ituSourceStem(stem: string, source = ''): string {
	if (stem.startsWith('T-REC-') || source === '') return stem;
	const cover =
		source
			.split('\n')
			.slice(0, 160)
			.join('\n')
			.split(/^\s*(?:CONTENTS|Table of Contents)\s*$/im)[0] ?? '';
	const recommendation =
		/^\s*(?:#{1,6}\s+)?(?:(?:Recommendation|Rec\.?)\s+)?(?:ITU[- ]T\s+)?([A-Z]\.\d+(?:\.\d+)?)\s*(?:\((?:0[1-9]|1[0-2])\/\d{4}\))?\s*$/m.exec(
			cover,
		)?.[1];
	const date = /\(\s*(0[1-9]|1[0-2])\/(\d{4})\s*\)/.exec(cover);
	if (recommendation === undefined || date?.[1] === undefined || date[2] === undefined) return stem;
	const variant = /\b(Corrigendum|Amendment|Erratum)\s+(\d+)\b/i.exec(cover);
	const prefix = variant?.[1]?.toLowerCase();
	const token =
		prefix === 'corrigendum'
			? 'Cor'
			: prefix === 'amendment'
				? 'Amd'
				: prefix === 'erratum'
					? 'Err'
					: '';
	return `T-REC-${recommendation}-${date[2]}${date[1]}-I!${token}${variant?.[2] ?? ''}!MSW-E`;
}

/** Do not turn unstyled, numbered body paragraphs into multi-kilobyte titles. */
export function looksLikeClauseProse(title: string): boolean {
	return (
		title.length > 180 ||
		(/\b(?:shall|must|is|are|may)\b/i.test(title) &&
			/[.;]$/.test(title) &&
			title.split(/\s+/).length > 12)
	);
}
