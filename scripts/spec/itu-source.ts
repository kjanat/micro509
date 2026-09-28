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

const CLAUSE_SENTENCE_START =
	/^(?:A|An|The|This|That|These|Those|It|Each|Every|Any|No|If|When|Where|While|Unless|There)\b/i;
const CLAUSE_VERB =
	/\b(?:shall|must|should|may|is|are|was|were|has|have|contains?|consists?|applies?|specifies?|indicates?|identifies?|defines?|represents?|uses?|provides?|requires?)\b/i;
const CLAUSE_SENTENCE_END = /[.;!?]$/;

/** Do not turn numbered body paragraphs into headings, regardless of sentence length. */
export function looksLikeClauseProse(title: string): boolean {
	return (
		title.length > 180 ||
		(CLAUSE_SENTENCE_END.test(title) &&
			(CLAUSE_SENTENCE_START.test(title) || CLAUSE_VERB.test(title)))
	);
}
