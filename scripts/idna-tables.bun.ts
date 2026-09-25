#!/usr/bin/env bun
/**
 * Regenerates `src/internal/shared/idna-tables.ts` from the IANA IDNA2008
 * derived-property table and the matching Unicode Character Database files
 * vendored under `docs/idna/`.
 *
 * @module
 */

import { deriveIdnaTables, IDNA_UNICODE_VERSION } from './spec/idna.ts';

const root = new URL('..', import.meta.url).pathname;
const tables = await deriveIdnaTables(`${root}docs/idna`);

function ranges(name: string, doc: string, values: readonly number[]): string {
	const rows: string[] = [];
	for (let index = 0; index < values.length; index += 16) {
		rows.push(
			`\t${values
				.slice(index, index + 16)
				.map((value) => `0x${value.toString(16)}`)
				.join(', ')},`,
		);
	}
	return `/** ${doc} */\nexport const ${name}: readonly number[] = [\n${rows.join('\n')}\n];\n`;
}

const unicodeLicense = (await Bun.file(`${root}docs/idna/UNICODE-LICENSE.txt`).text())
	.trimEnd()
	.split('\n')
	.map((line) => (line.length === 0 ? ' *' : ` * ${line}`))
	.join('\n');

const source = [
	`/**
 * Frozen IDNA2008 tables for Unicode ${IDNA_UNICODE_VERSION}: the IANA derived
 * property values (RFC 5892) and the Unicode properties the contextual rules
 * (RFC 5892 Appendix A) and the Bidi rule (RFC 5893) read. Each table is a flat
 * list of inclusive \`[first, last]\` code point pairs in ascending order.
 *
 * Do not edit by hand; regenerate with \`bun scripts/idna-tables.bun.ts\`.
 *
 * The Unicode properties are derived from the Unicode Character Database,
 * distributed under this notice:
 *
${unicodeLicense}
 *
 * @module
 */
`,
	`/** Unicode version the tables describe. */\nexport const IDNA_UNICODE_VERSION = '${IDNA_UNICODE_VERSION}';\n`,
	ranges('PVALID_RANGES', 'Code points whose IDNA2008 property is PVALID.', tables.pvalid),
	ranges('CONTEXTJ_RANGES', 'Code points whose IDNA2008 property is CONTEXTJ.', tables.contextj),
	ranges('CONTEXTO_RANGES', 'Code points whose IDNA2008 property is CONTEXTO.', tables.contexto),
	...[...tables.bidi].map(([bidiClass, values]) =>
		ranges(`BIDI_${bidiClass}_RANGES`, `Code points whose Bidi_Class is ${bidiClass}.`, values),
	),
	...[...tables.joining].map(([joiningType, values]) =>
		ranges(
			`JOINING_${joiningType}_RANGES`,
			`Code points whose Joining_Type is ${joiningType}.`,
			values,
		),
	),
	ranges(
		'VIRAMA_RANGES',
		'Code points whose Canonical_Combining_Class is Virama (9).',
		tables.virama,
	),
	...[...tables.scripts].map(([script, values]) =>
		ranges(
			`SCRIPT_${script.toUpperCase()}_RANGES`,
			`Code points whose Script is ${script}.`,
			values,
		),
	),
	ranges('MARK_RANGES', 'Code points whose General_Category is Mn, Mc or Me.', tables.marks),
].join('\n');

await Bun.write(`${root}src/internal/shared/idna-tables.ts`, source);
console.log(`wrote src/internal/shared/idna-tables.ts (Unicode ${IDNA_UNICODE_VERSION})`);
