/** Re-derives the frozen IDNA2008 tables from the vendored IANA and Unicode sources. */

import { describe, expect, test } from 'bun:test';
import * as frozen from '#micro509/internal/shared/idna-tables';
import { projectRoot } from '#test/helpers';
import { deriveIdnaTables, IDNA_UNICODE_VERSION } from '../scripts/spec/idna.ts';

const derived = await deriveIdnaTables(`${projectRoot}/docs/idna`);

describe('IDNA2008 tables', () => {
	test('describe the Unicode version the vendored sources carry', () => {
		expect(frozen.IDNA_UNICODE_VERSION).toBe(IDNA_UNICODE_VERSION);
	});

	test('match the IANA derived property values', () => {
		expect(frozen.PVALID_RANGES).toEqual(derived.pvalid);
		expect(frozen.CONTEXTJ_RANGES).toEqual(derived.contextj);
		expect(frozen.CONTEXTO_RANGES).toEqual(derived.contexto);
		expect(derived.pvalid.length).toBeGreaterThan(1000);
	});

	test('match the Unicode properties the contextual and Bidi rules read', () => {
		expect(frozen.BIDI_L_RANGES).toEqual(derived.bidi.get('L') ?? []);
		expect(frozen.BIDI_R_RANGES).toEqual(derived.bidi.get('R') ?? []);
		expect(frozen.BIDI_AL_RANGES).toEqual(derived.bidi.get('AL') ?? []);
		expect(frozen.BIDI_AN_RANGES).toEqual(derived.bidi.get('AN') ?? []);
		expect(frozen.BIDI_EN_RANGES).toEqual(derived.bidi.get('EN') ?? []);
		expect(frozen.BIDI_ES_RANGES).toEqual(derived.bidi.get('ES') ?? []);
		expect(frozen.BIDI_CS_RANGES).toEqual(derived.bidi.get('CS') ?? []);
		expect(frozen.BIDI_ET_RANGES).toEqual(derived.bidi.get('ET') ?? []);
		expect(frozen.BIDI_ON_RANGES).toEqual(derived.bidi.get('ON') ?? []);
		expect(frozen.BIDI_BN_RANGES).toEqual(derived.bidi.get('BN') ?? []);
		expect(frozen.BIDI_NSM_RANGES).toEqual(derived.bidi.get('NSM') ?? []);
		expect(frozen.JOINING_D_RANGES).toEqual(derived.joining.get('D') ?? []);
		expect(frozen.JOINING_L_RANGES).toEqual(derived.joining.get('L') ?? []);
		expect(frozen.JOINING_R_RANGES).toEqual(derived.joining.get('R') ?? []);
		expect(frozen.JOINING_T_RANGES).toEqual(derived.joining.get('T') ?? []);
		expect(frozen.VIRAMA_RANGES).toEqual(derived.virama);
		expect(frozen.SCRIPT_GREEK_RANGES).toEqual(derived.scripts.get('Greek') ?? []);
		expect(frozen.SCRIPT_HEBREW_RANGES).toEqual(derived.scripts.get('Hebrew') ?? []);
		expect(frozen.SCRIPT_HIRAGANA_RANGES).toEqual(derived.scripts.get('Hiragana') ?? []);
		expect(frozen.SCRIPT_KATAKANA_RANGES).toEqual(derived.scripts.get('Katakana') ?? []);
		expect(frozen.SCRIPT_HAN_RANGES).toEqual(derived.scripts.get('Han') ?? []);
		expect(frozen.MARK_RANGES).toEqual(derived.marks);
	});

	test('match the width decompositions the RFC 5895 mapping reads', () => {
		expect(frozen.WIDTH_DECOMPOSITIONS).toEqual(derived.widthDecompositions);
		expect(derived.widthDecompositions.length).toBe(452);
	});
});
