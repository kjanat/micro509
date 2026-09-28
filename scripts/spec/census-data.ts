import type { SourceLine } from './types.ts';

export interface CensusQuery {
	readonly pattern: string;
	readonly matches: number;
	readonly samples: readonly SourceLine[];
}

/** Count every line for every independent query; limit only retained examples. */
export function censusLines(
	lines: readonly SourceLine[],
	patterns: readonly RegExp[],
	sampleLimit: number,
): readonly CensusQuery[] {
	if (!Number.isSafeInteger(sampleLimit) || sampleLimit < 0) {
		throw new Error('sampleLimit must be a non-negative safe integer');
	}
	return patterns.map((pattern) => {
		const expression = new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, ''));
		let matches = 0;
		const samples: SourceLine[] = [];
		for (const line of lines) {
			if (!expression.test(line.text)) continue;
			matches += 1;
			if (samples.length < sampleLimit) samples.push(line);
		}
		return { pattern: pattern.source, matches, samples };
	});
}
