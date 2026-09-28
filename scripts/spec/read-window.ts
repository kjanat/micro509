import { CLIError } from 'dreamcli';
import type { SourceLine } from './types.ts';

/** Offsets count source lines in the section after page furniture is removed. */
export function readWindow(lines: readonly SourceLine[], offset = 0, limit?: number) {
	if (
		!Number.isSafeInteger(offset) ||
		offset < 0 ||
		offset > lines.length ||
		(limit !== undefined && (!Number.isSafeInteger(limit) || limit < 1))
	) {
		throw new CLIError('invalid section window', {
			code: 'SPEC_READ_RANGE',
			details: { offset, limit, totalLines: lines.length },
		});
	}
	const end = limit === undefined ? lines.length : Math.min(lines.length, offset + limit);
	return {
		lines: lines.slice(offset, end),
		selection: {
			offset,
			totalLines: lines.length,
			returnedLines: end - offset,
			truncated: offset > 0 || end < lines.length,
			nextOffset: end < lines.length ? end : null,
		},
	};
}
