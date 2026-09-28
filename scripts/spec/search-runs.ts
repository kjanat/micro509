export interface RenderLine {
	readonly line: number;
	readonly text: string;
	readonly match: boolean;
	readonly label: string;
}

/** Keep context across removed page furniture attached to an actual match. */
export function runsOf(lines: readonly RenderLine[]): readonly (readonly RenderLine[])[] {
	const runs: RenderLine[][] = [];
	let current: RenderLine[] = [];
	let label: string | undefined;
	for (const entry of lines) {
		const previous = current.at(-1);
		const gap = previous !== undefined && entry.line - previous.line > 1;
		const relabel = entry.match && label !== undefined && entry.label !== label;
		if (gap || relabel) {
			if (current.length > 0) runs.push(current);
			current = [];
			label = undefined;
		}
		if (entry.match) label = entry.label;
		current.push(entry);
	}
	if (current.length > 0) runs.push(current);
	if (!lines.some((line) => line.match)) return [];
	for (let index = 0; index < runs.length; ) {
		const run = runs[index];
		if (run === undefined || run.some((line) => line.match)) {
			index += 1;
			continue;
		}
		const previous = runs[index - 1];
		const next = runs[index + 1];
		const previousLabel = previous?.find((line) => line.match)?.label;
		if (previous !== undefined && (next === undefined || previousLabel === run[0]?.label)) {
			previous.push(...run);
		} else if (next !== undefined) {
			next.unshift(...run);
		}
		runs.splice(index, 1);
	}
	return runs;
}
