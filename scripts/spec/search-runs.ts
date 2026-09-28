export interface RenderLine {
	readonly line: number;
	readonly text: string;
	readonly match: boolean;
	readonly label: string;
}

function splitRuns(lines: readonly RenderLine[]): RenderLine[][] {
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
	return runs;
}

function matchLabel(run: readonly RenderLine[] | undefined): string | undefined {
	return run?.find((line) => line.match)?.label;
}

function attachOrphanRun(runs: RenderLine[][], index: number): void {
	const run = runs[index];
	if (run === undefined) return;
	const previous = runs[index - 1];
	const next = runs[index + 1];
	if (previous !== undefined && (next === undefined || matchLabel(previous) === run[0]?.label)) {
		previous.push(...run);
	} else {
		next?.unshift(...run);
	}
	runs.splice(index, 1);
}

function attachOrphanRuns(runs: RenderLine[][]): void {
	for (let index = 0; index < runs.length; ) {
		if (runs[index]?.some((line) => line.match) === true) {
			index += 1;
			continue;
		}
		attachOrphanRun(runs, index);
	}
}

/** Keep context across removed page furniture attached to an actual match. */
export function runsOf(lines: readonly RenderLine[]): readonly (readonly RenderLine[])[] {
	if (!lines.some((line) => line.match)) return [];
	const runs = splitRuns(lines);
	attachOrphanRuns(runs);
	return runs;
}
