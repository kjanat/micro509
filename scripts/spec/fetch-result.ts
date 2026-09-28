import path from 'node:path';
import type { Out } from 'dreamcli';
import { CLIError } from 'dreamcli';
import { discover, repositoryRoot } from './corpus.ts';
import type { SourceDiagnostic } from './source-quality.ts';

export interface FetchEvidence {
	readonly htmlPath?: string;
	readonly sourcePath?: string;
	readonly diagnostics?: readonly SourceDiagnostic[];
}

/** Report the written file using exactly the identifier the reader will resolve. */
export function reportFetched(
	out: Out,
	destination: string,
	url: string,
	root: string = repositoryRoot,
	evidence?: FetchEvidence,
): void {
	const absolute = path.resolve(destination);
	const relativePath = path.relative(root, absolute).split(path.sep).join('/');
	if (!out.jsonMode) {
		out.log(relativePath);
		if (evidence?.htmlPath !== undefined) out.log(evidence.htmlPath);
		return;
	}
	// Discovery owns normalization AND collision suffixes. Source aliases and
	// download item IDs are not necessarily reader IDs, even with a prefix.
	const document = discover(path.resolve(root)).find((ref) => ref.path === absolute);
	if (document === undefined) {
		throw new CLIError(`fetched file is not indexed: ${relativePath}`, {
			code: 'SPEC_FETCH_UNINDEXED',
		});
	}
	out.json({ kind: document.kind, id: document.id, path: relativePath, url, ...evidence });
}
