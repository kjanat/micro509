/**
 * Expands a manifest's `imports` map into a Deno import map.
 *
 * Node resolves subpath-pattern imports (`#lib/*` -> `./src/*.ts`) natively, and
 * so do `deno check` and `deno lint`. `deno doc` does not: it reports every such
 * specifier as "not a dependency". An import map bridges the gap, except import
 * maps support neither globs nor extension-appending — a prefix key must map to
 * a prefix value. So each pattern is expanded here into one explicit entry per
 * file it can resolve to, alongside the non-pattern entries copied verbatim.
 *
 * Nothing about the host project is assumed: which tree to read, which manifest
 * holds the `imports` map, and where the result is written are all arguments.
 * The patterns and the directories they point at come from that manifest.
 *
 * @module
 */
import fs from 'node:fs';
import path from 'node:path';

/** The `imports` map of a package.json — the only field this reads. */
interface PackageImports {
	readonly imports?: Readonly<Record<string, string>>;
}

/** A `key` -> `target` pair split around its single `*`. */
interface Pattern {
	readonly keyPrefix: string;
	readonly keySuffix: string;
	readonly targetPrefix: string;
	readonly targetSuffix: string;
}

function patternOf(key: string, target: string): Pattern | undefined {
	const keyStar = key.indexOf('*');
	const targetStar = target.indexOf('*');
	if (keyStar === -1 || targetStar === -1) return undefined;
	return {
		keyPrefix: key.slice(0, keyStar),
		keySuffix: key.slice(keyStar + 1),
		targetPrefix: target.slice(0, targetStar),
		targetSuffix: target.slice(targetStar + 1),
	};
}

/** Every file under `dir` (recursively), as paths relative to it. */
function filesUnder(dir: string, prefix = ''): string[] {
	if (!fs.existsSync(dir)) return [];
	const files: string[] = [];
	for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
		const rel = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
		if (entry.isDirectory()) files.push(...filesUnder(path.join(dir, entry.name), rel));
		else files.push(rel);
	}
	return files;
}

/** Which tree to map, which manifest to read, where to write the result. */
export interface ImportMapTarget {
	/** Tree the map's relative targets resolve against. */
	readonly root: string;
	/** Manifest holding the `imports` map, relative to `root`. Default `package.json`. */
	readonly manifest?: string;
	/** Where the import map is written, relative to `root`; parent directories are created. */
	readonly out: string;
}

/**
 * Write the import map and return its absolute path.
 *
 * Each pattern entry yields two specifiers per file — with and without the
 * target's extension (`#lib/x` and `#lib/x.ts` for `./src/x.ts`). Both are legal
 * Node imports, an import map cannot append the extension itself, and which one
 * a source file uses is the source file's business.
 */
export function writeDenoImportMap(target: ImportMapTarget): string {
	const manifest: PackageImports = JSON.parse(
		fs.readFileSync(path.join(target.root, target.manifest ?? 'package.json'), 'utf8'),
	);
	const imports: Record<string, string> = {};

	for (const [key, value] of Object.entries(manifest.imports ?? {})) {
		const pattern = patternOf(key, value);
		if (pattern === undefined) {
			imports[key] = value;
			continue;
		}
		const dir = path.join(target.root, pattern.targetPrefix);
		for (const file of filesUnder(dir)) {
			if (!file.endsWith(pattern.targetSuffix)) continue;
			const star = file.slice(0, file.length - pattern.targetSuffix.length);
			const resolved = `${pattern.targetPrefix}${file}`;
			imports[`${pattern.keyPrefix}${star}${pattern.keySuffix}`] = resolved;
			imports[`${pattern.keyPrefix}${file}${pattern.keySuffix}`] = resolved;
		}
	}

	const sorted = Object.fromEntries(Object.entries(imports).sort(([a], [b]) => a.localeCompare(b)));
	const out = path.join(target.root, target.out);
	fs.mkdirSync(path.dirname(out), { recursive: true });
	fs.writeFileSync(out, `${JSON.stringify({ imports: sorted }, null, '\t')}\n`);
	return out;
}
