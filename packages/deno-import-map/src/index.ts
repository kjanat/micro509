import fs from 'node:fs';
import path from 'node:path';

interface PackageImports {
	readonly imports?: Readonly<Record<string, unknown>>;
}

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

export interface ImportMapTarget {
	readonly root: string;
	readonly manifest?: string;
	readonly out: string;
	readonly additionalImports?: Readonly<Record<string, string>>;
}

export function writeDenoImportMap(target: ImportMapTarget): string {
	const manifest: PackageImports = JSON.parse(
		fs.readFileSync(path.join(target.root, target.manifest ?? 'package.json'), 'utf8'),
	);
	const imports: Record<string, string> = {};

	for (const [key, value] of Object.entries(manifest.imports ?? {})) {
		if (typeof value !== 'string') continue;
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
	for (const [key, value] of Object.entries(target.additionalImports ?? {})) imports[key] = value;

	const sorted = Object.fromEntries(
		Object.entries(imports).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
	);
	const out = path.join(target.root, target.out);
	fs.mkdirSync(path.dirname(out), { recursive: true });
	fs.writeFileSync(out, `${JSON.stringify({ imports: sorted }, null, '\t')}\n`);
	return out;
}
