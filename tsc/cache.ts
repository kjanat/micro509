import { createHash } from 'node:crypto';
import { mkdir, open, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

export async function fingerprint(root: string, paths: readonly string[]): Promise<string> {
	const hash = createHash('sha256');
	for (const path of [...paths].sort()) {
		await using file = await open(join(root, path), 'r');
		const metadata = await file.stat();
		hash.update(JSON.stringify([path, metadata.size, metadata.mode & 0o111]));
		hash.update(await file.readFile());
	}
	return hash.digest('hex');
}

/** A stamp is valid only while both the build inputs and every output match. */
export async function cachedBuild(options: {
	root: string;
	stamp: string;
	inputs: () => Promise<string>;
	outputs: () => Promise<readonly string[]>;
	build: () => Promise<void>;
}): Promise<'cached' | 'built'> {
	const inputs = await options.inputs();
	const stamp = join(options.root, options.stamp);
	try {
		const outputs = await fingerprint(options.root, await options.outputs());
		if ((await readFile(stamp, 'utf8')) === `${inputs}\n${outputs}\n`) return 'cached';
	} catch (error) {
		if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error;
	}
	await options.build();
	if ((await options.inputs()) !== inputs)
		throw new Error('Compiler build inputs changed during the build');
	const outputs = await fingerprint(options.root, await options.outputs());
	await mkdir(dirname(stamp), { recursive: true });
	const temporary = `${stamp}.${process.pid}`;
	await writeFile(temporary, `${inputs}\n${outputs}\n`);
	await rename(temporary, stamp);
	return 'built';
}
