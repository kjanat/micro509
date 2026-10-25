import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { TsdownPlugin } from 'tsdown';
import { argon2Artifacts } from './artifacts.ts';
import { argon2Inputs, buildArgon2 } from './build.ts';

/** Build and package micro509's portable Argon2 artifacts in tsdown. */
export function argon2Plugin(options: { root: string; workerd?: boolean }): TsdownPlugin {
	const root = resolve(options.root);
	const loader = resolve(root, argon2Artifacts.loader);
	let assetReference: string | undefined;
	return {
		name: 'micro509:argon2',
		buildStart: {
			order: 'pre',
			sequential: true,
			async handler() {
				const inputs = await argon2Inputs(root);
				for (const file of [...inputs.files, ...inputs.directories]) this.addWatchFile(file);
				for (const file of [argon2Artifacts.wasm, argon2Artifacts.manifest]) {
					this.addWatchFile(resolve(root, file));
				}
				const result = await buildArgon2(root);
				if (result.rebuilt) this.info('Rebuilt portable Argon2 WASM');
				assetReference = this.emitFile({
					type: 'asset',
					fileName: argon2Artifacts.output,
					source: await readFile(resolve(root, argon2Artifacts.wasm)),
				});
			},
		},
		resolveId(source, importer) {
			if (source === 'node:fs/promises' && importer === loader)
				return { id: source, external: true };
			if (!options.workerd) return;
			if (source === argon2Artifacts.moduleSpecifier) return argon2Artifacts.workerModule;
			if (source === argon2Artifacts.assetImport) return { id: source, external: true };
		},
		load(id) {
			if (id !== argon2Artifacts.workerModule) return;
			return `import module from '${argon2Artifacts.assetImport}';
export function moduleFor() { return Promise.resolve(module); }`;
		},
		transform(code, id) {
			if (options.workerd || id !== loader) return;
			if (assetReference === undefined) throw new Error('Argon2 asset has not been emitted');
			return {
				code: code.replace(
					argon2Artifacts.sourceUrl,
					`new URL(import.meta.ROLLUP_FILE_URL_${assetReference})`,
				),
				map: null,
			};
		},
	};
}
