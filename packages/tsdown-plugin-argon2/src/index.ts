import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import type { TsdownPlugin } from 'tsdown';
import { argon2Inputs, buildArgon2 } from './build.ts';

/** Build and package micro509's portable Argon2 artifacts in tsdown. */
export function argon2Plugin(options: { root: string; workerd?: boolean }): TsdownPlugin {
	const root = resolve(options.root);
	const moduleId = '\0micro509-argon2-workerd';
	const assetId = './kdf/argon2.wasm';
	return {
		name: 'micro509:argon2',
		buildStart: {
			order: 'pre',
			sequential: true,
			async handler() {
				const inputs = await argon2Inputs(root);
				for (const file of [...inputs.files, ...inputs.directories]) this.addWatchFile(file);
				for (const file of [
					'src/kdf/argon2.wasm',
					'src/kdf/argon2-wasm.ts',
					'vendor/argon2/build.json',
				]) {
					this.addWatchFile(resolve(root, file));
				}
				const result = await buildArgon2(root);
				if (result.rebuilt) this.info('Rebuilt portable Argon2 WASM');
			},
		},
		resolveId(source) {
			if (!options.workerd) return;
			if (source === '#micro509/kdf/argon2-module') return moduleId;
			if (source === assetId) return { id: assetId, external: true };
		},
		load(id) {
			if (id !== moduleId) return;
			return `import module from '${assetId}';
export function moduleFor() { return Promise.resolve(module); }`;
		},
		async generateBundle() {
			if (!options.workerd) return;
			this.emitFile({
				type: 'asset',
				fileName: 'kdf/argon2.wasm',
				source: await readFile(resolve(root, 'src/kdf/argon2.wasm')),
			});
		},
	};
}
