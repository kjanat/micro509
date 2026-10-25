const vendor = 'vendor/argon2';
const domain = 'kdf';
const binary = 'argon2.wasm';
const loader = 'argon2-module';
const output = `${domain}/${binary}`;

/** Repository inputs and package outputs shared by compilation and bundling. */
export const argon2Artifacts = {
	vendor,
	tooling: 'packages/tsdown-plugin-argon2/src',
	wasm: `src/${output}`,
	manifest: `${vendor}/build.json`,
	loader: `src/${domain}/${loader}.ts`,
	output,
	assetImport: `./${output}`,
	sourceUrl: `new URL('./${binary}', import.meta.url)`,
	moduleSpecifier: `#micro509/${domain}/${loader}`,
	workerModule: `\0micro509-${loader}-workerd`,
} as const;
