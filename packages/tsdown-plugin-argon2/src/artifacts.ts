const vendor = 'vendor/argon2';
const domain = 'kdf';
const binary = 'argon2.wasm';
const loader = 'argon2-module';
const output = `${domain}/${binary}`;
const oracle = 'test/oracles/argon2';

/** Repository inputs and package outputs shared by compilation and bundling. */
export const argon2Artifacts = {
	vendor,
	tooling: 'packages/tsdown-plugin-argon2/src',
	wasm: `${oracle}/${binary}`,
	manifest: `${vendor}/build.json`,
	loader: `${oracle}/${loader}.ts`,
	output,
	assetImport: `./${output}`,
	sourceUrl: `new URL('./${binary}', import.meta.url)`,
	moduleSpecifier: `#test/oracles/argon2/${loader}`,
	workerModule: `\0micro509-${loader}-workerd`,
} as const;
