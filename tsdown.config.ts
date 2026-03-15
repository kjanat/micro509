import { writeFile } from 'node:fs/promises';
import { defineConfig } from 'tsdown';
import jsr from './jsr.json' with { type: 'json' };
import pkg from './package.json' with { type: 'json' };

const jsrJson: Omit<typeof jsr, 'exports' | 'version'> & {
	exports: Record<string, string>;
	version: string;
} = { ...jsr, exports: {} };

const entry = {
	index: 'src/index.ts',
	certificate: 'src/certificate.ts',
	crl: 'src/crl.ts',
	csr: 'src/csr.ts',
	extensions: 'src/extensions.ts',
	identity: 'src/identity.ts',
	keys: 'src/keys/index.ts',
	name: 'src/name.ts',
	'name-constraints': 'src/name-constraints.ts',
	ocsp: 'src/ocsp.ts',
	parse: 'src/parse.ts',
	pem: 'src/pem/index.ts',
	pfx: 'src/pfx.ts',
	pkcs7: 'src/pkcs7.ts',
	'pkcs12-mac': 'src/pkcs12-mac.ts',
	policy: 'src/policy.ts',
	result: 'src/result/index.ts',
	revocation: 'src/revocation/index.ts',
	verify: 'src/verify/index.ts',
	x509: 'src/x509/index.ts',
} as const satisfies Record<string, string>;

export default defineConfig({
	entry,
	name: pkg.name,
	format: 'esm',
	dts: true,
	clean: true,
	platform: 'neutral',
	target: 'es2024',
	tsconfig: 'tsconfig.src.json',
	sourcemap: true,
	unbundle: true,
	hash: false,
	minify: true,
	inputOptions: { resolve: { mainFields: ['browser', 'module', 'main'] } },
	hooks: {
		'build:done': async () => {
			jsrJson.exports = Object.fromEntries(
				Object.entries(entry).map(([name, sourcePath]) => [
					name === 'index' ? '.' : `./${name}`,
					`./${sourcePath}`,
				]),
			);
			jsrJson.version = pkg.version;
			await writeFile('jsr.json', `${JSON.stringify(jsrJson, null, '\t')}\n`);
		},
	},
	exports: true,
	onSuccess: 'bunx sort-package-json --quiet {package,jsr}.json',
	attw: { profile: 'esm-only', ignoreRules: ['no-resolution'] },
	unused: true,
	publint: true,
});
