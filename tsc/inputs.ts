import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { $ } from 'bun';
import { fingerprint } from './cache.ts';

/** Build inputs shared by the local stamp and the GitHub Actions cache key. */
export async function compilerInputs(root: string): Promise<string> {
	const sources = await Array.fromAsync(
		new Bun.Glob('tsc/**/*.{ts,json}').scan({ cwd: root, onlyFiles: true }),
	);
	const paths = sources.filter(
		(path) => !/\/(bin|dist|node_modules|test)\//.test(path) && !path.endsWith('.test.ts'),
	);
	paths.push('bun.lock', 'tsdown.config.ts', '.dprint.json');

	const pkg = await Bun.file(join(root, 'package.json')).json();
	// Release metadata does not change the compiler packages. Keep dependency
	// resolution and the commands/configuration used to build them in the key.
	const manifest = {
		type: pkg.type,
		imports: pkg.imports,
		workspaces: pkg.workspaces,
		build: pkg.scripts?.['build:tsc'],
		dependencies: pkg.dependencies,
		devDependencies: pkg.devDependencies,
		overrides: pkg.overrides,
		catalog: pkg.catalog,
		catalogs: pkg.catalogs,
	};
	return createHash('sha256')
		.update(await fingerprint(root, paths))
		.update(JSON.stringify(manifest))
		.digest('hex');
}

/** Go artifacts depend on Go sources, build recipes and the Go toolchain. */
export async function goInputs(root: string): Promise<string> {
	const paths = await Array.fromAsync(
		new Bun.Glob('tsc/**/*.{go,mod,sum}').scan({ cwd: root, onlyFiles: true }),
	);
	paths.push(
		...(await Array.fromAsync(new Bun.Glob('go.work*').scan({ cwd: root, onlyFiles: true }))),
	);
	const hash = createHash('sha256');
	for (const name of ['bridge', 'compat', 'wasm']) {
		const pkg = await Bun.file(join(root, `tsc/${name}/package.json`)).json();
		hash.update(JSON.stringify([name, pkg.scripts.build]));
		const recipe = `tsc/${name}/build.ts`;
		if (await Bun.file(join(root, recipe)).exists()) paths.push(recipe);
	}
	const toolchain = await $.cwd(
		root,
	)`go -C tsc/bridge env -json GOVERSION GOOS GOARCH GOAMD64 GOARM GOARM64 CGO_ENABLED GOEXPERIMENT GOFLAGS CC CXX CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_LDFLAGS`.text();
	return hash
		.update(await fingerprint(root, paths))
		.update(toolchain)
		.digest('hex');
}
