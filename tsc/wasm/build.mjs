#!/usr/bin/env bun
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const directory = fileURLToPath(new URL('.', import.meta.url));
const native = path.dirname(fileURLToPath(import.meta.resolve('@kjanat/tsc-bridge')));
const bin = path.join(directory, 'bin');
const build = path.join(bin, 'build');
mkdirSync(build, { recursive: true });

// Reuse the native bridge and its exact dependency pin without a second copy to maintain.
for (const name of ['go.mod', 'go.sum']) {
	copyFileSync(path.join(native, name), path.join(build, name));
}
const source = readFileSync(path.join(native, 'main.go'), 'utf8');
assert.equal(source.match(/^func main\(\) \{/gm)?.length, 1, 'Expected one native main function');
writeFileSync(
	path.join(build, 'bridge.go'),
	source.replace(/^func main\(\) \{/m, 'func cliMain() {'),
);
copyFileSync(path.join(directory, 'main.go'), path.join(build, 'main.go'));

const env = {
	...process.env,
	GOWORK: 'off',
	GOOS: 'js',
	GOARCH: 'wasm',
	GOMAXPROCS: process.env.GOMAXPROCS ?? '2',
	GOMEMLIMIT: process.env.GOMEMLIMIT ?? '1GiB',
};
const options = { cwd: build, env };
execFileSync(
	'go',
	['build', '-p', '2', '-trimpath', '-ldflags=-s -w', '-o', path.join(bin, 'tsc-bridge.wasm'), '.'],
	{ ...options, stdio: 'inherit' },
);
const goroot = execFileSync('go', ['env', 'GOROOT'], { ...options, encoding: 'utf8' }).trim();
copyFileSync(path.join(goroot, 'lib/wasm/wasm_exec.js'), path.join(bin, 'wasm_exec.js'));
console.log(
	`Built ${path.relative(process.cwd(), path.join(bin, 'tsc-bridge.wasm'))} and its matching Go JS runtime.`,
);
