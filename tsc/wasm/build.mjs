#!/usr/bin/env bun
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const directory = fileURLToPath(new URL('.', import.meta.url));
const bin = path.join(directory, 'bin');
mkdirSync(bin, { recursive: true });

const env = {
	...process.env,
	GOWORK: 'off',
	GOOS: 'js',
	GOARCH: 'wasm',
	GOMAXPROCS: process.env.GOMAXPROCS ?? '2',
	GOMEMLIMIT: process.env.GOMEMLIMIT ?? '1GiB',
};
const options = { cwd: directory, env };
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
