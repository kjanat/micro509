#!/usr/bin/env bun
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const directory = fileURLToPath(new URL('.', import.meta.url));
const bin = path.join(directory, 'bin');
mkdirSync(bin, { recursive: true });

const env = { ...process.env, GOWORK: 'off', GOOS: 'js', GOARCH: 'wasm' };
const options = { cwd: directory, env };
execFileSync(
	'go',
	['build', '-trimpath', '-ldflags=-s -w', '-o', path.join(bin, 'compat.wasm'), '.'],
	{ ...options, stdio: 'inherit' },
);
const goroot = execFileSync('go', ['env', 'GOROOT'], { ...options, encoding: 'utf8' }).trim();
const runtime = path.join(bin, 'wasm_exec.cjs');
rmSync(runtime, { force: true });
writeFileSync(runtime, readFileSync(path.join(goroot, 'lib/wasm/wasm_exec.js')));
console.log(
	`Built ${path.relative(process.cwd(), path.join(bin, 'compat.wasm'))} and its matching Go JS runtime.`,
);
