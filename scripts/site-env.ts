#!/usr/bin/env bun
/**
 * Resolves the git branch + commit for the docs site, exports them as
 * `MICRO509_GIT_BRANCH` / `MICRO509_GIT_COMMIT`, then spawns the wrapped command.
 *
 * Precedence (first non-empty wins):
 *   explicit override   MICRO509_GIT_BRANCH / MICRO509_GIT_COMMIT
 *   Cloudflare CI       WORKERS_CI_BRANCH   / WORKERS_CI_COMMIT_SHA
 *   GitHub Actions      GITHUB_REF_NAME     / GITHUB_SHA
 *   local git           git branch --show-current / git rev-parse --short=7 HEAD
 *
 * Why a wrapper, not inline shell: this chain was duplicated across four package
 * scripts and broke on detached-HEAD CI checkouts (Cloudflare) where
 * `git branch --show-current` is empty. One source of truth, and it runs
 * identically everywhere — no Bun-Shell vs `sh` portability gaps, no reliance on
 * a `source` builtin.
 *
 * Usage: bun scripts/site-env.ts <command> [args...]
 */
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { argv, env, exit, platform } from 'node:process';
import { error } from 'node:console';

/** Run a git command, returning trimmed stdout, or '' on any failure. */
const gitOut = (args: readonly string[]): string => {
	const r = spawnSync('git', [...args], { encoding: 'utf8' });
	return r.status === 0 ? r.stdout.trim() : '';
};

/** First trimmed non-empty value, or '' if none. */
const firstNonEmpty = (...vals: readonly (string | undefined)[]): string => {
	for (const v of vals) {
		const t = v?.trim();
		if (t) return t;
	}
	return '';
};

const branch = firstNonEmpty(
	env.MICRO509_GIT_BRANCH,
	env.WORKERS_CI_BRANCH,
	env.GITHUB_REF_NAME,
	gitOut(['branch', '--show-current']),
);

const commit = firstNonEmpty(
	env.MICRO509_GIT_COMMIT,
	env.WORKERS_CI_COMMIT_SHA,
	env.GITHUB_SHA,
	gitOut(['rev-parse', '--short=7', 'HEAD']),
);

const [cmd, ...args] = argv.slice(2);
if (cmd === undefined) {
	error('site-env: no command given\nUsage: bun scripts/site-env.ts <command> [args...]');
	exit(2);
}

/** Doc-site tools (vitepress, typedoc, vue-tsc) are devDeps of the `site/.vitepress` workspace member,
 * so their binaries live in that member's node_modules, not the repo root. Prepend that .bin to PATH
 * so bare tool names resolve while cwd stays the repo root (typedoc/vitepress configs are root-relative).
 *
 * biome-ignore format: don't like it */
const siteBin = join(dirname(fileURLToPath(import.meta.url)), '..', 'site', '.vitepress', 'node_modules', '.bin');
const pathSep = platform === 'win32' ? ';' : ':';

const { status, error: e } = spawnSync(cmd, args, {
	stdio: 'inherit',
	env: {
		...env,
		PATH: `${siteBin}${pathSep}${env.PATH ?? ''}`,
		MICRO509_GIT_BRANCH: branch,
		MICRO509_GIT_COMMIT: commit,
	},
});

if (e) {
	error(`site-env: failed to spawn '${cmd}': ${e.message}`);
	exit(1);
}

exit(status ?? 1);
