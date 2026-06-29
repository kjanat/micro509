// @ts-check
import { argv, env } from 'node:process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import pkg from '#pkg' with { type: 'json' };

const root = resolve(dirname(fileURLToPath(import.meta.resolve('#pkg'))));

/** @type {Partial<import("typedoc").TypeDocOptions> & Partial<import("typedoc-plugin-markdown").PluginOptions>} */
const config = {
	plugin: ['typedoc-plugin-markdown', 'typedoc-vitepress-theme'],
	name: pkg.name,
	cname: new URL(pkg.homepage).hostname,
	includeVersion: true,
	githubPages: false, // This inserts a .nojekyll file, but we deploy with an Action, so we don't need it.
	entryPoints: [`${root}/src/**/index.ts`],
	entryPointStrategy: 'resolve',
	tsconfig: `${root}/tsconfig.src.json`,
	out: `${root}/site/api`,
	gitRevision: getRequiredEnv(),
	excludePrivate: true,
	excludeInternal: true,
	excludeReferences: true,
	readme: 'none',
	cleanOutputDir: false,
	entryFileName: 'modules',
	router: 'module',
	hidePageHeader: true,
	hideBreadcrumbs: false,
	typePrintWidth: 60,
	commentStyle: 'jsdoc',
	watch: env.WATCH === 'true' || argv.includes('--watch'),
};

export default config;

/**
 * @param {readonly string[]} names @default ``['MICRO509_GIT_BRANCH', 'WORKERS_CI_BRANCH', 'GITHUB_REF_NAME']``
 * @param {string} [fallback] @default ``"master"``
 * @returns {string}
 */
function getRequiredEnv(
	names = ['MICRO509_GIT_BRANCH', 'WORKERS_CI_BRANCH', 'GITHUB_REF_NAME'],
	fallback = 'master',
) {
	for (const name of names) {
		const v = env[name]?.trim();
		if (v) return v;
	}
	return fallback;
}
