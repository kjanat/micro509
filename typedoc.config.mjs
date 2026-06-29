import { argv, env } from 'node:process';
import { name, homepage } from './package.json' with { type: 'json' };

/** @type {Partial<import("typedoc").TypeDocOptions>} */
const config = {
	plugin: ['typedoc-plugin-markdown', 'typedoc-vitepress-theme'],
	name,
	cname: new URL(homepage).hostname,
	includeVersion: true,
	githubPages: false, // This inserts a .nojekyll file, but we deploy with an Action, so we don't need it.
	entryPoints: ['src/**/index.ts'],
	entryPointStrategy: 'resolve',
	tsconfig: 'tsconfig.src.json',
	out: 'site/api',
	gitRevision: env.MICRO509_GIT_BRANCH?.trim() || 'master',
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
