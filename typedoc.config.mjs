import pkg from './package.json' with { type: 'json' };

/** @type {Partial<import("typedoc").TypeDocOptions>} */
const config = {
	plugin: ['typedoc-plugin-markdown', 'typedoc-vitepress-theme'],
	name: pkg.name,
	cname: new URL(pkg.homepage).hostname,
	includeVersion: true,
	githubPages: false, // This inserts a .nojekyll file, but we deploy with an Action, so we don't need it.
	entryPoints: ['src/**/index.ts'],
	entryPointStrategy: 'resolve',
	tsconfig: './tsconfig.src.json',
	out: 'site/api',
	gitRevision: 'master',
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
};

export default config;
