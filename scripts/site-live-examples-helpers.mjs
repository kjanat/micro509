import path from 'node:path';

/**
 * Return one canonical route for every built HTML file containing LiveCode
 * markup, grouped under the version prefix encoded by its dist path.
 *
 * @param {Map<string, string>} routes
 * @param {(file: string) => string} readFile
 * @returns {Array<{version: string, route: string, expectedBlocks: number}>}
 */
export function findExamplePages(routes, readFile) {
	/** @type {Map<string, {version: string, route: string, expectedBlocks: number}>} */
	const pages = new Map();
	/** @type {Map<string, number>} */
	const blockCounts = new Map();

	for (const [servedRoute, file] of routes) {
		if (path.extname(file) !== '.html') continue;
		let expectedBlocks = blockCounts.get(file);
		if (expectedBlocks === undefined) {
			const content = readFile(file);
			expectedBlocks = [...content.matchAll(/(?:^|\s)class\s*=\s*(["'])(.*?)\1/g)].filter((match) =>
				match[2]?.trim().split(/\s+/).includes('live-code'),
			).length;
			blockCounts.set(file, expectedBlocks);
		}
		if (expectedBlocks === 0) continue;

		const route = canonicalRoute(servedRoute);
		const version = versionForRoute(route);
		const key = `${version}\0${file}`;
		if (!pages.has(key)) pages.set(key, { version, route, expectedBlocks });
	}

	return [...pages.values()].sort((a, b) => a.route.localeCompare(b.route));
}

/** @param {string} route */
function canonicalRoute(route) {
	if (route.endsWith('/index.html')) return route.slice(0, -'index.html'.length);
	if (route.endsWith('.html')) route = route.slice(0, -'.html'.length);
	if (route.endsWith('/index')) return route.slice(0, -'index'.length);
	return route;
}

/** @param {string} route */
function versionForRoute(route) {
	const first = route.split('/')[1];
	if (first === 'next') return 'next';
	if (first !== undefined && /^v\d+\.\d+\.\d+$/.test(first)) return first;
	return '(latest)';
}
