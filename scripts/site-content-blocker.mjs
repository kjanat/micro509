/**
 * Offline regression rules for generic module paths, sampled from EasyPrivacy
 * and uBlock's privacy list on 2026-10-23. This is a regression fixture, not a
 * complete content-blocker engine or a copy of either subscription.
 *
 * https://easylist.to/easylist/easyprivacy.txt
 * https://github.com/uBlockOrigin/uAssets/blob/master/filters/privacy.txt
 */
const RULES = [
	'/fingerprint.js^$domain=~github.com',
	'/fingerprint.min.js',
	'/fingerprint/iife.min.js',
	'/fingerprint2.js',
	'/fingerprint2.min.js',
	'/fingerprint3.js',
	'/fingerprint3.min.js',
	'/analytics.*/event?',
	'/analytics-tracking.js',
	'/_vercel/insights/script.js',
	'/_vercel/speed-insights/script.js',
	'/discourse-fingerprint-$domain=~btt.community',
	'/pmc-plugins/pmc-social-share-bar/*/tracking.js',
];

const compiled = RULES.map((rule) => {
	const [pattern = '', options = ''] = rule.split('$');
	const excludedDomains = options.startsWith('domain=')
		? options
				.slice('domain='.length)
				.split('|')
				.map((domain) => domain.slice(1))
		: [];
	const expression = [...pattern]
		.map((character) => {
			if (character === '*') return '.*';
			if (character === '^') return '(?:[^a-zA-Z0-9_.%-]|$)';
			return character.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
		})
		.join('');
	return { rule, excludedDomains, pattern: new RegExp(expression, 'i') };
});

/**
 * Match generic path rules, including wildcards, separator anchors and source
 * document domain exclusions. Domain exclusions concern the page, not the CDN.
 * @param {string} url
 * @param {string} documentUrl
 * @param {string} [_resourceType]
 * @returns {string | undefined}
 */
export function matchBlockedRequest(url, documentUrl, _resourceType) {
	const requestUrl = new URL(url);
	if (!/^https?:$/.test(requestUrl.protocol)) return undefined;
	const hostname = new URL(documentUrl).hostname.toLowerCase();
	return compiled.find(
		({ excludedDomains, pattern }) =>
			!excludedDomains.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`)) &&
			pattern.test(requestUrl.pathname + requestUrl.search),
	)?.rule;
}
