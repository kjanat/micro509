import assert from 'node:assert/strict';
import test from 'node:test';
import { matchBlockedRequest } from './site-content-blocker.mjs';

const page = 'http://127.0.0.1:4173/guide/verification';

test('blocks the original fingerprint regression including query strings', () => {
	for (const suffix of ['', '?v=1', '/extra']) {
		assert.equal(
			matchBlockedRequest(`https://cdn.example/fingerprint.js${suffix}`, page),
			'/fingerprint.js^$domain=~github.com',
		);
	}
	assert.equal(matchBlockedRequest('https://cdn.example/fingerprint.json', page), undefined);
	assert.equal(matchBlockedRequest('https://cdn.example/fingerprint.js.map', page), undefined);
});

test('domain exclusions apply to the document and its subdomains, not the resource', () => {
	const resource = 'https://cdn.example/fingerprint.js';
	assert.equal(matchBlockedRequest(resource, 'https://github.com/'), undefined);
	assert.equal(matchBlockedRequest(resource, 'https://docs.github.com/'), undefined);
	assert.ok(matchBlockedRequest(resource, 'https://notgithub.com/'));
	assert.ok(matchBlockedRequest('https://github.com/fingerprint.js', page));
});

test('matches generic wildcard paths from both source lists', () => {
	assert.equal(
		matchBlockedRequest('https://cdn.example/analytics.example/event?id=1', page),
		'/analytics.*/event?',
	);
	assert.equal(
		matchBlockedRequest(
			'https://cdn.example/pmc-plugins/pmc-social-share-bar/v2/tracking.js',
			page,
		),
		'/pmc-plugins/pmc-social-share-bar/*/tracking.js',
	);
	assert.equal(matchBlockedRequest('https://cdn.example/library.js', page), undefined);
	assert.equal(matchBlockedRequest('blob:http://127.0.0.1/fingerprint.js', page), undefined);
});
