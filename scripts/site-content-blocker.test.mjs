import assert from 'node:assert/strict';
import test from 'node:test';
import { matchBlockedRequest } from './site-content-blocker.mjs';

const page = 'http://127.0.0.1:4173/guide/verification';

test('blocks the original fingerprint regression including query strings', () => {
	for (const suffix of ['', '?v=1', '/extra']) {
		assert.equal(
			matchBlockedRequest(`https://cdn.example/fingerprint.js${suffix}`, page),
			'/fingerprint.js^$from=~github.com',
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

test('applies resource types to generic rules outside the original sample', () => {
	const url = 'https://cdn.example/2x2.gif?visit=1';
	assert.ok(matchBlockedRequest(url, page, 'image'));
	assert.equal(matchBlockedRequest(url, page, 'script'), undefined);
});

test('applies first-party restrictions using the public suffix list', () => {
	const url = 'https://cdn.example.co.uk/code/e.js';
	assert.ok(matchBlockedRequest(url, 'https://www.example.co.uk/'));
	assert.equal(matchBlockedRequest(url, 'https://unrelated.co.uk/'), undefined);
});

test('matches uBlock regex rules with strict first-party and case restrictions', () => {
	const url = `https://cdn.example/abcdefghijkl/${'A'.repeat(100)}`;
	assert.ok(matchBlockedRequest(url, 'https://cdn.example/'));
	assert.equal(matchBlockedRequest(url, 'https://www.example/'), undefined);
	assert.equal(matchBlockedRequest(url, 'https://cdn.example/', 'image'), undefined);
	assert.equal(
		matchBlockedRequest(url.replace('abcdefghijkl', 'ABCDEFGHIJKL'), 'https://cdn.example/'),
		undefined,
	);
});

test('loads generic EasyPrivacy and uBlock rules absent from the old fixture', () => {
	assert.ok(matchBlockedRequest('https://cdn.example/metrics/umd.min.js', page));
	assert.ok(
		matchBlockedRequest('https://cdn.jsdelivr.net/npm/tracker@latest/dist/script.min.js', page),
	);
	assert.equal(
		matchBlockedRequest(
			'https://cdn.jsdelivr.net/npm/tracker@latest/dist/script.min.js',
			page,
			'image',
		),
		undefined,
	);
});

test('applies source-scoped exceptions over generic blocking rules', () => {
	const resource = 'https://cdn.example/ga-tracking.min.js';
	assert.ok(matchBlockedRequest(resource, page));
	assert.equal(matchBlockedRequest(resource, 'https://boots.no/'), undefined);
	assert.equal(matchBlockedRequest(resource, 'https://checkout.platekompaniet.no/'), undefined);
	assert.ok(matchBlockedRequest(resource, 'https://boots.no/', 'image'));
});
