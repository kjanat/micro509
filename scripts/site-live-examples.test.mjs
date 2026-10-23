import assert from 'node:assert/strict';
import test from 'node:test';
import { findExamplePages } from './site-live-examples-helpers.mjs';

test('finds SSR examples across versions and nested pages without route aliases', () => {
	const routes = new Map([
		['/index.html', '/dist/index.html'],
		['/', '/dist/index.html'],
		['/index', '/dist/index.html'],
		['/guide/start.html', '/dist/guide/start.html'],
		['/guide/start', '/dist/guide/start.html'],
		['/next/index.html', '/dist/next/index.html'],
		['/next/index', '/dist/next/index.html'],
		['/next/reference/nested/example.html', '/dist/next/reference/nested/example.html'],
		['/v0.1.0/guide/start.html', '/dist/v0.1.0/guide/start.html'],
		['/v0.1.0/guide/start', '/dist/v0.1.0/guide/start.html'],
		['/plain.html', '/dist/plain.html'],
		['/widget.html', '/dist/widget.html'],
	]);
	const markup = new Map([
		[
			'/dist/index.html',
			'<div class="live-code"><button class="live-code-btn"></button><span class="live-code-bar"></span><pre class="live-code-pre"></pre><pre class="live-code-err"></pre></div>',
		],
		['/dist/guide/start.html', '<div class="live-code">'],
		['/dist/next/index.html', '<div class="live-code">'],
		['/dist/next/reference/nested/example.html', '<div class="other live-code example">'],
		['/dist/v0.1.0/guide/start.html', '<div class="live-code extra"><div class="live-code">'],
		[
			'/dist/widget.html',
			'<div class="widget"><button class="live-code-btn"></button><span class="live-code-bar"></span><pre class="live-code-pre"></pre></div>',
		],
	]);
	const reads = new Map();

	assert.deepEqual(
		findExamplePages(routes, (file) => {
			reads.set(file, (reads.get(file) ?? 0) + 1);
			return markup.get(file) ?? '<main/>';
		}),
		[
			{ version: '(latest)', route: '/', expectedBlocks: 1 },
			{ version: '(latest)', route: '/guide/start', expectedBlocks: 1 },
			{ version: 'next', route: '/next/', expectedBlocks: 1 },
			{ version: 'next', route: '/next/reference/nested/example', expectedBlocks: 1 },
			{ version: 'v0.1.0', route: '/v0.1.0/guide/start', expectedBlocks: 2 },
		],
	);
	assert.ok([...reads.values()].every((count) => count === 1));
});
