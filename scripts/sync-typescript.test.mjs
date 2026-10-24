import assert from 'node:assert/strict';
import test from 'node:test';
import { compilerCommit, compilerVersion } from './sync-typescript.mjs';

test('requires the same exact compiler version in both npm declarations', () => {
	const version = '7.1.0-dev.20261024.1';
	assert.equal(compilerVersion(`npm:typescript@${version}`, version), version);
	assert.throws(
		() => compilerVersion(`npm:typescript@${version}`, '7.1.0-dev.20261023.1'),
		/differ/,
	);
	for (const pin of [
		'npm:typescript@>=7',
		'npm:typescript@^7.1.0',
		'npm:typescript@6.0.0',
		undefined,
	]) {
		assert.throws(() => compilerVersion(pin, version), /exact TypeScript 7/);
	}
});

test('rejects missing or non-commit npm metadata before invoking Go', () => {
	const sha = '8d9b6da99ea7d4a8e7d906dd2532456dfe14e24f';
	assert.equal(compilerCommit(sha), sha);
	for (const value of [undefined, null, {}, 'main', sha.slice(0, 12), `${sha}\n`, '--help']) {
		assert.throws(() => compilerCommit(value), /full gitHead/);
	}
});
