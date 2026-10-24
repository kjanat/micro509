import assert from 'node:assert/strict';
import test from 'node:test';
import { parseArgs, stableVersions } from './docs-build.mjs';

test('parses explicit single-target build modes', () => {
	assert.deepEqual(parseArgs(['--channel', 'next', '--output', '.publish']), {
		channel: 'next',
		output: '.publish',
	});
	assert.deepEqual(
		parseArgs(['--channel', 'release', '--version', 'v1.2.3', '--output', '.publish']),
		{
			channel: 'release',
			version: 'v1.2.3',
			output: '.publish',
		},
	);
	assert.deepEqual(
		parseArgs(['--channel', 'repair', '--version', 'v1.2.3', '--output', '.publish']),
		{
			channel: 'repair',
			version: 'v1.2.3',
			output: '.publish',
			repair: true,
		},
	);
	assert.throws(() =>
		parseArgs(['--channel', 'next', '--version', 'v1.2.3', '--output', '.publish']),
	);
	assert.throws(() => parseArgs(['--channel', 'repair', '--output', '.publish']));
});

test('bootstrap release selection filters prereleases and sorts stable versions newest first', () => {
	assert.deepEqual(
		stableVersions({
			versions: {
				'0.10.0': {},
				'0.9.9': {},
				'1.0.0-beta.1': {},
				'1.0.0': {},
				'2.0.0-rc.1': {},
			},
		}),
		['1.0.0', '0.10.0', '0.9.9'],
	);
	assert.throws(() => stableVersions({}));
});
