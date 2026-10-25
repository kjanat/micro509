import { describe, expect, test } from 'bun:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { YAML } from 'bun';

const action: unknown = YAML.parse(
	await readFile(new URL('../.github/actions/cache-tsc/action.yml', import.meta.url), 'utf8'),
);

function scriptFor(name: string): string {
	assert.ok(action && typeof action === 'object' && 'runs' in action);
	const runs = action.runs;
	assert.ok(runs && typeof runs === 'object' && 'steps' in runs && Array.isArray(runs.steps));
	const step: unknown = runs.steps.find((step) => step.name === name);
	assert.ok(step && typeof step === 'object' && 'run' in step && typeof step.run === 'string');
	return step.run;
}

async function execute(name: string, env: Record<string, string>) {
	await mkdir('.cache', { recursive: true });
	const root = await mkdtemp(join(process.cwd(), '.cache/ci-cache-'));
	try {
		const output = join(root, 'environment');
		const subprocess = Bun.spawn(['bash', '-euo', 'pipefail', '-c', scriptFor(name)], {
			env: { ...process.env, ...env, GITHUB_ENV: output },
			stdout: 'pipe',
			stderr: 'pipe',
		});
		const [code, stdout, stderr] = await Promise.all([
			subprocess.exited,
			new Response(subprocess.stdout).text(),
			new Response(subprocess.stderr).text(),
		]);
		return {
			code,
			stdout,
			stderr,
			environment: (await Bun.file(output).exists()) ? await readFile(output, 'utf8') : '',
		};
	} finally {
		await rm(root, { recursive: true, force: true });
	}
}

describe('CI compiler cache environment', () => {
	test.each(['Linux', 'Linux\nINJECTED=1', 'Linux\r\nINJECTED=1'])(
		'keeps the cache key on one environment line for %j',
		async (runnerOS) => {
			const result = await execute('Select compiler artifact cache', {
				RUNNER_OS: runnerOS,
				RUNNER_ARCH: 'X64',
				ImageOS: 'ubuntu\nOTHER=1',
				ImageVersion: 'version\r\nANOTHER=1',
				INPUT_HASH: 'hash\nINJECTED=1',
			});
			expect(result.code).toBe(0);
			expect(result.environment).toStartWith('TSC_ARTIFACT_CACHE_KEY=tsc-');
			expect(result.environment.split('\n')).toHaveLength(2);
			expect(result.environment).not.toContain('\r');
		},
	);
	test.each([
		{ input: 'true', code: 0, output: 'TSC_ARTIFACT_CACHE_HIT=true\n' },
		{ input: 'false', code: 0, output: 'TSC_ARTIFACT_CACHE_HIT=false\n' },
		{ input: '', code: 0, output: 'TSC_ARTIFACT_CACHE_HIT=false\n' },
		{ input: 'true\nINJECTED=1', code: 1, output: '' },
		{ input: 'yes', code: 1, output: '' },
	])('validates cache-hit output $input', async ({ input, code, output }) => {
		const result = await execute('Record cache result', { CACHE_HIT: input });
		expect(result.code).toBe(code);
		expect(result.environment).toBe(output);
	});
});
