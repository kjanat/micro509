import { beforeAll, describe, it } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { projectRoot } from '#test/helpers';

const guideDir = path.join(projectRoot, 'site/guide');
const scratchDir = path.join(projectRoot, 'node_modules/.cache/guide-examples/guide');

function liveCodeBlocks(markdown: string): readonly { code: string; deterministic: boolean }[] {
	const blocks: { code: string; deterministic: boolean }[] = [];
	for (const live of markdown.matchAll(/<LiveCode([^>]*)>([\s\S]*?)<\/LiveCode>/g)) {
		const deterministic = /\bdata-output="deterministic"/.test(live[1] ?? '');
		const body = live[2] ?? '';
		for (const fence of body.matchAll(/```ts\n([\s\S]*?)```/g)) {
			const code = fence[1];
			if (code !== undefined) blocks.push({ code, deterministic });
		}
	}
	return blocks;
}

function rewriteBareImports(code: string): string {
	return code.replaceAll(
		/from 'micro509(\/[a-z0-9]+)?'/g,
		(_match, subpath: string | undefined) => `from '#micro509${subpath ?? ''}'`,
	);
}

describe('site guide LiveCode examples execute', () => {
	beforeAll(async () => {
		// Match the built site's guide/ and fixtures/ layout for relative asset URLs.
		await fsp.cp(
			path.join(projectRoot, 'site/assets/fixtures'),
			path.join(scratchDir, '../fixtures'),
			{ recursive: true },
		);
	});
	const guides = readdirSync(guideDir).filter((name) => name.endsWith('.md'));
	for (const guide of guides) {
		const markdown = readFileSync(path.join(guideDir, guide), 'utf8');
		const blocks = liveCodeBlocks(markdown);
		for (const [index, { code, deterministic }] of blocks.entries()) {
			it(`${guide} block ${index + 1} of ${blocks.length}`, async () => {
				const target = path.join(scratchDir, `${guide.replace(/\.md$/, '')}-${index + 1}.ts`);
				await fsp.mkdir(scratchDir, { recursive: true });
				await fsp.writeFile(target, rewriteBareImports(code));
				const outputs: string[] = [];
				for (let run = 0; run < 2; run += 1) {
					const child = Bun.spawn([process.execPath, 'run', target], {
						cwd: projectRoot,
						stdout: 'pipe',
						stderr: 'pipe',
					});
					const exitCode = await child.exited;
					if (exitCode !== 0) {
						const stderr = await new Response(child.stderr).text();
						throw new Error(`example exited ${exitCode}:\n${stderr}`);
					}
					outputs.push(await new Response(child.stdout).text());
				}
				if (outputs.some((output) => output.trim() === '')) {
					throw new Error('example printed no output');
				}
				if (deterministic && outputs[0] !== outputs[1]) {
					throw new Error('fixed-fixture example changed output between runs');
				}
				if (!deterministic && outputs[0] === outputs[1]) {
					throw new Error(
						're-running this example prints byte-identical output; show something run-varying',
					);
				}
			}, 60_000);
		}
	}
});
