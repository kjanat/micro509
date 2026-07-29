import { describe, expect, it } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { projectRoot } from '#test/helpers';

const guideDir = path.join(projectRoot, 'site/guide');
const scratchDir = path.join(projectRoot, 'node_modules/.cache/guide-examples');

function liveCodeBlocks(markdown: string): readonly string[] {
	const blocks: string[] = [];
	for (const live of markdown.matchAll(/<LiveCode>([\s\S]*?)<\/LiveCode>/g)) {
		const body = live[1] ?? '';
		for (const fence of body.matchAll(/```ts\n([\s\S]*?)```/g)) {
			const code = fence[1];
			if (code !== undefined) blocks.push(code);
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
	const guides = readdirSync(guideDir).filter((name) => name.endsWith('.md'));
	for (const guide of guides) {
		const markdown = readFileSync(path.join(guideDir, guide), 'utf8');
		const blocks = liveCodeBlocks(markdown);
		for (const [index, code] of blocks.entries()) {
			it(`${guide} block ${index + 1} of ${blocks.length}`, async () => {
				const target = path.join(scratchDir, `${guide.replace(/\.md$/, '')}-${index + 1}.ts`);
				await fsp.mkdir(scratchDir, { recursive: true });
				await fsp.writeFile(target, rewriteBareImports(code));
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
				expect(exitCode).toBe(0);
			}, 30_000);
		}
	}
});
