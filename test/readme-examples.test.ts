import { describe, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import type { Diagnostic } from '@kjanat/tsc-bridge';
import { createTscBridge } from '@kjanat/tsc-bridge';
import { projectRoot } from '#test/helpers';

const scratchDir = path.join(projectRoot, 'node_modules/.cache/readme-examples');

function tsFences(markdown: string): readonly string[] {
	return [...markdown.matchAll(/```ts\n([\s\S]*?)```/g)].flatMap((fence) =>
		fence[1] === undefined ? [] : [fence[1]],
	);
}

function rewriteBareImports(code: string): string {
	return code.replaceAll(
		/from 'micro509(\/[a-z0-9]+)?'/g,
		(_match, subpath: string | undefined) => `from '#micro509${subpath ?? ''}'`,
	);
}

const fences = tsFences(readFileSync(path.join(projectRoot, 'README.md'), 'utf8'));
const targets = fences.map((_, index) => path.join(scratchDir, `readme-${index + 1}.ts`));

async function checkFences(): Promise<readonly Diagnostic[]> {
	await fsp.mkdir(scratchDir, { recursive: true });
	await Promise.all(fences.map((code, index) => fsp.writeFile(targets[index] ?? '', code)));
	const bridge = createTscBridge({ cwd: projectRoot });
	try {
		return await bridge.checkProject('tsconfig.src.json', {
			files: targets,
			compilerOptions: {
				noEmit: true,
				composite: false,
				incremental: false,
				tsBuildInfoFile: null,
				rootDir: null,
				paths: {
					micro509: [path.join(projectRoot, 'src/index.ts')],
					'micro509/*': [path.join(projectRoot, 'src/*.ts')],
				},
			},
		});
	} finally {
		await bridge.close();
	}
}

const diagnostics = await checkFences();

describe('README ts examples', () => {
	it('checks the blocks under a configuration with no diagnostics of its own', () => {
		const configuration = diagnostics.filter(
			(diagnostic) => diagnostic.fileName === undefined || diagnostic.fileName.endsWith('.json'),
		);
		if (configuration.length > 0) {
			throw new Error(configuration.map((diagnostic) => diagnostic.messageText).join('\n'));
		}
	});

	for (const [index, code] of fences.entries()) {
		it(`block ${index + 1} of ${fences.length} compiles with zero diagnostics`, () => {
			const target = (targets[index] ?? '').replaceAll('\\', '/');
			const own = diagnostics.filter((diagnostic) => diagnostic.fileName === target);
			if (own.length > 0) {
				const rendered = own.map((diagnostic) => diagnostic.messageText).join('\n');
				throw new Error(`README block ${index + 1} has diagnostics:\n${rendered}`);
			}
		});

		it(`block ${index + 1} of ${fences.length} executes`, async () => {
			const target = path.join(scratchDir, `readme-run-${index + 1}.ts`);
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
				throw new Error(`README block ${index + 1} exited ${exitCode}:\n${stderr}`);
			}
		}, 60_000);
	}
});
