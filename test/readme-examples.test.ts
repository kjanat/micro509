import { describe, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import ts from 'typescript';
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

function compilerOptions(): ts.CompilerOptions {
	const configPath = path.join(projectRoot, 'tsconfig.src.json');
	const parsed = ts.parseJsonConfigFileContent(
		ts.readConfigFile(configPath, ts.sys.readFile).config,
		ts.sys,
		projectRoot,
	);
	return {
		...parsed.options,
		noEmit: true,
		composite: false,
		incremental: false,
		tsBuildInfoFile: undefined,
		rootDir: undefined,
		paths: {
			micro509: [path.join(projectRoot, 'src/index.ts')],
			'micro509/*': [path.join(projectRoot, 'src/*/index.ts')],
		},
	};
}

describe('README ts examples', () => {
	const markdown = readFileSync(path.join(projectRoot, 'README.md'), 'utf8');
	const fences = tsFences(markdown);
	const options = compilerOptions();

	for (const [index, code] of fences.entries()) {
		it(`block ${index + 1} of ${fences.length} compiles with zero diagnostics`, async () => {
			const target = path.join(scratchDir, `readme-${index + 1}.ts`);
			await fsp.mkdir(scratchDir, { recursive: true });
			await fsp.writeFile(target, code);
			const program = ts.createProgram([target], options);
			const diagnostics = ts
				.getPreEmitDiagnostics(program)
				.filter((diagnostic) => diagnostic.file?.fileName === target.replaceAll('\\', '/'));
			if (diagnostics.length > 0) {
				const rendered = diagnostics
					.map((diagnostic) => ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n'))
					.join('\n');
				throw new Error(`README block ${index + 1} has diagnostics:\n${rendered}`);
			}
		}, 60_000);

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
