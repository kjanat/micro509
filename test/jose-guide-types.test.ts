import { expect, it } from 'bun:test';
import { readFileSync } from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { createTscBridge } from '@kjanat/tsc-bridge';
import { projectRoot } from '#test/helpers';

it('compiles the actual JOSE LiveCode recipes with strict public API types', async () => {
	const targets: string[] = [];
	const directory = path.join(projectRoot, 'node_modules/.cache/jose-guide-types');
	await fsp.mkdir(directory, { recursive: true });
	for (const name of ['jose-integration', 'jose-cache', 'jose-jwe']) {
		const markdown = readFileSync(path.join(projectRoot, `site/guide/${name}.md`), 'utf8');
		for (const [index, match] of [
			...markdown.matchAll(/<LiveCode[^>]*>[\s\S]*?```ts\n([\s\S]*?)```[\s\S]*?<\/LiveCode>/g),
		].entries()) {
			const code = match[1];
			if (code === undefined) throw new Error('missing recipe');
			const target = path.join(directory, `${name}-${index}.ts`);
			await fsp.writeFile(target, code);
			targets.push(target);
		}
	}
	expect(targets.length).toBeGreaterThanOrEqual(4);
	const bridge = createTscBridge({ cwd: projectRoot });
	try {
		const diagnostics = await bridge.checkProject('tsconfig.src.json', {
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
		if (diagnostics.length > 0)
			throw new Error(
				diagnostics.map((item) => `${item.fileName}: ${item.messageText}`).join('\n'),
			);
	} finally {
		await bridge.close();
	}
});
