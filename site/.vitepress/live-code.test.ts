import { expect, test } from 'bun:test';
import { repairExamples, stripTypes } from './live-code.ts';

function liveCode(source: string): string {
	return `<LiveCode>\n\n\`\`\`ts\n${source}\n\`\`\`\n\n</LiveCode>\n`;
}

test('site transpilation produces executable ES modules and keeps Unicode', async () => {
	const javascript = stripTypes("export const greeting: string = '☃😀';");
	const emitted = await import(`data:text/javascript,${encodeURIComponent(javascript)}`);
	expect(emitted.greeting).toBe('☃😀');
});

test('archived LiveCode repairs preserve Unicode before a missing brace', async () => {
	const broken = [
		'export function greeting(): string {',
		'  try {',
		"    return '☃😀';",
		'  catch {',
		"    return 'fallback';",
		'  }',
		'}',
	].join('\n');
	const repaired = repairExamples(liveCode(broken));
	expect(repaired).not.toBe(liveCode(broken));
	const source = repaired.match(/```ts\n([\s\S]*?)```/)?.[1];
	expect(source).toBeDefined();
	if (source === undefined) throw new Error('Expected a repaired TypeScript fence');
	const emitted = await import(`data:text/javascript,${encodeURIComponent(stripTypes(source))}`);
	expect(emitted.greeting()).toBe('☃😀');
});

test('valid examples and irreparable syntax remain unchanged', () => {
	for (const source of ['export const answer: number = 42;', 'const = ;']) {
		const markdown = liveCode(source);
		expect(repairExamples(markdown)).toBe(markdown);
	}
	const ordinaryFence = '```ts\nexport function broken() {\n```\n';
	expect(repairExamples(ordinaryFence)).toBe(ordinaryFence);
});
