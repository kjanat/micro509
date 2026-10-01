import { createSourceFile, forEachChild, ScriptTarget, SyntaxKind } from '@kjanat/tsc-compat';

const source = `const greeting: string = 'hello';
export function add(a: number, b: number): number {
	return a + b;
}
let broken = ;
`;

const kindNames = new Map();
for (const [name, kind] of Object.entries(SyntaxKind)) {
	if (typeof kind === 'number' && !kindNames.has(kind)) kindNames.set(kind, name);
}

const file = createSourceFile('example.ts', source, ScriptTarget.Latest);

console.log('Top-level nodes:');
forEachChild(file, (node) => {
	const text = source.slice(node.pos, node.end).trim().split('\n')[0];
	console.log(`  ${kindNames.get(node.kind)}  ${text}`);
});

console.log('Parse diagnostics:');
for (const diagnostic of file.parseDiagnostics) {
	console.log(`  TS${diagnostic.code} at ${diagnostic.start}: ${diagnostic.messageText}`);
}
