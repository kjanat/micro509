import type { TranspileResult } from '@kjanat/tsc-bridge';
import { transpileSync } from '@kjanat/tsc-bridge';
import { Buffer } from 'node:buffer';

const LIVE_CODE_BLOCK = /(<LiveCode[^>]*>\s*\n\n```ts\n)([\s\S]*?)(```)/g;
const compiled = new Map<string, TranspileResult>();

function transpile(source: string): TranspileResult {
	const cached = compiled.get(source);
	if (cached !== undefined) return cached;
	const result = transpileSync(source);
	// Bound memory in the dev server while sharing results across versioned pages.
	if (compiled.size >= 1024) compiled.clear();
	compiled.set(source, result);
	return result;
}

/** A LiveCode fence executes in the browser, which parses JavaScript. */
export function stripTypes(source: string): string {
	return transpile(source).outputText;
}

/** Repair missing braces only when the resulting example parses successfully. */
function repairExample(source: string): string {
	let repaired = source;
	for (let attempt = 0; attempt < 20; attempt += 1) {
		const errors = transpile(repaired).diagnostics;
		if (errors.length === 0) return repaired;
		const missingBrace = errors.find((error) => error.code === 1005 || error.code === 1513);
		if (missingBrace === undefined || missingBrace.start < 0) return source;
		// Go reports UTF-8 bytes; JavaScript's slice uses UTF-16 code units.
		const offset = Buffer.from(repaired).subarray(0, missingBrace.start).toString('utf8').length;
		repaired = `${repaired.slice(0, offset)}}\n${repaired.slice(offset)}`;
	}
	return source;
}

/** Repair runnable examples an archived tag shipped with a syntax error. */
export function repairExamples(markdown: string): string {
	return markdown.replace(LIVE_CODE_BLOCK, (whole, open, body, close) => {
		const repaired = repairExample(body);
		return repaired === body ? whole : `${open}${repaired}${close}`;
	});
}
