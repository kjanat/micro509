#!/usr/bin/env bun
import { existsSync, realpathSync } from 'node:fs';
import path from 'node:path';

export type Decision =
	| { readonly kind: 'pass' }
	| { readonly kind: 'deny' }
	| { readonly kind: 'rewrite'; readonly input: Readonly<Record<string, unknown>> };

export interface Payload {
	readonly tool: string;
	readonly agent: string | undefined;
	readonly cwd: string;
	readonly input: Readonly<Record<string, unknown>>;
}

export interface Segment {
	readonly words: readonly string[];
	readonly piped: boolean;
}

export interface Script {
	readonly segments: readonly Segment[];
	readonly substitutions: boolean;
	readonly redirectsIn: boolean;
}

type Relation = 'inside' | 'ancestor' | 'none';

const CORPUS = ['rfc', 'itu', 'w3c'] as const;
const SPEC_RE = /docs\/(rfc|itu|w3c)(\/|$|[^A-Za-z0-9_.-])/;
const GLOB_META = /[*?[]/;
const INTENT_RE = /#\s*spec-intent:\s*\S.{9,}/;
const PROSE_CONSUMERS: ReadonlySet<string> = new Set(['git', 'gh', 'glab']);
const METADATA: ReadonlySet<string> = new Set([
	'ls',
	'find',
	'stat',
	'wc',
	'file',
	'basename',
	'dirname',
	'realpath',
	'test',
	'[',
]);
const FIND_ACTIONS: ReadonlySet<string> = new Set(['-exec', '-execdir', '-ok', '-okdir']);
const PREFIXES: ReadonlySet<string> = new Set([
	'xargs',
	'parallel',
	'command',
	'exec',
	'time',
	'nice',
	'nohup',
	'env',
	'sudo',
]);
const FANOUT: ReadonlySet<string> = new Set(['xargs', 'parallel']);
const GLOB_FLAGS: ReadonlySet<string> = new Set(['-g', '--glob', '--iglob']);
const SEARCHERS: ReadonlySet<string> = new Set(['rg', 'ag', 'ack', 'ugrep']);
const GREPS: ReadonlySet<string> = new Set(['grep', 'egrep', 'fgrep']);
const PATTERN_FLAGS = /^(?:--regexp|--file)(?:=|$)|^-[A-Za-z]*[ef]/;
const READER_COMMANDS: ReadonlySet<string> = new Set(['read', 'search', 'headings']);

export const EXCLUDE_GLOB = '!**/docs/{rfc,itu,w3c}/**';

export const DENY_MESSAGE = `STOP. The authoritative spec corpus (docs/rfc, docs/itu, docs/w3c) is read only by the spec-lookup agent.

Do not read, grep, or cat these files directly, and do not search a directory that contains them. Hand the question to the spec-lookup subagent, which censuses the whole docs/ tree, fetches missing or superseded documents, reads whole sections, and returns a cited answer:

  Agent(subagent_type: "spec-lookup", prompt: "<your exact spec question>")

To search the rest of the repository, scope the search to a directory that does not contain docs/rfc, docs/itu, or docs/w3c.`;

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringField(record: Readonly<Record<string, unknown>>, key: string): string | undefined {
	const value = record[key];
	return typeof value === 'string' && value !== '' ? value : undefined;
}

export function parsePayload(raw: string): Payload | undefined {
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		return undefined;
	}
	if (!isRecord(parsed)) return undefined;
	const tool = stringField(parsed, 'tool_name');
	const input = parsed['tool_input'];
	if (tool === undefined || !isRecord(input)) return undefined;
	return {
		tool,
		agent: stringField(parsed, 'agent_type'),
		cwd: stringField(parsed, 'cwd') ?? process.cwd(),
		input,
	};
}

function canonical(target: string): string {
	const resolved = path.resolve(target);
	try {
		return realpathSync(resolved);
	} catch {
		return resolved;
	}
}

function components(absolute: string): readonly string[] {
	return absolute.split(path.sep).filter((part) => part !== '');
}

function escapeRegExp(text: string): string {
	return text.replace(/[.+^${}()|\\]/g, '\\$&');
}

function componentPattern(component: string): RegExp | undefined {
	let source = '';
	for (let index = 0; index < component.length; index += 1) {
		const char = component.charAt(index);
		if (char === '*') source += '[^/]*';
		else if (char === '?') source += '[^/]';
		else if (char === '[' && component.charAt(index + 1) === '!') {
			source += '[^';
			index += 1;
		} else if (char === '[' || char === ']') source += char;
		else source += escapeRegExp(char);
	}
	try {
		return new RegExp(`^${source}$`);
	} catch {
		return undefined;
	}
}

function componentMatches(pattern: string, actual: string): boolean {
	if (!GLOB_META.test(pattern)) return pattern === actual;
	return componentPattern(pattern)?.test(actual) ?? pattern === actual;
}

function relationTo(target: readonly string[], corpus: readonly string[]): Relation {
	for (let index = 0; index < corpus.length; index += 1) {
		const part = target[index];
		if (part === undefined) return 'ancestor';
		if (part === '**') return index >= corpus.length - 1 ? 'inside' : 'ancestor';
		if (!componentMatches(part, corpus[index] ?? '')) return 'none';
	}
	return 'inside';
}

export function corpusDirs(project: string): readonly string[] {
	return CORPUS.map((dir) => canonical(path.join(project, 'docs', dir)));
}

export function relation(word: string, cwd: string, dirs: readonly string[]): Relation {
	if (word.includes('\n')) return 'none';
	const absolute = path.resolve(cwd, word);
	const target = components(GLOB_META.test(word) ? absolute : canonical(absolute));
	let strongest: Relation = 'none';
	for (const dir of dirs) {
		const found = relationTo(target, components(dir));
		if (found === 'inside') return 'inside';
		if (found === 'ancestor') strongest = 'ancestor';
	}
	return strongest;
}

interface Frame {
	readonly closer: ')' | '`' | undefined;
	words: string[];
	word: string | undefined;
	double: boolean;
}

interface Tokenizer {
	readonly source: string;
	readonly stack: Frame[];
	readonly segments: Segment[];
	index: number;
	substitutions: boolean;
	redirectsIn: boolean;
}

function frameOf(state: Tokenizer): Frame {
	const frame = state.stack[state.stack.length - 1];
	if (frame === undefined) throw new Error('tokenizer stack is empty');
	return frame;
}

function append(frame: Frame, text: string): void {
	frame.word = (frame.word ?? '') + text;
}

function flushWord(frame: Frame): void {
	if (frame.word !== undefined) frame.words.push(frame.word);
	frame.word = undefined;
}

function endSegment(state: Tokenizer, frame: Frame, piped: boolean): void {
	flushWord(frame);
	if (frame.words.length > 0) state.segments.push({ words: frame.words, piped });
	frame.words = [];
}

function openFrame(state: Tokenizer, closer: ')' | '`'): void {
	state.substitutions = true;
	state.stack.push({ closer, words: [], word: undefined, double: false });
}

function closeFrame(state: Tokenizer): void {
	const frame = frameOf(state);
	endSegment(state, frame, false);
	state.stack.pop();
}

function skipHeredocOperator(state: Tokenizer): void {
	const rest = state.source.slice(state.index);
	const operator = /^<<-?\s*(['"]?)[A-Za-z_][A-Za-z0-9_]*\1/.exec(rest);
	state.index += operator === null ? 2 : operator[0].length;
}

function stepDouble(state: Tokenizer, frame: Frame, char: string, next: string): void {
	if (char === '\\') {
		append(frame, next);
		state.index += 2;
		return;
	}
	state.index += 1;
	if (char === '"') frame.double = false;
	else if (char === '$' && next === '(') {
		state.index += 1;
		openFrame(state, ')');
	} else if (char === '`') openFrame(state, '`');
	else append(frame, char);
}

function stepQuote(state: Tokenizer, frame: Frame, char: string): boolean {
	if (char === "'") {
		const close = state.source.indexOf("'", state.index + 1);
		const end = close === -1 ? state.source.length : close;
		append(frame, state.source.slice(state.index + 1, end));
		state.index = end + 1;
		return true;
	}
	if (char === '"') {
		append(frame, '');
		frame.double = true;
		state.index += 1;
		return true;
	}
	return false;
}

function stepSubstitution(state: Tokenizer, frame: Frame, char: string, next: string): boolean {
	if ((char === '$' || char === '<' || char === '>') && next === '(') {
		flushWord(frame);
		state.index += 2;
		openFrame(state, ')');
		return true;
	}
	if (char === '`') {
		state.index += 1;
		if (frame.closer === '`') closeFrame(state);
		else openFrame(state, '`');
		return true;
	}
	if (char === ')') {
		state.index += 1;
		if (frame.closer === ')') closeFrame(state);
		else endSegment(state, frame, false);
		return true;
	}
	return false;
}

function stepSeparator(state: Tokenizer, frame: Frame, char: string, next: string): boolean {
	if (char === '|' && next !== '|') {
		state.index += next === '&' ? 2 : 1;
		endSegment(state, frame, true);
		return true;
	}
	if (char === '|' || char === '&' || char === ';' || char === '\n' || char === '(') {
		state.index += next === char ? 2 : 1;
		endSegment(state, frame, false);
		return true;
	}
	return false;
}

function stepRedirect(state: Tokenizer, frame: Frame, char: string, next: string): boolean {
	if (char === '<') {
		flushWord(frame);
		if (next === '<' && state.source.charAt(state.index + 2) !== '<') {
			skipHeredocOperator(state);
			return true;
		}
		if (next !== '<') state.redirectsIn = true;
		state.index += next === '<' ? 3 : 1;
		return true;
	}
	if (char === '>') {
		flushWord(frame);
		state.index += next === '>' || next === '&' ? 2 : 1;
		return true;
	}
	return false;
}

function stepPlain(state: Tokenizer, frame: Frame, char: string, next: string): void {
	if (char === '\\') {
		if (next !== '\n') append(frame, next);
		state.index += 2;
		return;
	}
	if (char === ' ' || char === '\t') {
		flushWord(frame);
		state.index += 1;
		return;
	}
	if (char === '#' && frame.word === undefined) {
		const newline = state.source.indexOf('\n', state.index);
		state.index = newline === -1 ? state.source.length : newline;
		return;
	}
	append(frame, char);
	state.index += 1;
}

export function tokenize(source: string): Script {
	const state: Tokenizer = {
		source,
		stack: [{ closer: undefined, words: [], word: undefined, double: false }],
		segments: [],
		index: 0,
		substitutions: false,
		redirectsIn: false,
	};
	while (state.index < source.length) {
		const frame = frameOf(state);
		const char = source.charAt(state.index);
		const next = source.charAt(state.index + 1);
		if (frame.double) stepDouble(state, frame, char, next);
		else if (
			!stepQuote(state, frame, char) &&
			!stepSubstitution(state, frame, char, next) &&
			!stepSeparator(state, frame, char, next) &&
			!stepRedirect(state, frame, char, next)
		) {
			stepPlain(state, frame, char, next);
		}
	}
	while (state.stack.length > 1) closeFrame(state);
	endSegment(state, frameOf(state), false);
	return {
		segments: state.segments,
		substitutions: state.substitutions,
		redirectsIn: state.redirectsIn,
	};
}

export interface SplitCommand {
	readonly text: string;
	readonly bodies: readonly string[];
}

interface PendingHeredoc {
	readonly delimiter: string;
	readonly strip: boolean;
	readonly prose: boolean;
}

function isProseConsumer(head: string, rest: string): boolean {
	if (/[|;&>]/.test(rest)) return false;
	const segment = head.split(/[;&|]/).at(-1) ?? '';
	const command = /^\s*(\S+)/.exec(segment)?.[1];
	return command !== undefined && PROSE_CONSUMERS.has(path.basename(command));
}

function heredocsOn(line: string): readonly PendingHeredoc[] {
	const found: PendingHeredoc[] = [];
	for (const match of line.matchAll(/(?<!<)<<(-?)\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2/g)) {
		const [operator, dash, , delimiter] = match;
		if (delimiter === undefined) continue;
		const head = line.slice(0, match.index);
		const rest = line.slice(match.index + operator.length);
		found.push({ delimiter, strip: dash === '-', prose: isProseConsumer(head, rest) });
	}
	return found;
}

export function splitHeredocs(command: string): SplitCommand {
	const text: string[] = [];
	const bodies: string[] = [];
	const pending: PendingHeredoc[] = [];
	let body: string[] = [];
	for (const line of command.split('\n')) {
		const current = pending[0];
		if (current !== undefined) {
			const candidate = current.strip ? line.replace(/^\t+/, '') : line;
			if (candidate !== current.delimiter) {
				body.push(line);
				continue;
			}
			if (!current.prose) bodies.push(body.join('\n'));
			body = [];
			pending.shift();
			continue;
		}
		text.push(line);
		pending.push(...heredocsOn(line));
	}
	const unterminated = pending[0];
	if (unterminated !== undefined && !unterminated.prose) bodies.push(body.join('\n'));
	return { text: text.join('\n'), bodies };
}

function commandIndex(words: readonly string[]): number {
	let index = 0;
	while (index < words.length) {
		const word = words[index] ?? '';
		if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word) || word.startsWith('-')) index += 1;
		else if (PREFIXES.has(path.basename(word))) index += 1;
		else break;
	}
	return index;
}

function commandName(segment: Segment): string {
	return path.basename(segment.words[commandIndex(segment.words)] ?? '');
}

function isRecursiveGrep(args: readonly string[]): boolean {
	return args.some(
		(word, index) =>
			/^-[A-Za-z]*[rR]/.test(word) ||
			word === '--recursive' ||
			word === '--dereference-recursive' ||
			word === '--directories=recurse' ||
			(word === '-d' && args[index + 1] === 'recurse'),
	);
}

function isSearch(segment: Segment, next: Segment | undefined): boolean {
	const start = commandIndex(segment.words);
	const name = path.basename(segment.words[start] ?? '');
	const args = segment.words.slice(start + 1);
	if (SEARCHERS.has(name)) return true;
	if (name === 'git') return args.includes('grep');
	if (GREPS.has(name)) return isRecursiveGrep(args);
	if (name !== 'find') return false;
	if (args.some((word) => FIND_ACTIONS.has(word))) return true;
	return segment.piped && next !== undefined && PREFIXES.has(path.basename(next.words[0] ?? ''));
}

function findOperands(args: readonly string[]): readonly string[] {
	const end = args.findIndex((word) => /^[-(!]/.test(word));
	return end === -1 ? args : args.slice(0, end);
}

function isRoot(word: string, cwd: string): boolean {
	if (!GLOB_META.test(word)) return word.includes('/') || existsSync(path.resolve(cwd, word));
	const prefix = word.slice(0, word.search(GLOB_META));
	return prefix.includes('/');
}

function patternIndex(segment: Segment): number | undefined {
	const words = segment.words;
	const start = commandIndex(words);
	const name = path.basename(words[start] ?? '');
	const gitGrep = name === 'git' ? words.indexOf('grep', start + 1) : -1;
	if (!SEARCHERS.has(name) && !GREPS.has(name) && gitGrep === -1) return undefined;
	const first = gitGrep === -1 ? start + 1 : gitGrep + 1;
	if (words.slice(first).some((word) => PATTERN_FLAGS.test(word))) return undefined;
	const index = words.findIndex((word, position) => position >= first && !word.startsWith('-'));
	return index === -1 ? undefined : index;
}

interface Exclusion {
	readonly index: number;
	readonly pattern: string;
}

function isSearcher(segment: Segment): boolean {
	const start = commandIndex(segment.words);
	const name = path.basename(segment.words[start] ?? '');
	return SEARCHERS.has(name) || GREPS.has(name) || name === 'git';
}

function exclusionsOf(segment: Segment): readonly Exclusion[] {
	if (!isSearcher(segment)) return [];
	const words = segment.words;
	const found: Exclusion[] = [];
	words.forEach((word, index) => {
		const previous = words[index - 1] ?? '';
		const joined =
			/^(?:--i?glob=|-g)!(.+)$/.exec(word) ??
			/^--exclude-dir=(.+)$/.exec(word) ??
			/^:(?:!|\^|\(exclude\))(.+)$/.exec(word);
		if (joined?.[1] !== undefined) found.push({ index, pattern: joined[1] });
		else if (GLOB_FLAGS.has(previous) && word.startsWith('!')) {
			found.push({ index, pattern: word.slice(1) });
		} else if (previous === '--exclude-dir') found.push({ index, pattern: word });
	});
	return found;
}

function expandBraces(pattern: string): readonly string[] {
	const match = /\{([^{}]*)\}/.exec(pattern);
	if (match?.[1] === undefined) return [pattern];
	const head = pattern.slice(0, match.index);
	const tail = pattern.slice(match.index + match[0].length);
	return match[1].split(',').flatMap((option) => expandBraces(`${head}${option}${tail}`));
}

function covers(pattern: string, relative: string): boolean {
	return expandBraces(pattern).some((option) => {
		const core = option
			.replace(/^\.\//, '')
			.replace(/^\*\*\//, '')
			.replace(/\/\*{1,2}$/, '')
			.replace(/\/$/, '');
		if (core.includes('/')) return relative === core || relative.endsWith(`/${core}`);
		return path.basename(relative) === core;
	});
}

function exposes(
	root: string,
	cwd: string,
	dirs: readonly string[],
	exclusions: readonly Exclusion[],
): boolean {
	const found = relation(root, cwd, dirs);
	if (found !== 'ancestor') return found === 'inside';
	const base = canonical(path.resolve(cwd, root));
	const here = canonical(cwd);
	return dirs.some(
		(dir) =>
			!exclusions.some(
				({ pattern }) =>
					covers(pattern, path.relative(base, dir)) || covers(pattern, path.relative(here, dir)),
			),
	);
}

function readsStdin(segment: Segment, previous: Segment | undefined): boolean {
	if (previous?.piped !== true) return false;
	const start = commandIndex(segment.words);
	if (segment.words.slice(0, start).some((word) => FANOUT.has(path.basename(word)))) return false;
	const name = path.basename(segment.words[start] ?? '');
	return SEARCHERS.has(name) || GREPS.has(name);
}

function searchRoots(
	segment: Segment,
	previous: Segment | undefined,
	cwd: string,
	skipped: ReadonlySet<number>,
): readonly string[] {
	const start = commandIndex(segment.words);
	const args = segment.words.filter((_, index) => index > start && !skipped.has(index));
	const candidates =
		commandName(segment) === 'find'
			? findOperands(args)
			: args.filter((word) => !word.startsWith('-'));
	const roots = candidates.filter((word) => isRoot(word, cwd));
	if (roots.length > 0) return roots;
	return readsStdin(segment, previous) ? [] : [cwd];
}

function isReader(segment: Segment): boolean {
	const words = segment.words;
	return words.some((word, index) => {
		const next = words[index + 1] ?? '';
		if (/scripts\/spec\/main\.ts$/.test(word)) return READER_COMMANDS.has(next);
		if (word !== 'spec') return false;
		const before = path.basename(words[index - 1] ?? '');
		return (before === 'bun' || before === 'run') && READER_COMMANDS.has(next);
	});
}

function isMetadataOnly(command: string, script: Script): boolean {
	const only = script.segments[0];
	return (
		!command.includes('\n') &&
		script.segments.length === 1 &&
		only !== undefined &&
		!script.substitutions &&
		!script.redirectsIn &&
		METADATA.has(only.words[0] ?? '') &&
		!only.words.some((word) => FIND_ACTIONS.has(word))
	);
}

function nextDirectory(segment: Segment, cwd: string): string {
	const [name, target] = segment.words;
	if ((name !== 'cd' && name !== 'pushd') || target === undefined || target.startsWith('-')) {
		return cwd;
	}
	return path.resolve(cwd, target);
}

function segmentReads(
	segment: Segment,
	previous: Segment | undefined,
	next: Segment | undefined,
	cwd: string,
	dirs: readonly string[],
): boolean {
	if (isReader(segment)) return true;
	const exclusions = exclusionsOf(segment);
	const pattern = patternIndex(segment);
	const skipped = new Set(exclusions.map(({ index }) => index));
	if (pattern !== undefined) skipped.add(pattern);
	const operands = segment.words.filter((_, index) => !skipped.has(index));
	if (operands.some((word) => SPEC_RE.test(word) || relation(word, cwd, dirs) === 'inside')) {
		return true;
	}
	if (!isSearch(segment, next)) return false;
	return searchRoots(segment, previous, cwd, skipped).some((root) =>
		exposes(root, cwd, dirs, exclusions),
	);
}

function decideBash(command: string, cwd: string, dirs: readonly string[]): Decision {
	if (INTENT_RE.test(command)) return { kind: 'pass' };
	const split = splitHeredocs(command);
	const script = tokenize(split.text);
	if (isMetadataOnly(command, script)) return { kind: 'pass' };
	if (split.bodies.some((text) => SPEC_RE.test(text))) return { kind: 'deny' };
	const segments = [...script.segments, ...split.bodies.flatMap((body) => tokenize(body).segments)];
	let directory = cwd;
	for (const [index, segment] of segments.entries()) {
		if (segmentReads(segment, segments[index - 1], segments[index + 1], directory, dirs)) {
			return { kind: 'deny' };
		}
		directory = nextDirectory(segment, directory);
	}
	return { kind: 'pass' };
}

function decideGrep(payload: Payload, dirs: readonly string[]): Decision {
	const searchPath = stringField(payload.input, 'path');
	if (searchPath !== undefined && SPEC_RE.test(searchPath)) return { kind: 'deny' };
	const found = relation(searchPath ?? payload.cwd, payload.cwd, dirs);
	if (found === 'none') return { kind: 'pass' };
	if (found === 'inside' || stringField(payload.input, 'glob') !== undefined) {
		return { kind: 'deny' };
	}
	return { kind: 'rewrite', input: { ...payload.input, glob: EXCLUDE_GLOB } };
}

function decideRead(payload: Payload, dirs: readonly string[]): Decision {
	const filePath = stringField(payload.input, 'file_path');
	if (filePath === undefined) return { kind: 'pass' };
	if (SPEC_RE.test(filePath) || relation(filePath, payload.cwd, dirs) === 'inside') {
		return { kind: 'deny' };
	}
	return { kind: 'pass' };
}

export function decide(payload: Payload, project: string): Decision {
	if (payload.agent === 'spec-lookup') return { kind: 'pass' };
	const dirs = corpusDirs(project);
	switch (payload.tool) {
		case 'Read':
			return decideRead(payload, dirs);
		case 'Grep':
			return decideGrep(payload, dirs);
		case 'Bash': {
			const command = stringField(payload.input, 'command');
			return command === undefined
				? { kind: 'pass' }
				: decideBash(command, payload.cwd, dirs);
		}
		default:
			return { kind: 'pass' };
	}
}

export function render(decision: Decision): string | undefined {
	switch (decision.kind) {
		case 'pass':
			return undefined;
		case 'deny':
			return JSON.stringify({
				hookSpecificOutput: {
					hookEventName: 'PreToolUse',
					permissionDecision: 'deny',
					permissionDecisionReason: DENY_MESSAGE,
				},
			});
		case 'rewrite':
			return JSON.stringify({
				hookSpecificOutput: {
					hookEventName: 'PreToolUse',
					permissionDecision: 'allow',
					permissionDecisionReason: 'spec corpus excluded from the search root',
					updatedInput: decision.input,
				},
			});
		default: {
			const _exhaustive: never = decision;
			return _exhaustive;
		}
	}
}

async function readStdin(): Promise<string> {
	const chunks: Buffer[] = [];
	for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
	return Buffer.concat(chunks).toString('utf8');
}

if (import.meta.main) {
	const payload = parsePayload(await readStdin());
	if (payload !== undefined) {
		const output = render(decide(payload, process.env['CLAUDE_PROJECT_DIR'] ?? payload.cwd));
		if (output !== undefined) process.stdout.write(`${output}\n`);
	}
}
