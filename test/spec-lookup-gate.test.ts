import { describe, expect, test } from 'bun:test';
import path from 'node:path';
import { projectRoot } from '#test/helpers';
import type { Decision } from '../.claude/hooks/spec-lookup-gate.ts';
import {
	decide,
	EXCLUDE_GLOB,
	parsePayload,
	render,
	splitHeredocs,
	tokenize,
} from '../.claude/hooks/spec-lookup-gate.ts';

type Verdict = 'pass' | 'deny' | 'rewrite';

function verdictOf(decision: Decision): Verdict {
	return decision.kind;
}

function bash(command: string, agent?: string): Decision {
	return decide({ tool: 'Bash', agent, cwd: projectRoot, input: { command } }, projectRoot);
}

function grep(input: Readonly<Record<string, unknown>>): Decision {
	return decide(
		{ tool: 'Grep', agent: undefined, cwd: projectRoot, input: { pattern: 'x', ...input } },
		projectRoot,
	);
}

function read(filePath: string): Decision {
	return decide(
		{ tool: 'Read', agent: undefined, cwd: projectRoot, input: { file_path: filePath } },
		projectRoot,
	);
}

const rfc5280 = path.join(projectRoot, 'docs', 'rfc', 'rfc5280.txt');

describe('Read', () => {
	test.each([
		['deny', rfc5280],
		['deny', path.join(projectRoot, 'docs', '.', 'rfc', '..', 'rfc', 'rfc5280.txt')],
		['deny', path.join(projectRoot, 'docs', 'itu')],
		['pass', path.join(projectRoot, 'docs', 'PKIX-SCOPE.md')],
		['pass', path.join(projectRoot, 'src', 'index.ts')],
	] as const)('%s %s', (want, filePath) => {
		expect(verdictOf(read(filePath))).toBe(want);
	});
});

describe('Grep', () => {
	test.each([
		['rewrite', {}],
		['rewrite', { path: 'docs' }],
		['rewrite', { path: '.' }],
		['rewrite', { path: projectRoot }],
		['deny', { glob: '*.txt' }],
		['deny', { path: 'docs', glob: '*.txt' }],
		['deny', { path: 'docs/rfc' }],
		['deny', { path: path.join(projectRoot, 'docs', 'itu', 'x.txt') }],
		['pass', { path: 'src' }],
		['pass', { path: path.join(projectRoot, 'test'), glob: '*.ts' }],
	] as const)('%s %o', (want, input) => {
		expect(verdictOf(grep(input))).toBe(want);
	});

	test('excludes the corpus when the search root contains it', () => {
		expect(grep({ path: 'docs', output_mode: 'count' })).toEqual({
			kind: 'rewrite',
			input: { pattern: 'x', path: 'docs', output_mode: 'count', glob: EXCLUDE_GLOB },
		});
	});
});

describe('Bash', () => {
	test.each([
		['pass', 'ls docs/rfc'],
		['pass', "find docs/rfc -name '*.txt'"],
		['pass', 'bun spec list'],
		['pass', 'rg nextUpdate src'],
		['pass', 'rg nextUpdate src/*.ts'],
		['pass', "rg -g '**/*.ts' nextUpdate src"],
		['pass', 'grep -rn nextUpdate src test'],
		['pass', 'grep -n nextUpdate src/index.ts'],
		['pass', 'find src -name x -exec wc -l {} +'],
		['pass', 'git commit -m "use rg in the script"'],
		['pass', "git commit -F - <<'EOF'\nfix docs/rfc parser\nEOF"],
		['pass', 'git commit -m "$(cat <<\'EOF\'\nfix docs/rfc parser\nEOF\n)"'],
		['pass', 'gh pr create --body-file - <<EOF\nmentions docs/rfc\nEOF'],
		['pass', 'cat docs/rfc/rfc5280.txt # spec-intent: vendoring check before upgrade'],
		['pass', 'python3 - <<\'EOF\'\ns = """\nx = [a, b]\ny = \'(10/2019)\'\n"""\nEOF'],
		['pass', 'echo "[a/[b/[c"'],
		['pass', `curl -sSL https://www.itu.int/rec/x | rg -o 'href="[^"]*(\\.pdf|!PDF)[^"]*"'`],
		['pass', 'git ls-files | rg -n "^docs/w3c"'],
		['pass', 'git ls-files | grep -E "^docs/(rfc|itu)/"'],
		['pass', 'rg -n "docs/rfc" src'],
		['pass', 'bun spec list > /var/tmp/absent/list.txt; rg -n webidl /var/tmp/absent/list.txt'],
		['deny', 'rg -n webidl ./absent/../docs/rfc'],
		['pass', "rg -n foo -g '!docs/rfc/**' -g '!docs/itu/**' -g '!docs/w3c/**' ."],
		['pass', `rg foo -g '${EXCLUDE_GLOB}'`],
		['pass', "rg foo --glob='!rfc' --glob='!itu' --glob='!w3c' docs"],
		['pass', 'grep -rn foo --exclude-dir=rfc --exclude-dir=itu --exclude-dir=w3c .'],
		['pass', "git grep -n foo -- . ':!docs/rfc' ':!docs/itu' ':!docs/w3c'"],
		['deny', "rg foo -g '!docs/rfc/**' ."],
		['deny', "rg foo -g '!docs/rfc/**' -g '!docs/itu/**' -g '!docs/w3c/**' docs/rfc"],
		['deny', "git grep -n foo -- . ':!docs/rfc'"],
		['deny', 'find . -name x | xargs rg foo'],
		['deny', 'ls | rg foo docs'],
		['deny', 'echo "^docs/w3c"'],
		['deny', 'cat docs/[r]fc/rfc5280.txt'],
		['deny', 'cat docs/rfc/rfc5280.txt'],
		['deny', 'find docs/rfc -maxdepth 0; cat docs/rfc/rfc5280.txt'],
		['deny', 'ls docs && cat docs/rfc/rfc5280.txt'],
		['deny', 'ls docs & cat docs/rfc/rfc5280.txt'],
		['deny', 'ls docs\ncat docs/rfc/rfc5280.txt'],
		['deny', 'cat docs/r*/rfc5280.txt'],
		['deny', 'cat docs/./rfc/rfc5280.txt'],
		['deny', 'cd docs && cat rfc/rfc5280.txt'],
		['deny', 'find docs -ok cat {} ;'],
		['deny', 'find docs -type f -exec cat {} +'],
		['deny', 'find . -name x | xargs cat'],
		['deny', "bash <<'EOF'\ncat docs/rfc/rfc5280.txt\nEOF"],
		['deny', 'python3 - <<EOF\nprint(open("docs/rfc/rfc5280.txt").read())\nEOF'],
		['deny', 'cat <<EOF | bash\ncat docs/rfc/rfc5280.txt\nEOF'],
		['deny', 'echo "$(cat <<EOF\ncat docs/rfc/rfc5280.txt\nEOF\n)" | sh'],
		['deny', 'rg nextUpdate'],
		['deny', 'rg -e foo/bar'],
		['deny', 'rg -n -e nextUpdate -e foo/bar'],
		['deny', 'grep -r -f patterns/list.txt .'],
		['deny', 'rg --regexp foo/bar'],
		['pass', 'rg -e foo/bar src'],
		['pass', 'rg --regexp=foo/bar src'],
		['deny', 'rg nextUpdate .'],
		['deny', 'rg nextUpdate docs'],
		['deny', 'rg foo docs/r*'],
		['deny', 'grep -rn nextUpdate .'],
		['deny', 'grep nextUpdate -r docs'],
		['deny', 'git grep nextUpdate'],
		['deny', 'xargs -0 rg nextUpdate'],
		['deny', 'bun spec read rfc5280 4.1'],
		['deny', 'bun scripts/spec/main.ts search nextUpdate'],
	] as const)('%s %s', (want, command) => {
		expect(verdictOf(bash(command))).toBe(want);
	});

	test('lets the spec-lookup agent read the corpus', () => {
		expect(verdictOf(bash('cat docs/rfc/rfc5280.txt', 'spec-lookup'))).toBe('pass');
		expect(verdictOf(bash('rg nextUpdate', 'spec-lookup'))).toBe('pass');
	});
});

describe('tokenize', () => {
	test('splits command lists and marks pipes', () => {
		expect(tokenize('a b; c | d && e').segments).toEqual([
			{ words: ['a', 'b'], piped: false },
			{ words: ['c'], piped: true },
			{ words: ['d'], piped: false },
			{ words: ['e'], piped: false },
		]);
	});

	test('keeps quoted words whole and escaped separators literal', () => {
		expect(tokenize(`printf '%s;%s' "a b" c\\;`).segments).toEqual([
			{ words: ['printf', '%s;%s', 'a b', 'c;'], piped: false },
		]);
	});

	test('splits command substitutions into their own segments', () => {
		const script = tokenize('echo "x $(cat f) y"');
		expect(script.substitutions).toBe(true);
		expect(script.segments.map((segment) => segment.words)).toContainEqual(['cat', 'f']);
	});
});

describe('splitHeredocs', () => {
	test('drops prose bodies and keeps executable ones', () => {
		expect(splitHeredocs("git commit -F - <<'EOF'\nbody\nEOF\nls")).toEqual({
			text: "git commit -F - <<'EOF'\nls",
			bodies: [],
		});
		expect(splitHeredocs('bash <<EOF\ncat x\nEOF')).toEqual({
			text: 'bash <<EOF',
			bodies: ['cat x'],
		});
	});
});

describe('hook output', () => {
	test('parses a payload and renders a deny decision', () => {
		const payload = parsePayload(
			JSON.stringify({
				tool_name: 'Read',
				cwd: projectRoot,
				tool_input: { file_path: rfc5280 },
			}),
		);
		expect(payload).toBeDefined();
		if (payload === undefined) return;
		const output = render(decide(payload, projectRoot));
		expect(output).toContain('"permissionDecision":"deny"');
	});

	test('renders nothing for a pass', () => {
		expect(render({ kind: 'pass' })).toBeUndefined();
	});

	test('ignores input that is not a tool payload', () => {
		expect(parsePayload('not json')).toBeUndefined();
		expect(parsePayload('{"tool_name":"Read"}')).toBeUndefined();
	});
});
