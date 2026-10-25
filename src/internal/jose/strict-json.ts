/** A parsed JSON value. Objects are plain records whose members are all own data properties. */
export type JsonValue =
	| null
	| boolean
	| number
	| string
	| readonly JsonValue[]
	| { readonly [member: string]: JsonValue };

/** A parsed JSON object. */
export type JsonObject = { readonly [member: string]: JsonValue };

/** Reason strict JSON parsing refused its input. */
export type StrictJsonFailureCode = 'invalid_json' | 'duplicate_member' | 'limit_exceeded';

/** Failure of {@linkcode parseStrictJson}. */
export interface StrictJsonFailure {
	readonly ok: false;
	readonly code: StrictJsonFailureCode;
	readonly message: string;
}

/** Result of {@linkcode parseStrictJson}. */
export type StrictJsonResult = { readonly ok: true; readonly value: JsonValue } | StrictJsonFailure;

/** Bounds applied while parsing. */
export interface StrictJsonLimits {
	/** Maximum array and object nesting. */
	readonly maxDepth: number;
	/** Maximum number of values (scalars, arrays, objects and members) in the document. */
	readonly maxNodes: number;
}

interface Cursor {
	readonly text: string;
	index: number;
	nodes: number;
	readonly limits: StrictJsonLimits;
}

const failureBrand = Symbol('micro509.jose.strictJsonFailure');

interface Refusal {
	readonly [failureBrand]: true;
	readonly code: StrictJsonFailureCode;
	readonly message: string;
}

function refuse(code: StrictJsonFailureCode, message: string): never {
	const refusal: Refusal = { [failureBrand]: true, code, message };
	throw refusal;
}

function isRefusal(value: unknown): value is Refusal {
	return typeof value === 'object' && value !== null && failureBrand in value;
}

/**
 * Parses RFC 8259 JSON text, refusing duplicate object member names, lone surrogate escapes,
 * non-finite numbers, and documents beyond the given depth and node bounds.
 */
export function parseStrictJson(text: string, limits: StrictJsonLimits): StrictJsonResult {
	const cursor: Cursor = { text, index: 0, nodes: 0, limits };
	try {
		skipWhitespace(cursor);
		const value = parseValue(cursor, 0);
		skipWhitespace(cursor);
		if (cursor.index !== text.length)
			refuse('invalid_json', 'Trailing characters after JSON value');
		return { ok: true, value };
	} catch (error) {
		if (isRefusal(error)) return { ok: false, code: error.code, message: error.message };
		throw error;
	}
}

function skipWhitespace(cursor: Cursor): void {
	while (cursor.index < cursor.text.length) {
		const char = cursor.text.charCodeAt(cursor.index);
		if (char !== 0x20 && char !== 0x09 && char !== 0x0a && char !== 0x0d) return;
		cursor.index++;
	}
}

function countNode(cursor: Cursor): void {
	cursor.nodes++;
	if (cursor.nodes > cursor.limits.maxNodes) {
		refuse('limit_exceeded', 'JSON document exceeds the node limit');
	}
}

function parseValue(cursor: Cursor, depth: number): JsonValue {
	countNode(cursor);
	const char = cursor.text[cursor.index];
	switch (char) {
		case '{':
			return parseObject(cursor, depth + 1);
		case '[':
			return parseArray(cursor, depth + 1);
		case '"':
			return parseString(cursor);
		case 't':
			return parseLiteral(cursor, 'true', true);
		case 'f':
			return parseLiteral(cursor, 'false', false);
		case 'n':
			return parseLiteral(cursor, 'null', null);
		default:
			return parseNumber(cursor);
	}
}

function parseLiteral<TValue extends boolean | null>(
	cursor: Cursor,
	literal: string,
	value: TValue,
): TValue {
	if (!cursor.text.startsWith(literal, cursor.index)) {
		refuse('invalid_json', 'Unexpected token in JSON');
	}
	cursor.index += literal.length;
	return value;
}

const NUMBER_PATTERN = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

function parseNumber(cursor: Cursor): number {
	NUMBER_PATTERN.lastIndex = cursor.index;
	const match = NUMBER_PATTERN.exec(cursor.text);
	if (match === null) refuse('invalid_json', 'Unexpected token in JSON');
	cursor.index += match[0].length;
	const value = Number(match[0]);
	if (!Number.isFinite(value)) refuse('invalid_json', 'JSON number is not finite');
	return value;
}

function enter(cursor: Cursor, depth: number): void {
	if (depth > cursor.limits.maxDepth) {
		refuse('limit_exceeded', 'JSON document exceeds the nesting limit');
	}
}

function parseArray(cursor: Cursor, depth: number): readonly JsonValue[] {
	enter(cursor, depth);
	cursor.index++;
	const items: JsonValue[] = [];
	skipWhitespace(cursor);
	if (cursor.text[cursor.index] === ']') {
		cursor.index++;
		return items;
	}
	for (;;) {
		skipWhitespace(cursor);
		items.push(parseValue(cursor, depth));
		skipWhitespace(cursor);
		const char = cursor.text[cursor.index++];
		if (char === ']') return items;
		if (char !== ',') refuse('invalid_json', 'Expected "," or "]" in JSON array');
	}
}

function parseObject(cursor: Cursor, depth: number): JsonObject {
	enter(cursor, depth);
	cursor.index++;
	const members = new Map<string, JsonValue>();
	skipWhitespace(cursor);
	if (cursor.text[cursor.index] === '}') {
		cursor.index++;
		return {};
	}
	for (;;) {
		skipWhitespace(cursor);
		if (cursor.text[cursor.index] !== '"')
			refuse('invalid_json', 'Expected member name in JSON object');
		countNode(cursor);
		const name = parseString(cursor);
		if (members.has(name)) refuse('duplicate_member', 'JSON object repeats a member name');
		skipWhitespace(cursor);
		if (cursor.text[cursor.index++] !== ':') refuse('invalid_json', 'Expected ":" in JSON object');
		skipWhitespace(cursor);
		members.set(name, parseValue(cursor, depth));
		skipWhitespace(cursor);
		const char = cursor.text[cursor.index++];
		if (char === '}') break;
		if (char !== ',') refuse('invalid_json', 'Expected "," or "}" in JSON object');
	}
	const object: Record<string, JsonValue> = {};
	for (const [name, value] of members) {
		Object.defineProperty(object, name, {
			value,
			enumerable: true,
			writable: true,
			configurable: true,
		});
	}
	return object;
}

const HEX4 = /[0-9a-fA-F]{4}/y;

function readEscapedUnit(cursor: Cursor): number {
	HEX4.lastIndex = cursor.index;
	const match = HEX4.exec(cursor.text);
	if (match === null) refuse('invalid_json', 'Invalid unicode escape in JSON string');
	cursor.index += 4;
	return Number.parseInt(match[0], 16);
}

function parseString(cursor: Cursor): string {
	cursor.index++;
	let out = '';
	let runStart = cursor.index;
	for (;;) {
		if (cursor.index >= cursor.text.length) refuse('invalid_json', 'Unterminated JSON string');
		const code = cursor.text.charCodeAt(cursor.index);
		if (code === 0x22) {
			out += cursor.text.slice(runStart, cursor.index);
			cursor.index++;
			return out;
		}
		if (code < 0x20) refuse('invalid_json', 'Control character in JSON string');
		if (code !== 0x5c) {
			cursor.index++;
			continue;
		}
		out += cursor.text.slice(runStart, cursor.index);
		cursor.index++;
		out += parseEscape(cursor);
		runStart = cursor.index;
	}
}

const SIMPLE_ESCAPES: Readonly<Record<string, string>> = {
	'"': '"',
	'\\': '\\',
	'/': '/',
	b: '\b',
	f: '\f',
	n: '\n',
	r: '\r',
	t: '\t',
};

function parseEscape(cursor: Cursor): string {
	const marker = cursor.text[cursor.index++];
	if (marker === undefined) refuse('invalid_json', 'Unterminated JSON string');
	if (marker !== 'u') {
		const simple = Object.hasOwn(SIMPLE_ESCAPES, marker) ? SIMPLE_ESCAPES[marker] : undefined;
		if (simple === undefined) refuse('invalid_json', 'Invalid escape in JSON string');
		return simple;
	}
	const unit = readEscapedUnit(cursor);
	if (unit >= 0xdc00 && unit <= 0xdfff) {
		refuse('invalid_json', 'Lone low surrogate escape in JSON string');
	}
	if (unit < 0xd800 || unit > 0xdbff) return String.fromCharCode(unit);
	if (!cursor.text.startsWith('\\u', cursor.index)) {
		refuse('invalid_json', 'Lone high surrogate escape in JSON string');
	}
	cursor.index += 2;
	const low = readEscapedUnit(cursor);
	if (low < 0xdc00 || low > 0xdfff) {
		refuse('invalid_json', 'High surrogate escape without a low surrogate');
	}
	return String.fromCharCode(unit, low);
}

/** Narrows a parsed value to a JSON object. */
export function isJsonObject(value: JsonValue | undefined): value is JsonObject {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Narrows a parsed value to a JSON array. */
export function isJsonArray(value: JsonValue | undefined): value is readonly JsonValue[] {
	return Array.isArray(value);
}
