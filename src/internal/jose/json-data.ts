/** Bounded, descriptor-based snapshots of an already parsed JSON data model. @module */

import type { JsonValue } from '#micro509/internal/jose/strict-json';

interface Budget {
	bytes: number;
	nodes: number;
	readonly maxBytes: number;
	readonly maxNodes: number;
	readonly maxDepth: number;
	readonly active: Set<object>;
}

interface Refusal {
	readonly marker: typeof refusalMarker;
	readonly code: 'invalid_json' | 'limit_exceeded';
}
const refusalMarker: unique symbol = Symbol('JSON data refusal');

function refuse(code: Refusal['code']): never {
	throw { marker: refusalMarker, code } satisfies Refusal;
}
function isRefusal(value: unknown): value is Refusal {
	return (
		typeof value === 'object' &&
		value !== null &&
		'marker' in value &&
		value.marker === refusalMarker
	);
}
function bytes(budget: Budget, size: number): void {
	budget.bytes += size;
	if (budget.bytes > budget.maxBytes) refuse('limit_exceeded');
}
function node(budget: Budget): void {
	if (++budget.nodes > budget.maxNodes) refuse('limit_exceeded');
}
/** Counts the UTF-8 bytes of the shortest JSON string spelling without allocating it. */
function string(budget: Budget, value: string): string {
	if (value.length > budget.maxBytes - budget.bytes) refuse('limit_exceeded');
	bytes(budget, 2);
	for (let i = 0; i < value.length; i++) {
		const c = value.charCodeAt(i);
		if (c >= 0xd800 && c <= 0xdbff) {
			const next = value.charCodeAt(++i);
			if (!(next >= 0xdc00 && next <= 0xdfff)) refuse('invalid_json');
			bytes(budget, 4);
		} else bytes(budget, characterBytes(c));
	}
	return value;
}
function characterBytes(c: number): number {
	if (c >= 0xdc00 && c <= 0xdfff) refuse('invalid_json');
	if (c === 0x22 || c === 0x5c) return 2;
	if (c < 0x20) return [8, 9, 10, 12, 13].includes(c) ? 2 : 6;
	return c < 0x80 ? 1 : c < 0x800 ? 2 : 3;
}
function dataMember(value: object, name: string): unknown {
	const descriptor = Object.getOwnPropertyDescriptor(value, name);
	if (descriptor === undefined || !('value' in descriptor) || !descriptor.enumerable)
		refuse('invalid_json');
	return descriptor.value;
}
function checkPrototype(value: object, array: boolean): void {
	const prototype = Object.getPrototypeOf(value);
	if (array ? prototype !== Array.prototype : prototype !== null && prototype !== Object.prototype)
		refuse('invalid_json');
}
function copy(value: unknown, budget: Budget, depth: number): JsonValue {
	node(budget);
	if (value === null || typeof value === 'boolean') {
		bytes(budget, value === null ? 4 : value ? 4 : 5);
		return value;
	}
	if (typeof value === 'string') return string(budget, value);
	if (typeof value === 'number') {
		if (!Number.isFinite(value)) refuse('invalid_json');
		bytes(budget, String(value).length);
		return value;
	}
	if (typeof value !== 'object') refuse('invalid_json');
	if (depth >= budget.maxDepth) refuse('limit_exceeded');
	if (budget.active.has(value)) refuse('invalid_json');
	const array = Array.isArray(value);
	checkPrototype(value, array);
	budget.active.add(value);
	const names = Reflect.ownKeys(value);
	if (names.length > budget.maxNodes - budget.nodes + (array ? 1 : 0)) refuse('limit_exceeded');
	bytes(budget, 2);
	const result = array
		? copyArray(value, names, budget, depth)
		: copyObject(value, names, budget, depth);
	budget.active.delete(value);
	return result;
}

function copyArray(
	value: object,
	names: readonly PropertyKey[],
	budget: Budget,
	depth: number,
): JsonValue {
	const length: unknown = Object.getOwnPropertyDescriptor(value, 'length')?.value;
	if (typeof length !== 'number' || length > budget.maxNodes - budget.nodes)
		refuse('limit_exceeded');
	if (names.length !== length + 1) refuse('invalid_json');
	const items: JsonValue[] = [];
	for (let i = 0; i < length; i++) {
		if (i > 0) bytes(budget, 1);
		items.push(copy(dataMember(value, String(i)), budget, depth + 1));
	}
	return Object.freeze(items);
}
function copyObject(
	value: object,
	names: readonly PropertyKey[],
	budget: Budget,
	depth: number,
): JsonValue {
	const record: Record<string, JsonValue> = {};
	for (const [i, name] of names.entries()) {
		if (typeof name !== 'string') refuse('invalid_json');
		node(budget);
		string(budget, name);
		bytes(budget, i > 0 ? 2 : 1);
		Object.defineProperty(record, name, {
			value: copy(dataMember(value, name), budget, depth + 1),
			enumerable: true,
		});
	}
	return Object.freeze(record);
}

/** Copies plain JSON data without invoking getters, coercion or `toJSON`. */
export function snapshotJsonData(
	value: unknown,
	limits: { readonly maxBytes: number; readonly maxDepth: number; readonly maxNodes: number },
):
	| { readonly ok: true; readonly value: JsonValue }
	| { readonly ok: false; readonly code: Refusal['code'] } {
	try {
		return {
			ok: true,
			value: copy(value, { ...limits, bytes: 0, nodes: 0, active: new Set() }, 0),
		};
	} catch (error) {
		if (isRefusal(error)) return { ok: false, code: error.code };
		throw error;
	}
}
