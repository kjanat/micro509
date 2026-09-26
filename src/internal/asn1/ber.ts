import { throwDecodeRefusal } from '#micro509/internal/asn1/decode-refusal';
import {
	concatBytes,
	DEFAULT_MAX_DER_DEPTH,
	encodeLength,
	readIdentifier,
	tlv,
} from '#micro509/internal/asn1/der';

export interface BerElement {
	readonly tag: number;
	readonly headerStart: number;
	readonly identifierLength: number;
	readonly start: number;
	readonly contentEnd: number;
	readonly end: number;
	readonly children: readonly BerElement[];
}

const CONSTRUCTED = 0x20;
const BIT_STRING = 0x03;
const FLATTENED_STRING_TAGS: ReadonlySet<number> = new Set([
	0x04, 0x07, 0x0c, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1e,
]);

export function readBerRoot(
	bytes: Uint8Array,
	maxDepth: number = DEFAULT_MAX_DER_DEPTH,
): BerElement {
	if (!Number.isSafeInteger(maxDepth) || maxDepth < 1) {
		throw new RangeError('BER max depth must be a positive safe integer');
	}
	const root = readBerElement(bytes, 0, bytes.length, 1, maxDepth);
	if (root.end !== bytes.length) {
		throw new Error('Trailing data after BER element');
	}
	return root;
}

export function berEncoding(bytes: Uint8Array, element: BerElement): Uint8Array {
	return bytes.slice(element.headerStart, element.end);
}

export function berPrimitiveContent(
	bytes: Uint8Array,
	element: BerElement,
	tag: number,
): Uint8Array {
	if (element.tag !== tag || (tag & CONSTRUCTED) !== 0) {
		throw new Error(`Expected primitive BER tag 0x${tag.toString(16)}`);
	}
	return bytes.slice(element.start, element.contentEnd);
}

export function berSequenceChildren(element: BerElement): readonly BerElement[] {
	if (element.tag !== 0x30) {
		throw new Error('Expected SEQUENCE');
	}
	return element.children;
}

export function berStringContent(
	bytes: Uint8Array,
	element: BerElement,
	primitiveTag: number,
	segmentTag: number = primitiveTag,
): Uint8Array {
	if (element.tag === primitiveTag) {
		return berPrimitiveContent(bytes, element, primitiveTag);
	}
	if (element.tag !== (primitiveTag | CONSTRUCTED)) {
		throw new Error(`Expected BER string tag 0x${primitiveTag.toString(16)}`);
	}
	return concatBytes(
		element.children.map((segment) => berStringContent(bytes, segment, segmentTag)),
	);
}

function definiteElement(bytes: Uint8Array, element: BerElement, content: Uint8Array): Uint8Array {
	return concatBytes([
		bytes.subarray(element.headerStart, element.headerStart + element.identifierLength),
		encodeLength(content.length),
		content,
	]);
}

export function berToDefiniteLength(bytes: Uint8Array, element: BerElement): Uint8Array {
	if ((element.tag & CONSTRUCTED) === 0) {
		return definiteElement(bytes, element, bytes.slice(element.start, element.contentEnd));
	}
	const primitiveTag = element.tag & ~CONSTRUCTED;
	if (primitiveTag === BIT_STRING) {
		return tlv(BIT_STRING, bitStringContent(bytes, element));
	}
	if (FLATTENED_STRING_TAGS.has(primitiveTag)) {
		return tlv(primitiveTag, berStringContent(bytes, element, primitiveTag));
	}
	return definiteElement(
		bytes,
		element,
		concatBytes(element.children.map((child) => berToDefiniteLength(bytes, child))),
	);
}

function bitStringContent(bytes: Uint8Array, element: BerElement): Uint8Array {
	const segments = bitStringSegments(bytes, element);
	const last = segments.at(-1);
	if (last === undefined) {
		return Uint8Array.of(0);
	}
	const data: Uint8Array[] = [];
	for (const segment of segments) {
		const unusedBits = segment[0];
		if (unusedBits === undefined || unusedBits > 7) {
			throw new Error('Malformed BER BIT STRING segment');
		}
		if (segment !== last && unusedBits !== 0) {
			throw new Error('Only the last BER BIT STRING segment may have unused bits');
		}
		if (segment.length === 1 && unusedBits !== 0) {
			throw new Error('Empty BER BIT STRING segment must have zero unused bits');
		}
		data.push(segment.subarray(1));
	}
	return concatBytes([Uint8Array.of(last[0] ?? 0), ...data]);
}

function bitStringSegments(bytes: Uint8Array, element: BerElement): readonly Uint8Array[] {
	if (element.tag === BIT_STRING) {
		return [bytes.slice(element.start, element.contentEnd)];
	}
	if (element.tag !== (BIT_STRING | CONSTRUCTED)) {
		throw new Error('Expected BER BIT STRING segment');
	}
	return element.children.flatMap((segment) => bitStringSegments(bytes, segment));
}

function readBerElement(
	bytes: Uint8Array,
	offset: number,
	limit: number,
	depth: number,
	maxDepth: number,
): BerElement {
	if (depth > maxDepth) {
		throwDecodeRefusal('limit_exceeded', `BER exceeds max depth of ${maxDepth}`);
	}
	const tag = byteAt(bytes, offset);
	if (tag === 0x00) {
		throw new Error('Unexpected end-of-contents octets');
	}
	const identifier = readIdentifier(bytes, offset);
	const lengthOffset = offset + identifier.length;
	const lengthByte = byteAt(bytes, lengthOffset);
	const constructed = (tag & CONSTRUCTED) !== 0;
	if (lengthByte === 0x80) {
		if (!constructed) {
			throw new Error('Indefinite length requires a constructed encoding');
		}
		return readIndefiniteElement(bytes, offset, identifier.length, tag, limit, depth, maxDepth);
	}
	const { lengthOctets, length } = readDefiniteLength(bytes, lengthOffset, lengthByte);
	const start = lengthOffset + lengthOctets;
	const end = start + length;
	if (end > limit) {
		throw new Error('BER element exceeds its container');
	}
	return {
		tag,
		headerStart: offset,
		identifierLength: identifier.length,
		start,
		contentEnd: end,
		end,
		children: constructed ? readDefiniteChildren(bytes, start, end, depth, maxDepth) : [],
	};
}

function readIndefiniteElement(
	bytes: Uint8Array,
	offset: number,
	identifierLength: number,
	tag: number,
	limit: number,
	depth: number,
	maxDepth: number,
): BerElement {
	const start = offset + identifierLength + 1;
	const children: BerElement[] = [];
	let position = start;
	while (position < limit && bytes[position] !== 0x00) {
		const child = readBerElement(bytes, position, limit, depth + 1, maxDepth);
		children.push(child);
		position = child.end;
	}
	if (position + 1 >= limit || bytes[position + 1] !== 0x00) {
		throw new Error('Missing end-of-contents octets');
	}
	return {
		tag,
		headerStart: offset,
		identifierLength,
		start,
		contentEnd: position,
		end: position + 2,
		children,
	};
}

function readDefiniteChildren(
	bytes: Uint8Array,
	start: number,
	end: number,
	depth: number,
	maxDepth: number,
): readonly BerElement[] {
	const children: BerElement[] = [];
	let position = start;
	while (position < end) {
		const child = readBerElement(bytes, position, end, depth + 1, maxDepth);
		children.push(child);
		position = child.end;
	}
	return children;
}

function readDefiniteLength(
	bytes: Uint8Array,
	lengthOffset: number,
	lengthByte: number,
): { readonly lengthOctets: number; readonly length: number } {
	if ((lengthByte & 0x80) === 0) {
		return { lengthOctets: 1, length: lengthByte };
	}
	const octets = lengthByte & 0x7f;
	if (octets === 0x7f) {
		throw new Error('Reserved BER length octet');
	}
	let length = 0;
	for (let index = 0; index < octets; index += 1) {
		const next = byteAt(bytes, lengthOffset + 1 + index);
		if (length > Math.floor((Number.MAX_SAFE_INTEGER - next) / 256)) {
			throw new Error('BER length exceeds safe integer range');
		}
		length = length * 256 + next;
	}
	return { lengthOctets: 1 + octets, length };
}

function byteAt(bytes: Uint8Array, index: number): number {
	const value = bytes[index];
	if (value === undefined) {
		throw new Error('Unexpected end of BER input');
	}
	return value;
}
