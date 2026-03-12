export function encodeLength(length: number): Uint8Array {
	if (length < 128) {
		return Uint8Array.of(length);
	}

	const parts = encodeBase256(length);
	return Uint8Array.of(0x80 | parts.length, ...parts);
}

export function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
	const length = parts.reduce((sum, part) => sum + part.length, 0);
	const out = new Uint8Array(length);
	let offset = 0;
	for (const part of parts) {
		out.set(part, offset);
		offset += part.length;
	}
	return out;
}

export function tlv(tag: number, value: Uint8Array): Uint8Array {
	return concatBytes([Uint8Array.of(tag), encodeLength(value.length), value]);
}

export function sequence(parts: readonly Uint8Array[]): Uint8Array {
	return tlv(0x30, concatBytes(parts));
}

export function setOf(parts: readonly Uint8Array[]): Uint8Array {
	const sorted = parts.slice().sort((a, b) => {
		const len = Math.min(a.length, b.length);
		for (let i = 0; i < len; i++) {
			const diff = (a[i] ?? 0) - (b[i] ?? 0);
			if (diff !== 0) return diff;
		}
		return a.length - b.length;
	});
	return tlv(0x31, concatBytes(sorted));
}

export function explicitContext(tag: number, value: Uint8Array): Uint8Array {
	return tlv(0xa0 + tag, value);
}

export function implicitConstructedContext(tag: number, value: Uint8Array): Uint8Array {
	return tlv(0xa0 + tag, value);
}

export function implicitPrimitiveContext(tag: number, value: Uint8Array): Uint8Array {
	return tlv(0x80 + tag, value);
}

export function integer(bytes: Uint8Array): Uint8Array {
	if (bytes.length === 0) {
		return tlv(0x02, Uint8Array.of(0));
	}

	let start = 0;
	while (start < bytes.length - 1 && bytes[start] === 0) {
		start += 1;
	}

	const value = bytes.slice(start);
	if ((value[0] ?? 0) >= 0x80) {
		return tlv(0x02, concatBytes([Uint8Array.of(0), value]));
	}

	return tlv(0x02, value);
}

export function integerFromNumber(value: number): Uint8Array {
	if (!Number.isInteger(value) || value < 0) {
		throw new Error('INTEGER must be a non-negative integer');
	}

	if (value === 0) {
		return integer(Uint8Array.of(0));
	}

	return integer(Uint8Array.from(encodeBase256(value)));
}

export function bool(value: boolean): Uint8Array {
	return tlv(0x01, Uint8Array.of(value ? 0xff : 0x00));
}

export function nullValue(): Uint8Array {
	return tlv(0x05, new Uint8Array());
}

export function octetString(value: Uint8Array): Uint8Array {
	return tlv(0x04, value);
}

export function bitString(value: Uint8Array, unusedBits = 0): Uint8Array {
	if (unusedBits < 0 || unusedBits > 7) {
		throw new Error('unusedBits must be between 0 and 7');
	}
	if (value.length === 0 && unusedBits !== 0) {
		throw new Error('unusedBits must be 0 when value is empty');
	}
	if (value.length > 0 && unusedBits > 0) {
		const lastByte = value[value.length - 1] ?? 0;
		if ((lastByte & ((1 << unusedBits) - 1)) !== 0) {
			throw new Error('unused bits in the last byte must be zero');
		}
	}
	return tlv(0x03, concatBytes([Uint8Array.of(unusedBits), value]));
}

export function utf8String(value: string): Uint8Array {
	return tlv(0x0c, new TextEncoder().encode(value));
}

export function printableString(value: string): Uint8Array {
	if (!/^[A-Za-z0-9 '()+,\-./:=?]*$/.test(value)) {
		throw new Error('Invalid PrintableString: contains characters outside the allowed set');
	}
	return tlv(0x13, new TextEncoder().encode(value));
}

export function ia5String(value: string): Uint8Array {
	for (let i = 0; i < value.length; i++) {
		if (value.charCodeAt(i) > 0x7f) {
			throw new Error('Invalid IA5String: contains non-ASCII characters');
		}
	}
	return tlv(0x16, new TextEncoder().encode(value));
}

export function objectIdentifier(oid: string): Uint8Array {
	const segments = oid.split('.').map((segment) => Number(segment));
	if (segments.length < 2) {
		throw new Error(`Invalid OID: ${oid}`);
	}

	const [first, second, ...rest] = segments;
	if (first === undefined || second === undefined) {
		throw new Error(`Invalid OID: ${oid}`);
	}
	if (first !== 0 && first !== 1 && first !== 2) {
		throw new Error(`Invalid OID first arc: ${first}`);
	}
	if ((first === 0 || first === 1) && second >= 40) {
		throw new Error(`Invalid OID second arc: ${second} (must be < 40 when first arc is ${first})`);
	}
	const bytes: number[] = [first * 40 + second];
	for (const segment of rest) {
		if (!Number.isInteger(segment) || segment < 0) {
			throw new Error(`Invalid OID segment in ${oid}`);
		}
		const encoded: number[] = [segment & 0x7f];
		let current = segment >> 7;
		while (current > 0) {
			encoded.unshift(0x80 | (current & 0x7f));
			current >>= 7;
		}
		bytes.push(...encoded);
	}

	return tlv(0x06, Uint8Array.from(bytes));
}

export function utcTime(date: Date): Uint8Array {
	const value = `${[
		twoDigits(date.getUTCFullYear() % 100),
		twoDigits(date.getUTCMonth() + 1),
		twoDigits(date.getUTCDate()),
		twoDigits(date.getUTCHours()),
		twoDigits(date.getUTCMinutes()),
		twoDigits(date.getUTCSeconds()),
	].join('')}Z`;
	return tlv(0x17, new TextEncoder().encode(value));
}

export function generalizedTime(date: Date): Uint8Array {
	const value = `${[
		String(date.getUTCFullYear()).padStart(4, '0'),
		twoDigits(date.getUTCMonth() + 1),
		twoDigits(date.getUTCDate()),
		twoDigits(date.getUTCHours()),
		twoDigits(date.getUTCMinutes()),
		twoDigits(date.getUTCSeconds()),
	].join('')}Z`;
	return tlv(0x18, new TextEncoder().encode(value));
}

export function time(date: Date): Uint8Array {
	if (date.getUTCFullYear() >= 2050 || date.getUTCFullYear() < 1950) {
		return generalizedTime(date);
	}
	return utcTime(date);
}

function twoDigits(value: number): string {
	return String(value).padStart(2, '0');
}

function encodeBase256(value: number): readonly number[] {
	const parts: number[] = [];
	let current = value;
	while (current > 0) {
		parts.unshift(current & 0xff);
		current = Math.floor(current / 256);
	}
	return parts;
}

export interface DerElement {
	readonly tag: number;
	readonly headerLength: number;
	readonly length: number;
	readonly start: number;
	readonly end: number;
	readonly value: Uint8Array;
}

export function readElement(bytes: Uint8Array, offset = 0): DerElement {
	const tag = bytes[offset];
	if (tag === undefined) {
		throw new Error('Unexpected end of DER input');
	}
	const lengthByte = bytes[offset + 1];
	if (lengthByte === undefined) {
		throw new Error('Unexpected end of DER input');
	}

	let headerLength = 2;
	let length = 0;
	if ((lengthByte & 0x80) === 0) {
		length = lengthByte;
	} else {
		const octets = lengthByte & 0x7f;
		if (octets === 0) {
			throw new Error('Indefinite lengths are not supported');
		}
		headerLength += octets;
		for (let index = 0; index < octets; index += 1) {
			const next = bytes[offset + 2 + index];
			if (next === undefined) {
				throw new Error('Unexpected end of DER input');
			}
			length = (length << 8) | next;
		}
	}

	const start = offset + headerLength;
	const end = start + length;
	if (end > bytes.length) {
		throw new Error('DER element exceeds input length');
	}

	return {
		tag,
		headerLength,
		length,
		start,
		end,
		value: bytes.slice(start, end),
	};
}

export function readSequenceChildren(bytes: Uint8Array): DerElement[] {
	const sequenceElement = readElement(bytes, 0);
	if (sequenceElement.tag !== 0x30) {
		throw new Error('Expected SEQUENCE');
	}

	const children: DerElement[] = [];
	let offset = sequenceElement.start;
	while (offset < sequenceElement.end) {
		const element = readElement(bytes, offset);
		children.push(element);
		offset = element.end;
	}
	if (offset !== sequenceElement.end) {
		throw new Error('Malformed DER sequence');
	}
	return children;
}
