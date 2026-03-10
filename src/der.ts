function encodeLength(length: number): Uint8Array {
	if (length < 128) {
		return Uint8Array.of(length);
	}

	const parts: number[] = [];
	let current = length;
	while (current > 0) {
		parts.unshift(current & 0xff);
		current >>= 8;
	}

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
	return tlv(0x31, concatBytes(parts));
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
		throw new Error("INTEGER must be a non-negative integer");
	}

	if (value === 0) {
		return integer(Uint8Array.of(0));
	}

	const parts: number[] = [];
	let current = value;
	while (current > 0) {
		parts.unshift(current & 0xff);
		current = Math.floor(current / 256);
	}

	return integer(Uint8Array.from(parts));
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
	return tlv(0x03, concatBytes([Uint8Array.of(unusedBits), value]));
}

export function utf8String(value: string): Uint8Array {
	return tlv(0x0c, new TextEncoder().encode(value));
}

export function printableString(value: string): Uint8Array {
	return tlv(0x13, new TextEncoder().encode(value));
}

export function ia5String(value: string): Uint8Array {
	return tlv(0x16, new TextEncoder().encode(value));
}

export function objectIdentifier(oid: string): Uint8Array {
	const segments = oid.split(".").map((segment) => Number(segment));
	if (segments.length < 2) {
		throw new Error(`Invalid OID: ${oid}`);
	}

	const [first, second, ...rest] = segments;
	if (first === undefined || second === undefined) {
		throw new Error(`Invalid OID: ${oid}`);
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
	const value = [
		twoDigits(date.getUTCFullYear() % 100),
		twoDigits(date.getUTCMonth() + 1),
		twoDigits(date.getUTCDate()),
		twoDigits(date.getUTCHours()),
		twoDigits(date.getUTCMinutes()),
		twoDigits(date.getUTCSeconds()),
	].join("") + "Z";
	return tlv(0x17, new TextEncoder().encode(value));
}

export function generalizedTime(date: Date): Uint8Array {
	const value = [
		String(date.getUTCFullYear()).padStart(4, "0"),
		twoDigits(date.getUTCMonth() + 1),
		twoDigits(date.getUTCDate()),
		twoDigits(date.getUTCHours()),
		twoDigits(date.getUTCMinutes()),
		twoDigits(date.getUTCSeconds()),
	].join("") + "Z";
	return tlv(0x18, new TextEncoder().encode(value));
}

export function time(date: Date): Uint8Array {
	if (date.getUTCFullYear() >= 2050 || date.getUTCFullYear() < 1950) {
		return generalizedTime(date);
	}
	return utcTime(date);
}

function twoDigits(value: number): string {
	return String(value).padStart(2, "0");
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
		throw new Error("Unexpected end of DER input");
	}
	const lengthByte = bytes[offset + 1];
	if (lengthByte === undefined) {
		throw new Error("Unexpected end of DER input");
	}

	let headerLength = 2;
	let length = 0;
	if ((lengthByte & 0x80) === 0) {
		length = lengthByte;
	} else {
		const octets = lengthByte & 0x7f;
		if (octets === 0) {
			throw new Error("Indefinite lengths are not supported");
		}
		headerLength += octets;
		for (let index = 0; index < octets; index += 1) {
			const next = bytes[offset + 2 + index];
			if (next === undefined) {
				throw new Error("Unexpected end of DER input");
			}
			length = (length << 8) | next;
		}
	}

	const start = offset + headerLength;
	const end = start + length;
	if (end > bytes.length) {
		throw new Error("DER element exceeds input length");
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
		throw new Error("Expected SEQUENCE");
	}

	const children: DerElement[] = [];
	let offset = sequenceElement.start;
	while (offset < sequenceElement.end) {
		const element = readElement(bytes, offset);
		children.push(element);
		offset = element.end;
	}
	if (offset !== sequenceElement.end) {
		throw new Error("Malformed DER sequence");
	}
	return children;
}
