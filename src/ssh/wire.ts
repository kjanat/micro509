import { concatBytes } from '#micro509/internal/asn1/der';
import { throwMicro509Error } from '#micro509/result/result';

/** Machine-readable failure reason of the SSH key import functions. */
export type SshErrorCode =
	| 'malformed'
	| 'unsupported'
	| 'limit_exceeded'
	| 'key_mismatch'
	| 'invalid_options';

const SSH_ERROR_CODES = [
	'invalid_options',
	'malformed',
	'unsupported',
	'limit_exceeded',
	'key_mismatch',
] as const satisfies readonly SshErrorCode[];

/** The {@linkcode SshErrorCode} spelled `code`, if it is one. */
export function asSshErrorCode(code: string): SshErrorCode | undefined {
	return SSH_ERROR_CODES.find((candidate) => candidate === code);
}

/** Throws a `ResultError` carrying an {@linkcode SshErrorCode}. */
export function sshFail(code: SshErrorCode, message: string): never {
	return throwMicro509Error<SshErrorCode>(code, message);
}

const MAX_NAME_BYTES = 64;

/** Cursor over one SSH-encoded buffer (RFC 4251 §5). Every read is bounds-checked. */
export interface SshReader {
	/** Bytes not yet consumed. */
	readonly remaining: () => number;
	/** The next `uint32`. */
	readonly uint32: () => number;
	/** The next `length` raw bytes, as a view into the input. */
	readonly raw: (length: number) => Uint8Array;
	/** The next `string`, as a view into the input. */
	readonly string: (maxLength: number) => Uint8Array;
	/** The next `string` as a printable US-ASCII name of at most 64 bytes. */
	readonly name: () => string;
	/** The next `string` as UTF-8 text without NUL. */
	readonly text: (maxLength: number) => string;
	/** The next `mpint`, as a positive magnitude without leading zero bytes. */
	readonly mpint: (maxLength: number) => Uint8Array;
}

/** Creates an {@linkcode SshReader} over `data`. */
export function createSshReader(data: Uint8Array): SshReader {
	let offset = 0;
	const remaining = (): number => data.length - offset;
	const raw = (length: number): Uint8Array => {
		if (length > remaining()) {
			return sshFail('malformed', 'SSH data is truncated');
		}
		const view = data.subarray(offset, offset + length);
		offset += length;
		return view;
	};
	const uint32 = (): number => {
		const bytes = raw(4);
		return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, false);
	};
	const string = (maxLength: number): Uint8Array => {
		const length = uint32();
		if (length > maxLength) {
			return sshFail('limit_exceeded', `SSH string of ${length} bytes exceeds ${maxLength}`);
		}
		return raw(length);
	};
	const name = (): string => {
		const bytes = string(MAX_NAME_BYTES);
		if (bytes.length === 0 || bytes.some((byte) => byte < 0x21 || byte > 0x7e)) {
			return sshFail('malformed', 'SSH name is not printable US-ASCII');
		}
		return String.fromCharCode(...bytes);
	};
	const text = (maxLength: number): string => {
		const bytes = string(maxLength);
		if (bytes.includes(0)) {
			return sshFail('malformed', 'SSH text contains a NUL byte');
		}
		return decodeUtf8(bytes);
	};
	const mpint = (maxLength: number): Uint8Array => {
		const bytes = string(maxLength);
		const first = bytes[0];
		const second = bytes[1];
		if (first === undefined) {
			return sshFail('malformed', 'SSH key integer is zero');
		}
		if (first >= 0x80) {
			return sshFail('malformed', 'SSH key integer is negative');
		}
		if (first === 0) {
			if (second === undefined || second < 0x80) {
				return sshFail('malformed', 'SSH integer has a redundant leading zero byte');
			}
			return bytes.subarray(1);
		}
		return bytes;
	};
	return { remaining, uint32, raw, string, name, text, mpint };
}

/** Strict UTF-8 decode; invalid sequences are malformed input. */
export function decodeUtf8(bytes: Uint8Array): string {
	try {
		return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
	} catch {
		return sshFail('malformed', 'SSH text is not valid UTF-8');
	}
}

/** Encodes a `uint32` (RFC 4251 §5). */
export function sshUint32(value: number): Uint8Array {
	const bytes = new Uint8Array(4);
	new DataView(bytes.buffer).setUint32(0, value, false);
	return bytes;
}

/** Encodes a `string` (RFC 4251 §5). */
export function sshString(bytes: Uint8Array): Uint8Array {
	return concatBytes([sshUint32(bytes.length), bytes]);
}

/** Encodes a US-ASCII or UTF-8 text `string`. */
export function sshTextString(text: string): Uint8Array {
	return sshString(new TextEncoder().encode(text));
}

/** Encodes a non-negative integer, given as a big-endian magnitude, as an `mpint` (RFC 4251 §5). */
export function sshMpint(magnitude: Uint8Array): Uint8Array {
	const start = magnitude.findIndex((byte) => byte !== 0);
	if (start === -1) {
		return sshUint32(0);
	}
	const significant = magnitude.subarray(start);
	const needsSignByte = (significant[0] ?? 0) >= 0x80;
	return sshString(needsSignByte ? concatBytes([Uint8Array.of(0), significant]) : significant);
}

/** Big-endian magnitude of a non-negative `bigint`. */
export function bigintToBytes(value: bigint, length?: number): Uint8Array {
	let hex = value.toString(16);
	if (hex.length % 2 === 1) {
		hex = `0${hex}`;
	}
	const bytes = new Uint8Array(hex.length / 2);
	for (let index = 0; index < bytes.length; index++) {
		bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
	}
	if (length === undefined) {
		return bytes;
	}
	if (bytes.length > length) {
		return sshFail('malformed', 'SSH integer is larger than its field');
	}
	const padded = new Uint8Array(length);
	padded.set(bytes, length - bytes.length);
	return padded;
}

/** The non-negative `bigint` of a big-endian magnitude. */
export function bytesToBigint(bytes: Uint8Array): bigint {
	let value = 0n;
	for (const byte of bytes) {
		value = (value << 8n) | BigInt(byte);
	}
	return value;
}

/** Whether two byte strings are equal. */
export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
	return left.length === right.length && left.every((byte, index) => byte === right[index]);
}
