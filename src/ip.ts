const IPV6_SEGMENT = /^[0-9a-f]{1,4}$/;

export function normalizeIpAddress(value: string): string {
	if (!value.includes(':')) {
		return value;
	}
	return expandIpv6(value).join(':');
}

export function expandIpv6(value: string): readonly string[] {
	const normalized = value.toLowerCase();
	const pieces = normalized.split('::');
	const head = pieces[0] ?? '';
	const tail = pieces[1];
	if (tail !== undefined && normalized.indexOf('::') !== normalized.lastIndexOf('::')) {
		throw new Error(`Invalid IPv6 address: ${value}`);
	}
	const headParts = head.length > 0 ? head.split(':') : [];
	const tailParts = tail !== undefined && tail.length > 0 ? tail.split(':') : [];
	const missing = 8 - (headParts.length + tailParts.length);
	if ((tail === undefined && headParts.length !== 8) || missing < 0) {
		throw new Error(`Invalid IPv6 address: ${value}`);
	}
	const zeroes = Array.from({ length: missing }, () => '0');
	const parts = tail === undefined ? headParts : [...headParts, ...zeroes, ...tailParts];
	if (parts.length !== 8) {
		throw new Error(`Invalid IPv6 address: ${value}`);
	}
	return parts.map((segment) => {
		if (!IPV6_SEGMENT.test(segment)) {
			throw new Error(`Invalid IPv6 address: ${value}`);
		}
		return segment.padStart(4, '0');
	});
}

export function parseIpAddressToBytes(value: string): Uint8Array {
	if (value.includes(':')) {
		return parseIpv6ToBytes(value);
	}
	const segments = value.split('.');
	if (segments.length !== 4) {
		throw new Error(`Invalid IPv4 address: ${value}`);
	}
	return Uint8Array.from(
		segments.map((segment) => {
			const parsed = Number(segment);
			if (!Number.isInteger(parsed) || parsed < 0 || parsed > 255) {
				throw new Error(`Invalid IPv4 address: ${value}`);
			}
			return parsed;
		}),
	);
}

export function decodeIpAddress(bytes: Uint8Array): string {
	if (bytes.length === 4) {
		return Array.from(bytes, (value) => String(value)).join('.');
	}
	if (bytes.length === 16) {
		const groups: string[] = [];
		for (let index = 0; index < bytes.length; index += 2) {
			const left = bytes[index] ?? 0;
			const right = bytes[index + 1] ?? 0;
			groups.push(((left << 8) | right).toString(16));
		}
		return groups.join(':');
	}
	throw new Error(`Unsupported IP address length: ${bytes.length}`);
}

export function allOnesMaskForIpAddress(value: string): Uint8Array {
	const mask = new Uint8Array(value.includes(':') ? 16 : 4);
	mask.fill(0xff);
	return mask;
}

function parseIpv6ToBytes(value: string): Uint8Array {
	const expanded = expandIpv6(value);
	const bytes = new Uint8Array(16);
	expanded.forEach((segment, index) => {
		const parsed = Number.parseInt(segment, 16);
		bytes[index * 2] = parsed >> 8;
		bytes[index * 2 + 1] = parsed & 0xff;
	});
	return bytes;
}
