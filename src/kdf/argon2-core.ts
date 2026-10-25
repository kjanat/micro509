/**
 * Argon2 core: RFC 9106 sections 3.2–3.6, with version 0x10 compatibility.
 * BLAKE2b uses 64-bit BigInts; the memory matrix uses little-endian pairs of
 * 32-bit words. Each derivation owns its state and clears mutable work buffers.
 */
import type { Argon2Input } from '#micro509/kdf/argon2';
import { multiplyHigh } from '#micro509/kdf/argon2-arithmetic';

const MASK_64 = 0xffff_ffff_ffff_ffffn;
const IV = [
	0x6a09e667f3bcc908n,
	0xbb67ae8584caa73bn,
	0x3c6ef372fe94f82bn,
	0xa54ff53a5f1d36f1n,
	0x510e527fade682d1n,
	0x9b05688c2b3e6c1fn,
	0x1f83d9abfb41bd6bn,
	0x5be0cd19137e2179n,
];
const SIGMA = [
	[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
	[14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
	[11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
	[7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
	[9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
	[2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
	[12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
	[13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
	[6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
	[10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
	[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
	[14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];
// Column and diagonal quarter-round indexes shared by BLAKE2b and BlaMka.
const ROUND_INDEXES = [
	[0, 4, 8, 12],
	[1, 5, 9, 13],
	[2, 6, 10, 14],
	[3, 7, 11, 15],
	[0, 5, 10, 15],
	[1, 6, 11, 12],
	[2, 7, 8, 13],
	[3, 4, 9, 14],
] as const;
type MutableWords = { length: number; [index: number]: bigint };

function read32(bytes: Uint8Array, offset: number): number {
	return (
		((bytes[offset] ?? 0) |
			((bytes[offset + 1] ?? 0) << 8) |
			((bytes[offset + 2] ?? 0) << 16) |
			((bytes[offset + 3] ?? 0) << 24)) >>>
		0
	);
}

function write32(bytes: Uint8Array, offset: number, value: number): void {
	bytes[offset] = value & 0xff;
	bytes[offset + 1] = (value >>> 8) & 0xff;
	bytes[offset + 2] = (value >>> 16) & 0xff;
	bytes[offset + 3] = value >>> 24;
}

function read64(bytes: Uint8Array, offset: number): bigint {
	let value = 0n;
	for (let index = 7; index >= 0; index -= 1) {
		value = (value << 8n) | BigInt(bytes[offset + index] ?? 0);
	}
	return value;
}

function concat(...parts: Uint8Array[]): Uint8Array {
	const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
	let offset = 0;
	for (const part of parts) {
		output.set(part, offset);
		offset += part.length;
	}
	return output;
}

function blakeMix(
	v: MutableWords,
	a: number,
	b: number,
	c: number,
	d: number,
	x: bigint,
	y: bigint,
): void {
	v[a] = ((v[a] ?? 0n) + (v[b] ?? 0n) + x) & MASK_64;
	v[d] = rotateRight((v[d] ?? 0n) ^ (v[a] ?? 0n), 32);
	v[c] = ((v[c] ?? 0n) + (v[d] ?? 0n)) & MASK_64;
	v[b] = rotateRight((v[b] ?? 0n) ^ (v[c] ?? 0n), 24);
	v[a] = ((v[a] ?? 0n) + (v[b] ?? 0n) + y) & MASK_64;
	v[d] = rotateRight((v[d] ?? 0n) ^ (v[a] ?? 0n), 16);
	v[c] = ((v[c] ?? 0n) + (v[d] ?? 0n)) & MASK_64;
	v[b] = rotateRight((v[b] ?? 0n) ^ (v[c] ?? 0n), 63);
}

function rotateRight(value: bigint, bits: number): bigint {
	const shift = BigInt(bits);
	return ((value >> shift) | (value << (64n - shift))) & MASK_64;
}

function blakeRound(v: MutableWords, words: bigint[], sigma: number[]): void {
	for (const [index, [a, b, c, d]] of ROUND_INDEXES.entries()) {
		blakeMix(
			v,
			a,
			b,
			c,
			d,
			words[sigma[index * 2] ?? 0] ?? 0n,
			words[sigma[index * 2 + 1] ?? 0] ?? 0n,
		);
	}
}

function blake2bCompress(h: bigint[], block: Uint8Array, count: bigint, last: boolean): void {
	const words = Array.from({ length: 16 }, (_, index) => read64(block, index * 8));
	const v = [...h, ...IV];
	try {
		v[12] = (v[12] ?? 0n) ^ (count & MASK_64);
		v[13] = (v[13] ?? 0n) ^ (count >> 64n);
		if (last) v[14] = (v[14] ?? 0n) ^ MASK_64;
		for (const sigma of SIGMA) blakeRound(v, words, sigma);
		for (let index = 0; index < 8; index += 1) {
			h[index] = (h[index] ?? 0n) ^ (v[index] ?? 0n) ^ (v[index + 8] ?? 0n);
		}
	} finally {
		words.fill(0n);
		v.fill(0n);
	}
}

function blake2b(input: Uint8Array, outputBytes: number): Uint8Array {
	const h = [...IV];
	const finalBlock = new Uint8Array(128);
	try {
		h[0] = (h[0] ?? 0n) ^ (0x01010000n | BigInt(outputBytes));
		let offset = 0;
		while (input.length - offset > 128) {
			blake2bCompress(h, input.subarray(offset, offset + 128), BigInt(offset + 128), false);
			offset += 128;
		}
		finalBlock.set(input.subarray(offset));
		blake2bCompress(h, finalBlock, BigInt(input.length), true);
		const output = new Uint8Array(outputBytes);
		for (let index = 0; index < outputBytes; index += 1) {
			output[index] = Number(((h[Math.floor(index / 8)] ?? 0n) >> BigInt((index % 8) * 8)) & 0xffn);
		}
		return output;
	} finally {
		h.fill(0n);
		finalBlock.fill(0);
	}
}

function blakeLong(input: Uint8Array, outputBytes: number): Uint8Array {
	const seed = concat(
		Uint8Array.from([
			outputBytes & 0xff,
			(outputBytes >>> 8) & 0xff,
			(outputBytes >>> 16) & 0xff,
			outputBytes >>> 24,
		]),
		input,
	);
	let value: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
	try {
		if (outputBytes <= 64) return blake2b(seed, outputBytes);
		value = blake2b(seed, 64);
		const output = new Uint8Array(outputBytes);
		let offset = 0;
		while (outputBytes - offset > 64) {
			output.set(value.subarray(0, 32), offset);
			offset += 32;
			if (outputBytes - offset > 64) {
				const next = blake2b(value, 64);
				value.fill(0);
				value = next;
			}
		}
		const last = blake2b(value, outputBytes - offset);
		try {
			output.set(last, offset);
			return output;
		} finally {
			last.fill(0);
		}
	} finally {
		seed.fill(0);
		value.fill(0);
	}
}

function initialHash(input: Argon2Input, type: number): Uint8Array {
	const password = input.password;
	const salt = input.salt;
	const secret = input.secret ?? new Uint8Array();
	const associatedData = input.associatedData ?? new Uint8Array();
	const fields = new Uint8Array(28);
	const values = [
		input.parallelism,
		input.outputBytes,
		input.memoryKiB,
		input.passes,
		input.version,
		type,
		password.length,
	];
	let offset = 0;
	for (const value of values) {
		write32(fields, offset, value);
		offset += 4;
	}
	const tail = new Uint8Array(12);
	write32(tail, 0, salt.length);
	write32(tail, 4, secret.length);
	write32(tail, 8, associatedData.length);
	const message = concat(
		fields.subarray(0, 28),
		password,
		tail.subarray(0, 4),
		salt,
		tail.subarray(4, 8),
		secret,
		tail.subarray(8, 12),
		associatedData,
	);
	try {
		return blake2b(message, 64);
	} finally {
		message.fill(0);
	}
}

// Keep the four 64-bit registers local throughout the quarter round. The
// scratch block is read once and written once, instead of at each add/rotate.
// Low words stay unsigned for carry calculation; high words stay signed so
// the JIT can use 32-bit addition. Storing into Uint32Array preserves the bits.
function argonMix(words: Uint32Array, a: number, b: number, c: number, d: number): void {
	let aLow = words[a] ?? 0;
	let aHigh = (words[a + 1] ?? 0) | 0;
	let bLow = words[b] ?? 0;
	let bHigh = (words[b + 1] ?? 0) | 0;
	let cLow = words[c] ?? 0;
	let cHigh = (words[c + 1] ?? 0) | 0;
	let dLow = words[d] ?? 0;
	let dHigh = (words[d + 1] ?? 0) | 0;
	let product: number;
	let sum: number;
	let low: number;
	let high: number;

	product = Math.imul(aLow, bLow);
	sum = aLow + bLow + ((product << 1) >>> 0);
	aHigh =
		(aHigh +
			bHigh +
			((multiplyHigh(aLow, bLow, product) << 1) | (product >>> 31)) +
			((sum / 0x1_0000_0000) | 0)) |
		0;
	aLow = sum >>> 0;
	low = dLow ^ aLow;
	high = dHigh ^ aHigh;
	dLow = high >>> 0;
	dHigh = low | 0;

	product = Math.imul(cLow, dLow);
	sum = cLow + dLow + ((product << 1) >>> 0);
	cHigh =
		(cHigh +
			dHigh +
			((multiplyHigh(cLow, dLow, product) << 1) | (product >>> 31)) +
			((sum / 0x1_0000_0000) | 0)) |
		0;
	cLow = sum >>> 0;
	low = bLow ^ cLow;
	high = bHigh ^ cHigh;
	bLow = ((low >>> 24) | (high << 8)) >>> 0;
	bHigh = (high >>> 24) | (low << 8) | 0;

	product = Math.imul(aLow, bLow);
	sum = aLow + bLow + ((product << 1) >>> 0);
	aHigh =
		(aHigh +
			bHigh +
			((multiplyHigh(aLow, bLow, product) << 1) | (product >>> 31)) +
			((sum / 0x1_0000_0000) | 0)) |
		0;
	aLow = sum >>> 0;
	low = dLow ^ aLow;
	high = dHigh ^ aHigh;
	dLow = ((low >>> 16) | (high << 16)) >>> 0;
	dHigh = (high >>> 16) | (low << 16) | 0;

	product = Math.imul(cLow, dLow);
	sum = cLow + dLow + ((product << 1) >>> 0);
	cHigh =
		(cHigh +
			dHigh +
			((multiplyHigh(cLow, dLow, product) << 1) | (product >>> 31)) +
			((sum / 0x1_0000_0000) | 0)) |
		0;
	cLow = sum >>> 0;
	low = bLow ^ cLow;
	high = bHigh ^ cHigh;
	bLow = ((low << 1) | (high >>> 31)) >>> 0;
	bHigh = (high << 1) | (low >>> 31) | 0;
	words[a] = aLow;
	words[a + 1] = aHigh;
	words[b] = bLow;
	words[b + 1] = bHigh;
	words[c] = cLow;
	words[c + 1] = cHigh;
	words[d] = dLow;
	words[d + 1] = dHigh;
}

// Each round uses fixed word strides: contiguous rows, then paired columns.
// Spell out the eight quarter rounds to avoid schedule-array loads in the hot loop.
function argonRound(words: Uint32Array, offset: number, stride: number, pair: number): void {
	argonMix(words, offset, offset + 2 * stride, offset + 4 * stride, offset + 6 * stride);
	argonMix(
		words,
		offset + pair,
		offset + 2 * stride + pair,
		offset + 4 * stride + pair,
		offset + 6 * stride + pair,
	);
	argonMix(words, offset + stride, offset + 3 * stride, offset + 5 * stride, offset + 7 * stride);
	argonMix(
		words,
		offset + stride + pair,
		offset + 3 * stride + pair,
		offset + 5 * stride + pair,
		offset + 7 * stride + pair,
	);
	argonMix(
		words,
		offset,
		offset + 2 * stride + pair,
		offset + 5 * stride,
		offset + 7 * stride + pair,
	);
	argonMix(
		words,
		offset + pair,
		offset + 3 * stride,
		offset + 5 * stride + pair,
		offset + 6 * stride,
	);
	argonMix(
		words,
		offset + stride,
		offset + 3 * stride + pair,
		offset + 4 * stride,
		offset + 6 * stride + pair,
	);
	argonMix(
		words,
		offset + stride + pair,
		offset + 2 * stride,
		offset + 4 * stride + pair,
		offset + 7 * stride,
	);
}

function permuteBlock(words: Uint32Array): void {
	for (let offset = 0; offset < 256; offset += 32) argonRound(words, offset, 4, 2);
	for (let offset = 0; offset < 32; offset += 4) argonRound(words, offset, 32, 2);
}

function fillBlock(
	memory: Uint32Array,
	previousOffset: number,
	referenceOffset: number,
	destinationOffset: number,
	withXor: boolean,
	original: Uint32Array,
	permuted: Uint32Array,
): void {
	for (let index = 0; index < 256; index += 1) {
		const value = (memory[previousOffset + index] ?? 0) ^ (memory[referenceOffset + index] ?? 0);
		original[index] = value;
		permuted[index] = value;
	}
	permuteBlock(permuted);
	if (withXor) {
		for (let index = 0; index < 256; index += 1) {
			memory[destinationOffset + index] =
				(original[index] ?? 0) ^ (permuted[index] ?? 0) ^ (memory[destinationOffset + index] ?? 0);
		}
	} else {
		for (let index = 0; index < 256; index += 1) {
			memory[destinationOffset + index] = (original[index] ?? 0) ^ (permuted[index] ?? 0);
		}
	}
}

function indexAlpha(
	pass: number,
	slice: number,
	index: number,
	sameLane: boolean,
	segmentLength: number,
	laneLength: number,
	pseudoRandom: number,
): number {
	let areaSize: number;
	if (pass === 0) {
		areaSize =
			slice === 0
				? index - 1
				: slice * segmentLength + (sameLane ? index - 1 : index === 0 ? -1 : 0);
	} else {
		areaSize = laneLength - segmentLength + (sameLane ? index - 1 : index === 0 ? -1 : 0);
	}
	const squareHigh = multiplyHigh(
		pseudoRandom,
		pseudoRandom,
		Math.imul(pseudoRandom, pseudoRandom),
	);
	const relative =
		areaSize - 1 - multiplyHigh(areaSize, squareHigh, Math.imul(areaSize, squareHigh));
	const start = pass === 0 ? 0 : slice === 3 ? 0 : (slice + 1) * segmentLength;
	return (start + relative) % laneLength;
}

function dataIndependent(type: number, pass: number, slice: number): boolean {
	return type === 1 || (type === 2 && pass === 0 && slice < 2);
}

function compressBlocks(
	previous: Uint32Array,
	reference: Uint32Array,
	output: Uint32Array,
	original: Uint32Array,
	permuted: Uint32Array,
): void {
	for (let index = 0; index < 256; index += 1) {
		const value = (previous[index] ?? 0) ^ (reference[index] ?? 0);
		original[index] = value;
		permuted[index] = value;
	}
	permuteBlock(permuted);
	for (let index = 0; index < 256; index += 1) {
		output[index] = (original[index] ?? 0) ^ (permuted[index] ?? 0);
	}
}

function generateAddressBlock(
	inputBlock: Uint32Array,
	addressBlock: Uint32Array,
	zero: Uint32Array,
	original: Uint32Array,
	permuted: Uint32Array,
	addressTemporary: Uint32Array,
): void {
	inputBlock[12] = ((inputBlock[12] ?? 0) + 1) >>> 0;
	compressBlocks(zero, inputBlock, addressTemporary, original, permuted);
	compressBlocks(zero, addressTemporary, addressBlock, original, permuted);
}

function toWords(bytes: Uint8Array): Uint32Array {
	const words = new Uint32Array(256);
	for (let index = 0; index < 256; index += 1) words[index] = read32(bytes, index * 4);
	return words;
}

interface Workspace {
	readonly memory: Uint32Array;
	readonly memoryBlocks: number;
	readonly laneLength: number;
	readonly segmentLength: number;
	readonly original: Uint32Array;
	readonly permuted: Uint32Array;
	readonly zero: Uint32Array;
	readonly addressTemporary: Uint32Array;
}

function fillIndexedBlock(
	input: Argon2Input,
	workspace: Workspace,
	position: { pass: number; slice: number; lane: number },
	index: number,
	addressBlock: Uint32Array | undefined,
): void {
	const { pass, slice, lane } = position;
	const { memory, laneLength, segmentLength, original, permuted } = workspace;
	const currentBlock = lane * laneLength + slice * segmentLength + index;
	const previousBlock =
		currentBlock % laneLength === 0 ? currentBlock + laneLength - 1 : currentBlock - 1;
	const previousOffset = previousBlock * 256;
	const pseudoOffset = addressBlock === undefined ? previousOffset : (index % 128) * 2;
	const pseudo = addressBlock ?? memory;
	const pseudoLow = pseudo[pseudoOffset] ?? 0;
	const pseudoHigh = pseudo[pseudoOffset + 1] ?? 0;
	let referenceLane = pseudoHigh % input.parallelism;
	if (pass === 0 && slice === 0) referenceLane = lane;
	const referenceIndex = indexAlpha(
		pass,
		slice,
		index,
		referenceLane === lane,
		segmentLength,
		laneLength,
		pseudoLow,
	);
	const destinationBlock = currentBlock * 256;
	fillBlock(
		memory,
		previousOffset,
		(referenceLane * laneLength + referenceIndex) * 256,
		destinationBlock,
		input.version !== 0x10 && pass !== 0,
		original,
		permuted,
	);
}

async function fillSegment(
	input: Argon2Input,
	type: number,
	workspace: Workspace,
	position: { pass: number; slice: number; lane: number },
): Promise<void> {
	const { pass, slice, lane } = position;
	const { memoryBlocks, segmentLength, original, permuted, zero, addressTemporary } = workspace;
	const independent = dataIndependent(type, pass, slice);
	const inputBlock = new Uint32Array(256);
	const addressBlock = new Uint32Array(256);
	try {
		if (independent) {
			inputBlock[0] = pass;
			inputBlock[2] = lane;
			inputBlock[4] = slice;
			inputBlock[6] = memoryBlocks;
			inputBlock[8] = input.passes;
			inputBlock[10] = type;
		}
		const startingIndex = pass === 0 && slice === 0 ? 2 : 0;
		if (independent && startingIndex !== 0) {
			generateAddressBlock(inputBlock, addressBlock, zero, original, permuted, addressTemporary);
		}
		for (let start = startingIndex; start < segmentLength; start += 512) {
			// Start the timer before computing so its delay overlaps useful work.
			// Awaiting it still yields to the event loop after at most 512 blocks.
			const pause = new Promise<void>((resolve) => setTimeout(resolve, 0));
			const end = Math.min(start + 512, segmentLength);
			for (let index = start; index < end; index += 1) {
				if (independent && index % 128 === 0) {
					generateAddressBlock(
						inputBlock,
						addressBlock,
						zero,
						original,
						permuted,
						addressTemporary,
					);
				}
				fillIndexedBlock(input, workspace, position, index, independent ? addressBlock : undefined);
			}
			await pause;
		}
	} finally {
		inputBlock.fill(0);
		addressBlock.fill(0);
		addressTemporary.fill(0);
	}
}

export async function deriveArgon2TypeScript(input: Argon2Input): Promise<Uint8Array> {
	const type = { argon2d: 0, argon2i: 1, argon2id: 2 }[input.algorithm];
	const memoryBlocks =
		Math.floor(input.memoryKiB / (4 * input.parallelism)) * 4 * input.parallelism;
	const laneLength = memoryBlocks / input.parallelism;
	const segmentLength = laneLength / 4;
	let memory = new Uint32Array(0);
	let h0: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
	let original = new Uint32Array(0);
	let permuted = new Uint32Array(0);
	let zero = new Uint32Array(0);
	let addressTemporary = new Uint32Array(0);
	let finalBlock: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
	let finalWords: Uint32Array<ArrayBufferLike> = new Uint32Array(0);
	try {
		memory = new Uint32Array(memoryBlocks * 256);
		h0 = initialHash(input, type);
		original = new Uint32Array(256);
		permuted = new Uint32Array(256);
		zero = new Uint32Array(256);
		addressTemporary = new Uint32Array(256);
		for (let lane = 0; lane < input.parallelism; lane += 1) {
			for (let block = 0; block < 2; block += 1) {
				const suffix = new Uint8Array(8);
				write32(suffix, 0, block);
				write32(suffix, 4, lane);
				const seed = concat(h0, suffix);
				let bytes: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
				let words: Uint32Array<ArrayBufferLike> = new Uint32Array(0);
				try {
					bytes = blakeLong(seed, 1024);
					words = toWords(bytes);
					memory.set(words, (lane * laneLength + block) * 256);
				} finally {
					seed.fill(0);
					bytes.fill(0);
					words.fill(0);
				}
			}
		}
		const workspace: Workspace = {
			memory,
			memoryBlocks,
			laneLength,
			segmentLength,
			original,
			permuted,
			zero,
			addressTemporary,
		};
		for (let pass = 0; pass < input.passes; pass += 1) {
			for (let slice = 0; slice < 4; slice += 1) {
				for (let lane = 0; lane < input.parallelism; lane += 1) {
					await fillSegment(input, type, workspace, { pass, slice, lane });
				}
			}
		}
		finalBlock = new Uint8Array(1024);
		finalWords = toWords(finalBlock);
		for (let lane = 0; lane < input.parallelism; lane += 1) {
			const lastOffset = (lane * laneLength + laneLength - 1) * 256;
			for (let index = 0; index < 256; index += 1) {
				finalWords[index] = (finalWords[index] ?? 0) ^ (memory[lastOffset + index] ?? 0);
			}
		}
		for (let index = 0; index < 256; index += 1)
			write32(finalBlock, index * 4, finalWords[index] ?? 0);
		return blakeLong(finalBlock, input.outputBytes);
	} finally {
		memory.fill(0);
		h0.fill(0);
		original.fill(0);
		permuted.fill(0);
		zero.fill(0);
		addressTemporary.fill(0);
		finalBlock.fill(0);
		finalWords.fill(0);
	}
}
