import { describe, expect, test } from 'bun:test';
import { createMatrixPool } from '#micro509/kdf/argon2-memory';

describe('Argon2 matrix ownership', () => {
	test('wipes a returned matrix before making it available again', () => {
		const pool = createMatrixPool();
		const matrix = pool.take(16);
		matrix.fill(0xdeadbeef);
		pool.release(matrix);
		expect(matrix).toEqual(new Uint32Array(16));
		expect(pool.take(16)).toBe(matrix);
	});

	test('checked-out matrices belong exclusively to their callers', () => {
		const pool = createMatrixPool();
		const first = pool.take(16);
		pool.release(first);
		const borrowed = pool.take(16);
		const concurrent = pool.take(16);
		expect(borrowed).toBe(first);
		expect(concurrent).not.toBe(borrowed);
		borrowed.fill(1);
		concurrent.fill(2);
		expect(borrowed).toEqual(new Uint32Array(16).fill(1));
		pool.release(concurrent);
		expect(borrowed).toEqual(new Uint32Array(16).fill(1));
	});

	test.each([8, 16, 32])('reuses only matrices with exactly %i words', (words) => {
		const pool = createMatrixPool();
		const matching = pool.take(words);
		const other = pool.take(words + 1);
		pool.release(matching);
		pool.release(other);
		expect(pool.take(words)).toBe(matching);
		expect(pool.take(words + 1)).toBe(other);
	});

	test.each([1, 4, 5, 8])('bounds idle entries after %i returns', (count) => {
		const pool = createMatrixPool();
		const matrices = Array.from({ length: count }, () => pool.take(16));
		matrices.forEach((matrix) => {
			pool.release(matrix);
		});
		const available = Array.from({ length: count }, () => pool.take(16));
		expect(available.filter((matrix) => matrices.includes(matrix))).toHaveLength(
			Math.min(count, 4),
		);
		expect(new Set(available).size).toBe(count);
	});

	test('does not save empty matrices from failed allocations', () => {
		const pool = createMatrixPool();
		const empty = pool.take(0);
		pool.release(empty);
		expect(pool.take(0)).not.toBe(empty);
	});
});
