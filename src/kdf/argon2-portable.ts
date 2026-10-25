import type { Argon2Input, Argon2Result } from '#micro509/kdf/argon2';
import { moduleFor } from '#micro509/kdf/argon2-module';

// Reuse already-wiped memories without keeping them alive. Concurrent calls
// remove their memory from the pool, so no instance can observe another's data.
const idleMemories: WeakRef<WebAssembly.Memory>[] = [];

function memoryFor(pages: number): WebAssembly.Memory {
	for (let index = idleMemories.length - 1; index >= 0; index -= 1) {
		const memory = idleMemories[index]?.deref();
		if (memory === undefined || memory.buffer.byteLength === pages * 65536) {
			idleMemories.splice(index, 1);
			if (memory !== undefined) return memory;
		}
	}
	return new WebAssembly.Memory({ initial: pages, maximum: pages });
}

/** Internal portable implementation; callers enter through deriveArgon2's limits. */
export async function portableArgon2(input: Argon2Input): Promise<Argon2Result> {
	if (typeof WebAssembly === 'undefined' || input.salt.byteLength < 8) {
		return {
			ok: false,
			error: { code: 'unsupported', message: 'Portable Argon2 is unavailable for this request' },
		};
	}
	const inputs = [input.password, input.salt, input.secret, input.associatedData];
	// Include the C stack, static data, allocator overhead, and all input/output
	// buffers. Bound wasm32 addressing before creating memory, even with raised limits.
	const bytes =
		input.memoryKiB * 1024 +
		input.outputBytes +
		inputs.reduce((total, value) => total + (value?.byteLength ?? 0), 0) +
		2 * 1024 * 1024;
	if (bytes > 0x7fff0000) {
		return {
			ok: false,
			error: { code: 'unsupported', message: 'Request exceeds portable Argon2 address space' },
		};
	}
	let memory: WebAssembly.Memory | undefined;
	try {
		const module = await moduleFor();
		const pages = Math.ceil(bytes / 65536);
		memory = memoryFor(pages);
		const { exports } = await WebAssembly.instantiate(module, {
			env: { memory, emscripten_notify_memory_growth: () => undefined },
		});
		const { malloc, begin, step, finish, _initialize: initialize } = exports;
		if (
			typeof malloc !== 'function' ||
			typeof begin !== 'function' ||
			typeof step !== 'function' ||
			typeof finish !== 'function' ||
			typeof initialize !== 'function'
		) {
			throw new Error('Invalid portable Argon2 module');
		}
		initialize();
		const heap = new Uint8Array(memory.buffer);
		const allocate = (length: number): number => {
			const pointer: unknown = malloc(Math.max(1, length));
			if (
				typeof pointer !== 'number' ||
				!Number.isInteger(pointer) ||
				pointer <= 0 ||
				pointer + length > heap.length
			) {
				throw new Error('Portable Argon2 allocation failed');
			}
			return pointer;
		};
		const argumentsForInputs = inputs.flatMap((value) => {
			if (value === undefined || value.length === 0) return [0, 0];
			const pointer = allocate(value.length);
			heap.set(value, pointer);
			return [pointer, value.length];
		});
		const output = allocate(input.outputBytes);
		const result: unknown = begin(
			...argumentsForInputs,
			output,
			input.outputBytes,
			input.memoryKiB,
			input.passes,
			input.parallelism,
			input.version,
			input.algorithm === 'argon2d' ? 0 : 2,
		);
		if (result !== 0) throw new Error('Portable Argon2 initialization failed');
		// Yield between reference segments, without workers, threads, shared memory,
		// Node imports, external fetches, or changes to the requested lane count.
		let yieldedAt = performance.now();
		let segments = 0;
		while (step() !== 0) {
			segments += 1;
			// Some edge clocks advance only after I/O. Yield by count there too.
			if (segments >= 4 || performance.now() - yieldedAt >= 8) {
				await new Promise<void>((resolve) => setTimeout(resolve, 0));
				yieldedAt = performance.now();
				segments = 0;
			}
		}
		finish();
		return { ok: true, value: heap.slice(output, output + input.outputBytes) };
	} catch {
		return {
			ok: false,
			error: { code: 'derivation_failed', message: 'Portable Argon2 derivation failed' },
		};
	} finally {
		// Also erase the stack, allocator storage, partial results and inputs on failure.
		if (memory !== undefined) {
			new Uint8Array(memory.buffer).fill(0);
			if (idleMemories.length === 4) idleMemories.shift();
			idleMemories.push(new WeakRef(memory));
		}
	}
}
