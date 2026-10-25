/**
 * Argon2 derivation and resource-policy boundary. The default backend prefers
 * native WebCrypto and uses the TypeScript implementation when unsupported.
 *
 * @module
 */

import type { Micro509Error, Result } from '#micro509/result/result';

/** RFC 9106 Argon2 variants. Use Argon2id for new password-based applications. */
export type Argon2Algorithm = 'argon2d' | 'argon2i' | 'argon2id';

/** Argon2 versions used by KDBX. The native backend supports only 0x13. */
export type Argon2Version = 0x10 | 0x13;

/** Exact derivation inputs. Password encoding and format preprocessing belong to the caller. */
export interface Argon2Input {
	/** Select Argon2id for new applications. */
	readonly algorithm: Argon2Algorithm;
	/** Exact version. No version substitution is performed. */
	readonly version: Argon2Version;
	/** Password or format-preprocessed input bytes. */
	readonly password: Uint8Array;
	/** Salt bytes. RFC 9106 recommends 16 bytes; the native backend requires at least eight. */
	readonly salt: Uint8Array;
	/** Total memory in kibibytes, at least eight times parallelism. */
	readonly memoryKiB: number;
	/** Number of full passes through memory. */
	readonly passes: number;
	/** Number of lanes. */
	readonly parallelism: number;
	/** Requested output length in bytes, at least four. */
	readonly outputBytes: number;
	/** Optional secret input, separate from the password. */
	readonly secret?: Uint8Array;
	/** Optional associated data included in the derivation. */
	readonly associatedData?: Uint8Array;
}

/** Per-invocation ceilings, checked before copying inputs or calling the backend. */
export interface Argon2Limits {
	/** Memory ceiling in KiB. Default: 262144 (256 MiB). */
	readonly maxMemoryKiB?: number;
	/** Pass ceiling. Default: 16. */
	readonly maxPasses?: number;
	/** Lane ceiling. Default: 16. */
	readonly maxParallelism?: number;
	/** Output-byte ceiling. Default: 1024. */
	readonly maxOutputBytes?: number;
	/** Sum of password, salt, secret, and associated-data lengths. Default: 1048576. */
	readonly maxInputBytes?: number;
}

/** Stable failures without password, salt, or backend exception content. */
export type Argon2ErrorCode =
	| 'invalid_parameters'
	| 'limit_exceeded'
	| 'unsupported'
	| 'derivation_failed';

/** Derived bytes or a typed error. Successful output belongs to the caller. */
export type Argon2Result = Result<Uint8Array, Micro509Error<Argon2ErrorCode>>;

/**
 * Trusted, explicitly supplied implementation for the exact requested algorithm
 * and version. Called only after parameter and resource checks. Input arrays are
 * private copies, wiped when the promise settles. A backend that transfers an input
 * buffer must erase it in the receiving worker. Transfer ownership of output
 * bytes to the caller: the wrapper copies and wipes that array before returning.
 * Report unsupported requests explicitly, without fallback. Execution behavior
 * and cancellation of a custom backend are its provider's responsibility.
 */
export type Argon2Backend = (input: Argon2Input) => Promise<Argon2Result>;

/** Resource policy and optional external implementation for {@linkcode deriveArgon2}. */
export interface Argon2Options {
	/** Per-call ceilings. Applications must separately bound concurrent calls. */
	readonly limits?: Argon2Limits;
	/**
	 * Omit to prefer native WebCrypto, then the TypeScript implementation on `unsupported` only.
	 * Select `native` or `portable` to require that implementation, or supply a
	 * trusted callback. Explicit selections never fall back to another backend.
	 */
	readonly backend?: Argon2Backend | 'native' | 'portable';
}

function failure(code: Argon2ErrorCode, message: string): Argon2Result {
	return { ok: false, error: { code, message } };
}

function uintInRange(value: number, min: number, max: number): boolean {
	return Number.isSafeInteger(value) && value >= min && value <= max;
}

function validate(input: Argon2Input, limits: Argon2Limits): Argon2Result | undefined {
	if (
		input.algorithm !== 'argon2id' &&
		input.algorithm !== 'argon2d' &&
		input.algorithm !== 'argon2i'
	) {
		return failure('unsupported', 'Unsupported Argon2 variant');
	}
	if (input.version !== 0x10 && input.version !== 0x13) {
		return failure('unsupported', 'Unsupported Argon2 version');
	}
	// RFC 9106 section 3.1. Memory is passed exactly, including values not
	// divisible by 4*p: rounding the input would change the initial hash.
	if (
		!uintInRange(input.parallelism, 1, 0xffffff) ||
		!uintInRange(input.memoryKiB, 8 * input.parallelism, 0xffffffff) ||
		!uintInRange(input.passes, 1, 0xffffffff) ||
		!uintInRange(input.outputBytes, 4, 0xffffffff)
	) {
		return failure('invalid_parameters', 'Invalid Argon2 numeric parameters');
	}
	const inputs = [input.password, input.salt, input.secret, input.associatedData];
	if (
		!(input.password instanceof Uint8Array) ||
		!(input.salt instanceof Uint8Array) ||
		inputs.some((bytes) => bytes !== undefined && !(bytes instanceof Uint8Array))
	) {
		return failure('invalid_parameters', 'Argon2 inputs must be Uint8Array values');
	}
	try {
		// A detached or out-of-bounds view reports zero length. Validate its
		// backing store before copying any of the caller's secret material.
		for (const bytes of inputs) {
			if (bytes !== undefined) Uint8Array.prototype.values.call(bytes);
		}
	} catch {
		return failure('invalid_parameters', 'Argon2 input buffer is unavailable');
	}
	const bounds = [
		[input.memoryKiB, limits.maxMemoryKiB ?? 262144],
		[input.passes, limits.maxPasses ?? 16],
		[input.parallelism, limits.maxParallelism ?? 16],
		[input.outputBytes, limits.maxOutputBytes ?? 1024],
		[
			inputs.reduce((sum, bytes) => sum + (bytes?.byteLength ?? 0), 0),
			limits.maxInputBytes ?? 1048576,
		],
	] as const;
	if (bounds.some(([, maximum]) => !uintInRange(maximum, 1, 0xffffffff))) {
		return failure('invalid_parameters', 'Argon2 resource limits must be positive uint32 values');
	}
	if (bounds.some(([actual, maximum]) => actual > maximum)) {
		return failure('limit_exceeded', 'Argon2 request exceeds resource limits');
	}
	return undefined;
}

function snapshotInput(input: Argon2Input): Argon2Input {
	// Read declared properties once, including inherited and non-enumerable ones.
	// Byte arrays remain references until validation has enforced resource bounds.
	const {
		algorithm,
		version,
		password,
		salt,
		memoryKiB,
		passes,
		parallelism,
		outputBytes,
		secret,
		associatedData,
	} = input;
	return {
		algorithm,
		version,
		password,
		salt,
		memoryKiB,
		passes,
		parallelism,
		outputBytes,
		...(secret === undefined ? {} : { secret }),
		...(associatedData === undefined ? {} : { associatedData }),
	};
}

function copyInput(input: Argon2Input): Argon2Input {
	return {
		algorithm: input.algorithm,
		version: input.version,
		memoryKiB: input.memoryKiB,
		passes: input.passes,
		parallelism: input.parallelism,
		outputBytes: input.outputBytes,
		password: new Uint8Array(input.password),
		salt: new Uint8Array(input.salt),
		...(input.secret === undefined ? {} : { secret: new Uint8Array(input.secret) }),
		...(input.associatedData === undefined
			? {}
			: { associatedData: new Uint8Array(input.associatedData) }),
	};
}

function eraseAccessible(bytes: Uint8Array | undefined): void {
	// Transfer detaches the sender's view. Its bytes can only be erased by the
	// receiving worker, and cleanup must still proceed through the other inputs.
	if (bytes !== undefined && bytes.byteLength > 0) Uint8Array.prototype.fill.call(bytes, 0);
}

async function nativeArgon2(input: Argon2Input): Promise<Argon2Result> {
	if (input.version !== 0x13) {
		return failure('unsupported', 'Native Argon2 supports version 0x13 only');
	}
	if (input.salt.byteLength < 8) {
		return failure('unsupported', 'Native Argon2 requires a salt of at least eight bytes');
	}
	if (input.outputBytes > Math.floor(0xffffffff / 8)) {
		return failure('unsupported', 'Requested output exceeds the native WebCrypto bit-length range');
	}
	if (typeof globalThis.crypto?.subtle === 'undefined') {
		return failure('unsupported', 'Native WebCrypto is unavailable');
	}
	const subtle = globalThis.crypto.subtle;
	let name: 'Argon2d' | 'Argon2i' | 'Argon2id';
	switch (input.algorithm) {
		case 'argon2id':
			name = 'Argon2id';
			break;
		case 'argon2d':
			name = 'Argon2d';
			break;
		case 'argon2i':
			name = 'Argon2i';
			break;
		default:
			return failure('unsupported', 'Unsupported Argon2 variant');
	}
	try {
		// raw-secret is a runtime WebCrypto extension not present in every DOM
		// declaration. The result is narrowed rather than asserted or globally
		// augmenting consumers' SubtleCrypto definitions.
		let key: unknown;
		try {
			key = await Reflect.apply(subtle.importKey, subtle, [
				'raw-secret',
				input.password,
				name,
				false,
				['deriveBits'],
			]);
		} catch (error) {
			// Older WebCrypto KeyFormat enums reject raw-secret with TypeError.
			// Keep this classification local to import; deriveBits failures stay failures.
			if (error instanceof TypeError) {
				return failure('unsupported', 'This runtime does not support the raw-secret key format');
			}
			throw error;
		}
		if (typeof CryptoKey === 'undefined' || !(key instanceof CryptoKey)) {
			return failure('derivation_failed', 'Native Argon2 returned an invalid key');
		}
		const params = {
			name,
			version: input.version,
			memory: input.memoryKiB,
			passes: input.passes,
			parallelism: input.parallelism,
			nonce: new Uint8Array(input.salt),
			...(input.secret === undefined ? {} : { secretValue: new Uint8Array(input.secret) }),
			...(input.associatedData === undefined
				? {}
				: { associatedData: new Uint8Array(input.associatedData) }),
		};
		try {
			const output = await subtle.deriveBits(params, key, input.outputBytes * 8);
			return { ok: true, value: new Uint8Array(output) };
		} finally {
			params.nonce.fill(0);
			params.secretValue?.fill(0);
			params.associatedData?.fill(0);
		}
	} catch (error) {
		return error instanceof Error && error.name === 'NotSupportedError'
			? failure('unsupported', 'This runtime does not support native Argon2')
			: failure('derivation_failed', 'Native Argon2 derivation failed');
	}
}

async function builtinArgon2(
	input: Argon2Input,
	backend: 'native' | 'portable' | undefined,
): Promise<Argon2Result> {
	if (backend !== 'portable') {
		const result = await nativeArgon2(input);
		if (backend === 'native' || result.ok || result.error.code !== 'unsupported') return result;
	}
	const { portableArgon2 } = await import('#micro509/kdf/argon2-portable');
	return portableArgon2(input);
}

/**
 * Derives raw Argon2 bytes after validating parameters and resource ceilings.
 *
 * Native WebCrypto is preferred for version 0x13. An unsupported request uses
 * the TypeScript implementation for the exact variant and version, including
 * 0x10. Other native failures are returned without retrying. Explicit
 * backends never fall back. No algorithm, version, or parameter is substituted.
 *
 * Caller buffers are copied synchronously before the first await and never
 * modified. Owned temporary arrays are zeroed on completion. Native key storage
 * and runtime copies cannot be explicitly erased by JavaScript. The returned
 * output is caller-owned. Calls cannot cancel native work once dispatched.
 * TypeScript work yields while filling memory blocks. Its private memory matrix
 * is erased on completion or failure.
 * Limits apply per call, not to concurrent invocations.
 */
export async function deriveArgon2(
	input: Argon2Input,
	options: Argon2Options = {},
): Promise<Argon2Result> {
	if (input === null || typeof input !== 'object') {
		return failure('invalid_parameters', 'Argon2 input must be an object');
	}
	let snapshot: Argon2Input;
	try {
		snapshot = snapshotInput(input);
	} catch {
		return failure('invalid_parameters', 'Argon2 input properties could not be read');
	}
	const invalid = validate(snapshot, options.limits ?? {});
	if (invalid !== undefined) return invalid;
	const owned = copyInput(snapshot);
	try {
		const result =
			typeof options.backend === 'function'
				? await options.backend(owned)
				: await builtinArgon2(owned, options.backend);
		if (!result.ok) {
			// A custom provider's diagnostic may contain secrets. Return only the
			// recognized code and a fixed message at this public boundary.
			const code = result.error.code;
			return failure(
				code === 'unsupported' || code === 'limit_exceeded' || code === 'invalid_parameters'
					? code
					: 'derivation_failed',
				'Argon2 backend could not derive the requested key',
			);
		}
		if (!(result.value instanceof Uint8Array)) {
			return failure('derivation_failed', 'Argon2 backend returned invalid output');
		}
		try {
			return result.value.byteLength === owned.outputBytes
				? { ok: true, value: new Uint8Array(result.value) }
				: failure('derivation_failed', 'Argon2 backend returned an incorrect output length');
		} finally {
			eraseAccessible(result.value);
		}
	} catch {
		return failure('derivation_failed', 'Argon2 backend failed');
	} finally {
		eraseAccessible(owned.password);
		eraseAccessible(owned.salt);
		eraseAccessible(owned.secret);
		eraseAccessible(owned.associatedData);
	}
}
