// ../../dist/kdf/argon2.js
function failure(e, t) {
	return {
		ok: !1,
		error: {
			code: e,
			message: t
		}
	};
}
function uintInRange(e, t, n) {
	return Number.isSafeInteger(e) && e >= t && e <= n;
}
function validate(e, t) {
	if (e.algorithm !== "argon2id" && e.algorithm !== "argon2d" && e.algorithm !== "argon2i") return failure("unsupported", "Unsupported Argon2 variant");
	if (e.version !== 16 && e.version !== 19) return failure("unsupported", "Unsupported Argon2 version");
	if (!uintInRange(e.parallelism, 1, 16777215) || !uintInRange(e.memoryKiB, 8 * e.parallelism, 4294967295) || !uintInRange(e.passes, 1, 4294967295) || !uintInRange(e.outputBytes, 4, 4294967295)) return failure("invalid_parameters", "Invalid Argon2 numeric parameters");
	let n = [
		e.password,
		e.salt,
		e.secret,
		e.associatedData
	];
	if (!(e.password instanceof Uint8Array) || !(e.salt instanceof Uint8Array) || n.some((e) => e !== void 0 && !(e instanceof Uint8Array))) return failure("invalid_parameters", "Argon2 inputs must be Uint8Array values");
	try {
		for (let e of n) e !== void 0 && Uint8Array.prototype.values.call(e);
	} catch {
		return failure("invalid_parameters", "Argon2 input buffer is unavailable");
	}
	let r = [
		[e.memoryKiB, t.maxMemoryKiB ?? 262144],
		[e.passes, t.maxPasses ?? 16],
		[e.parallelism, t.maxParallelism ?? 16],
		[e.outputBytes, t.maxOutputBytes ?? 1024],
		[n.reduce((e, t) => e + (t?.byteLength ?? 0), 0), t.maxInputBytes ?? 1048576]
	];
	if (r.some(([, e]) => !uintInRange(e, 1, 4294967295))) return failure("invalid_parameters", "Argon2 resource limits must be positive uint32 values");
	if (r.some(([e, t]) => e > t)) return failure("limit_exceeded", "Argon2 request exceeds resource limits");
}
function snapshotInput(e) {
	let { algorithm: t, version: n, password: r, salt: i, memoryKiB: a, passes: o, parallelism: s, outputBytes: c, secret: l, associatedData: u } = e;
	return {
		algorithm: t,
		version: n,
		password: r,
		salt: i,
		memoryKiB: a,
		passes: o,
		parallelism: s,
		outputBytes: c,
		...l === void 0 ? {} : { secret: l },
		...u === void 0 ? {} : { associatedData: u }
	};
}
function copyInput(e) {
	return {
		algorithm: e.algorithm,
		version: e.version,
		memoryKiB: e.memoryKiB,
		passes: e.passes,
		parallelism: e.parallelism,
		outputBytes: e.outputBytes,
		password: new Uint8Array(e.password),
		salt: new Uint8Array(e.salt),
		...e.secret === void 0 ? {} : { secret: new Uint8Array(e.secret) },
		...e.associatedData === void 0 ? {} : { associatedData: new Uint8Array(e.associatedData) }
	};
}
function eraseAccessible(e) {
	e !== void 0 && e.byteLength > 0 && Uint8Array.prototype.fill.call(e, 0);
}
async function nativeArgon2(e) {
	if (e.version !== 19) return failure("unsupported", "Native Argon2 supports version 0x13 only");
	if (e.salt.byteLength < 8) return failure("unsupported", "Native Argon2 requires a salt of at least eight bytes");
	if (e.outputBytes > 536870911) return failure("unsupported", "Requested output exceeds the native WebCrypto bit-length range");
	if (globalThis.crypto?.subtle === void 0) return failure("unsupported", "Native WebCrypto is unavailable");
	let t = globalThis.crypto.subtle, n;
	switch (e.algorithm) {
		case "argon2id":
			n = "Argon2id";
			break;
		case "argon2d":
			n = "Argon2d";
			break;
		case "argon2i":
			n = "Argon2i";
			break;
		default: return failure("unsupported", "Unsupported Argon2 variant");
	}
	try {
		let r;
		try {
			r = await Reflect.apply(t.importKey, t, [
				"raw-secret",
				e.password,
				n,
				!1,
				["deriveBits"]
			]);
		} catch (e) {
			if (e instanceof TypeError) return failure("unsupported", "This runtime does not support the raw-secret key format");
			throw e;
		}
		if (typeof CryptoKey > "u" || !(r instanceof CryptoKey)) return failure("derivation_failed", "Native Argon2 returned an invalid key");
		let i = {
			name: n,
			version: e.version,
			memory: e.memoryKiB,
			passes: e.passes,
			parallelism: e.parallelism,
			nonce: new Uint8Array(e.salt),
			...e.secret === void 0 ? {} : { secretValue: new Uint8Array(e.secret) },
			...e.associatedData === void 0 ? {} : { associatedData: new Uint8Array(e.associatedData) }
		};
		try {
			let n = await t.deriveBits(i, r, e.outputBytes * 8);
			return {
				ok: !0,
				value: new Uint8Array(n)
			};
		} finally {
			i.nonce.fill(0), i.secretValue?.fill(0), i.associatedData?.fill(0);
		}
	} catch (e) {
		return e instanceof Error && e.name === "NotSupportedError" ? failure("unsupported", "This runtime does not support native Argon2") : failure("derivation_failed", "Native Argon2 derivation failed");
	}
}
async function builtinArgon2(e, t) {
	if (t !== "portable") {
		let n = await nativeArgon2(e);
		if (t === "native" || n.ok || n.error.code !== "unsupported") return n;
	}
	let { portableArgon2: n } = await import("./argon2-portable-CG5tIWWd.js");
	return n(e);
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
async function deriveArgon2(e, t = {}) {
	if (typeof e != "object" || !e) return failure("invalid_parameters", "Argon2 input must be an object");
	let n;
	try {
		n = snapshotInput(e);
	} catch {
		return failure("invalid_parameters", "Argon2 input properties could not be read");
	}
	let r = validate(n, t.limits ?? {});
	if (r !== void 0) return r;
	let i = copyInput(n);
	try {
		let e = typeof t.backend == "function" ? await t.backend(i) : await builtinArgon2(i, t.backend);
		if (!e.ok) {
			let t = e.error.code;
			return failure(t === "unsupported" || t === "limit_exceeded" || t === "invalid_parameters" ? t : "derivation_failed", "Argon2 backend could not derive the requested key");
		}
		if (!(e.value instanceof Uint8Array)) return failure("derivation_failed", "Argon2 backend returned invalid output");
		try {
			return e.value.byteLength === i.outputBytes ? {
				ok: !0,
				value: new Uint8Array(e.value)
			} : failure("derivation_failed", "Argon2 backend returned an incorrect output length");
		} finally {
			eraseAccessible(e.value);
		}
	} catch {
		return failure("derivation_failed", "Argon2 backend failed");
	} finally {
		eraseAccessible(i.password), eraseAccessible(i.salt), eraseAccessible(i.secret), eraseAccessible(i.associatedData);
	}
}
export { deriveArgon2 };
