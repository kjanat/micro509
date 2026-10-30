// ../../dist/result/result.js
/** Wraps a value in a success result (`{ ok: true, value }`). */
function successResult(e) {
	return {
		ok: !0,
		value: e
	};
}
/** Module-private brand so {@link isResultError} cannot be fooled by look-alike objects. */
const e = Symbol("micro509.ResultError");
/** Builds a {@link ResultError}: a branded `Error` (no class) carrying the structured failure. */
function makeResultError(t) {
	return Object.assign(/* @__PURE__ */ Error(`${t.code}: ${t.message}`), {
		name: "ResultError",
		code: t.code,
		error: t,
		[e]: !0
	});
}
/** Type guard: was {@linkcode value} thrown by {@link unwrap}? Narrows to {@link ResultError}. */
function isResultError(t) {
	return t instanceof Error && e in t;
}
/**
* Explicit escape hatch: returns the success value, or throws a {@link ResultError} carrying the structured failure.
*
* Use when you have already validated the input (or prefer exceptions) and the Result ceremony is noise.
* Accepts any of the library's `*Result` types.
*/
function unwrap(e) {
	if (e.ok) return e.value;
	throw makeResultError(e.error);
}
/** Returns the success value, or {@linkcode fallback} when the result is a failure. */
function unwrapOr(e, t) {
	return e.ok ? e.value : t;
}
/** JS error types that signal a programmer bug / broken invariant rather than malformed input. */
const t = [
	TypeError,
	RangeError,
	ReferenceError,
	SyntaxError
];
/**
* Rethrows {@link error} if it is an invariant/programmer error ({@link TypeError}, {@link RangeError},
* {@link ReferenceError}, {@link SyntaxError}); otherwise returns.
*
* Boundary wrappers that turn an expected failure into a `Result` should call this first, so a genuine crash
* is never masked as a clean parse/decode failure.
*/
function rethrowIfInvariant(e) {
	if (t.some((t) => e instanceof t)) throw e;
}
/** Constructs a {@link Micro509Error} payload. */
function micro509Error(e, t, n) {
	return {
		code: e,
		message: t,
		...n === void 0 ? {} : { details: n }
	};
}
/**
* Throws a {@link ResultError} carrying a typed {@link Micro509Error}.
*
* The direct-throw counterpart to {@link unwrap}, for builders that reject
* invalid construction input. Callers branch on `error.code` via
* {@link isResultError} instead of matching message strings.
*/
function throwMicro509Error(e, t, n) {
	throw makeResultError(micro509Error(e, t, n));
}
/** Constructs an {@link IndexedMicro509Error} payload with an optional collection index. */
function indexedMicro509Error(e, t, n, r) {
	return {
		code: e,
		message: t,
		...n === void 0 ? {} : { index: n },
		...r === void 0 ? {} : { details: r }
	};
}
/** Wraps a {@link Micro509Error} in a flattened {@link ErrorResult}. */
function errorResult(e) {
	return {
		ok: !1,
		error: e,
		code: e.code,
		message: e.message,
		...e.details === void 0 ? {} : { details: e.details }
	};
}
/**
* Builds a flattened failure result in one step.
*
* Single source of truth for the `{ ok: false, error, code, message }` shape:
* modules should construct failures with this instead of hand-rolling the
* object literal. The `error` payload carries the redundant `ok: false`
* discriminant so it matches the per-operation `*Failure` interfaces
* (`interface XFailure extends Micro509Error<…> { ok: false }`).
*/
function failureResult(e, t, n) {
	return errorResult({
		ok: !1,
		...micro509Error(e, t, n)
	});
}
/** Wraps an {@link IndexedMicro509Error} in a flattened {@link IndexedErrorResult}. */
function indexedErrorResult(e) {
	return {
		ok: !1,
		error: e,
		code: e.code,
		message: e.message,
		...e.details === void 0 ? {} : { details: e.details },
		...e.index === void 0 ? {} : { index: e.index }
	};
}
/**
* Codes a parse boundary returns for input it refuses without calling it
* malformed: `unsupported` for a construct micro509 does not decode, and
* `limit_exceeded` for an implementation limit of micro509's own.
*/
const n = ["unsupported", "limit_exceeded"];
export { isResultError as a, rethrowIfInvariant as c, unwrap as d, unwrapOr as f, indexedMicro509Error as i, successResult as l, failureResult as n, micro509Error as o, indexedErrorResult as r, n as s, errorResult as t, throwMicro509Error as u };
