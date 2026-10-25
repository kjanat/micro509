/**
 * Opt-in remote JWK Set resolution. A resolver is bound to one trusted JWKS URL from caller
 * configuration and keeps its own cache, so two issuers never share keys. Importing this module
 * performs no request; only a verification that reaches the resolver can.
 *
 * @module
 */

import type { JoseErrorResult, JoseResult, KeyResolutionErrorCode } from '#micro509/jose/errors';
import { joseFailure } from '#micro509/jose/errors';
import type { JwkSelector, Jwks, RsaJwkEntry } from '#micro509/jose/jwks';
import { importJwkEntry, parseJwks, selectJwk } from '#micro509/jose/jwks';
import type { JwsKeyRequest, JwsKeyResolver } from '#micro509/jose/jws';
import { successResult, throwMicro509Error } from '#micro509/result/result';

/** The request {@linkcode JwksTransport} must issue. */
export interface JwksRequestInit {
	/** Always `GET`. */
	readonly method: 'GET';
	/** Always `manual`: the resolver validates every redirect destination itself. */
	readonly redirect: 'manual';
	/** Always `omit`. */
	readonly credentials: 'omit';
	/** Always `no-store`: each resolver refresh must reach the issuer, bypassing the HTTP cache. */
	readonly cache: 'no-store';
	/** Configured request headers. Withheld from any origin other than the configured URL's. */
	readonly headers: Readonly<Record<string, string>>;
	/** Aborts on timeout, cancellation or when no verification still waits for the response. */
	readonly signal: AbortSignal;
}

/**
 * Performs one HTTP request. `fetch` satisfies this type. Supply another to route through a proxy,
 * apply egress or DNS controls, or serve fixtures; the transport sees only URLs the resolver
 * already validated.
 */
export type JwksTransport = (url: string, init: JwksRequestInit) => Promise<Response>;

/** Redirect handling for a remote JWK Set. By default redirects are refused. */
export interface RemoteJwksRedirectPolicy {
	/** Maximum redirects followed per fetch. */
	readonly maxRedirects: number;
	/**
	 * Approves a redirect destination. Default: same origin as the hop it came from. The scheme
	 * rule applies first: `https`, or `http` for a loopback host.
	 */
	readonly allow?: (destination: URL, from: URL) => boolean;
}

/** Configuration of {@linkcode createRemoteJwksKeyResolver}. */
export interface RemoteJwksConfig {
	/** The trusted JWKS URL. `https`, or `http` for a loopback host. Never taken from a token. */
	readonly url: string | URL;
	/** Request transport. Default: `globalThis.fetch`. */
	readonly transport?: JwksTransport;
	/** Request headers, sent only to the configured URL's origin. */
	readonly headers?: Readonly<Record<string, string>>;
	/** Whole-request deadline in milliseconds, response body included. Default `5000`. */
	readonly timeoutMs?: number;
	/** Maximum response body in bytes, enforced while streaming. Default `65536`. */
	readonly maxResponseBytes?: number;
	/** Maximum keys in the set. Default `32`. */
	readonly maxKeys?: number;
	/** Redirect handling. Default: refuse every redirect. */
	readonly redirects?: RemoteJwksRedirectPolicy;
	/** Freshness applied when the response states none, in milliseconds. Default `600000`. */
	readonly defaultTtlMs?: number;
	/** Longest freshness the resolver will keep a response for, in milliseconds. Default `86400000`. */
	readonly maxTtlMs?: number;
	/**
	 * Minimum interval between the starts of two fetches, in milliseconds. It bounds how often
	 * unknown `kid` values, expired responses and failures can cause a request, and does not
	 * lengthen how long a response stays fresh. Default `30000`.
	 */
	readonly cooldownMs?: number;
	/** The clock in milliseconds since the epoch. Default `Date.now`. */
	readonly now?: () => number;
}

/** Codes {@linkcode createRemoteJwksKeyResolver} throws for unusable configuration. */
export type RemoteJwksConfigErrorCode = 'invalid_remote_jwks_config';

type FetchFailureCode = 'jwks_unavailable' | 'jwks_malformed';

interface Snapshot {
	readonly jwks: Jwks;
	readonly expiresAt: number;
	readonly imported: Map<string, Promise<JoseResult<CryptoKey, 'key_unsuitable'>>>;
}

type RefreshOutcome =
	| { readonly kind: 'fresh'; readonly snapshot: Snapshot }
	| { readonly kind: 'failed'; readonly failure: JoseErrorResult<FetchFailureCode> }
	| { readonly kind: 'abandoned' };

interface Refresh {
	readonly promise: Promise<RefreshOutcome>;
	readonly controller: AbortController;
	readonly startedAt: number;
	readonly previousAttemptAt: number | undefined;
	waiters: number;
}

const ABORTED: unique symbol = Symbol('micro509.jose.aborted');

const DEFAULTS = {
	timeoutMs: 5000,
	maxResponseBytes: 65_536,
	maxKeys: 32,
	defaultTtlMs: 600_000,
	maxTtlMs: 86_400_000,
	cooldownMs: 30_000,
} as const;

const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(['localhost', '127.0.0.1', '[::1]']);

function isPermittedUrl(url: URL): boolean {
	return (
		url.protocol === 'https:' || (url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname))
	);
}

function positiveInteger(value: number | undefined, fallback: number, name: string): number {
	const resolved = value ?? fallback;
	if (!Number.isSafeInteger(resolved) || resolved <= 0) {
		return throwMicro509Error('invalid_remote_jwks_config', `${name} must be a positive integer`);
	}
	return resolved;
}

interface ResolvedConfig {
	readonly url: URL;
	readonly transport: JwksTransport;
	readonly headers: Readonly<Record<string, string>>;
	readonly timeoutMs: number;
	readonly maxResponseBytes: number;
	readonly maxKeys: number;
	readonly maxRedirects: number;
	readonly allowRedirect: (destination: URL, from: URL) => boolean;
	readonly defaultTtlMs: number;
	readonly maxTtlMs: number;
	readonly cooldownMs: number;
	readonly now: () => number;
}

function resolveConfig(config: RemoteJwksConfig): ResolvedConfig {
	let url: URL;
	try {
		url = new URL(config.url);
	} catch {
		return throwMicro509Error('invalid_remote_jwks_config', 'url is not an absolute URL');
	}
	if (!isPermittedUrl(url)) {
		return throwMicro509Error(
			'invalid_remote_jwks_config',
			'url must use https, or http on a loopback host',
		);
	}
	if (url.username !== '' || url.password !== '') {
		return throwMicro509Error('invalid_remote_jwks_config', 'url must not embed credentials');
	}
	const maxRedirects = config.redirects?.maxRedirects ?? 0;
	if (!Number.isSafeInteger(maxRedirects) || maxRedirects < 0 || maxRedirects > 10) {
		return throwMicro509Error(
			'invalid_remote_jwks_config',
			'maxRedirects must be an integer from 0 to 10',
		);
	}
	const maxTtlMs = positiveInteger(config.maxTtlMs, DEFAULTS.maxTtlMs, 'maxTtlMs');
	const cooldownMs = positiveInteger(config.cooldownMs, DEFAULTS.cooldownMs, 'cooldownMs');
	return {
		url,
		transport: config.transport ?? ((target, init) => globalThis.fetch(target, init)),
		headers: { ...config.headers },
		timeoutMs: positiveInteger(config.timeoutMs, DEFAULTS.timeoutMs, 'timeoutMs'),
		maxResponseBytes: positiveInteger(
			config.maxResponseBytes,
			DEFAULTS.maxResponseBytes,
			'maxResponseBytes',
		),
		maxKeys: positiveInteger(config.maxKeys, DEFAULTS.maxKeys, 'maxKeys'),
		maxRedirects,
		allowRedirect:
			config.redirects?.allow ?? ((destination, from) => destination.origin === from.origin),
		defaultTtlMs: positiveInteger(config.defaultTtlMs, DEFAULTS.defaultTtlMs, 'defaultTtlMs'),
		maxTtlMs,
		cooldownMs,
		now: config.now ?? Date.now,
	};
}

function unavailable(message: string, status?: number): JoseErrorResult<'jwks_unavailable'> {
	return joseFailure('jwks_unavailable', message, status === undefined ? undefined : { status });
}

const NOT_A_NUMBER = Number.NaN;

function secondsHeader(headers: Headers, name: string): number {
	const value = headers.get(name);
	return value !== null && /^\d{1,10}$/.test(value) ? Number(value) * 1000 : NOT_A_NUMBER;
}

/**
 * Remaining freshness in milliseconds, never below zero and never above `maxTtlMs`.
 *
 * The lifetime is `Cache-Control: max-age`, else `Expires` less `Date`, else `defaultTtlMs`
 * (RFC 9111 §4.2.1); `no-store`, `no-cache` and unusable values give none. The response age is the
 * larger of the apparent age from `Date` and the `Age` header plus the transit delay
 * (RFC 9111 §4.2.3).
 */
function freshnessMs(
	headers: Headers,
	requestedAt: number,
	receivedAt: number,
	config: ResolvedConfig,
): number {
	const directives = (headers.get('cache-control') ?? '')
		.split(',')
		.map((directive) => directive.trim().toLowerCase())
		.filter((directive) => directive.length > 0);
	if (directives.includes('no-store') || directives.includes('no-cache')) return 0;
	const date = Date.parse(headers.get('date') ?? '');
	const apparentAge = Number.isNaN(date) ? 0 : Math.max(0, receivedAt - date);
	const reportedAge = secondsHeader(headers, 'age');
	const transit = Math.max(0, receivedAt - requestedAt);
	const age = Math.max(apparentAge, (Number.isNaN(reportedAge) ? 0 : reportedAge) + transit);
	const maxAge = directives.find((directive) => directive.startsWith('max-age'));
	let lifetime = config.defaultTtlMs;
	if (maxAge !== undefined) {
		const match = /^max-age=("?)(\d{1,10})\1$/.exec(maxAge);
		lifetime = match?.[2] === undefined ? 0 : Number(match[2]) * 1000;
	} else if (headers.has('expires')) {
		const expires = Date.parse(headers.get('expires') ?? '');
		lifetime = Number.isNaN(expires) ? 0 : expires - (Number.isNaN(date) ? receivedAt : date);
	}
	return Math.min(config.maxTtlMs, Math.max(0, lifetime - age));
}

type BodyResult = JoseResult<Uint8Array, 'jwks_unavailable' | 'jwks_malformed'>;

async function readBounded(
	response: Response,
	maxBytes: number,
	signal: AbortSignal,
): Promise<BodyResult> {
	const tooLarge = joseFailure('jwks_malformed', `The JWKS response exceeds ${maxBytes} bytes`);
	const declared = response.headers.get('content-length');
	if (declared !== null && /^\d+$/.test(declared) && Number(declared) > maxBytes) {
		await response.body?.cancel();
		return tooLarge;
	}
	if (response.body === null) return successResult(new Uint8Array(0));
	const reader = response.body.getReader();
	const release = (): void => {
		reader.cancel().catch(() => undefined);
	};
	signal.addEventListener('abort', release, { once: true });
	try {
		const chunks: Uint8Array[] = [];
		let total = 0;
		for (;;) {
			const { done, value } = await reader.read();
			if (signal.aborted) return unavailable('The JWKS request was cancelled');
			if (done) break;
			total += value.byteLength;
			if (total > maxBytes) {
				release();
				return tooLarge;
			}
			chunks.push(value);
		}
		const body = new Uint8Array(total);
		let offset = 0;
		for (const chunk of chunks) {
			body.set(chunk, offset);
			offset += chunk.byteLength;
		}
		return successResult(body);
	} finally {
		signal.removeEventListener('abort', release);
	}
}

interface Fetched {
	readonly jwks: Jwks;
	readonly expiresAt: number;
}

function nextHop(
	config: ResolvedConfig,
	from: URL,
	response: Response,
	redirects: number,
): JoseResult<URL, 'jwks_unavailable'> {
	const location = response.headers.get('location');
	if (redirects >= config.maxRedirects || location === null) {
		return unavailable('The JWKS endpoint redirected', response.status);
	}
	let destination: URL;
	try {
		destination = new URL(location, from);
	} catch {
		return unavailable('The JWKS redirect target is not a URL', response.status);
	}
	if (
		!isPermittedUrl(destination) ||
		destination.username !== '' ||
		destination.password !== '' ||
		!config.allowRedirect(destination, from)
	) {
		return unavailable('The JWKS redirect target is not permitted', response.status);
	}
	return successResult(destination);
}

async function readJwks(
	config: ResolvedConfig,
	response: Response,
	requestedAt: number,
	signal: AbortSignal,
): Promise<JoseResult<Fetched, FetchFailureCode>> {
	if (response.status !== 200) {
		await response.body?.cancel();
		return unavailable('The JWKS endpoint did not answer 200', response.status);
	}
	const receivedAt = config.now();
	const body = await readBounded(response, config.maxResponseBytes, signal);
	if (!body.ok) return body;
	const jwks = parseJwks(body.value, {
		maxBytes: config.maxResponseBytes,
		maxKeys: config.maxKeys,
	});
	if (!jwks.ok) return joseFailure('jwks_malformed', jwks.message);
	return successResult({
		jwks: jwks.value,
		expiresAt: receivedAt + freshnessMs(response.headers, requestedAt, receivedAt, config),
	});
}

async function fetchJwks(
	config: ResolvedConfig,
	signal: AbortSignal,
	requestedAt: number,
): Promise<JoseResult<Fetched, FetchFailureCode>> {
	let url = config.url;
	for (let redirects = 0; ; redirects++) {
		const response = await config.transport(url.href, {
			method: 'GET',
			redirect: 'manual',
			credentials: 'omit',
			cache: 'no-store',
			headers: url.origin === config.url.origin ? config.headers : {},
			signal,
		});
		if (signal.aborted) {
			await response.body?.cancel();
			return unavailable('The JWKS request was cancelled');
		}
		if (response.type === 'opaqueredirect') {
			return unavailable('The runtime hides redirects, so they cannot be validated');
		}
		if (!REDIRECT_STATUSES.has(response.status)) {
			return await readJwks(config, response, requestedAt, signal);
		}
		await response.body?.cancel();
		const hop = nextHop(config, url, response, redirects);
		if (!hop.ok) return hop;
		url = hop.value;
	}
}

function entryKey(entry: RsaJwkEntry): string {
	return `${entry.n}.${entry.e}`;
}

function carryOver(fetched: Fetched, previous: Snapshot | undefined): Snapshot {
	const imported = new Map<string, Promise<JoseResult<CryptoKey, 'key_unsuitable'>>>();
	for (const entry of fetched.jwks.keys) {
		const carried = entry.kind === 'rsa' ? previous?.imported.get(entryKey(entry)) : undefined;
		if (entry.kind === 'rsa' && carried !== undefined) imported.set(entryKey(entry), carried);
	}
	return { jwks: fetched.jwks, expiresAt: fetched.expiresAt, imported };
}

const TIMED_OUT: unique symbol = Symbol('micro509.jose.timedOut');

/**
 * Creates a key resolver that reads a JWK Set from one trusted URL.
 *
 * Behaviour, per resolver:
 *
 * - The first verification fetches the set. Later ones reuse it while fresh. Freshness is the
 *   remaining lifetime from `Cache-Control: max-age`, else `Expires`, else `defaultTtlMs`, less the
 *   response age (the larger of the apparent age from `Date` and `Age` plus the transit delay),
 *   capped at `maxTtlMs`. `no-store`, `no-cache` and a lifetime already spent leave none: the set
 *   serves the verification that fetched it and nothing after. No heuristic freshness is applied.
 * - A set that is no longer fresh is never used, whether or not a refresh succeeds. There is no
 *   stale-if-error. A refresh that fails while the cached set is still fresh keeps that set until
 *   it expires.
 * - Refreshes are separate from freshness: after any attempt the next one waits `cooldownMs`.
 *   Within that interval a token whose `kid` is absent gets `key_not_found`, and a token that
 *   needs a set that is no longer fresh gets `jwks_unavailable`. Concurrent verifications share
 *   a single request, and unknown `kid` values are never cached.
 * - A refresh replaces the whole set, so a rotated-out key stops verifying as soon as the new
 *   set is read. Rotation must therefore introduce a new `kid`.
 * - The whole request, response body included, is bounded by `timeoutMs` and enforced even when
 *   the transport ignores the abort signal. Redirects, bytes and keys are bounded by `redirects`,
 *   `maxResponseBytes` and `maxKeys`. No retry happens inside a fetch. Cancelling the last waiting
 *   verification aborts the request, and a response that finishes afterwards is discarded.
 * - Request headers go only to the configured origin. `jku`, `x5u` and `jwk` headers are never
 *   used.
 *
 * Throws a `ResultError` coded {@linkcode RemoteJwksConfigErrorCode} for unusable configuration.
 * Redirect destinations, and the addresses a hostname resolves to, are limited by `redirects` and
 * the transport; this module cannot see DNS answers, and browsers hide redirect targets.
 */
export function createRemoteJwksKeyResolver(config: RemoteJwksConfig): JwsKeyResolver {
	const settings = resolveConfig(config);
	let snapshot: Snapshot | undefined;
	let refresh: Refresh | undefined;
	let lastAttemptAt: number | undefined;

	function startRefresh(): Refresh {
		const controller = new AbortController();
		const requestedAt = settings.now();
		const previousAttemptAt = lastAttemptAt;
		const previous = snapshot;
		lastAttemptAt = requestedAt;

		async function run(): Promise<RefreshOutcome> {
			let timer: ReturnType<typeof setTimeout> | undefined;
			const deadline = new Promise<typeof TIMED_OUT>((resolve) => {
				timer = setTimeout(() => resolve(TIMED_OUT), settings.timeoutMs);
			});
			const work = fetchJwks(settings, controller.signal, requestedAt);
			work.catch(() => undefined);
			try {
				const fetched = await Promise.race([work, deadline]);
				if (fetched === TIMED_OUT) {
					controller.abort();
					return { kind: 'failed', failure: unavailable('The JWKS request timed out') };
				}
				if (!fetched.ok) return { kind: 'failed', failure: fetched };
				return { kind: 'fresh', snapshot: carryOver(fetched.value, previous) };
			} catch {
				return controller.signal.aborted
					? { kind: 'abandoned' }
					: { kind: 'failed', failure: unavailable('The JWKS request failed') };
			} finally {
				clearTimeout(timer);
			}
		}

		const tracked: Promise<RefreshOutcome> = run()
			.then((outcome): RefreshOutcome => {
				if (refresh?.promise !== tracked) return { kind: 'abandoned' };
				if (outcome.kind === 'fresh') snapshot = outcome.snapshot;
				return outcome;
			})
			.finally(() => {
				if (refresh?.promise === tracked) refresh = undefined;
			});
		return {
			promise: tracked,
			controller,
			startedAt: requestedAt,
			previousAttemptAt,
			waiters: 0,
		};
	}

	async function awaitRefresh(
		signal: AbortSignal | undefined,
	): Promise<RefreshOutcome | typeof ABORTED> {
		if (signal?.aborted === true) return ABORTED;
		refresh ??= startRefresh();
		const joined = refresh;
		joined.waiters++;
		if (signal === undefined) return await joined.promise;
		return await new Promise<RefreshOutcome | typeof ABORTED>((resolve) => {
			let settled = false;
			const finish = (): void => {
				settled = true;
				signal.removeEventListener('abort', onAbort);
			};
			const onAbort = (): void => {
				if (settled) return;
				finish();
				joined.waiters--;
				if (joined.waiters === 0) {
					if (refresh === joined) refresh = undefined;
					if (lastAttemptAt === joined.startedAt) lastAttemptAt = joined.previousAttemptAt;
					joined.controller.abort();
				}
				resolve(ABORTED);
			};
			signal.addEventListener('abort', onAbort, { once: true });
			if (signal.aborted) onAbort();
			void joined.promise.then((outcome) => {
				if (settled) return;
				finish();
				resolve(outcome);
			});
		});
	}

	function refreshAllowed(): boolean {
		if (refresh !== undefined || lastAttemptAt === undefined) return true;
		return settings.now() - lastAttemptAt >= settings.cooldownMs;
	}

	async function obtain(
		signal: AbortSignal | undefined,
	): Promise<JoseResult<Snapshot | undefined, FetchFailureCode | 'aborted'>> {
		if (!refreshAllowed()) return successResult(undefined);
		const outcome = await awaitRefresh(signal);
		if (outcome === ABORTED || outcome.kind === 'abandoned') {
			return joseFailure('aborted', 'Key resolution was cancelled');
		}
		if (outcome.kind === 'failed') return outcome.failure;
		return successResult(outcome.snapshot);
	}

	async function importFrom(
		current: Snapshot,
		entry: RsaJwkEntry,
	): Promise<JoseResult<CryptoKey, 'key_unsuitable'>> {
		const key = entryKey(entry);
		const cached = current.imported.get(key);
		if (cached !== undefined) return await cached;
		const pending = importJwkEntry(entry);
		current.imported.set(key, pending);
		return await pending;
	}

	async function currentSnapshot(
		signal: AbortSignal | undefined,
	): Promise<JoseResult<Snapshot, FetchFailureCode | 'aborted'>> {
		if (snapshot !== undefined && settings.now() < snapshot.expiresAt) {
			return successResult(snapshot);
		}
		snapshot = undefined;
		const loaded = await obtain(signal);
		if (!loaded.ok) return loaded;
		return loaded.value === undefined
			? unavailable('The JWKS endpoint is in cooldown')
			: successResult(loaded.value);
	}

	async function select(
		current: Snapshot,
		selector: JwkSelector,
		signal: AbortSignal | undefined,
	): Promise<JoseResult<CryptoKey, KeyResolutionErrorCode>> {
		let source = current;
		let selected = selectJwk(source.jwks, selector);
		if (!selected.ok && selected.code === 'key_not_found') {
			const reloaded = await obtain(signal);
			if (!reloaded.ok) return reloaded;
			if (reloaded.value !== undefined) {
				source = reloaded.value;
				selected = selectJwk(source.jwks, selector);
			}
		}
		if (!selected.ok) return selected;
		const key = await importFrom(source, selected.value);
		return signal?.aborted === true ? joseFailure('aborted', 'Key resolution was cancelled') : key;
	}

	return async (request: JwsKeyRequest) => {
		if (request.signal?.aborted === true) {
			return joseFailure('aborted', 'Key resolution was cancelled');
		}
		const current = await currentSnapshot(request.signal);
		if (!current.ok) return current;
		return await select(
			current.value,
			{ algorithm: request.algorithm, ...(request.kid === undefined ? {} : { kid: request.kid }) },
			request.signal,
		);
	};
}
