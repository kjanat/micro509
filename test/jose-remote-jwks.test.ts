import { afterAll, describe, expect, it } from 'bun:test';
import type { JwksRequestInit, RemoteJwksConfig, VerifiedJws } from '#micro509/jose';
import { createRemoteJwksKeyResolver, signCompactJws, verifyCompactJws } from '#micro509/jose';
import { expectBuildErrorCode, joseTestKeys, rsaJwkEntry, signRawRs256Token } from '#test/helpers';

const [primary, secondary] = await joseTestKeys();
const payload = new TextEncoder().encode('{}');
const HOUR = 3_600_000;

type Handler = (request: Request, hit: number) => Response | Promise<Response>;

interface Fixture {
	readonly server: ReturnType<typeof Bun.serve>;
	readonly routes: Map<string, Handler>;
	readonly hits: Map<string, number>;
	readonly seenHeaders: Map<string, Headers[]>;
	origin(): string;
	url(path: string): string;
	route(path: string, handler: Handler): string;
}

function startFixture(): Fixture {
	const routes = new Map<string, Handler>();
	const hits = new Map<string, number>();
	const seenHeaders = new Map<string, Headers[]>();
	const server = Bun.serve({
		port: 0,
		hostname: '127.0.0.1',
		async fetch(request) {
			const path = new URL(request.url).pathname;
			const hit = (hits.get(path) ?? 0) + 1;
			hits.set(path, hit);
			seenHeaders.set(path, [...(seenHeaders.get(path) ?? []), request.headers]);
			const handler = routes.get(path);
			return handler === undefined
				? new Response('no route', { status: 404 })
				: await handler(request, hit);
		},
	});
	const origin = (): string => `http://127.0.0.1:${server.port}`;
	return {
		server,
		routes,
		hits,
		seenHeaders,
		origin,
		url: (path) => `${origin()}${path}`,
		route(path, handler) {
			routes.set(path, handler);
			return `${origin()}${path}`;
		},
	};
}

const primaryServer = startFixture();
const otherServer = startFixture();

afterAll(async () => {
	await primaryServer.server.stop(true);
	await otherServer.server.stop(true);
});

let routeCounter = 0;

function freshPath(): string {
	routeCounter++;
	return `/jwks-${routeCounter}`;
}

async function jwksJson(...keys: readonly Record<string, unknown>[]): Promise<string> {
	return JSON.stringify({ keys });
}

async function keyA(): Promise<Record<string, unknown>> {
	return await rsaJwkEntry(primary, { kid: 'a', use: 'sig' });
}

async function keyB(): Promise<Record<string, unknown>> {
	return await rsaJwkEntry(secondary, { kid: 'b', use: 'sig' });
}

function jsonResponse(body: string, headers: Record<string, string> = {}): Response {
	return new Response(body, {
		headers: { 'content-type': 'application/jwk-set+json', ...headers },
	});
}

async function token(kid: string, pair = primary): Promise<string> {
	return await signCompactJws({
		privateKey: pair.privateKey,
		algorithm: 'RS256',
		payload,
		header: { kid },
	});
}

interface Clock {
	value: number;
	now(): number;
	advance(ms: number): void;
}

function clock(start = 1_700_000_000_000): Clock {
	const state: Clock = {
		value: start,
		now: () => state.value,
		advance(ms) {
			state.value += ms;
		},
	};
	return state;
}

function resolverFor(
	url: string,
	time: Clock,
	overrides: Partial<RemoteJwksConfig> = {},
): ReturnType<typeof createRemoteJwksKeyResolver> {
	return createRemoteJwksKeyResolver({
		url,
		now: time.now,
		cooldownMs: 1000,
		maxTtlMs: HOUR,
		defaultTtlMs: 60_000,
		...overrides,
	});
}

async function verifyKid(
	kid: string,
	resolver: ReturnType<typeof createRemoteJwksKeyResolver>,
	pair = primary,
	signal?: AbortSignal,
): Promise<string> {
	const result = await verifyCompactJws(await token(kid, pair), {
		algorithms: ['RS256'],
		key: resolver,
		tokenType: { unchecked: true },
		...(signal === undefined ? {} : { signal }),
	});
	return result.ok ? 'ok' : result.code;
}

async function eventually(condition: () => boolean, timeoutMs = 2000): Promise<boolean> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (condition()) return true;
		await Bun.sleep(10);
	}
	return condition();
}

describe('opt-in and caching', () => {
	it('makes no request until a verification needs a key', async () => {
		const path = freshPath();
		const url = primaryServer.route(path, async () => jsonResponse(await jwksJson(await keyA())));
		const time = clock();
		const resolver = resolverFor(url, time);
		expect(primaryServer.hits.get(path)).toBeUndefined();
		expect(await verifyKid('a', resolver)).toBe('ok');
		expect(primaryServer.hits.get(path)).toBe(1);
	});

	it('does not touch the network when verifying with a local key', async () => {
		const isolated = startFixture();
		try {
			const url = isolated.route('/token-keys', async () =>
				jsonResponse(await jwksJson(await keyB())),
			);
			const signed = await signRawRs256Token(
				primary.privateKey,
				JSON.stringify({ alg: 'RS256', kid: 'a', jku: url, x5u: url }),
				'{}',
			);
			const result = await verifyCompactJws(signed, {
				algorithms: ['RS256'],
				key: primary.publicKey,
				tokenType: { unchecked: true },
			});
			expect(result.ok).toBe(true);
			expect(isolated.hits.size).toBe(0);
		} finally {
			await isolated.server.stop(true);
		}
	});

	it('reuses a fresh set and one imported key across verifications', async () => {
		const path = freshPath();
		const url = primaryServer.route(path, async () => jsonResponse(await jwksJson(await keyA())));
		const time = clock();
		const resolver = resolverFor(url, time);
		const keys: CryptoKey[] = [];
		for (let index = 0; index < 5; index++) {
			const request = {
				header: { alg: 'RS256', kid: 'a', members: {} },
				algorithm: 'RS256',
				kid: 'a',
			} as const;
			const resolved = await resolver(request);
			if (!resolved.ok) throw new Error('unreachable');
			keys.push(resolved.value);
		}
		expect(primaryServer.hits.get(path)).toBe(1);
		expect(new Set(keys).size).toBe(1);
	});

	it('refetches after the default freshness lifetime', async () => {
		const path = freshPath();
		const url = primaryServer.route(path, async () => jsonResponse(await jwksJson(await keyA())));
		const time = clock();
		const resolver = resolverFor(url, time);
		await verifyKid('a', resolver);
		time.advance(59_999);
		await verifyKid('a', resolver);
		expect(primaryServer.hits.get(path)).toBe(1);
		time.advance(2);
		expect(await verifyKid('a', resolver)).toBe('ok');
		expect(primaryServer.hits.get(path)).toBe(2);
	});

	const lifetimes: readonly {
		readonly name: string;
		readonly headers: () => Record<string, string>;
		readonly freshForMs: number;
	}[] = [
		{
			name: 'max-age',
			headers: () => ({ 'cache-control': 'public, max-age=120' }),
			freshForMs: 120_000,
		},
		{
			name: 'max-age less Age',
			headers: () => ({ 'cache-control': 'max-age=120', age: '100' }),
			freshForMs: 20_000,
		},
		{
			name: 'quoted max-age with other directives',
			headers: () => ({ 'cache-control': 'Max-Age="90", must-revalidate' }),
			freshForMs: 90_000,
		},
		{
			name: 'max-age over Expires',
			headers: () => ({
				'cache-control': 'max-age=30',
				expires: new Date(1_700_000_000_000 + 600_000).toUTCString(),
			}),
			freshForMs: 30_000,
		},
		{
			name: 'Expires relative to Date',
			headers: () => ({
				expires: new Date(1_700_000_000_000 + 45_000).toUTCString(),
				date: new Date(1_700_000_000_000).toUTCString(),
			}),
			freshForMs: 45_000,
		},
		{ name: 'no-store', headers: () => ({ 'cache-control': 'no-store' }), freshForMs: 1000 },
		{
			name: 'no-cache',
			headers: () => ({ 'cache-control': 'no-cache, max-age=500' }),
			freshForMs: 1000,
		},
		{ name: 'max-age=0', headers: () => ({ 'cache-control': 'max-age=0' }), freshForMs: 1000 },
		{
			name: 'invalid max-age',
			headers: () => ({ 'cache-control': 'max-age=-5' }),
			freshForMs: 1000,
		},
		{
			name: 'non-numeric max-age',
			headers: () => ({ 'cache-control': 'max-age=soon' }),
			freshForMs: 1000,
		},
		{ name: 'invalid Expires', headers: () => ({ expires: '0' }), freshForMs: 1000 },
		{
			name: 'max-age over the ceiling',
			headers: () => ({ 'cache-control': 'max-age=99999999' }),
			freshForMs: HOUR,
		},
		{ name: 'no cache headers', headers: () => ({}), freshForMs: 60_000 },
	];

	for (const { name, headers, freshForMs } of lifetimes) {
		it(`derives freshness from ${name}`, async () => {
			const path = freshPath();
			const time = clock();
			const url = primaryServer.route(path, async () =>
				jsonResponse(await jwksJson(await keyA()), headers()),
			);
			const resolver = resolverFor(url, time);
			await verifyKid('a', resolver);
			time.advance(freshForMs - 1);
			await verifyKid('a', resolver);
			expect({ name, hits: primaryServer.hits.get(path) }).toEqual({ name, hits: 1 });
			time.advance(2);
			await verifyKid('a', resolver);
			expect({ name, hits: primaryServer.hits.get(path) }).toEqual({ name, hits: 2 });
		});
	}
});

describe('unknown kid, cooldown and deduplication', () => {
	it('refreshes once for an unknown kid and then suppresses refreshes for the cooldown', async () => {
		const path = freshPath();
		const url = primaryServer.route(path, async () => jsonResponse(await jwksJson(await keyA())));
		const time = clock();
		const resolver = resolverFor(url, time);
		expect(await verifyKid('a', resolver)).toBe('ok');
		time.advance(1000);
		expect(await verifyKid('zzz', resolver, secondary)).toBe('key_not_found');
		expect(primaryServer.hits.get(path)).toBe(2);
		for (let index = 0; index < 50; index++) {
			expect(await verifyKid(`attacker-${index}`, resolver, secondary)).toBe('key_not_found');
		}
		expect(primaryServer.hits.get(path)).toBe(2);
		time.advance(999);
		await verifyKid('late', resolver, secondary);
		expect(primaryServer.hits.get(path)).toBe(2);
		time.advance(1);
		await verifyKid('later', resolver, secondary);
		expect(primaryServer.hits.get(path)).toBe(3);
	});

	it('does not refresh for the first unknown kid until the cooldown since the load', async () => {
		const path = freshPath();
		const url = primaryServer.route(path, async () => jsonResponse(await jwksJson(await keyA())));
		const time = clock();
		const resolver = resolverFor(url, time);
		await verifyKid('a', resolver);
		time.advance(999);
		expect(await verifyKid('x', resolver, secondary)).toBe('key_not_found');
		expect(primaryServer.hits.get(path)).toBe(1);
	});

	it('shares one request among concurrent verifications', async () => {
		const path = freshPath();
		const url = primaryServer.route(path, async () => {
			await Bun.sleep(80);
			return jsonResponse(await jwksJson(await keyA()));
		});
		const time = clock();
		const resolver = resolverFor(url, time);
		const results = await Promise.all(
			Array.from({ length: 40 }, (_, index) =>
				verifyKid(index % 2 === 0 ? 'a' : `u${index}`, resolver),
			),
		);
		expect(primaryServer.hits.get(path)).toBe(1);
		expect(results.filter((result) => result === 'ok')).toHaveLength(20);
		expect(results.filter((result) => result === 'key_not_found')).toHaveLength(20);
	});

	it('shares one unknown-kid refresh among concurrent misses and bounds a storm', async () => {
		const path = freshPath();
		let slow = false;
		const url = primaryServer.route(path, async () => {
			if (slow) await Bun.sleep(80);
			return jsonResponse(await jwksJson(await keyA()));
		});
		const time = clock();
		const resolver = resolverFor(url, time);
		await verifyKid('a', resolver);
		time.advance(1000);
		slow = true;
		const storm = await Promise.all(
			Array.from({ length: 200 }, (_, index) => verifyKid(`evil-${index}`, resolver, secondary)),
		);
		expect(new Set(storm)).toEqual(new Set(['key_not_found']));
		expect(primaryServer.hits.get(path)).toBe(2);
		const sequential: string[] = [];
		for (let index = 0; index < 200; index++) {
			sequential.push(await verifyKid(`again-${index}`, resolver, secondary));
		}
		expect(new Set(sequential)).toEqual(new Set(['key_not_found']));
		expect(primaryServer.hits.get(path)).toBe(2);
	});

	it('never caches an unknown kid: a key added later verifies after the cooldown', async () => {
		const path = freshPath();
		let withB = false;
		const url = primaryServer.route(path, async () =>
			jsonResponse(await jwksJson(await keyA(), ...(withB ? [await keyB()] : []))),
		);
		const time = clock();
		const resolver = resolverFor(url, time);
		await verifyKid('a', resolver);
		time.advance(1000);
		expect(await verifyKid('b', resolver, secondary)).toBe('key_not_found');
		withB = true;
		expect(await verifyKid('b', resolver, secondary)).toBe('key_not_found');
		time.advance(1000);
		expect(await verifyKid('b', resolver, secondary)).toBe('ok');
	});
});

describe('rotation, removal and stale keys', () => {
	it('picks up a rotated key and drops the removed one on refresh', async () => {
		const path = freshPath();
		let rotated = false;
		const url = primaryServer.route(path, async () =>
			jsonResponse(await jwksJson(rotated ? await keyB() : await keyA())),
		);
		const time = clock();
		const resolver = resolverFor(url, time);
		expect(await verifyKid('a', resolver)).toBe('ok');
		rotated = true;
		expect(await verifyKid('a', resolver)).toBe('ok');
		time.advance(1000);
		expect(await verifyKid('b', resolver, secondary)).toBe('ok');
		expect(await verifyKid('a', resolver)).toBe('key_not_found');
	});

	it('keeps serving a removed key only until the cached set expires', async () => {
		const path = freshPath();
		let removed = false;
		const url = primaryServer.route(path, async () =>
			jsonResponse(await jwksJson(...(removed ? [await keyB()] : [await keyA(), await keyB()]))),
		);
		const time = clock();
		const resolver = resolverFor(url, time);
		expect(await verifyKid('a', resolver)).toBe('ok');
		removed = true;
		time.advance(59_000);
		expect(await verifyKid('a', resolver)).toBe('ok');
		time.advance(2000);
		expect(await verifyKid('a', resolver)).toBe('key_not_found');
		expect(await verifyKid('b', resolver, secondary)).toBe('ok');
	});

	it('replaces a key published under the same kid at the next refresh', async () => {
		const path = freshPath();
		let swapped = false;
		const url = primaryServer.route(path, async () =>
			jsonResponse(await jwksJson(await rsaJwkEntry(swapped ? secondary : primary, { kid: 'k' }))),
		);
		const time = clock();
		const resolver = resolverFor(url, time);
		expect(await verifyKid('k', resolver)).toBe('ok');
		swapped = true;
		time.advance(61_000);
		expect(await verifyKid('k', resolver, secondary)).toBe('ok');
		expect(await verifyKid('k', resolver)).toBe('invalid_signature');
	});

	it('never reuses an expired set when the refresh fails', async () => {
		const path = freshPath();
		let failing = false;
		const url = primaryServer.route(path, async () =>
			failing ? new Response('boom', { status: 503 }) : jsonResponse(await jwksJson(await keyA())),
		);
		const time = clock();
		const resolver = resolverFor(url, time);
		expect(await verifyKid('a', resolver)).toBe('ok');
		failing = true;
		time.advance(61_000);
		expect(await verifyKid('a', resolver)).toBe('jwks_unavailable');
		expect(primaryServer.hits.get(path)).toBe(2);
		failing = false;
		expect(await verifyKid('a', resolver)).toBe('jwks_unavailable');
		expect(primaryServer.hits.get(path)).toBe(2);
		time.advance(1000);
		expect(await verifyKid('a', resolver)).toBe('ok');
		expect(primaryServer.hits.get(path)).toBe(3);
	});

	it('does not reuse the expired set while the endpoint is unreachable', async () => {
		const path = freshPath();
		const url = primaryServer.route(path, async () => jsonResponse(await jwksJson(await keyA())));
		const time = clock();
		const resolver = resolverFor(url, time);
		expect(await verifyKid('a', resolver)).toBe('ok');
		primaryServer.routes.set(path, () => new Response('gone', { status: 500 }));
		time.advance(HOUR);
		for (let index = 0; index < 3; index++) {
			expect(await verifyKid('a', resolver)).toBe('jwks_unavailable');
		}
		expect(primaryServer.hits.get(path)).toBe(2);
	});

	it('keeps a still-fresh set when an unknown-kid refresh fails', async () => {
		const path = freshPath();
		let failing = false;
		const url = primaryServer.route(path, async () =>
			failing ? new Response('boom', { status: 500 }) : jsonResponse(await jwksJson(await keyA())),
		);
		const time = clock();
		const resolver = resolverFor(url, time);
		await verifyKid('a', resolver);
		failing = true;
		time.advance(1000);
		expect(await verifyKid('unknown', resolver, secondary)).toBe('jwks_unavailable');
		expect(await verifyKid('a', resolver)).toBe('ok');
		time.advance(60_000);
		expect(await verifyKid('a', resolver)).toBe('jwks_unavailable');
	});
});

describe('endpoint failures', () => {
	async function codeFor(
		handler: Handler,
		overrides: Partial<RemoteJwksConfig> = {},
	): Promise<{ code: string; path: string }> {
		const path = freshPath();
		const url = primaryServer.route(path, handler);
		const result = await verifyKid('a', resolverFor(url, clock(), overrides));
		return { code: result, path };
	}

	it('maps non-200 statuses to jwks_unavailable', async () => {
		for (const status of [201, 204, 301, 304, 400, 401, 403, 404, 429, 500, 502, 503]) {
			const { code } = await codeFor(() => new Response(status === 204 ? null : 'x', { status }));
			expect({ status, code }).toEqual({ status, code: 'jwks_unavailable' });
		}
	});

	it('reports the status without the body', async () => {
		const path = freshPath();
		const url = primaryServer.route(path, () => new Response('secret-body', { status: 418 }));
		const result = await verifyCompactJws(await token('a'), {
			algorithms: ['RS256'],
			key: resolverFor(url, clock()),
			tokenType: { unchecked: true },
		});
		expect(result).toMatchObject({ ok: false, code: 'jwks_unavailable', details: { status: 418 } });
		expect(JSON.stringify(result)).not.toContain('secret-body');
	});

	it('maps malformed bodies to jwks_malformed', async () => {
		for (const body of [
			'',
			'not json',
			'[]',
			'{}',
			'{"keys":{}}',
			'{"keys":[],"keys":[]}',
			'\u0000',
		]) {
			const { code } = await codeFor(() => new Response(body));
			expect({ body, code }).toEqual({ body, code: 'jwks_malformed' });
		}
	});

	it('maps a refused connection to jwks_unavailable', async () => {
		const closed = startFixture();
		const url = closed.url('/jwks');
		await closed.server.stop(true);
		const result = await verifyKid('a', resolverFor(url, clock()));
		expect(result).toBe('jwks_unavailable');
	});

	it('maps a transport that throws to jwks_unavailable', async () => {
		const result = await verifyKid(
			'a',
			resolverFor(primaryServer.url('/x'), clock(), {
				transport: async () => {
					throw new TypeError('network down');
				},
			}),
		);
		expect(result).toBe('jwks_unavailable');
	});

	it('enforces the deadline over the whole response', async () => {
		const started = Date.now();
		const { code } = await codeFor(
			async () => {
				await Bun.sleep(600);
				return jsonResponse(await jwksJson(await keyA()));
			},
			{ timeoutMs: 60 },
		);
		expect(code).toBe('jwks_unavailable');
		expect(Date.now() - started).toBeLessThan(450);
	});

	it('enforces the deadline while the body is still streaming', async () => {
		const started = Date.now();
		const { code } = await codeFor(
			() =>
				new Response(
					new ReadableStream<Uint8Array>({
						async pull(controller) {
							controller.enqueue(new TextEncoder().encode(' '));
							await Bun.sleep(20);
						},
					}),
				),
			{ timeoutMs: 100, maxResponseBytes: 1_000_000 },
		);
		expect(code).toBe('jwks_unavailable');
		expect(Date.now() - started).toBeLessThan(1500);
	});
});

describe('response bounds', () => {
	it('stops reading a streamed body that exceeds the limit and cancels the stream', async () => {
		let cancelled = false;
		const { code } = await (async () => {
			const path = freshPath();
			const url = primaryServer.route(
				path,
				() =>
					new Response(
						new ReadableStream<Uint8Array>({
							pull(controller) {
								controller.enqueue(new Uint8Array(1024).fill(0x20));
							},
							cancel() {
								cancelled = true;
							},
						}),
					),
			);
			return { code: await verifyKid('a', resolverFor(url, clock(), { maxResponseBytes: 4096 })) };
		})();
		expect(code).toBe('jwks_malformed');
		expect(await eventually(() => cancelled)).toBe(true);
	});

	it('refuses a declared length over the limit although the body would fit', async () => {
		const body = await jwksJson(await keyA());
		const resolver = createRemoteJwksKeyResolver({
			url: 'https://issuer.example/jwks.json',
			maxResponseBytes: new TextEncoder().encode(body).length + 100,
			transport: async () => jsonResponse(body, { 'content-length': '999999' }),
		});
		expect(await verifyKid('a', resolver)).toBe('jwks_malformed');
		const honest = createRemoteJwksKeyResolver({
			url: 'https://issuer.example/jwks.json',
			maxResponseBytes: new TextEncoder().encode(body).length + 100,
			transport: async () => jsonResponse(body),
		});
		expect(await verifyKid('a', honest)).toBe('ok');
	});

	it('accepts a body exactly at the limit', async () => {
		const path = freshPath();
		const body = await jwksJson(await keyA());
		const url = primaryServer.route(path, () => jsonResponse(body));
		const length = new TextEncoder().encode(body).length;
		expect(await verifyKid('a', resolverFor(url, clock(), { maxResponseBytes: length }))).toBe(
			'ok',
		);
		const tooSmall = primaryServer.route(freshPath(), () => jsonResponse(body));
		expect(
			await verifyKid('a', resolverFor(tooSmall, clock(), { maxResponseBytes: length - 1 })),
		).toBe('jwks_malformed');
	});

	it('bounds the number of keys', async () => {
		const path = freshPath();
		const filler = Array.from({ length: 5 }, (_, index) => ({ kty: 'oct', kid: `f${index}` }));
		const url = primaryServer.route(path, async () =>
			jsonResponse(await jwksJson(...filler, await keyA())),
		);
		expect(await verifyKid('a', resolverFor(url, clock(), { maxKeys: 5 }))).toBe('jwks_malformed');
		expect(await verifyKid('a', resolverFor(url, clock(), { maxKeys: 6 }))).toBe('ok');
	});
});

describe('cancellation', () => {
	it('returns aborted without a request when the signal is already aborted', async () => {
		const path = freshPath();
		const url = primaryServer.route(path, async () => jsonResponse(await jwksJson(await keyA())));
		const resolver = resolverFor(url, clock());
		expect(await verifyKid('a', resolver, primary, AbortSignal.abort())).toBe('aborted');
		expect(primaryServer.hits.get(path)).toBeUndefined();
	});

	it('aborts the request when the only waiter cancels', async () => {
		const path = freshPath();
		let sawAbort = false;
		const url = primaryServer.route(path, async (request) => {
			request.signal.addEventListener('abort', () => {
				sawAbort = true;
			});
			await Bun.sleep(1500);
			return jsonResponse(await jwksJson(await keyA()));
		});
		const resolver = resolverFor(url, clock());
		const controller = new AbortController();
		const pending = verifyKid('a', resolver, primary, controller.signal);
		await eventually(() => primaryServer.hits.get(path) === 1);
		controller.abort();
		expect(await pending).toBe('aborted');
		expect(await eventually(() => sawAbort)).toBe(true);
	});

	it('keeps the request alive while another verification still waits', async () => {
		const path = freshPath();
		const url = primaryServer.route(path, async () => {
			await Bun.sleep(150);
			return jsonResponse(await jwksJson(await keyA()));
		});
		const resolver = resolverFor(url, clock());
		const controller = new AbortController();
		const cancelled = verifyKid('a', resolver, primary, controller.signal);
		const patient = verifyKid('a', resolver);
		await eventually(() => primaryServer.hits.get(path) === 1);
		controller.abort();
		expect(await cancelled).toBe('aborted');
		expect(await patient).toBe('ok');
		expect(primaryServer.hits.get(path)).toBe(1);
	});

	it('does not count a cancelled request as a failure', async () => {
		const path = freshPath();
		let slow = true;
		const url = primaryServer.route(path, async (request) => {
			if (slow) {
				await new Promise<void>((resolve) => {
					request.signal.addEventListener('abort', () => resolve());
					setTimeout(resolve, 1500);
				});
			}
			return jsonResponse(await jwksJson(await keyA()));
		});
		const time = clock();
		const resolver = resolverFor(url, time);
		const controller = new AbortController();
		const pending = verifyKid('a', resolver, primary, controller.signal);
		await eventually(() => primaryServer.hits.get(path) === 1);
		controller.abort();
		expect(await pending).toBe('aborted');
		slow = false;
		expect(await verifyKid('a', resolver)).toBe('ok');
	});
});

describe('redirects', () => {
	it('refuses redirects by default', async () => {
		const target = primaryServer.route(freshPath(), async () =>
			jsonResponse(await jwksJson(await keyA())),
		);
		const path = freshPath();
		const url = primaryServer.route(path, () => Response.redirect(target, 302));
		const result = await verifyCompactJws(await token('a'), {
			algorithms: ['RS256'],
			key: resolverFor(url, clock()),
			tokenType: { unchecked: true },
		});
		expect(result).toMatchObject({ ok: false, code: 'jwks_unavailable', details: { status: 302 } });
		expect(primaryServer.hits.get(new URL(target).pathname)).toBeUndefined();
	});

	it('follows same-origin redirects up to the configured limit', async () => {
		const target = primaryServer.route(freshPath(), async () =>
			jsonResponse(await jwksJson(await keyA())),
		);
		const hop = primaryServer.route(freshPath(), () => Response.redirect(target, 307));
		const entry = primaryServer.route(freshPath(), () => Response.redirect(hop, 301));
		expect(
			await verifyKid('a', resolverFor(entry, clock(), { redirects: { maxRedirects: 2 } })),
		).toBe('ok');
		expect(
			await verifyKid('a', resolverFor(entry, clock(), { redirects: { maxRedirects: 1 } })),
		).toBe('jwks_unavailable');
	});

	it('stops a redirect loop at the limit', async () => {
		const path = freshPath();
		const url = primaryServer.route(path, (request) => Response.redirect(request.url, 302));
		expect(
			await verifyKid('a', resolverFor(url, clock(), { redirects: { maxRedirects: 5 } })),
		).toBe('jwks_unavailable');
		expect(primaryServer.hits.get(path)).toBe(6);
	});

	it('refuses a cross-origin destination unless the caller approves it', async () => {
		const target = otherServer.route(freshPath(), async () =>
			jsonResponse(await jwksJson(await keyA())),
		);
		const url = primaryServer.route(freshPath(), () => Response.redirect(target, 302));
		const base = { redirects: { maxRedirects: 3 } };
		expect(await verifyKid('a', resolverFor(url, clock(), base))).toBe('jwks_unavailable');
		expect(otherServer.hits.get(new URL(target).pathname)).toBeUndefined();
		const approved: string[] = [];
		const allowed = {
			redirects: {
				maxRedirects: 3,
				allow: (destination: URL, from: URL) => {
					approved.push(`${from.origin}>${destination.origin}`);
					return destination.origin === otherServer.origin();
				},
			},
		};
		expect(await verifyKid('a', resolverFor(url, clock(), allowed))).toBe('ok');
		expect(approved).toEqual([`${primaryServer.origin()}>${otherServer.origin()}`]);
	});

	it('refuses destinations that are not https or loopback http, even when the caller approves', async () => {
		for (const location of [
			'http://example.com/jwks',
			'ftp://127.0.0.1/jwks',
			'file:///etc/passwd',
			'javascript:alert(1)',
			'data:application/json,{}',
			'//example.com/jwks',
		]) {
			const url = primaryServer.route(
				freshPath(),
				() => new Response(null, { status: 302, headers: { location } }),
			);
			const code = await verifyKid(
				'a',
				resolverFor(url, clock(), { redirects: { maxRedirects: 3, allow: () => true } }),
			);
			expect({ location, code }).toEqual({ location, code: 'jwks_unavailable' });
		}
	});

	it('refuses a redirect without a usable Location', async () => {
		const withoutTarget: readonly Record<string, string>[] = [{}, { location: 'http://[' }];
		for (const headers of withoutTarget) {
			const url = primaryServer.route(
				freshPath(),
				() => new Response(null, { status: 302, headers }),
			);
			const code = await verifyKid(
				'a',
				resolverFor(url, clock(), { redirects: { maxRedirects: 3, allow: () => true } }),
			);
			expect({ headers, code }).toEqual({ headers, code: 'jwks_unavailable' });
		}
	});

	it('refuses a redirect destination that embeds credentials', async () => {
		const target = primaryServer.route(freshPath(), async () =>
			jsonResponse(await jwksJson(await keyA())),
		);
		const withCredentials = target.replace('http://', 'http://user:secret@');
		const url = primaryServer.route(freshPath(), () => Response.redirect(withCredentials, 302));
		const permissive = { redirects: { maxRedirects: 3, allow: () => true } };
		expect(await verifyKid('a', resolverFor(url, clock(), permissive))).toBe('jwks_unavailable');
		expect(primaryServer.hits.get(new URL(target).pathname)).toBeUndefined();
		const sameOrigin = { redirects: { maxRedirects: 3 } };
		expect(await verifyKid('a', resolverFor(url, clock(), sameOrigin))).toBe('jwks_unavailable');
		const justPassword = primaryServer.route(freshPath(), () =>
			Response.redirect(target.replace('http://', 'http://:pw@'), 302),
		);
		expect(await verifyKid('a', resolverFor(justPassword, clock(), permissive))).toBe(
			'jwks_unavailable',
		);
	});

	it('sends configured headers to the configured origin only', async () => {
		const target = otherServer.route(freshPath(), async () =>
			jsonResponse(await jwksJson(await keyA())),
		);
		const sameOriginTarget = primaryServer.route(freshPath(), async () =>
			jsonResponse(await jwksJson(await keyA())),
		);
		const crossing = primaryServer.route(freshPath(), () => Response.redirect(target, 302));
		const staying = primaryServer.route(freshPath(), () =>
			Response.redirect(sameOriginTarget, 302),
		);
		const headers = { authorization: 'Bearer secret', 'x-tenant': 't1' };
		const policy = { maxRedirects: 2, allow: () => true };
		expect(
			await verifyKid('a', resolverFor(crossing, clock(), { headers, redirects: policy })),
		).toBe('ok');
		const first = primaryServer.seenHeaders.get(new URL(crossing).pathname)?.[0];
		expect(first?.get('authorization')).toBe('Bearer secret');
		const crossed = otherServer.seenHeaders.get(new URL(target).pathname)?.[0];
		expect(crossed?.get('authorization')).toBeNull();
		expect(crossed?.get('x-tenant')).toBeNull();
		expect(
			await verifyKid('a', resolverFor(staying, clock(), { headers, redirects: policy })),
		).toBe('ok');
		const stayed = primaryServer.seenHeaders.get(new URL(sameOriginTarget).pathname)?.[0];
		expect(stayed?.get('authorization')).toBe('Bearer secret');
	});

	it('refuses a runtime that hides redirect targets', async () => {
		const opaque = Object.defineProperty(new Response(null), 'type', { value: 'opaqueredirect' });
		const code = await verifyKid(
			'a',
			resolverFor(primaryServer.url('/x'), clock(), { transport: async () => opaque }),
		);
		expect(code).toBe('jwks_unavailable');
	});
});

describe('transport', () => {
	it('issues the documented request through an injected transport', async () => {
		const seen: { url: string; init: JwksRequestInit }[] = [];
		const body = await jwksJson(await keyA());
		const resolver = createRemoteJwksKeyResolver({
			url: 'https://issuer.example/.well-known/jwks.json',
			headers: { 'x-api-key': 'k' },
			transport: async (url, init) => {
				seen.push({ url, init });
				return jsonResponse(body);
			},
		});
		expect(await verifyKid('a', resolver)).toBe('ok');
		expect(seen).toHaveLength(1);
		expect(seen[0]?.url).toBe('https://issuer.example/.well-known/jwks.json');
		expect(seen[0]?.init).toMatchObject({
			method: 'GET',
			redirect: 'manual',
			credentials: 'omit',
			headers: { 'x-api-key': 'k' },
		});
		expect(seen[0]?.init.signal).toBeInstanceOf(AbortSignal);
	});

	it('uses the global fetch by default', async () => {
		const path = freshPath();
		const url = primaryServer.route(path, async () => jsonResponse(await jwksJson(await keyA())));
		expect(await verifyKid('a', createRemoteJwksKeyResolver({ url }))).toBe('ok');
		expect(primaryServer.hits.get(path)).toBe(1);
	});
});

describe('freshness is separate from the refresh cooldown', () => {
	async function resolverWith(headers: () => Record<string, string>, cooldownMs = 1000) {
		const path = freshPath();
		const time = clock();
		const url = primaryServer.route(path, async () =>
			jsonResponse(await jwksJson(await keyA()), headers()),
		);
		return { resolver: resolverFor(url, time, { cooldownMs }), time, path };
	}

	it('does not reuse a no-store or no-cache set, and does not refetch inside the cooldown', async () => {
		for (const directive of [
			'no-store',
			'no-cache',
			'max-age=0',
			'private, no-store, max-age=600',
		]) {
			const { resolver, time, path } = await resolverWith(() => ({ 'cache-control': directive }));
			expect(await verifyKid('a', resolver)).toBe('ok');
			time.advance(1);
			expect({ directive, code: await verifyKid('a', resolver) }).toEqual({
				directive,
				code: 'jwks_unavailable',
			});
			expect(primaryServer.hits.get(path)).toBe(1);
			time.advance(999);
			expect(await verifyKid('a', resolver)).toBe('ok');
			expect(primaryServer.hits.get(path)).toBe(2);
		}
	});

	it('does not extend trust past the stated lifetime when the cooldown is longer', async () => {
		const { resolver, time, path } = await resolverWith(
			() => ({ 'cache-control': 'max-age=10' }),
			60_000,
		);
		expect(await verifyKid('a', resolver)).toBe('ok');
		time.advance(9999);
		expect(await verifyKid('a', resolver)).toBe('ok');
		time.advance(2);
		expect(await verifyKid('a', resolver)).toBe('jwks_unavailable');
		expect(primaryServer.hits.get(path)).toBe(1);
		time.advance(60_000);
		expect(await verifyKid('a', resolver)).toBe('ok');
		expect(primaryServer.hits.get(path)).toBe(2);
	});

	it('counts the apparent age from Date against the lifetime', async () => {
		const path = freshPath();
		const time = clock();
		const url = primaryServer.route(path, async () =>
			jsonResponse(await jwksJson(await keyA()), {
				'cache-control': 'max-age=60',
				date: new Date(time.now() - 3_600_000).toUTCString(),
			}),
		);
		const resolver = resolverFor(url, time);
		expect(await verifyKid('a', resolver)).toBe('ok');
		time.advance(1);
		expect(await verifyKid('a', resolver)).toBe('jwks_unavailable');
		expect(primaryServer.hits.get(path)).toBe(1);
	});

	it('counts a Date only partly in the past, ignores a Date in the future, and honours Age with it', async () => {
		const cases: readonly {
			readonly offsetMs: number;
			readonly age?: string;
			readonly freshMs: number;
		}[] = [
			{ offsetMs: -20_000, freshMs: 40_000 },
			{ offsetMs: 3_600_000, freshMs: 60_000 },
			{ offsetMs: -10_000, age: '30', freshMs: 30_000 },
			{ offsetMs: -40_000, age: '30', freshMs: 20_000 },
		];
		for (const { offsetMs, age, freshMs } of cases) {
			const path = freshPath();
			const time = clock();
			const url = primaryServer.route(path, async () =>
				jsonResponse(await jwksJson(await keyA()), {
					'cache-control': 'max-age=60',
					date: new Date(time.now() + offsetMs).toUTCString(),
					...(age === undefined ? {} : { age }),
				}),
			);
			const resolver = resolverFor(url, time, { cooldownMs: 1 });
			await verifyKid('a', resolver);
			time.advance(freshMs - 1000);
			await verifyKid('a', resolver);
			expect({ offsetMs, age, hits: primaryServer.hits.get(path) }).toEqual({
				offsetMs,
				age,
				hits: 1,
			});
			time.advance(2000);
			await verifyKid('a', resolver);
			expect({ offsetMs, age, hits: primaryServer.hits.get(path) }).toEqual({
				offsetMs,
				age,
				hits: 2,
			});
		}
	});

	it('counts the transit delay against the lifetime', async () => {
		const time = clock();
		const body = await jwksJson(await keyA());
		let requests = 0;
		const resolver = createRemoteJwksKeyResolver({
			url: 'https://issuer.example/jwks.json',
			now: time.now,
			cooldownMs: 1,
			transport: async () => {
				requests++;
				time.advance(40_000);
				return jsonResponse(body, { 'cache-control': 'max-age=60' });
			},
		});
		expect(await verifyKid('a', resolver)).toBe('ok');
		time.advance(19_000);
		expect(await verifyKid('a', resolver)).toBe('ok');
		expect(requests).toBe(1);
		time.advance(2000);
		expect(await verifyKid('a', resolver)).toBe('ok');
		expect(requests).toBe(2);
	});
});

describe('superseded, hung and cancelled refreshes', () => {
	it('completes normally for a signal that is never aborted, and ignores a later abort', async () => {
		const path = freshPath();
		const url = primaryServer.route(path, async () => jsonResponse(await jwksJson(await keyA())));
		const resolver = resolverFor(url, clock());
		const controller = new AbortController();
		expect(await verifyKid('a', resolver, primary, controller.signal)).toBe('ok');
		controller.abort();
		expect(await verifyKid('a', resolver)).toBe('ok');
		expect(primaryServer.hits.get(path)).toBe(1);
	});

	it('lets a refresh that finishes after cancellation neither replace the cache nor count', async () => {
		const bodyA = await jwksJson(await keyA());
		const bodyB = await jwksJson(await keyB());
		let requests = 0;
		const time = clock();
		const resolver = createRemoteJwksKeyResolver({
			url: 'https://issuer.example/jwks.json',
			now: time.now,
			cooldownMs: 1000,
			transport: async () => {
				requests++;
				if (requests === 1) {
					await Bun.sleep(250);
					return jsonResponse(bodyA);
				}
				return jsonResponse(bodyB);
			},
		});
		const controller = new AbortController();
		const cancelled = verifyKid('a', resolver, primary, controller.signal);
		await eventually(() => requests === 1);
		controller.abort();
		expect(await cancelled).toBe('aborted');
		expect(await verifyKid('b', resolver, secondary)).toBe('ok');
		expect(requests).toBe(2);
		await Bun.sleep(400);
		expect(await verifyKid('b', resolver, secondary)).toBe('ok');
		expect(await verifyKid('a', resolver)).toBe('key_not_found');
		expect(requests).toBe(2);
	});

	it('stops waiting on a transport that never answers and ignores the abort signal', async () => {
		const started = Date.now();
		const resolver = createRemoteJwksKeyResolver({
			url: 'https://issuer.example/jwks.json',
			timeoutMs: 100,
			transport: () => new Promise<Response>(() => undefined),
		});
		expect(await verifyKid('a', resolver)).toBe('jwks_unavailable');
		expect(Date.now() - started).toBeLessThan(1500);
	});

	it('stops reading a body stream that hangs and ignores the abort signal, and releases it', async () => {
		let cancelled = false;
		const started = Date.now();
		const resolver = createRemoteJwksKeyResolver({
			url: 'https://issuer.example/jwks.json',
			timeoutMs: 100,
			transport: async () =>
				new Response(
					new ReadableStream<Uint8Array>({
						pull: () => new Promise<void>(() => undefined),
						cancel() {
							cancelled = true;
						},
					}),
				),
		});
		expect(await verifyKid('a', resolver)).toBe('jwks_unavailable');
		expect(Date.now() - started).toBeLessThan(1500);
		expect(await eventually(() => cancelled)).toBe(true);
	});

	it('releases the body of a response that arrives after the request was cancelled', async () => {
		let cancelled = false;
		const resolver = createRemoteJwksKeyResolver({
			url: 'https://issuer.example/jwks.json',
			transport: async () => {
				await Bun.sleep(150);
				return new Response(
					new ReadableStream<Uint8Array>({
						pull: () => new Promise<void>(() => undefined),
						cancel() {
							cancelled = true;
						},
					}),
				);
			},
		});
		const controller = new AbortController();
		const pending = verifyKid('a', resolver, primary, controller.signal);
		await Bun.sleep(20);
		controller.abort();
		expect(await pending).toBe('aborted');
		expect(await eventually(() => cancelled)).toBe(true);
	});

	it('does not start a fetch for a signal that aborts while the caller yields', async () => {
		const path = freshPath();
		const url = primaryServer.route(path, async () => jsonResponse(await jwksJson(await keyA())));
		const time = clock();
		const resolver = resolverFor(url, time);
		await verifyKid('a', resolver);
		time.advance(1000);
		const controller = new AbortController();
		const request = {
			header: { alg: 'RS256', kid: 'unknown', members: {} },
			algorithm: 'RS256',
			kid: 'unknown',
			signal: controller.signal,
		} as const;
		const pending = resolver(request);
		controller.abort();
		expect(await pending).toMatchObject({ ok: false, code: 'aborted' });
		expect(primaryServer.hits.get(path)).toBe(1);
	});

	it('honours cancellation even when the key is already cached', async () => {
		const path = freshPath();
		const url = primaryServer.route(path, async () => jsonResponse(await jwksJson(await keyA())));
		const time = clock();
		const resolver = resolverFor(url, time);
		await verifyKid('a', resolver);
		const controller = new AbortController();
		const request = {
			header: { alg: 'RS256', kid: 'a', members: {} },
			algorithm: 'RS256',
			kid: 'a',
			signal: controller.signal,
		} as const;
		const pending = resolver(request);
		controller.abort();
		expect(await pending).toMatchObject({ ok: false, code: 'aborted' });
		expect(await resolver({ ...request, signal: undefined })).toMatchObject({ ok: true });
	});
});

describe('caller clock failure', () => {
	function brokenClock(throwOnCall: number) {
		const path = freshPath();
		const url = primaryServer.route(path, async () => jsonResponse(await jwksJson(await keyA())));
		const time = clock();
		let calls = 0;
		const resolver = createRemoteJwksKeyResolver({
			url,
			cooldownMs: 1000,
			now: () => {
				calls++;
				if (calls === throwOnCall) throw new Error('clock broke');
				return time.now();
			},
		});
		return { resolver, time, path };
	}

	it('reports a clock that throws before the request as a resolver failure and recovers', async () => {
		for (const signal of [new AbortController().signal, undefined]) {
			const { resolver, path } = brokenClock(1);
			expect(await verifyKid('a', resolver, primary, signal)).toBe('key_resolution_failed');
			expect(primaryServer.hits.get(path)).toBeUndefined();
			expect(await verifyKid('a', resolver)).toBe('ok');
			expect(primaryServer.hits.get(path)).toBe(1);
		}
	});

	it('reports a clock that throws while the response is read as an unavailable endpoint', async () => {
		const { resolver, time, path } = brokenClock(2);
		expect(await verifyKid('a', resolver)).toBe('jwks_unavailable');
		expect(primaryServer.hits.get(path)).toBe(1);
		time.advance(1000);
		expect(await verifyKid('a', resolver)).toBe('ok');
		expect(primaryServer.hits.get(path)).toBe(2);
	});
});

describe('issuer isolation', () => {
	it('keeps one cache per configured source, never keyed by kid alone', async () => {
		const pathA = freshPath();
		const pathB = freshPath();
		const urlA = primaryServer.route(pathA, async () =>
			jsonResponse(await jwksJson(await rsaJwkEntry(primary, { kid: 'shared' }))),
		);
		const urlB = otherServer.route(pathB, async () =>
			jsonResponse(await jwksJson(await rsaJwkEntry(secondary, { kid: 'shared' }))),
		);
		const time = clock();
		const issuerA = resolverFor(urlA, time);
		const issuerB = resolverFor(urlB, time);
		expect(await verifyKid('shared', issuerA, primary)).toBe('ok');
		expect(await verifyKid('shared', issuerB, secondary)).toBe('ok');
		expect(await verifyKid('shared', issuerA, secondary)).toBe('invalid_signature');
		expect(await verifyKid('shared', issuerB, primary)).toBe('invalid_signature');
		expect(primaryServer.hits.get(pathA)).toBe(1);
		expect(otherServer.hits.get(pathB)).toBe(1);
	});

	it('does not let one source satisfy a kid published only by another', async () => {
		const urlA = primaryServer.route(freshPath(), async () =>
			jsonResponse(await jwksJson(await keyA())),
		);
		const urlB = otherServer.route(freshPath(), async () =>
			jsonResponse(await jwksJson(await keyB())),
		);
		const time = clock();
		const issuerA = resolverFor(urlA, time);
		const issuerB = resolverFor(urlB, time);
		expect(await verifyKid('a', issuerA)).toBe('ok');
		expect(await verifyKid('b', issuerB, secondary)).toBe('ok');
		expect(await verifyKid('b', issuerA, secondary)).toBe('key_not_found');
		expect(await verifyKid('a', issuerB)).toBe('key_not_found');
	});

	it('ignores jku and x5u headers in the token', async () => {
		const trusted = primaryServer.route(freshPath(), async () =>
			jsonResponse(await jwksJson(await keyA())),
		);
		const attacker = otherServer.route(freshPath(), async () =>
			jsonResponse(await jwksJson(await keyB())),
		);
		const signed = await signCompactJws({
			privateKey: secondary.privateKey,
			algorithm: 'RS256',
			payload,
			header: { kid: 'b' },
		});
		const [header, body, signature] = signed.split('.');
		const forgedHeader = Buffer.from(
			JSON.stringify({ alg: 'RS256', kid: 'b', jku: attacker, x5u: attacker }),
		).toString('base64url');
		const result = await verifyCompactJws(`${forgedHeader}.${body}.${signature}`, {
			algorithms: ['RS256'],
			key: resolverFor(trusted, clock()),
			tokenType: { unchecked: true },
		});
		expect(result).toMatchObject({ ok: false });
		expect(otherServer.hits.get(new URL(attacker).pathname)).toBeUndefined();
		expect(header).toBeDefined();
	});
});

describe('configuration', () => {
	const valid = 'https://issuer.example/jwks.json';

	it('rejects unusable URLs', () => {
		for (const url of [
			'',
			'not a url',
			'/relative',
			'http://issuer.example/jwks',
			'http://127.0.0.2.example/jwks',
			'ftp://issuer.example/jwks',
			'file:///jwks',
			'javascript:void(0)',
			'https://user:pass@issuer.example/jwks',
		]) {
			expectBuildErrorCode(
				() => createRemoteJwksKeyResolver({ url }),
				'invalid_remote_jwks_config',
			);
		}
	});

	it('accepts https and loopback http', () => {
		for (const url of [
			valid,
			new URL(valid),
			'http://localhost:8080/jwks',
			'http://127.0.0.1/jwks',
			'http://[::1]:3000/jwks',
		]) {
			expect(typeof createRemoteJwksKeyResolver({ url })).toBe('function');
		}
	});

	it('rejects non-positive and non-integer limits', () => {
		for (const name of [
			'timeoutMs',
			'maxResponseBytes',
			'maxKeys',
			'defaultTtlMs',
			'maxTtlMs',
			'cooldownMs',
		] as const) {
			for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
				expectBuildErrorCode(
					() => createRemoteJwksKeyResolver({ url: valid, [name]: bad }),
					'invalid_remote_jwks_config',
				);
			}
		}
	});

	it('bounds the redirect count', () => {
		for (const maxRedirects of [-1, 11, 1.5, Number.NaN]) {
			expectBuildErrorCode(
				() => createRemoteJwksKeyResolver({ url: valid, redirects: { maxRedirects } }),
				'invalid_remote_jwks_config',
			);
		}
		expect(
			typeof createRemoteJwksKeyResolver({ url: valid, redirects: { maxRedirects: 10 } }),
		).toBe('function');
	});
});

describe('selection through the resolver', () => {
	it('reports ambiguity and unsuitability from the fetched set', async () => {
		const duplicate = primaryServer.route(freshPath(), async () =>
			jsonResponse(
				await jwksJson(
					await rsaJwkEntry(primary, { kid: 'd' }),
					await rsaJwkEntry(secondary, { kid: 'd' }),
				),
			),
		);
		const unsuitable = primaryServer.route(freshPath(), async () =>
			jsonResponse(await jwksJson(await rsaJwkEntry(primary, { kid: 'e', use: 'enc' }))),
		);
		expect(await verifyKid('d', resolverFor(duplicate, clock()))).toBe('ambiguous_key');
		expect(await verifyKid('e', resolverFor(unsuitable, clock()))).toBe('key_unsuitable');
	});

	it('resolves a token without kid only against a single-key set', async () => {
		const single = primaryServer.route(freshPath(), async () =>
			jsonResponse(await jwksJson(await keyA())),
		);
		const pair = primaryServer.route(freshPath(), async () =>
			jsonResponse(await jwksJson(await keyA(), await keyB())),
		);
		const noKid = await signCompactJws({
			privateKey: primary.privateKey,
			algorithm: 'RS256',
			payload,
		});
		const check = async (url: string): Promise<string> => {
			const result: Awaited<ReturnType<typeof verifyCompactJws>> = await verifyCompactJws(noKid, {
				algorithms: ['RS256'],
				key: resolverFor(url, clock()),
				tokenType: { unchecked: true },
			});
			return result.ok ? 'ok' : result.code;
		};
		expect(await check(single)).toBe('ok');
		expect(await check(pair)).toBe('ambiguous_key');
	});

	it('exposes the verified header of a successful verification', async () => {
		const url = primaryServer.route(freshPath(), async () =>
			jsonResponse(await jwksJson(await keyA())),
		);
		const result = await verifyCompactJws(await token('a'), {
			algorithms: ['RS256'],
			key: resolverFor(url, clock()),
			tokenType: { unchecked: true },
		});
		const value: VerifiedJws | undefined = result.ok ? result.value : undefined;
		expect(value?.header.kid).toBe('a');
	});
});
