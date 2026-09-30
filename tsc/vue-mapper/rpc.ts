export type Handler = (method: string, params: unknown) => unknown;

export function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function send(message: Readonly<Record<string, unknown>>): void {
	const body = Buffer.from(JSON.stringify({ jsonrpc: '2.0', ...message }), 'utf8');
	process.stdout.write(
		Buffer.concat([Buffer.from(`Content-Length: ${body.length}\r\n\r\n`, 'ascii'), body]),
	);
}

function dispatch(message: unknown, handle: Handler): void {
	if (!isRecord(message) || typeof message.method !== 'string') return;
	const { id, method, params } = message;
	try {
		const result = handle(method, params);
		if (id !== undefined) send({ id, result: result ?? null });
	} catch (error) {
		if (id === undefined) return;
		const text = error instanceof Error ? (error.stack ?? error.message) : String(error);
		send({ id, error: { code: -32603, message: text } });
	}
}

/** Serves JSON-RPC over stdio with Content-Length framing until stdin closes. */
export function serve(handle: Handler): void {
	let pending = Buffer.alloc(0);
	process.stdin.on('data', (chunk: Buffer) => {
		pending = Buffer.concat([pending, chunk]);
		for (;;) {
			const headerEnd = pending.indexOf('\r\n\r\n');
			if (headerEnd === -1) return;
			const header = pending.subarray(0, headerEnd).toString('ascii');
			const length = /^Content-Length: *(\d+)$/im.exec(header)?.[1];
			if (length === undefined)
				throw new Error(`Missing Content-Length in ${JSON.stringify(header)}`);
			const start = headerEnd + 4;
			const end = start + Number(length);
			if (pending.length < end) return;
			const message: unknown = JSON.parse(pending.subarray(start, end).toString('utf8'));
			pending = pending.subarray(end);
			dispatch(message, handle);
		}
	});
	process.stdin.on('end', () => process.exit(0));
}
