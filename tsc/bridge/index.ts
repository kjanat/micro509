import { spawn, spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';

export interface Diagnostic {
	readonly code: number;
	readonly category: number;
	readonly message: string;
	/** `message` followed by its chained messages, as TypeScript prints them. */
	readonly messageText: string;
	readonly fileName?: string;
	/** Zero-based UTF-8 byte offset, matching the Go compiler. */
	readonly start: number;
	/** Length in UTF-8 bytes. */
	readonly length: number;
	readonly children?: readonly Diagnostic[];
}

export interface TranspileResult {
	readonly outputText: string;
	/** Syntactic and compiler-option diagnostics; transpilation does not typecheck. */
	readonly diagnostics: readonly Diagnostic[];
}

export interface CodeUnion {
	readonly name: string;
	readonly codes: readonly string[];
}

/** Applied as a tsconfig that extends the project's configuration. */
export interface ProjectOverrides {
	/** Replaces the project's root files. Paths are relative to the configuration file's directory. */
	readonly files?: readonly string[];
	/** tsconfig `compilerOptions` layered over the project's own. */
	readonly compilerOptions?: Readonly<Record<string, unknown>>;
}

export interface TscBridge {
	transpile(source: string, fileName?: string): Promise<TranspileResult>;
	checkProject(configPath: string, overrides?: ProjectOverrides): Promise<readonly Diagnostic[]>;
	/** Entrypoints are relative to the configuration file's directory. */
	exportedCodeUnions(
		configPath: string,
		entrypoints: readonly string[],
	): Promise<readonly CodeUnion[]>;
	/** Finishes queued work, closes stdin, and waits for the helper to exit. */
	close(): Promise<void>;
}

interface Response extends TranspileResult {
	readonly unions: readonly CodeUnion[];
}

type Request =
	| { readonly method: 'transpile'; readonly source: string; readonly fileName?: string }
	| ({ readonly method: 'checkProject'; readonly configPath: string } & ProjectOverrides)
	| {
			readonly method: 'exportedCodeUnions';
			readonly configPath: string;
			readonly entrypoints: readonly string[];
	  };

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isDiagnostic(value: unknown): value is Diagnostic {
	return (
		isRecord(value) &&
		typeof value.code === 'number' &&
		typeof value.category === 'number' &&
		typeof value.message === 'string' &&
		typeof value.messageText === 'string' &&
		typeof value.start === 'number' &&
		typeof value.length === 'number' &&
		(value.fileName === undefined || typeof value.fileName === 'string') &&
		(value.children === undefined ||
			(Array.isArray(value.children) && value.children.every(isDiagnostic)))
	);
}

function isCodeUnion(value: unknown): value is CodeUnion {
	return (
		isRecord(value) &&
		typeof value.name === 'string' &&
		Array.isArray(value.codes) &&
		value.codes.every((code: unknown) => typeof code === 'string')
	);
}

function executableOf(executable?: string): string {
	return (
		executable ??
		fileURLToPath(
			new URL(
				process.platform === 'win32' ? './bin/tsc-bridge.exe' : './bin/tsc-bridge',
				import.meta.url,
			),
		)
	);
}

function responseOf(value: Record<string, unknown>): Response {
	const { outputText, diagnostics, unions } = value;
	if (
		typeof outputText !== 'string' ||
		!Array.isArray(diagnostics) ||
		!diagnostics.every(isDiagnostic) ||
		!Array.isArray(unions) ||
		!unions.every(isCodeUnion)
	) {
		throw new Error('Invalid helper response payload');
	}
	return { outputText, diagnostics, unions };
}

export interface HelperOptions {
	readonly executable?: string;
	readonly cwd?: string;
	readonly timeoutMs?: number;
}

function requestSync(payload: Request, options: HelperOptions): Response {
	const timeoutMs = options.timeoutMs ?? 60_000;
	if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error('timeoutMs must be positive');
	const result = spawnSync(executableOf(options.executable), [], {
		cwd: options.cwd,
		encoding: 'utf8',
		timeout: timeoutMs,
		maxBuffer: 16 * 1024 * 1024,
		input: `${JSON.stringify({ id: 1, ...payload })}\n`,
	});
	if (result.error) throw result.error;
	if (result.status !== 0) {
		throw new Error(
			`TypeScript helper exited (${result.signal ?? result.status}): ${result.stderr.trim()}`,
		);
	}
	const value: unknown = JSON.parse(result.stdout);
	if (!isRecord(value) || value.id !== 1) throw new Error('Invalid helper response');
	if (typeof value.error === 'string') throw new Error(value.error);
	return responseOf(value);
}

/** Runs one helper for integrations that require a synchronous transpiler. */
export function transpileSync(
	source: string,
	options: HelperOptions & { readonly fileName?: string } = {},
): TranspileResult {
	const { outputText, diagnostics } = requestSync(
		{ method: 'transpile', source, fileName: options.fileName },
		options,
	);
	return { outputText, diagnostics };
}

/** Runs one helper for integrations that require a synchronous project check. */
export function checkProjectSync(
	configPath: string,
	options: HelperOptions & ProjectOverrides = {},
): readonly Diagnostic[] {
	const { files, compilerOptions } = options;
	return requestSync({ method: 'checkProject', configPath, files, compilerOptions }, options)
		.diagnostics;
}

/** Starts one persistent helper process. Paths passed to it resolve against cwd. */
export function createTscBridge(options: HelperOptions = {}): TscBridge {
	const timeoutMs = options.timeoutMs ?? 60_000;
	if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error('timeoutMs must be positive');
	const executable = executableOf(options.executable);
	const child = spawn(executable, [], { cwd: options.cwd, stdio: ['pipe', 'pipe', 'pipe'] });
	const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
	const pending = new Map<
		number,
		{
			readonly resolve: (response: Response) => void;
			readonly reject: (error: Error) => void;
			readonly timer: ReturnType<typeof setTimeout>;
		}
	>();
	let nextId = 1;
	let closing = false;
	let failure: Error | undefined;
	let stderr = '';
	let resolveExit: () => void = () => {};
	let rejectExit: (error: Error) => void = () => {};
	const exited = new Promise<void>((resolve, reject) => {
		resolveExit = resolve;
		rejectExit = reject;
	});
	// A process can fail before the caller reaches close(). Preserve that rejection.
	void exited.catch(() => {});

	function fail(error: Error): void {
		failure ??= error;
		for (const item of pending.values()) {
			clearTimeout(item.timer);
			item.reject(failure);
		}
		pending.clear();
	}

	child.stderr.setEncoding('utf8');
	child.stderr.on('data', (chunk: string) => {
		stderr = (stderr + chunk).slice(-16_384);
	});
	child.on('error', (error) => {
		fail(error);
		rejectExit(error);
	});
	child.stdin.on('error', fail);
	child.on('close', (code, signal) => {
		lines.close();
		if (code !== 0 || pending.size > 0 || !closing) {
			fail(new Error(`TypeScript helper exited (${signal ?? code}): ${stderr.trim()}`));
		}
		if (failure) rejectExit(failure);
		else resolveExit();
	});
	lines.on('line', (line) => {
		try {
			const value: unknown = JSON.parse(line);
			if (!isRecord(value) || typeof value.id !== 'number')
				throw new Error('Invalid helper response');
			const item = pending.get(value.id);
			if (!item) throw new Error(`Unexpected response ID: ${value.id}`);
			if (typeof value.error === 'string') {
				pending.delete(value.id);
				clearTimeout(item.timer);
				item.reject(new Error(value.error));
				return;
			}
			const response = responseOf(value);
			pending.delete(value.id);
			clearTimeout(item.timer);
			item.resolve(response);
		} catch (error) {
			fail(error instanceof Error ? error : new Error(String(error)));
			child.kill();
		}
	});

	function request(payload: Request): Promise<Response> {
		if (failure) return Promise.reject(failure);
		if (closing) return Promise.reject(new Error('TypeScript bridge is closed'));
		return new Promise((resolve, reject) => {
			const id = nextId++;
			const timer = setTimeout(() => {
				fail(new Error(`TypeScript request timed out: ${payload.method}`));
				child.kill();
			}, timeoutMs);
			pending.set(id, { resolve, reject, timer });
			child.stdin.write(`${JSON.stringify({ id, ...payload })}\n`, (error) => {
				if (error) fail(error);
			});
		});
	}

	return {
		async transpile(source, fileName) {
			const { outputText, diagnostics } = await request({ method: 'transpile', source, fileName });
			return { outputText, diagnostics };
		},
		async checkProject(configPath, overrides = {}) {
			const { files, compilerOptions } = overrides;
			return (await request({ method: 'checkProject', configPath, files, compilerOptions }))
				.diagnostics;
		},
		async exportedCodeUnions(configPath, entrypoints) {
			return (await request({ method: 'exportedCodeUnions', configPath, entrypoints })).unions;
		},
		close() {
			if (!closing) {
				closing = true;
				child.stdin.end();
			}
			return exited;
		},
	};
}
