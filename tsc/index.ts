import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';

export interface Diagnostic {
	readonly code: number;
	readonly category: number;
	readonly message: string;
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

export interface TscBridge {
	transpile(source: string, fileName?: string): Promise<TranspileResult>;
	checkProject(configPath: string): Promise<readonly Diagnostic[]>;
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
	| { readonly method: 'checkProject'; readonly configPath: string }
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

/** Starts one persistent helper process. Paths passed to it resolve against cwd. */
export function createTscBridge(
	options: {
		readonly executable?: string;
		readonly cwd?: string;
		readonly timeoutMs?: number;
	} = {},
): TscBridge {
	const timeoutMs = options.timeoutMs ?? 60_000;
	if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error('timeoutMs must be positive');
	const executable =
		options.executable ??
		fileURLToPath(
			new URL(
				process.platform === 'win32' ? './bin/tsc-bridge.exe' : './bin/tsc-bridge',
				import.meta.url,
			),
		);
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
			pending.delete(value.id);
			clearTimeout(item.timer);
			item.resolve({ outputText, diagnostics, unions });
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
		async checkProject(configPath) {
			return (await request({ method: 'checkProject', configPath })).diagnostics;
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
