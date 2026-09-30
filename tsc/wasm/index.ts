import type { ChildProcess } from 'node:child_process';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { readFile } from 'node:fs/promises';
import type { BridgeRequest, BridgeResponse, TscBridge } from '@kjanat/tsc-protocol';
import { clientFor, readResponse } from '@kjanat/tsc-protocol';

export type {
	CodeUnion,
	Diagnostic,
	ProjectOverrides,
	TranspileResult,
	TscBridge,
} from '@kjanat/tsc-protocol';

interface GoRuntime {
	env: Record<string, string>;
	readonly importObject: WebAssembly.Imports;
	run(instance: WebAssembly.Instance): Promise<void>;
	readonly _scheduledTimeouts: Map<number, ReturnType<typeof setTimeout>>;
}

interface HostProcess {
	write(chunk: Uint8Array): void;
	close(): void;
}

type Spawn = (
	command: readonly string[],
	cwd: string,
	onStdout: (chunk: Uint8Array) => void,
	onStderr: (chunk: Uint8Array) => void,
	onClose: (code: number | null, error?: string) => void,
) => HostProcess;

interface Exported {
	invoke(input: string): Promise<string>;
	close(): void;
}

export interface WasmBridgeOptions {
	/** The compiled bridge. Defaults to `bin/tsc-bridge.wasm`, which `build.ts` writes. */
	readonly wasm?: string | URL;
}

let instances = 0;

function isGoConstructor(value: unknown): value is new () => GoRuntime {
	return typeof value === 'function';
}

function isExported(value: unknown): value is Exported {
	return (
		typeof value === 'object' &&
		value !== null &&
		typeof Reflect.get(value, 'invoke') === 'function' &&
		typeof Reflect.get(value, 'close') === 'function'
	);
}

async function goRuntime(): Promise<new () => GoRuntime> {
	if (Reflect.get(globalThis, 'fs') === undefined) Reflect.set(globalThis, 'fs', fs);
	await import(new URL('./bin/wasm_exec.js', import.meta.url).href);
	const Go: unknown = Reflect.get(globalThis, 'Go');
	if (!isGoConstructor(Go)) throw new Error('wasm_exec.js did not define Go');
	return Go;
}

/**
 * Starts the compiler in this process. Paths resolve against the process's working
 * directory, and requests run concurrently.
 */
export async function createWasmBridge(options: WasmBridgeOptions = {}): Promise<TscBridge> {
	const Go = await goRuntime();
	const bytes = await readFile(options.wasm ?? new URL('./bin/tsc-bridge.wasm', import.meta.url));
	const go = new Go();
	const name = `tscWasm${++instances}`;
	go.env = { ...go.env, TSC_WASM_GLOBAL: name };
	const children = new Set<ChildProcess>();
	let stopped = false;
	const host: Spawn = (command, cwd, onStdout, onStderr, onClose) => {
		const [file = '', ...args] = command;
		const child = spawn(file, args, { cwd, stdio: ['pipe', 'pipe', 'pipe'] });
		children.add(child);
		let failure: string | undefined;
		child.stdout.on('data', (chunk: Buffer) => {
			if (!stopped) onStdout(chunk);
		});
		child.stderr.on('data', (chunk: Buffer) => {
			if (!stopped) onStderr(chunk);
		});
		child.stdin.on('error', () => {});
		child.on('error', (error) => {
			failure = error.message;
		});
		child.on('close', (code) => {
			children.delete(child);
			if (!stopped) onClose(code, failure);
		});
		return {
			write(chunk) {
				child.stdin.write(chunk);
			},
			close() {
				child.stdin.end();
				child.kill();
			},
		};
	};
	Reflect.set(globalThis, name, { spawn: host });
	const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
	const running = go.run(instance);
	const api: unknown = Reflect.get(globalThis, name);
	if (!isExported(api)) throw new Error('The WASM bridge did not start');

	const pending = new Set<Promise<string>>();
	let nextId = 1;
	let closed: Promise<void> | undefined;

	async function request(payload: BridgeRequest): Promise<BridgeResponse> {
		if (closed !== undefined || !isExported(api)) throw new Error('TypeScript bridge is closed');
		const id = nextId++;
		const call = api.invoke(JSON.stringify({ id, ...payload }));
		pending.add(call);
		try {
			const text = await call.catch((error: unknown) => {
				throw error instanceof Error ? error : new Error(String(error));
			});
			return readResponse(text, id);
		} finally {
			pending.delete(call);
		}
	}

	return clientFor(request, () => {
		closed ??= (async () => {
			await Promise.allSettled(pending);
			stopped = true;
			for (const child of children) child.kill();
			api.close();
			await running;
			for (const timer of go._scheduledTimeouts.values()) clearTimeout(timer);
			go._scheduledTimeouts.clear();
		})();
		return closed;
	});
}
