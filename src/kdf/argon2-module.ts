import { base64Decode } from '#micro509/internal/shared/base64';
import { wasmBase64 } from '#micro509/kdf/argon2-wasm';

// Share compiled code only; each call gets private linear memory and state.
let compiled: WebAssembly.Module | undefined;

export async function moduleFor(): Promise<WebAssembly.Module> {
	// Cache successful compilation only. Failed compilation can be retried;
	// concurrent first calls may compile the same small, immutable module.
	compiled ??= await WebAssembly.compile(new Uint8Array(base64Decode(wasmBase64)));
	return compiled;
}
