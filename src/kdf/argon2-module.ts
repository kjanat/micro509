// Share compiled code only; each call gets private linear memory and state.
let compiled: WebAssembly.Module | undefined;

export async function moduleFor(): Promise<WebAssembly.Module> {
	// Cache successful compilation only. Failed compilation can be retried;
	// concurrent first calls may compile the same small, immutable module.
	compiled ??= await compileModule(new URL('./argon2.wasm', import.meta.url));
	return compiled;
}

/** Load a packaged WASM asset from a filesystem or HTTP module URL. */
export async function compileModule(url: URL): Promise<WebAssembly.Module> {
	let bytes: Uint8Array<ArrayBuffer>;
	if (url.protocol === 'file:') {
		const { readFile } = await import('node:fs/promises');
		bytes = new Uint8Array(await readFile(url));
	} else {
		const response = await fetch(url);
		if (!response.ok) throw new Error('Could not load the Argon2 WASM asset');
		bytes = new Uint8Array(await response.arrayBuffer());
	}
	return WebAssembly.compile(bytes);
}
