# Experimental TypeScript compiler in WebAssembly

This is the runnable WASM proof for [`@kjanat/tsc-bridge`](../bridge/README.md).
It runs the same pinned compiler inside Node or Bun through Go's `js/wasm` target.
The compiler calls execute in-process. The test also starts the native bridge to
compare its exported code unions with the WASM results.

Requires Go 1.27+ and Node 26. From the repository root:

```sh
bun run --filter '@kjanat/tsc-*' build
bun run --filter '@kjanat/tsc-*' test
```

After building, the WASM probe also runs directly in Bun:

```sh
bun tsc/wasm/probe.mjs
```

The build produces `bin/tsc-bridge.wasm` and the matching `bin/wasm_exec.js`.
Both are available locally and ignored by Git. All paths are derived from the
scripts' locations; no `/tmp` files or machine-specific paths are needed.
`build.mjs` resolves the `@kjanat/tsc-bridge` workspace dependency and generates
its Go build inputs under `bin/build/` from that package's `main.go`, `go.mod`,
and `go.sum`, replacing only the CLI entrypoint with [`main.go`](./main.go).
Compiler logic and dependency pins stay in `../bridge`.

The probe checks:

- Emitted JavaScript executes correctly, and invalid syntax produces diagnostics.
- The repository's `tsconfig.src.json` checks without diagnostics.
- Root-exported error and reason code unions exactly match the native bridge.
- The runtime shuts down and its remaining JS timers are disposed.

It reports module size, gzip size, timings, diagnostic and union counts, and
linear memory size. The initial standard-Go build was about 32 MiB, or 7.5 MiB
gzipped; timings and memory are measurements of the current run.

This is a Node/Bun proof, with filesystem access supplied by `node:fs`.
`main.go` exposes Promise-returning JSON calls through `tscProbeInvoke` and a
shutdown callback through `tscProbeClose`. The wrapper owns global runtime state
and handles one instance. A browser adaptation needs a virtual filesystem and
should put the compiler in a Worker. Runtime cleanup currently uses the matching
Go glue's internal timeout map, so it must be rechecked on Go upgrades.

TinyGo 0.42.0 failed to compile the pinned native bridge with
`panic: unknown type: T`; this build uses standard Go. Newer TinyGo versions have
not been tested.
