# Experimental TypeScript Go bridge

A persistent Go helper with a dependency-free JS-facing client, authored in
TypeScript. Node 26 and Bun can import the client directly.

The helper imports TypeScript's compiler, checker, and transpiler directly. Its
module path, `github.com/microsoft/TypeScript/tsc/bridge`, satisfies Go's `internal`
import rule. The upstream module is a normal dependency; no fork or source patches
are used. Request handling lives in the `protocol` package, which the native
helper and [`../wasm`](../wasm/README.md) both import.

Pinned upstream commit: `299a555c3a91519552b471c5b8ce3eb4247ab044`.
This is an upstream development snapshot, not the installed npm TypeScript 7.0.2.
The Go API is internal and may change when this pin is updated.

## Build and test

Requires Go 1.27 or newer. From this directory:

```sh
go build -p 2 -trimpath -o bin/tsc-bridge .
go test -race -count=1 ./...
node --test test/smoke.mts test/cache.mts
```

The executable is ignored by Git. On Windows, use `bin/tsc-bridge.exe`.

## Use from the repository root

```ts
import { createTscBridge } from '@kjanat/tsc-bridge';

const compiler = createTscBridge();
try {
  const emitted = await compiler.transpile('export const answer: number = 42;');
  console.log(emitted.outputText);

  const diagnostics = await compiler.checkProject('tsconfig.src.json');
  console.log(diagnostics);

  const unions = await compiler.exportedCodeUnions('tsconfig.src.json', ['src/index.ts']);
  console.log(unions);
} finally {
  await compiler.close();
}
```

- `transpile(source, fileName?)` emits ESNext modules and reports syntax and option
  diagnostics. It does not perform semantic type checking.
- `checkProject(configPath, { files, compilerOptions }?)` returns configuration,
  syntax, global, and semantic diagnostics for one project. It reads the project's
  compiler options and embeds the matching upstream standard libraries. It never
  emits project files and does not recursively build project references. `files`
  replaces the project's root files and `compilerOptions` is layered over the
  project's own, as a tsconfig that extends `configPath` would; both resolve
  relative to the configuration file.
- `exportedCodeUnions(configPath, entrypoints)` evaluates exported types whose names
  end in `ErrorCode` or `ReasonCode`, following re-exports and collecting their string
  literal members. Results are sorted and duplicate exports are deduplicated;
  conflicting same-name unions are rejected. This is tailored to micro509's error
  reference check rather than a general type-graph API.

Paths resolve against the helper's `cwd` (the caller's working directory by
default); entrypoints resolve relative to the configuration file. Each project
request rereads the configuration and every source file. The helper keeps each
project's parsed files and per-file semantic diagnostics, and reuses them for
files whose text is unchanged and whose dependencies are unaffected, as
`tsc --watch` does. Requests share one process and execute sequentially.
Diagnostics use zero-based UTF-8 byte offsets, not JavaScript string offsets.
`message` holds a diagnostic's own text and `messageText` the text with its
chained messages, indented as TypeScript prints them.

`createTscBridge({ executable, cwd, timeoutMs })` can override the binary, working
directory, and per-request timeout (60 seconds by default). Always await `close()`
to finish pending work and reap the process. Compiler diagnostics are returned as
data; request, transport, and process failures reject the promise.

The transport is newline-delimited JSON over stdin/stdout. For a direct smoke test:

```sh
printf '%s\n' '{"id":1,"method":"transpile","source":"export const x: number = 1;"}' |
  ./bin/tsc-bridge
```

`transpileSync(source, { fileName, executable, cwd, timeoutMs }?)` provides the
same transpilation result for synchronous consumers such as Markdown renderers.
It starts and reaps one helper per call; repeated snippets should be cached by
the caller. Its timeout defaults to 60 seconds and output is limited to 16 MiB.
`checkProjectSync(configPath, { files, compilerOptions, executable, cwd, timeoutMs }?)`
does the same for `checkProject`.
