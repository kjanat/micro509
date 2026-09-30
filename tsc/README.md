# TypeScript compiler bridges

Workspace packages that give micro509's tooling access to TypeScript's native compiler. The compiler is the Go code in [microsoft/TypeScript] under `tsc/`, pinned to commit [`299a555c3a91519552b471c5b8ce3eb4247ab044`]. That is an upstream development snapshot, not the TypeScript 7.0.2 release on npm, and its Go API is internal.

[microsoft/TypeScript]: https://github.com/microsoft/TypeScript
[`299a555c3a91519552b471c5b8ce3eb4247ab044`]: https://github.com/microsoft/TypeScript/commit/299a555c3a91519552b471c5b8ce3eb4247ab044 'Fix flaky diagnostic added by declaration emit for untyped module imports (#64479)'

| Package                    | Directory       | Contents                                                                         |
| -------------------------- | --------------- | -------------------------------------------------------------------------------- |
| [`@kjanat/tsc-protocol`]   | [`protocol/`]   | Request and response contract, and the Go request handler both transports share. |
| [`@kjanat/tsc-bridge`]     | [`bridge/`]     | Native helper process with async and synchronous clients.                        |
| [`@kjanat/tsc-wasm`]       | [`wasm/`]       | The same compiler compiled to WebAssembly, running inside Node or Bun.           |
| [`@kjanat/tsc-vue-mapper`] | [`vue-mapper/`] | Content mapper that lets the compiler type-check Vue single-file components.     |

[`@kjanat/tsc-protocol`]: ./protocol/README.md
[`@kjanat/tsc-bridge`]: ./bridge/README.md
[`@kjanat/tsc-wasm`]: ./wasm/README.md
[`@kjanat/tsc-vue-mapper`]: ./vue-mapper/README.md
[`protocol/`]: ./protocol/
[`bridge/`]: ./bridge/
[`wasm/`]: ./wasm/
[`vue-mapper/`]: ./vue-mapper/

## How they fit together

[`protocol`][protocol] holds the Go module [`github.com/microsoft/TypeScript/tsc/protocol`][tsc/protocol] and the package [`@kjanat/tsc-protocol`]. Its module path sits under the upstream module, which lets it import the compiler's `internal` packages. `bridge` and `wasm` are separate Go modules that replace the protocol module with `../protocol` and add only a transport: stdin and stdout for the native helper, a JavaScript global for WebAssembly. Both return the same `TscBridge` interface. The repository's [`go.work`][go.work] lists the three modules for editors and root-level `go` commands.

Every transport answers three requests:

- `transpile` emits JavaScript for one source text.
- `checkProject` returns a project's diagnostics and keeps parsed files between requests.
- `exportedCodeUnions` collects the string members of exported `*ErrorCode` and `*ReasonCode` types.

[protocol]: ./protocol/README.md
[tsc/protocol]: ./protocol/go.mod
[go.work]: ../go.work

## Content mappers and Vue

A `checkProject` request with `runExternalCode` starts the content mappers a tsconfig declares under `contentMappers`, the way `tsc --runExternalCode` does. The native helper starts them as processes. The WebAssembly bridge imports a mapper's `tscBridge.module` into its own runtime and falls back to a child process for mappers without one. `vue-mapper` is such a mapper. It also sets `tscBridge.verify`, which lets the bridge place each diagnostic in a `.vue` file the way vue-tsc does. [`protocol/README.md`][protocol] describes that request.

The site's type check, [`site/.vitepress/typecheck.ts`][.vitepress/typecheck], runs through this path and checks the theme's components.

To get the same `.vue` resolution in Zed with the [`typescript`][kjanat/zed-typescript] extension, start the pinned compiler as the language server and let it run external code:

[.vitepress/typecheck]: ../site/.vitepress/typecheck.ts
[kjanat/zed-typescript]: https://github.com/kjanat/zed-typescript

```jsonc
{
  "lsp": {
    "typescript": {
      "binary": {
        "path": "go",
        "arguments": [
          "-C",
          "tsc/bridge",
          "run",
          "github.com/microsoft/TypeScript/tsc/cmd/tsc",
          "--lsp",
          "--stdio",
        ],
      },
      "initialization_options": {
        "runExternalCode": true,
      },
    },
  },
}
```

Inside `.vue` files the editor uses upstream's placement rules alone, because the verifier is a bridge feature.

## Users in this repository

- [`site/.vitepress/typecheck.ts`][.vitepress/typecheck] checks the site with `checkProjectSync` and `runExternalCode`.
- [`site/.vitepress/live-code.ts`][.vitepress/live-code] transpiles runnable examples with `transpileSync`.
- [`packages/vitepress-doc-examples`][package/vitepress-doc-examples] type-checks the documentation's examples with `checkProjectSync`.
- [`test/readme-examples.test.ts`][test/readme-examples] and [`test/error-codes-docs.test.ts`][test/error-codes-docs] use `createTscBridge`.

[.vitepress/live-code]: ../site/.vitepress/live-code.ts
[package/vitepress-doc-examples]: ../packages/vitepress-doc-examples/src/index.ts
[test/readme-examples]: ../test/readme-examples.test.ts
[test/error-codes-docs]: ../test/error-codes-docs.test.ts

## Build and test

Requires Go 1.27 or newer and Bun 1.4.2 or newer. `bun install` builds the native helper and the
WebAssembly module through the root `prepare` script. From the repository root:

```sh
run -s @kjanat/tsc-bridge:build @kjanat/tsc-wasm:build
run -s @kjanat/tsc-protocol:test @kjanat/tsc-bridge:test @kjanat/tsc-wasm:test @kjanat/tsc-vue-mapper:test
```

CI runs the same tests in the "TypeScript compiler bridges" job of [`.github/workflows/test.yml`][wf/test].

[wf/test]: ../.github/workflows/test.yml
