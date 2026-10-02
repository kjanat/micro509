# TypeScript compiler bridges

Workspace packages that give micro509's tooling access to TypeScript's native compiler. The compiler is the Go code in [microsoft/TypeScript] under `tsc/`, pinned to commit [`9adc871ff47f79b3e99ff2b1cbe9efb140d76af8`]. npm publishes that commit as the nightly `typescript@7.1.0-dev.20260930.4`. Its Go API is internal.

[microsoft/TypeScript]: https://github.com/microsoft/TypeScript
[`9adc871ff47f79b3e99ff2b1cbe9efb140d76af8`]: https://github.com/microsoft/TypeScript/commit/9adc871ff47f79b3e99ff2b1cbe9efb140d76af8 "Update Azure pipeline Node installation task (#64547)"

| Package                    | Directory       | Contents                                                                         |
| -------------------------- | --------------- | -------------------------------------------------------------------------------- |
| [`@kjanat/tsc-protocol`]   | [`protocol/`]   | Request and response contract, and the Go request handler both transports share. |
| [`@kjanat/tsc-bridge`]     | [`bridge/`]     | Native helper process with async and synchronous clients.                        |
| [`@kjanat/tsc-wasm`]       | [`wasm/`]       | The same compiler compiled to WebAssembly, running inside Node or Bun.           |
| [`@kjanat/tsc-compat`]     | [`compat/`]     | The compiler's parser behind the synchronous TypeScript 6 API Vue tooling calls. |
| [`@kjanat/tsc-vue-mapper`] | [`vue-mapper/`] | Content mapper that lets the compiler type-check Vue single-file components.     |

[`@kjanat/tsc-protocol`]: ./protocol/README.md
[`@kjanat/tsc-bridge`]: ./bridge/README.md
[`@kjanat/tsc-wasm`]: ./wasm/README.md
[`@kjanat/tsc-compat`]: ./compat/README.md
[`@kjanat/tsc-vue-mapper`]: ./vue-mapper/README.md
[`protocol/`]: ./protocol/
[`bridge/`]: ./bridge/
[`wasm/`]: ./wasm/
[`compat/`]: ./compat/
[`vue-mapper/`]: ./vue-mapper/

## How they fit together

[`protocol`][protocol] holds the Go module [`github.com/microsoft/TypeScript/tsc/protocol`][tsc/protocol] and the package [`@kjanat/tsc-protocol`]. Its module path sits under the upstream module, which lets it import the compiler's `internal` packages. `bridge` and `wasm` are separate Go modules that replace the protocol module with `../protocol` and add only a transport: stdin and stdout for the native helper, a JavaScript global for WebAssembly. Both return the same `TscBridge` interface. `compat` is a fourth Go module under the same path, with its own WebAssembly build. The repository's [`go.work`][go.work] lists the four modules for editors and root-level `go` commands.

Every transport answers three requests:

- `transpile` emits JavaScript for one source text.
- `checkProject` returns a project's diagnostics and keeps parsed files between requests.
- `exportedCodeUnions` collects the string members of exported `*ErrorCode` and `*ReasonCode` types.

[protocol]: ./protocol/README.md
[tsc/protocol]: ./protocol/go.mod
[go.work]: ../go.work

## Content mappers and Vue

A `checkProject` request with `runExternalCode` starts the content mappers a tsconfig declares under `contentMappers`, the way `tsc --runExternalCode` does. The native helper starts them as processes. The WebAssembly bridge imports a mapper's `tscBridge.module` into its own runtime and falls back to a child process for mappers without one. `vue-mapper` is such a mapper. It generates code with `@vue/language-core`, which parses `<script>` blocks through TypeScript 6's synchronous JavaScript API, and `compat` serves that API from the pinned compiler. It also sets `tscBridge.verify`, which lets the bridge place each diagnostic in a `.vue` file the way vue-tsc does. [`protocol/README.md`][protocol] describes that request.

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
					"--stdio"
				]
			},
			"initialization_options": {
				"runExternalCode": true
			}
		}
	}
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

Requires Go 1.27 or newer and Bun 1.4.2 or newer. Each package keeps its TypeScript in `src/` and
ships only the bundle in `dist/`, which runs on Node 24 and newer as well as Bun. The root
[`tsdown.config.ts`](../tsdown.config.ts) builds the packages as a `tsc/*` workspace next to
micro509, each package's own `tsdown.config.ts` names its entries, and tsdown writes the
`exports` and `bin` of every `package.json`. `build:tsc` builds the five packages alone.
`bun install` runs `build:tsc` and then builds the native
helper and both WebAssembly modules through the root `prepare` script. Each push to `master` or a pull request
publishes all five packages with their built binaries to [pkg.pr.new] through [`.github/workflows/pkg-pr-new.yml`][wf/pkg-pr-new].
Under Cloudflare Workers Builds, where `WORKERS_CI` is set, `prepare` skips the Go builds and
`@kjanat/tsc-bridge:fetch` downloads the native helper pkg.pr.new published for the commit, its
branch, or `master`, in that order. It reads the commit and branch from `WORKERS_CI_COMMIT_SHA` and
`WORKERS_CI_BRANCH`, and `--sha` and `--branch` override them for a local run. Only the protocol
and bridge packages are bundled there, since compat and wasm need the WebAssembly modules that Go
builds. The site build needs no Go. From the repository root:

[pkg.pr.new]: https://pkg.pr.new
[wf/pkg-pr-new]: ../.github/workflows/pkg-pr-new.yml

```sh
run -s @kjanat/tsc-bridge:build @kjanat/tsc-wasm:build @kjanat/tsc-compat:build
run -s @kjanat/tsc-protocol:test @kjanat/tsc-bridge:test @kjanat/tsc-wasm:test @kjanat/tsc-compat:test @kjanat/tsc-vue-mapper:test
```

CI runs the same tests in the "TypeScript compiler bridges" job of [`.github/workflows/test.yml`][wf/test].

[wf/test]: ../.github/workflows/test.yml
