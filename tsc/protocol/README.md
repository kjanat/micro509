# TypeScript compiler bridge protocol

The request/response contract shared by the native bridge
([`@kjanat/tsc-bridge`](../bridge/README.md)) and the WebAssembly bridge
([`@kjanat/tsc-wasm`](../wasm/README.md)). Both halves of the contract live here:

- **Go**, module `github.com/microsoft/TypeScript/tsc/protocol`: `Request`,
  `Response` and `Handle`, which answers a request with the pinned compiler and
  keeps each project's parsed files and per-file diagnostics between requests.
- **TypeScript**, package `@kjanat/tsc-protocol`: the matching wire types, the
  `TscBridge` interface, `decodeResponse` and `readResponse` to validate
  serialized responses, and `clientFor(request, close)`, which builds a
  `TscBridge` over any transport.

Each transport supplies only its own entry point and delivery: stdin/stdout for
the native helper, a JS global for WebAssembly.

The Go package imports TypeScript's compiler, checker, and transpiler directly.
Its module path sits under `github.com/microsoft/TypeScript/tsc`, which satisfies
Go's `internal` import rule. The upstream module is a normal dependency; no fork
or source patches are used.

Pinned upstream commit: `299a555c3a91519552b471c5b8ce3eb4247ab044`.
This is an upstream development snapshot, not the installed npm TypeScript 7.0.2.
The Go API is internal and may change when this pin is updated.

## Test

Requires Go 1.27 or newer. From this directory:

```sh
go test -race -count=1 ./...
```

The race test sends concurrent project requests through `Handle` and requires
each result to match the sequential one.
