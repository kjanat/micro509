# Portable Argon2 source

Unmodified reference implementation files from
[`P-H-C/phc-winner-argon2`](https://github.com/P-H-C/phc-winner-argon2/tree/f57e61e19229e23c4445b85494dbf7c07de721cb),
commit `f57e61e19229e23c4445b85494dbf7c07de721cb`.

The reference implementation is used under its **CC0-1.0** option. See `LICENSE`
and the attribution in each source file. `bridge.c` is micro509 code; it exposes
initialization, one reference memory segment, and finalization so JavaScript can
yield between segments. The reference algorithm files are not patched.

Build through the workspace:

```sh
bun build
bun build:watch
```

Build the Argon2 artifacts independently with `bun build:argon2`. Use
`bun build:argon2 --force` to recompile or `bun build:argon2 --check` to verify
reproducibility. The command runs the build script owned by the plugin workspace.

`@micro509/tsdown-plugin-argon2` owns compilation and packaging. It fingerprints
all C sources, headers, compiler settings and generated artifacts. Changes trigger
a rebuild with **Emscripten 5.0.2**. The fingerprint is stored in `build.json`;
current artifacts are reused without invoking the compiler.

The plugin generates `src/kdf/argon2.wasm` and emits the binary asset into each
package build. JavaScript loads that asset by URL; Workers use a static WASM
import. Watch mode tracks the C inputs.
The build uses the single-threaded reference implementation without SIMD, shared
memory, filesystem, network, or host crypto imports.

Each call gets a separate WASM instance and bounded linear memory. JavaScript
copies the output, then wipes the complete linear memory on success or failure.
The compiled module is cached. Up to four wiped memories are weakly referenced
for reuse, allowing garbage collection rather than retaining them permanently. Argon2's memory cost and lane count are
passed unchanged; lanes execute sequentially with the reference synchronization
order. Yielding occurs between segments, not inside a segment, and cancellation
is not currently exposed.

Verification uses RFC 9106 vectors, independent libargon2 version 0x10/0x13
vectors, the Bitwarden hashed-salt vector, differential checks against native
Argon2, and concurrent calls at 64 MiB. See `test/kdf.test.ts` and
`docs/ARGON2.md`. The compiled module is only reachable through `micro509/kdf`.
