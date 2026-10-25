# Argon2 derivation evidence

`micro509/kdf` provides raw byte derivation with resource limits and a native-first
portable default. It tries native WebCrypto and, only on `unsupported`, uses its
bundled WASM reference implementation for the exact requested variant and version.
Argon2d and Argon2id versions `0x10` and `0x13` are supported. The WASM asset is
included in the package. No runtime dependency or backend callback is required.

`backend: 'native'` and `backend: 'portable'` select one implementation explicitly;
callbacks remain supported. Explicit backends never trigger fallback. Native
`derivation_failed`, invalid parameters, and resource-limit rejections remain
failures. This is not a KDBX parser or an Argon2 PKCS#8/PFX encoding.

## Portable implementation and packaging

The source and build instructions are in `vendor/argon2/README.md`.
The pinned reference C implementation is compiled with Emscripten 5.0.2 under its
CC0 license option. Its 17,352-byte WASM artifact supports both versions, secret
inputs and associated data. It uses the unmodified scalar reference algorithm,
without threads, SIMD, shared memory, Node APIs, filesystem access or network I/O.

The WASM binary ships as a separate asset and is loaded lazily. The `workerd` package export
uses a static WASM import for deployment-time compilation; consumers keep using
`micro509/kdf`. Certificate-only entrypoints do not import or initialize either
implementation. The workspace's `@micro509/tsdown-plugin-argon2` plugin builds
and packages the binary during `bun build`. Content hashes track C sources,
headers, the build recipe and generated files. Recompilation uses Emscripten
5.0.2; current artifacts are reused directly. `bun build:watch` tracks C changes.
`bun build:argon2` builds the artifacts independently; `--force` recompiles them
and `--check` verifies reproducibility.

Each call owns a separate instance and linear memory. The requested memory cost
is included unchanged in the initial hash; internal segment sizing follows the
reference algorithm. Parallelism specifies lanes, which the portable backend
executes serially. It yields between segments after an 8 ms time budget or four
segments, whichever comes first. Initialization, one segment, finalization and
memory wiping run synchronously; this is cooperative scheduling, not background
execution or a hard latency guarantee. Cancellation is not currently exposed.

The output is copied out and the entire linear memory is erased in `finally`,
including partial state on failure. Up to four wiped memories are weakly referenced
for reuse; they remain eligible for garbage collection. JS cannot force release
of a WASM allocation. Per-call limits still require application-level concurrency
limits. Total memory, input, output and overhead must fit below 2 GiB; larger
portable requests return `unsupported` before allocation. Both built-in backends
require at least eight salt bytes. Environments that disable WebAssembly cannot
use the portable backend, and browser CSP must allow WASM compilation.

The shared built-artifact smoke checks require successful derivation with both
automatic selection and explicit portable selection, including the RFC 9106
vectors and all four independent variant/version vectors. Verified locally on
Node 26.12.0, Bun 1.4.4, Deno 2.9.6, Chromium 156.0.8078.4, and workerd.

## Governing inputs and scope

Research on 25 October 2026 used `bun spec list`, `status`, `census`, `headings`,
and `read`. Census expressions were `Argon2`, `memory-hard`, and
`password-based key derivation`. The expanded corpus contained 165 documents.
RFC 9106 was fetched through `bun spec fetch rfc 9106`.

- **Governing:** RFC 9106 §3.1 (`docs/rfc/rfc9106.txt`, lines 189–226) defines
  parameter ranges and units. The adapter passes the specified memory value
  exactly. Rounding memory before passing it would change the initial hash.
  §4 lines 578–619 gives parameter-selection guidance. Salt minimum eight bytes
  is a bundled implementation boundary, not a universal RFC 9106 requirement.
- **Governing:** RFC 9106 §§5.1 and 5.3 (lines 625–689 and 753–803) supply the
  Argon2d/id vectors with secret and associated data. Both are exercised by the
  shared runtime smoke suite and the real optional backend in `test/kdf.test.ts`.
- **Governing for the native adapter:** Node's
  [Argon2Params documentation](https://nodejs.org/api/webcrypto.html#class-argon2params)
  specifies native field names and version `0x13`. Actual Node 26.12.0 and
  the project-installed Deno 2.9.6 produce the RFC vectors. A separate direct
  probe with system Deno 2.9.8 also matched. Bun 1.4.3 exposes Argon2 through its
  Node-compatible crypto module but not through WebCrypto.
- **Format boundary:** the [KDBX format](https://keepass.info/help/kb/kdbx.html)
  permits `0x10` and `0x13`, records memory in bytes, and requires at least an
  eight-byte salt. Callers convert units and prepare the composite key.
- **Analogous:** RFC 9580 §3.7.1.4 describes the OpenPGP Argon2id profile.
  Its fixed profile values do not govern this raw KDF interface.
- **Outside this change:** RFC 8018 §6.2 specifies PBKDF2 for its PBES2 profile.
  RFC 9879 updates PKCS#12 password handling. These do not establish an Argon2
  container encoding. PKITS and X.509 certificate path rules do not govern raw
  Argon2 derivation.

The live RFC status observation reported no updates or obsoletions for RFC
9106. Verified editorial erratum 7721 concerns §3.2, outside this adapter's
parameter-mapping implementation. RFC 8018's updates 9579 and 9879 were inspected
for the container boundary. RFC 9580's reported updates and errata do not alter
the raw RFC 9106 interface.

## Independent inputs

`test/kdf.test.ts` uses a real `node:crypto.argon2` backend under Bun rather
than replacing global crypto. It compares outputs with:

- RFC 9106's Argon2d/id vectors, including secret and associated data.
- The Bitwarden SDK vector already exercised by the separate Vaultwarden
  client: UTF-8 `67t9b5g67$%Dh89n`, SHA-256 of `test_key` as salt, 32 MiB,
  four passes, two lanes, and 32 output bytes. The expected hex output is
  `cff0e1b1a213a34c626ab3afe00911f01493ed2ff6968db83ee183f23335e1f2`.
- Independently generated raw KDBX-style key material using
  `@noble/hashes` 2.4.0: password bytes `0..31`, salt bytes `255..224`,
  1 MiB, three passes, two lanes, and 32 output bytes, for both variants.
  These are raw KDF fixtures, not full KDBX files. Both `0x10` and `0x13`
  are additionally checked against the independent libargon2 vectors from issue #203.
  Native-only `0x10` refusal remains covered separately.

The optional-backend contract is also exercised for snapshot ownership,
temporary-array wiping, worker transfer of input buffers, genuine runtime failure, exact limit boundaries,
malformed numeric values, and memory values that are not multiples of `4*p`.

## Native baseline performance

Commands, each in a separate process after `bun run build`:

```sh
node scripts/benchmark-argon2.mjs native 1
node scripts/benchmark-argon2.mjs native 4
node scripts/benchmark-argon2.mjs portable 1
node scripts/benchmark-argon2.mjs portable 4
node scripts/benchmark-argon2.mjs node 1
node scripts/benchmark-argon2.mjs node 4
```

Sample on Linux x86-64, Node 26.12.0, 25 October 2026. Each process performed
three batches using 64 MiB, three passes, four lanes, and a 32-byte output.
Other development work was active, so these are reproducibility examples,
not a performance guarantee.

| Route                     | Concurrent calls | Median call (ms) | Process peak RSS (MiB) | Largest 5 ms timer delay (ms) |
| ------------------------- | ---------------: | ---------------: | ---------------------: | ----------------------------: |
| micro509 native WebCrypto |                1 |             82.2 |                  118.4 |                           6.3 |
| micro509 native WebCrypto |                4 |            140.7 |                  311.4 |                           5.9 |
| direct `node:crypto`      |                1 |             78.0 |                  116.8 |                           0.5 |
| direct `node:crypto`      |                4 |            148.0 |                  308.4 |                           1.4 |

RSS is the whole-process high-water mark reported by `resourceUsage`, including
roughly 51–52 MiB baseline runtime memory. It is not an isolated allocation
measurement. Both native routes may use the same native crypto implementation, so
this comparison measures adapter overhead and scheduling. It does not compare
native Argon2 against a portable JavaScript/WASM implementation. The timer
probe confirms that this sample allowed event-loop progress during native work.

## Portable performance sample

The same benchmark with the bundled portable backend on Node 26.12.0,
25 October 2026, using 64 MiB, three passes, four lanes and three batches:

| Concurrent calls | Median call (ms) | Process peak RSS (MiB) | Largest 5 ms timer delay (ms) |
| ---------------: | ---------------: | ---------------------: | ----------------------------: |
|                1 |            194.8 |                  126.9 |                          25.5 |
|                4 |            893.4 |                  325.0 |                         115.2 |

Baseline process RSS was about 52 MiB. Other checks were active, so these numbers
are observations, not a throughput or latency guarantee. The portable backend
executes on the caller's thread and cooperatively yields; concurrent derivations
interleave rather than run their lanes on separate CPU threads. Applications with
strict UI latency requirements can run derivation in their own worker. Native
WebCrypto remains the preferred default when available.
