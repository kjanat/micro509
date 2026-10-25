# Argon2 adapter evidence

`micro509/kdf` exposes raw byte derivation with an explicit backend boundary.
Its bundled implementation is a native WebCrypto adapter for Argon2d and
Argon2id version `0x13`. A portable implementation and a version `0x10`
implementation are separate work. This is not a KDBX parser or an Argon2
PKCS#8/PFX encoding.

## Governing inputs and scope

Research on 25 October 2026 used `bun spec list`, `status`, `census`, `headings`,
and `read`. Census expressions were `Argon2`, `memory-hard`, and
`password-based key derivation`. The expanded corpus contained 165 documents.
RFC 9106 was fetched through `bun spec fetch rfc 9106`.

- **Governing:** RFC 9106 §3.1 (`docs/rfc/rfc9106.txt`, lines 189–226) defines
  parameter ranges and units. The adapter passes the specified memory value
  exactly. Rounding memory before passing it would change the initial hash.
  §4 lines 578–619 gives parameter-selection guidance. Salt minimum eight bytes
  is a native implementation boundary, not a universal RFC 9106 requirement.
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
  These are raw KDF fixtures, not full KDBX files. `0x10` refusal is covered
  separately.

The optional-backend contract is also exercised for snapshot ownership,
temporary-array wiping, worker transfer of input buffers, genuine runtime failure, exact limit boundaries,
malformed numeric values, and memory values that are not multiples of `4*p`.

## Sample performance

Commands, each in a separate process after `bun run build`:

```sh
node scripts/benchmark-argon2.mjs native 1
node scripts/benchmark-argon2.mjs native 4
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
measurement. Both routes may use the same native crypto implementation, so
this comparison measures adapter overhead and scheduling. It does not compare
native Argon2 against a portable JavaScript/WASM implementation. The timer
probe confirms that this sample allowed event-loop progress during native work.
