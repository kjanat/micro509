# Argon2 derivation

`micro509/kdf` derives raw bytes with Argon2d, Argon2i, or Argon2id, versions
`0x10` and `0x13`. The implementation is TypeScript and works in Node.js, Bun,
Deno, browsers, and Cloudflare Workers. It has no WASM binary, native addon, or
runtime dependency.

The default backend tries native WebCrypto for version `0x13`. When WebCrypto
reports that the requested operation is unsupported, the TypeScript core derives
the exact requested variant, version, and parameters. Other native failures are
returned without retrying. `backend: 'native'` and `backend: 'portable'` select
one backend explicitly; callbacks remain supported. The portable backend uses
the same Argon2 algorithm in every runtime.

The TypeScript core implements BLAKE2b, H′, data dependent and data independent
address generation, reference block indexing, BlaMka compression, and Argon2's
memory filling and finalization. It follows RFC 9106 §3 and the version 1.2
compatibility behavior used by Argon2 version `0x10`. The memory matrix is held
in a private `Uint32Array`; its full contents and temporary input blocks are
cleared after success or failure. Owned password, salt, secret, and associated
data copies are cleared by the public wrapper. As with other JavaScript memory,
the runtime may retain inaccessible copies until garbage collection.

The implementation processes lanes serially and yields to the event loop while
filling memory. Parallelism still determines the number of Argon2 lanes and is
included unchanged in the derivation. This scheduling does not move the work to
another thread or provide cancellation. Resource ceilings apply per call, so
applications must also limit concurrent derivations. Requests above the
TypeScript backend's 2 GiB address limit return `unsupported` before allocation.

## Reference oracle

The C/WASM test oracle lives in `test/oracles/argon2`, with
its pinned C sources under `vendor/argon2` and its compiler plugin in
`packages/tsdown-plugin-argon2`. Run `bun build:argon2` to rebuild stale artifacts,
`bun build:argon2 --check` to check reproducibility, and `bun test:argon2:oracle`
to compare the TypeScript port against the oracle. This suite covers all three
variants and both versions, minimum and unaligned memory sizes, repeated passes,
multiple lanes, address-block rollover, long inputs and outputs, optional secret
and associated data, and the 64 MiB recommended profile.

## Evidence

The governing specification is [RFC 9106](rfc/rfc9106.txt). Tests compare the
implementation with all three RFC 9106 vectors, independent libargon2 vectors
for versions `0x10` and `0x13`, Node's independent `node:crypto.argon2`
implementation, and the Bitwarden SDK vector. The tests cover secret and
associated data, output lengths above 64 bytes, unaligned memory parameters,
input snapshots, resource limits, cooperative scheduling, and temporary-buffer
cleanup.

RFC 9106 recommends Argon2id for general password-based applications. Its
second recommended profile uses 64 MiB, three passes, four lanes, a 16-byte salt,
and a 32-byte output. Use Argon2d or Argon2i when an existing format requires
that exact variant. `memoryKiB` is passed unchanged into Argon2's initial hash;
the implementation rounds only its internal block allocation as required by
the algorithm.
