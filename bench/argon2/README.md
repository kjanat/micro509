# Argon2 benchmarks

Compare the TypeScript implementation, reference WASM oracle, native
WebCrypto, and `node:crypto.argon2` under Node and Bun. Every result is checked
against `node:crypto.argon2Sync` outside the measured interval. Errors and
mismatched keys fail the command; unsupported backends are reported explicitly.

```sh
bun run build
bun run build:argon2
bun run bench:argon2 --output bench/argon2/results/node.json
bun bench/argon2/benchmark.ts --output bench/argon2/results/bun.json
```

Defaults match the guide: all three variants at version `0x13`, 64 MiB, three
passes, four lanes, and a 32-byte output. Each backend gets two warm-up batches
followed by five measured batches, with one derivation per batch. Backends and
runtimes should run sequentially to avoid competing for CPU and memory bandwidth.

For a focused iteration on the source:

```sh
bun run bench:argon2 --source --backend typescript --algorithm argon2id
```

All workload controls are explicit: `--memory-kib`, `--passes`, `--lanes`,
`--output-bytes`, `--warmups`, `--samples`, and `--concurrency`. Use `--help` for
their ranges. `--json` prints the complete report; `--output` saves it while
retaining the readable progress lines.

Reports record the runtime, CPU, platform, workload, measured core's SHA-256,
every latency sample, median and range, batch throughput, and the maximum lateness
of a 5 ms timer. Call latency includes the normal API boundary, cooperative
scheduling, and memory cleanup. Correctness checks and the final timer observation
are excluded. The first batch is also recorded separately; CLI startup is not timed.

## CPU profiles

```sh
node --cpu-prof --cpu-prof-dir=bench/argon2/results \
  bench/argon2/benchmark.ts --source --backend typescript --algorithm argon2id
```

Open the resulting `.cpuprofile` in a JavaScript CPU-profile viewer. Profiles are
ignored by Git; result reports can be committed to document backend comparisons.

## TypeScript versus WASM

Measured on an AMD Ryzen 9 3900X at the default workload: 64 MiB, three passes,
four lanes, and 32 output bytes. Values are medians of five calls after two
warm-ups. The ratio is TypeScript time divided by WASM time.

| Runtime       | Variant  | TypeScript |   WASM | TS / WASM |
| ------------- | -------- | ---------: | -----: | --------: |
| Node v26.12.0 | argon2id |    1213 ms | 182 ms |     6.66× |
| Node v26.12.0 | argon2i  |    1227 ms | 183 ms |     6.72× |
| Node v26.12.0 | argon2d  |    1208 ms | 181 ms |     6.68× |
| Bun 1.4.4     | argon2id |    1011 ms | 171 ms |     5.93× |
| Bun 1.4.4     | argon2i  |    1025 ms | 175 ms |     5.86× |
| Bun 1.4.4     | argon2d  |    1009 ms | 171 ms |     5.89× |

Reports: [Node](results/optimized-node.json) and [Bun](results/optimized-bun.json).
