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
ignored by Git; result reports can be committed for before/after comparisons.

## Baseline

`results/baseline-2026-10-25.jsonl` preserves the initial comparison on an AMD
Ryzen 9 3900X with Node 26.12.0 and Bun 1.4.4. At the default workload, warmed
TypeScript medians were 2.62–2.64 seconds on Node and 2.48–2.51 seconds on Bun;
WASM medians were 179–183 ms and 172–173 ms respectively. Those results use the
original JSONL report layout and two warm-ups plus five samples per backend.

This replaces the former `scripts/benchmark-argon2.mjs` command.

## Optimized TypeScript results

Same host and default workload; medians of five calls after two warm-ups.

| Runtime       | Variant  | Baseline | Optimized | Less time |
| ------------- | -------- | -------: | --------: | --------: |
| Node v26.12.0 | argon2id |  2617 ms |   1596 ms |     39.0% |
| Node v26.12.0 | argon2i  |  2643 ms |   1612 ms |     39.0% |
| Node v26.12.0 | argon2d  |  2617 ms |   1592 ms |     39.2% |
| Bun 1.4.4     | argon2id |  2493 ms |   1541 ms |     38.2% |
| Bun 1.4.4     | argon2i  |  2512 ms |   1553 ms |     38.2% |
| Bun 1.4.4     | argon2d  |  2483 ms |   1542 ms |     37.9% |

Reports: [Node](results/optimized-node.json) and [Bun](results/optimized-bun.json).

The core keeps mixing registers in local variables, precomputes the row/column
mixing schedule, and uses exact 32-bit partial products for reference indexing.
The workload, yield frequency, and buffer cleanup are unchanged.
