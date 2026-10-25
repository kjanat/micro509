# Argon2 benchmarks

Compare the TypeScript implementation, reference WASM oracle, native
WebCrypto, and `node:crypto.argon2` under Node and Bun. Every result is checked
against `node:crypto.argon2Sync` outside the measured interval. Errors and
mismatched keys fail the command; unsupported backends are reported explicitly.

```sh
bun run build
bun run build:argon2
bun run bench:argon2 --output bench/argon2/results/node.json
bun --bun bench/argon2/benchmark.ts --output bench/argon2/results/bun.json
```

Defaults match the guide: all three variants at version `0x13`, 64 MiB, three
passes, four lanes, and a 32-byte output. Each backend gets two warm-up batches
followed by five measured batches, with one derivation per batch. Each backend/workload runs in a fresh process, sequentially. Run
runtimes sequentially to avoid competing for CPU and memory bandwidth.

For a focused iteration on the source:

```sh
bun run bench:argon2 --source --backend typescript --algorithm argon2id
```

All workload controls are explicit: `--memory-kib`, `--passes`, `--lanes`,
`--output-bytes`, `--warmups`, `--samples`, and `--concurrency`. Use `--help` for
their ranges. `--json` prints the complete report; `--output` saves it while
retaining the readable progress lines.

Reports record the runtime, CPU, platform, workload, SHA-256 hashes of the Argon2 modules,
every latency sample, median and range, batch throughput, and the maximum lateness
of a 5 ms timer. They also record baseline RSS before warm-ups and
`sampledPeakRssMiB`: RSS sampled every 5 ms and at batch boundaries during warm-ups
and measured calls. This measures the worker process, including its runtime and
loaded modules. Peaks between observations can be missed. The report records
`rssSamplingIntervalMs` alongside the workload.

The native reference key is computed in the parent. Sampling the worker
RSS avoids the inherited parent peak that Linux can include in
`process.resourceUsage().maxRSS`.
Call latency includes the normal API boundary, cooperative
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

| Runtime       | Variant  | TypeScript |   WASM | TS / WASM | TS sampled RSS peak | WASM sampled RSS peak |
| ------------- | -------- | ---------: | -----: | --------: | ------------------: | --------------------: |
| Node v26.12.0 | argon2id |    1189 ms | 178 ms |     6.69× |           154.7 MiB |             152.0 MiB |
| Node v26.12.0 | argon2i  |    1200 ms | 179 ms |     6.72× |           154.4 MiB |             152.2 MiB |
| Node v26.12.0 | argon2d  |    1186 ms | 181 ms |     6.55× |           155.0 MiB |             151.7 MiB |
| Bun 1.4.4     | argon2id |     880 ms | 171 ms |     5.15× |           142.9 MiB |             110.9 MiB |
| Bun 1.4.4     | argon2i  |     886 ms | 172 ms |     5.15× |           143.3 MiB |             110.9 MiB |
| Bun 1.4.4     | argon2d  |     877 ms | 169 ms |     5.18× |           142.3 MiB |             110.2 MiB |

Reports: [Node](results/node.json) and [Bun](results/bun.json).
