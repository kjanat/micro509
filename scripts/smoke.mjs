// Runtime smoke test against the built dist output.
// Runs under Node (`node scripts/smoke.mjs`) and Deno (`deno run scripts/smoke.mjs`)
// to back the multi-runtime support claim with executable evidence.

import { runSmoke } from './smoke-core.mjs';

const m = await import(new URL('../dist/index.js', import.meta.url).href);

// Deno 2 also exposes the `process` global; the CI step name identifies the runtime.
console.log(`${await runSmoke(m)} (${process.version})`);
