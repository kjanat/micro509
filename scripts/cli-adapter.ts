import { writeSync } from 'node:fs';
import type { RuntimeAdapter } from 'dreamcli/runtime';
import { createAdapter } from 'dreamcli/runtime';

/** Bun drops queued pipe writes on `process.exit` (https://github.com/kjanat/dreamcli/issues/141). */
export function synchronousAdapter(): RuntimeAdapter {
	return {
		...createAdapter(),
		stdout: (data) => {
			writeSync(1, data);
		},
		stderr: (data) => {
			writeSync(2, data);
		},
	};
}
