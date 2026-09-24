import type { RuntimeAdapter } from 'dreamcli/runtime';
import { createAdapter, ExitError } from 'dreamcli/runtime';

/** `process.exit` drops stdout still queued for a pipe (https://github.com/kjanat/dreamcli/issues/141). */
export function deferredExitAdapter(): RuntimeAdapter {
	return {
		...createAdapter(),
		exit: (code) => {
			throw new ExitError(code);
		},
	};
}

export async function runUntilDrained(running: Promise<never>): Promise<void> {
	try {
		await running;
	} catch (error) {
		if (!(error instanceof ExitError)) throw error;
		process.exitCode = error.code;
	}
}
