import { argon2 } from 'node:crypto';
import { promisify } from 'node:util';
import { parentPort } from 'node:worker_threads';

parentPort?.once(
	'message',
	/** @param {import('#micro509/kdf').Argon2Input} input */ async (input) => {
		try {
			const output = await promisify(argon2)(input.algorithm, {
				message: input.password,
				nonce: input.salt,
				memory: input.memoryKiB,
				passes: input.passes,
				parallelism: input.parallelism,
				tagLength: input.outputBytes,
				secret: input.secret,
				associatedData: input.associatedData,
			});
			parentPort?.postMessage(new Uint8Array(output));
			output.fill(0);
		} finally {
			input.password.fill(0);
			input.salt.fill(0);
			input.secret?.fill(0);
			input.associatedData?.fill(0);
		}
	},
);
