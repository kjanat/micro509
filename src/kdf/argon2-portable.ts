import type { Argon2Input, Argon2Result } from '#micro509/kdf/argon2';
import { deriveArgon2TypeScript } from '#micro509/kdf/argon2-core';

/** Internal TypeScript backend; the public boundary validates inputs and limits. */
export async function portableArgon2(input: Argon2Input): Promise<Argon2Result> {
	const bytes =
		input.memoryKiB * 1024 +
		input.outputBytes +
		input.password.byteLength +
		input.salt.byteLength +
		(input.secret?.byteLength ?? 0) +
		(input.associatedData?.byteLength ?? 0);
	if (bytes >= 0x80000000) {
		return {
			ok: false,
			error: { code: 'unsupported', message: 'Request exceeds portable Argon2 address space' },
		};
	}
	return { ok: true, value: await deriveArgon2TypeScript(input) };
}
