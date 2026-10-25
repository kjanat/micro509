/**
 * Public test inputs, not application credentials.
 * RFC 9106 sections 5.1 and 5.3 include secret and associated data.
 * @module
 */

/** @type {readonly {input: import('#micro509/kdf').Argon2Input, expected: string}[]} */
export const rfc9106Vectors = [
	{
		input: {
			algorithm: 'argon2d',
			version: 0x13,
			password: new Uint8Array(32).fill(1),
			salt: new Uint8Array(16).fill(2),
			secret: new Uint8Array(8).fill(3),
			associatedData: new Uint8Array(12).fill(4),
			memoryKiB: 32,
			passes: 3,
			parallelism: 4,
			outputBytes: 32,
		},
		expected: '512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb',
	},
	{
		input: {
			algorithm: 'argon2id',
			version: 0x13,
			password: new Uint8Array(32).fill(1),
			salt: new Uint8Array(16).fill(2),
			secret: new Uint8Array(8).fill(3),
			associatedData: new Uint8Array(12).fill(4),
			memoryKiB: 32,
			passes: 3,
			parallelism: 4,
			outputBytes: 32,
		},
		expected: '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659',
	},
];
