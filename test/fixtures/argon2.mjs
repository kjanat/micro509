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

/** Independent libargon2 vectors, also used by every built-runtime smoke. */
export const libargon2Vectors = /** @type {const} */ ([
	['argon2d', 0x10, 'c9da08c31fa64957a1bf63d30cc881474775ce827bc61b0128e5d07119c1e54a'],
	['argon2id', 0x10, '190432db4cacd25d7f023c4eee4ccfa1ccd31e499daecd434e07aa005315edd1'],
	['argon2d', 0x13, 'fa50b00aee2c79eb02a575fd1b54c8d3956b0c5ddfc6db886e2bda9e738e597d'],
	['argon2id', 0x13, 'cb88616cdd8e3cd798580402fc2a39cccbb66568ae01f140a358d7fc5e5a210a'],
]).map(([algorithm, version, expected]) => ({
	input: {
		algorithm,
		version,
		password: new TextEncoder().encode('password'),
		salt: new TextEncoder().encode('salt1234'),
		memoryKiB: 32,
		passes: 2,
		parallelism: 2,
		outputBytes: 32,
	},
	expected,
}));

/**
 * Equivalent JavaScript representations of one declared input record.
 * @param {import('#micro509/kdf').Argon2Input} input
 * @returns {readonly {name: string, input: unknown}[]}
 */
export function inputRepresentations(input) {
	const entries = Object.entries(input);
	const { algorithm, ...otherFields } = input;
	return [
		{
			name: 'inherited algorithm',
			input: Object.assign(Object.create({ algorithm }), otherFields),
		},
		{
			name: 'non-enumerable algorithm',
			input: Object.defineProperty(otherFields, 'algorithm', { value: algorithm }),
		},
		{ name: 'inherited', input: Object.create(input) },
		{
			name: 'non-enumerable',
			input: Object.create(
				null,
				Object.fromEntries(entries.map(([key, value]) => [key, { value }])),
			),
		},
		{
			name: 'getters',
			input: Object.create(
				null,
				Object.fromEntries(entries.map(([key, value]) => [key, { get: () => value }])),
			),
		},
	];
}

/**
 * Accessors change after their first read, including the algorithm and resource costs.
 * @param {import('#micro509/kdf').Argon2Input} input
 * @returns {{input: unknown, reads: Map<string, number>}}
 */
export function changingInput(input) {
	const reads = new Map();
	return {
		reads,
		input: Object.create(
			null,
			Object.fromEntries(
				Object.entries(input).map(([key, value]) => [
					key,
					{
						enumerable: true,
						get() {
							const count = (reads.get(key) ?? 0) + 1;
							reads.set(key, count);
							return count === 1 ? value : key === 'algorithm' ? 'argon2d' : 0;
						},
					},
				]),
			),
		),
	};
}
