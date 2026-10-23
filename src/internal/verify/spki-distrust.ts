/** Caller-supplied SHA-256 SPKI distrust, scoped to one verification operation. */
import { toArrayBuffer, toHex } from '#micro509/internal/asn1/asn1';
import { getCrypto } from '#micro509/internal/crypto/webcrypto';

/** Validates and snapshots the caller's hashes before any asynchronous work. */
export function createSpkiDistrustCheck(
	hashes: readonly string[] | undefined,
): (spki: Uint8Array) => Promise<string | undefined> {
	const blocked = new Set<string>();
	for (const hash of hashes ?? []) {
		if (typeof hash !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hash)) {
			throw new RangeError('distrustedSpkiSha256 entries must be 64 hexadecimal characters');
		}
		blocked.add(hash.toLowerCase());
	}
	const digests = new Map<string, Promise<string>>();
	return async (spki) => {
		if (blocked.size === 0) return undefined;
		const key = toHex(spki);
		let digest = digests.get(key);
		if (digest === undefined) {
			digest = getCrypto()
				.subtle.digest('SHA-256', toArrayBuffer(spki))
				.then((bytes) => toHex(new Uint8Array(bytes)));
			digests.set(key, digest);
		}
		const hash = await digest;
		return blocked.has(hash) ? hash : undefined;
	};
}
