#!/usr/bin/env -S timeout 30s bun

import { decodeObjectIdentifier, MAX_OID_SUBIDENTIFIER_OCTETS } from '#micro509/internal/asn1/asn1';

function oneArcOf(octets: number): Uint8Array {
	const contents = new Uint8Array(octets + 1);
	contents[0] = 0x2a;
	contents.fill(0xff, 1, octets);
	contents[octets] = 0x7f;
	return contents;
}

for (const octets of [MAX_OID_SUBIDENTIFIER_OCTETS, 1_000, 10_000, 100_000, 1_000_000]) {
	const contents = oneArcOf(octets);
	const started = performance.now();
	let outcome: string;
	try {
		outcome = `${decodeObjectIdentifier(contents).length} characters`;
	} catch (error) {
		outcome = error instanceof Error ? error.message : String(error);
	}
	console.log(
		`${octets} octets in one arc: ${(performance.now() - started).toFixed(3)} ms, ${outcome}`,
	);
}
