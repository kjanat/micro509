import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'bun:test';
import { checkChainRevocation, parseCertificateDer } from 'micro509';

async function loadPkitsCert(name: string) {
	const der = await readFile(
		new URL(`./fixtures/pkits/certs/${name}.crt`, import.meta.url),
	);
	return parseCertificateDer(new Uint8Array(der));
}

describe('checkChainRevocation', () => {
	it('returns allow for empty chain', async () => {
		const result = await checkChainRevocation({ chain: [] });

		expect(result.ok).toBe(true);
		expect(result.value.decision).toBe('allow');
		expect(result.value.certificates).toEqual([]);
		expect(result.value.summary.revokedCertificates).toEqual([]);
		expect(result.value.summary.indeterminateCertificates).toEqual([]);
	});

	it('skips trust anchor (last cert in chain)', async () => {
		const root = await loadPkitsCert('TrustAnchorRootCertificate');
		const result = await checkChainRevocation({ chain: [root] });

		expect(result.ok).toBe(true);
		// Trust anchor not checked — returns allow with empty certificates
		expect(result.value.decision).toBe('allow');
		expect(result.value.certificates).toHaveLength(0);
	});

	it('returns indeterminate for non-anchor certs without evidence', async () => {
		const root = await loadPkitsCert('TrustAnchorRootCertificate');
		const goodCa = await loadPkitsCert('GoodCACert');

		const result = await checkChainRevocation({ chain: [goodCa, root] });

		expect(result.ok).toBe(true);
		// No CRLs provided → indeterminate for goodCa, but soft-fail allows
		expect(result.value.certificates).toHaveLength(1);
		expect(result.value.certificates[0].status).toBe('indeterminate');
		expect(result.value.certificates[0].indeterminateReasons).toContain(
			'no_applicable_crl',
		);
		expect(result.value.decision).toBe('allow'); // soft-fail default
	});

	it('denies with hard-fail policy when indeterminate', async () => {
		const root = await loadPkitsCert('TrustAnchorRootCertificate');
		const goodCa = await loadPkitsCert('GoodCACert');

		const result = await checkChainRevocation({
			chain: [goodCa, root],
			policy: { mode: 'hard-fail' },
		});

		expect(result.ok).toBe(true);
		expect(result.value.decision).toBe('deny');
		expect(result.value.summary.indeterminateCertificates).toHaveLength(1);
	});
});
