import { describe, expect, it } from 'bun:test';
import {
	createSelfSignedCertificate,
	matchServiceIdentity,
	parseCertificateDerOrThrow,
	verifyCertificateChain,
} from '#micro509';
import { flattenedText, rfcDir } from '#test/helpers';

const rfc9549 = (await flattenedText(`${rfcDir}/rfc9549.txt`)).replaceAll(' | ', ' ');

async function presenting(dnsName: string) {
	const issued = await createSelfSignedCertificate({
		subject: { commonName: 'rfc9549' },
		extensions: { subjectAltNames: [{ type: 'dns', value: dnsName }] },
	});
	return parseCertificateDerOrThrow(issued.certificate.der);
}

async function matches(presented: string, reference: string): Promise<boolean> {
	return matchServiceIdentity({
		certificate: await presenting(presented),
		serviceIdentity: { type: 'dns', value: reference },
	}).ok;
}

describe('RFC 9549 §2.3 (replacing RFC 5280 §7.2): DNS names compare by a case-insensitive exact match', () => {
	it('prints the sentences this suite relies on', () => {
		expect(rfc9549).toContain(
			'When comparing DNS names for equality, conforming implementations MUST perform a case-insensitive exact match on the entire DNS name.',
		);
	});

	it('ignores ASCII case in the presented name', async () => {
		expect(await matches('WWW.Example.COM', 'www.example.com')).toBe(true);
	});

	it('does not percent-decode a presented name', async () => {
		expect(await matches('a%62c.example', 'abc.example')).toBe(false);
	});

	it('does not read a presented name as an IPv4 address', async () => {
		expect(await matches('0x7f.0.0.1', '127.0.0.1')).toBe(false);
	});

	it('compares a presented A-label with its ASCII form only', async () => {
		expect(await matches('xn--bcher-kva.example', 'XN--BCHER-KVA.example')).toBe(true);
	});
});

describe('RFC 9549 §1: all IDNs are carried and processed as A-labels', () => {
	it('prints the sentences this suite relies on', () => {
		expect(rfc9549).toContain('Now, all IDNs are carried and processed as A-labels.');
	});

	it('refuses caller-supplied initial name constraints written with U-labels', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'RFC 9549 Root' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		for (const type of ['dns', 'email', 'uri'] as const) {
			const result = await verifyCertificateChain({
				leaf: root.certificate.der,
				roots: [root.certificate.der],
				allowSelfSignedLeaf: true,
				nameConstraints: { excludedSubtrees: [{ base: { type, value: 'bücher.example' } }] },
			});
			expect(result).toMatchObject({ ok: false, code: 'unsupported_initial_name_constraints' });
		}
	});
});
