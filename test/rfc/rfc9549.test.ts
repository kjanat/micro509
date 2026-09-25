import { describe, expect, it } from 'bun:test';
import {
	createCertificate,
	createSelfSignedCertificate,
	generateKeyPair,
	isResultError,
	matchServiceIdentity,
	parseCertificateDerOrThrow,
	type SubjectAltName,
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

	it('applies caller-supplied initial DNS and mail constraints written with U-labels as A-labels', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'RFC 9549 Root' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const leafFor = async (subjectAltNames: readonly SubjectAltName[]) => {
			const keys = await generateKeyPair();
			return (
				await createCertificate({
					issuer: { commonName: 'RFC 9549 Root' },
					subject: { commonName: 'rfc9549-leaf' },
					publicKey: keys.publicKey,
					signerPrivateKey: root.keyPair.privateKey,
					issuerPublicKey: root.keyPair.publicKey,
					extensions: { subjectAltNames },
				})
			).der;
		};
		for (const [type, san] of [
			['dns', { type: 'dns', value: 'www.xn--bcher-kva.example' }],
			['email', { type: 'email', value: 'user@mail.xn--bcher-kva.example' }],
		] as const) {
			const result = await verifyCertificateChain({
				leaf: await leafFor([san]),
				roots: [root.certificate.der],
				nameConstraints: { excludedSubtrees: [{ base: { type, value: '.bücher.example' } }] },
			});
			expect(result).toMatchObject({ ok: false, code: 'name_constraints_violated' });
		}
	});

	it('refuses caller-supplied initial constraints that are not valid IDNA2008, and U-label URI constraints', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'RFC 9549 Root' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		for (const base of [
			{ type: 'dns', value: '\u265a.example' },
			{ type: 'email', value: 'xn--45h.example' },
			{ type: 'uri', value: 'bücher.example' },
		] as const) {
			const result = await verifyCertificateChain({
				leaf: root.certificate.der,
				roots: [root.certificate.der],
				allowSelfSignedLeaf: true,
				nameConstraints: { excludedSubtrees: [{ base }] },
			});
			expect(result).toMatchObject({ ok: false, code: 'unsupported_initial_name_constraints' });
		}
	});
});

describe('RFC 9549 §2.2 (replacing part of RFC 5280 §4.2.1.10): mail constraints name a host or a domain', () => {
	it('prints the sentences this suite relies on', () => {
		expect(rfc9549).toContain(
			'A name constraint for Internet mail addresses MAY specify all addresses at a particular host or all mailboxes in a domain.',
		);
	});

	it('refuses to build an rfc822Name constraint that names a mailbox', async () => {
		const error = await createSelfSignedCertificate({
			subject: { commonName: 'RFC 9549 Mailbox Constraint' },
			extensions: {
				basicConstraints: { ca: true },
				keyUsage: ['keyCertSign', 'cRLSign'],
				nameConstraints: {
					permittedSubtrees: [{ base: { type: 'email', value: 'root@example.com' } }],
				},
			},
		}).then(
			() => undefined,
			(caught: unknown) => (isResultError(caught) ? caught.code : undefined),
		);
		expect(error).toBe('email_name_constraint_names_mailbox');
	});

	it('refuses a caller-supplied initial rfc822Name constraint that names a mailbox', async () => {
		const root = await createSelfSignedCertificate({
			subject: { commonName: 'RFC 9549 Root' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		const result = await verifyCertificateChain({
			leaf: root.certificate.der,
			roots: [root.certificate.der],
			allowSelfSignedLeaf: true,
			nameConstraints: {
				permittedSubtrees: [{ base: { type: 'email', value: 'root@example.com' } }],
			},
		});
		expect(result).toMatchObject({ ok: false, code: 'unsupported_initial_name_constraints' });
	});
});
