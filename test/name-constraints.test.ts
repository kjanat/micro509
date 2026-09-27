import { describe, expect, it } from 'bun:test';
import type { createSelfSignedCertificate } from '#micro509';
import { createCertificate, generateKeyPair, verifyCertificateChain } from '#micro509';
import {
	concatBytes,
	ia5String,
	objectIdentifier,
	printableString,
	sequence,
	setOf,
	tlv,
	utf8String,
} from '#micro509/internal/asn1/der';
import { OIDS } from '#micro509/internal/asn1/oids';
import {
	createSelfSignedCertificateWithRawExtensions,
	legacyMailboxNameConstraints,
} from '#test/helpers';

type TestDnStringEncoding = 'printable' | 'utf8' | 'teletex';
type DirectoryNameAttribute = {
	readonly oid: string;
	readonly value: string;
	readonly encoding: TestDnStringEncoding;
};
type CreateCertificateInput = Parameters<typeof createCertificate>[0];
type CreateSelfSignedCertificateInput = Parameters<typeof createSelfSignedCertificate>[0];
type NameConstraintsInput = NonNullable<
	NonNullable<CreateSelfSignedCertificateInput['extensions']>['nameConstraints']
>;
type LeafSubject = CreateCertificateInput['subject'];
type LeafSubjectAltNames = NonNullable<
	NonNullable<CreateCertificateInput['extensions']>['subjectAltNames']
>;
type ServiceIdentity = NonNullable<Parameters<typeof verifyCertificateChain>[0]['serviceIdentity']>;

function encodeDirectoryNameString(value: string, encoding: TestDnStringEncoding): Uint8Array {
	switch (encoding) {
		case 'printable':
			return printableString(value);
		case 'utf8':
			return utf8String(value);
		case 'teletex':
			return tlv(
				0x14,
				Uint8Array.from(value, (character) => character.charCodeAt(0)),
			);
	}
}

function buildDirectoryNameDerHex(rdns: readonly (readonly DirectoryNameAttribute[])[]): string {
	const encoded = sequence(
		rdns.map((rdn) =>
			setOf(
				rdn.map((attribute) =>
					sequence([
						objectIdentifier(attribute.oid),
						encodeDirectoryNameString(attribute.value, attribute.encoding),
					]),
				),
			),
		),
	);
	return Buffer.from(encoded).toString('hex');
}

async function verifyNameConstraintFixture(options: {
	readonly rootNameConstraints: NameConstraintsInput | Uint8Array;
	readonly leafSubject?: LeafSubject;
	readonly leafSubjectAltNames?: LeafSubjectAltNames;
	readonly serviceIdentity?: ServiceIdentity;
}) {
	const rootCommonName = 'Name Constraint Fixture Root';
	const constraints = options.rootNameConstraints;
	const root = await createSelfSignedCertificateWithRawExtensions({
		subject: { commonName: rootCommonName },
		extensions: {
			basicConstraints: { ca: true },
			keyUsage: ['keyCertSign', 'cRLSign'],
			...(constraints instanceof Uint8Array
				? {
						customExtensions: [{ oid: OIDS.nameConstraints, value: constraints, critical: true }],
					}
				: { nameConstraints: constraints }),
		},
	});
	const leafKeys = await generateKeyPair();
	const leafExtensions =
		options.leafSubjectAltNames === undefined
			? ({
					keyUsage: ['digitalSignature'],
				} satisfies NonNullable<CreateCertificateInput['extensions']>)
			: ({
					keyUsage: ['digitalSignature'],
					subjectAltNames: options.leafSubjectAltNames,
				} satisfies NonNullable<CreateCertificateInput['extensions']>);
	const leaf = await createCertificate({
		issuer: { commonName: rootCommonName },
		subject: options.leafSubject ?? { commonName: 'fixture-leaf' },
		publicKey: leafKeys.publicKey,
		signerPrivateKey: root.keyPair.privateKey,
		issuerPublicKey: root.keyPair.publicKey,
		extensions: leafExtensions,
	});
	return await verifyCertificateChain({
		leaf: leaf.pem,
		roots: [root.certificate.pem],
		...(options.serviceIdentity === undefined ? {} : { serviceIdentity: options.serviceIdentity }),
	});
}

function rawUriNameConstraints(kind: 'permitted' | 'excluded', value: string): Uint8Array {
	return sequence([
		tlv(kind === 'permitted' ? 0xa0 : 0xa1, sequence([tlv(0x86, new TextEncoder().encode(value))])),
	]);
}

describe('name constraint fixtures', () => {
	it('covers DNS permitted and excluded subtrees', async () => {
		const permitted = await verifyNameConstraintFixture({
			rootNameConstraints: {
				permittedSubtrees: [{ base: { type: 'dns', value: '.example.com' } }],
			},
			leafSubjectAltNames: [{ type: 'dns', value: 'api.example.com' }],
		});
		expect(permitted).toMatchObject({ ok: true });

		const excluded = await verifyNameConstraintFixture({
			rootNameConstraints: {
				excludedSubtrees: [{ base: { type: 'dns', value: '.example.com' } }],
			},
			leafSubjectAltNames: [{ type: 'dns', value: 'api.example.com' }],
		});
		expect(excluded).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});

	it.each([
		['.example.com', 'example.com', false],
		['.example.com', 'www.example.com', true],
		['.example.com', 'a.b.example.com', true],
		['.example.com', 'notexample.com', false],
		['.example.com', 'example.com.evil', false],
		['example.com', 'example.com', true],
		['example.com', 'www.example.com', true],
		['example.com', 'a.b.example.com', true],
		['example.com', 'notexample.com', false],
	] as const)('the dNSName constraint %s covers %s: %p', async (constraint, name, covered) => {
		const permitted = await verifyNameConstraintFixture({
			rootNameConstraints: { permittedSubtrees: [{ base: { type: 'dns', value: constraint } }] },
			leafSubjectAltNames: [{ type: 'dns', value: name }],
		});
		const excluded = await verifyNameConstraintFixture({
			rootNameConstraints: { excludedSubtrees: [{ base: { type: 'dns', value: constraint } }] },
			leafSubjectAltNames: [{ type: 'dns', value: name }],
		});
		const violated = { ok: false, code: 'name_constraints_violated' };
		expect(permitted).toMatchObject(covered ? { ok: true } : violated);
		expect(excluded).toMatchObject(covered ? violated : { ok: true });
	});

	it.each([
		['evil.example.com.', 0x82, 'dns', 'email'],
		['user@evil.example.com.', 0x81, 'email', 'dns'],
	] as const)(
		'fails a received name %s ending in the root dot while constraints of its type apply',
		async (value, tag, type, otherType) => {
			const leafSubjectAltNames = [
				{ type: 'unknown', tag, value: new TextEncoder().encode(value) },
			] as const;
			const excluded = await verifyNameConstraintFixture({
				rootNameConstraints: { excludedSubtrees: [{ base: { type, value: 'example.com' } }] },
				leafSubjectAltNames,
			});
			expect(excluded).toMatchObject({ ok: false, code: 'name_constraints_violated' });
			const permitted = await verifyNameConstraintFixture({
				rootNameConstraints: { permittedSubtrees: [{ base: { type, value: 'example.com' } }] },
				leafSubjectAltNames,
			});
			expect(permitted).toMatchObject({ ok: false, code: 'name_constraints_violated' });
			const unrelated = await verifyNameConstraintFixture({
				rootNameConstraints: {
					excludedSubtrees: [{ base: { type: otherType, value: 'example.com' } }],
				},
				leafSubjectAltNames,
			});
			expect(unrelated).toMatchObject({ ok: true });
		},
	);

	it('fails every name of a type while a dNSName or rfc822Name constraint of that type is malformed', async () => {
		const cases = [
			{
				constraint: rawExcludedDomainConstraint(0x82, '.example.com.'),
				san: { type: 'dns', value: 'host.example.com' },
			},
			{
				constraint: rawExcludedDomainConstraint(0x81, '.example.com.'),
				san: { type: 'email', value: 'user@host.example.com' },
			},
			{
				constraint: rawExcludedDomainConstraint(0x81, '.example.com.'),
				san: { type: 'smtpUtf8Mailbox', value: '用户@host.example.com' },
			},
			{
				constraint: { excludedSubtrees: [{ base: { type: 'dns', value: 'bad label.example' } }] },
				san: { type: 'dns', value: 'host.example.com' },
			},
		] as const;
		for (const { constraint, san } of cases) {
			const unrelated = await verifyNameConstraintFixture({
				rootNameConstraints: { excludedSubtrees: [{ base: { type: 'dns', value: 'other.test' } }] },
				leafSubjectAltNames: [san],
			});
			expect(unrelated).toMatchObject({ ok: true });
			const result = await verifyNameConstraintFixture({
				rootNameConstraints: constraint,
				leafSubjectAltNames: [san],
			});
			expect(result).toMatchObject({ ok: false, code: 'name_constraints_violated' });
		}
	});

	it('covers exact rfc822Name mailbox matching for a constraint issued before RFC 9549', async () => {
		const permitted = await verifyNameConstraintFixture({
			rootNameConstraints: legacyMailboxNameConstraints('permitted', 'user@example.com'),
			leafSubjectAltNames: [{ type: 'email', value: 'user@example.com' }],
		});
		expect(permitted).toMatchObject({ ok: true });

		const rejected = await verifyNameConstraintFixture({
			rootNameConstraints: legacyMailboxNameConstraints('permitted', 'user@example.com'),
			leafSubjectAltNames: [{ type: 'email', value: 'admin@example.com' }],
		});
		expect(rejected).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});

	it('covers URI host-subtree matching', async () => {
		const permitted = await verifyNameConstraintFixture({
			rootNameConstraints: {
				permittedSubtrees: [{ base: { type: 'uri', value: '.example.com' } }],
			},
			leafSubjectAltNames: [{ type: 'uri', value: 'https://www.example.com/app' }],
		});
		expect(permitted).toMatchObject({ ok: true });

		const rejected = await verifyNameConstraintFixture({
			rootNameConstraints: {
				permittedSubtrees: [{ base: { type: 'uri', value: '.example.com' } }],
			},
			leafSubjectAltNames: [{ type: 'uri', value: 'https://www.example.net/app' }],
		});
		expect(rejected).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});

	it('covers IPv4 subnet matching', async () => {
		const permitted = await verifyNameConstraintFixture({
			rootNameConstraints: {
				permittedSubtrees: [
					{
						base: {
							type: 'ip',
							addressBytes: Uint8Array.of(10, 0, 0, 0),
							maskBytes: Uint8Array.of(255, 0, 0, 0),
						},
					},
				],
			},
			leafSubjectAltNames: [{ type: 'ip', value: '10.1.2.3' }],
		});
		expect(permitted).toMatchObject({ ok: true });

		const rejected = await verifyNameConstraintFixture({
			rootNameConstraints: {
				permittedSubtrees: [
					{
						base: {
							type: 'ip',
							addressBytes: Uint8Array.of(10, 0, 0, 0),
							maskBytes: Uint8Array.of(255, 0, 0, 0),
						},
					},
				],
			},
			leafSubjectAltNames: [{ type: 'ip', value: '192.0.2.10' }],
		});
		expect(rejected).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});

	it('covers directoryName subject and SAN matching semantics', async () => {
		const constraintDerHex = buildDirectoryNameDerHex([
			[{ oid: OIDS.organizationName, value: 'allowed org', encoding: 'printable' }],
		]);
		const matchingSubject = await verifyNameConstraintFixture({
			rootNameConstraints: {
				permittedSubtrees: [{ base: { type: 'directoryName', derHex: constraintDerHex } }],
			},
			leafSubject: { organization: '  ALLOWED   ORG  ', commonName: 'fixture-leaf' },
			leafSubjectAltNames: [{ type: 'dns', value: 'fixture.example.com' }],
		});
		expect(matchingSubject).toMatchObject({ ok: true });

		const rejectedSan = await verifyNameConstraintFixture({
			rootNameConstraints: {
				excludedSubtrees: [{ base: { type: 'directoryName', derHex: constraintDerHex } }],
			},
			leafSubjectAltNames: [
				{
					type: 'directoryName',
					derHex: buildDirectoryNameDerHex([
						[{ oid: OIDS.organizationName, value: 'Allowed Org', encoding: 'utf8' }],
					]),
				},
			],
		});
		expect(rejectedSan).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});

	it('rejects a URI SAN without an FQDN authority under URI constraints', async () => {
		const ipv4 = await verifyNameConstraintFixture({
			rootNameConstraints: {
				excludedSubtrees: [{ base: { type: 'uri', value: '.example.com' } }],
			},
			leafSubjectAltNames: [{ type: 'uri', value: 'https://192.0.2.1/x' }],
		});
		expect(ipv4).toMatchObject({ ok: false, code: 'name_constraints_violated' });

		const ipv6 = await verifyNameConstraintFixture({
			rootNameConstraints: {
				permittedSubtrees: [{ base: { type: 'uri', value: '.example.com' } }],
			},
			leafSubjectAltNames: [{ type: 'uri', value: 'https://[2001:db8::1]/x' }],
		});
		expect(ipv6).toMatchObject({ ok: false, code: 'name_constraints_violated' });

		const noAuthority = await verifyNameConstraintFixture({
			rootNameConstraints: {
				permittedSubtrees: [{ base: { type: 'uri', value: '.example.com' } }],
			},
			leafSubjectAltNames: [{ type: 'uri', value: 'urn:example:resource' }],
		});
		expect(noAuthority).toMatchObject({ ok: false, code: 'name_constraints_violated' });

		const singleLabel = await verifyNameConstraintFixture({
			rootNameConstraints: {
				excludedSubtrees: [{ base: { type: 'uri', value: '.example.com' } }],
			},
			leafSubjectAltNames: [{ type: 'uri', value: 'https://localhost/x' }],
		});
		expect(singleLabel).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});

	it('accepts a non-FQDN URI SAN when no URI constraints apply', async () => {
		const result = await verifyNameConstraintFixture({
			rootNameConstraints: {
				permittedSubtrees: [{ base: { type: 'dns', value: '.example.com' } }],
			},
			leafSubjectAltNames: [
				{ type: 'dns', value: 'api.example.com' },
				{ type: 'uri', value: 'https://192.0.2.1/x' },
			],
		});
		expect(result).toMatchObject({ ok: true });
	});

	it('reads a URI SAN host by RFC 3986 §3.2.2 under an excluded host constraint', async () => {
		const rootNameConstraints: NameConstraintsInput = {
			excludedSubtrees: [{ base: { type: 'uri', value: 'blocked.example' } }],
		};
		for (const value of [
			'ldap://%62locked.example/',
			'https://blocked%2Eexample/',
			'https://blocked.example./',
			'https://BLOCKED.Example/',
			'https://user@blocked.example:8443/x',
		]) {
			const result = await verifyNameConstraintFixture({
				rootNameConstraints,
				leafSubjectAltNames: [{ type: 'uri', value }],
			});
			expect(result).toMatchObject({ ok: false, code: 'name_constraints_violated' });
		}
		for (const value of ['https://allowed.example/', 'https://www.blocked.example/']) {
			const result = await verifyNameConstraintFixture({
				rootNameConstraints,
				leafSubjectAltNames: [{ type: 'uri', value }],
			});
			expect(result).toMatchObject({ ok: true });
		}
	});

	it('keeps a leading-period URI constraint to subdomains', async () => {
		const rootNameConstraints: NameConstraintsInput = {
			excludedSubtrees: [{ base: { type: 'uri', value: '.blocked.example' } }],
		};
		const subdomain = await verifyNameConstraintFixture({
			rootNameConstraints,
			leafSubjectAltNames: [{ type: 'uri', value: 'https://www.blocked.example./' }],
		});
		expect(subdomain).toMatchObject({ ok: false, code: 'name_constraints_violated' });
		const domain = await verifyNameConstraintFixture({
			rootNameConstraints,
			leafSubjectAltNames: [{ type: 'uri', value: 'https://blocked.example/' }],
		});
		expect(domain).toMatchObject({ ok: true });
	});

	it('rejects a URI SAN whose reg-name is not a domain name under URI constraints', async () => {
		for (const [rootNameConstraints, value] of [
			[
				{ excludedSubtrees: [{ base: { type: 'uri', value: 'blocked.example' } }] },
				'https://blocked.example;extra/',
			],
			[
				{ excludedSubtrees: [{ base: { type: 'uri', value: '.blocked.example' } }] },
				'https://*.blocked.example/',
			],
			[
				{ permittedSubtrees: [{ base: { type: 'uri', value: '.example.com' } }] },
				'https://www.example.com%3Bx/',
			],
			[
				{ permittedSubtrees: [{ base: { type: 'uri', value: '.example.com' } }] },
				'https://www.example..com/',
			],
			[
				{ permittedSubtrees: [{ base: { type: 'uri', value: '.example' } }] },
				'https://b%C3%BCcher.example/',
			],
		] as const) {
			const result = await verifyNameConstraintFixture({
				rootNameConstraints,
				leafSubjectAltNames: [{ type: 'uri', value }],
			});
			expect(result).toMatchObject({ ok: false, code: 'name_constraints_violated' });
		}
	});

	it('rejects the chain before matching a URI-ID whose host an excluded URI constraint covers', async () => {
		const leafSubjectAltNames: LeafSubjectAltNames = [
			{ type: 'uri', value: 'ldap://%62locked.example/' },
		];
		const serviceIdentity: ServiceIdentity = { type: 'uri', value: 'ldap://blocked.example/' };
		const unconstrained = await verifyNameConstraintFixture({
			rootNameConstraints: {
				excludedSubtrees: [{ base: { type: 'uri', value: 'other.example' } }],
			},
			leafSubjectAltNames,
			serviceIdentity,
		});
		expect(unconstrained).toMatchObject({ ok: true });
		const constrained = await verifyNameConstraintFixture({
			rootNameConstraints: {
				excludedSubtrees: [{ base: { type: 'uri', value: 'blocked.example' } }],
			},
			leafSubjectAltNames,
			serviceIdentity,
		});
		expect(constrained).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});

	it('rejects every URI SAN while a received URI constraint is not a domain name', async () => {
		for (const kind of ['permitted', 'excluded'] as const) {
			const uri = await verifyNameConstraintFixture({
				rootNameConstraints: rawUriNameConstraints(kind, 'https://blocked.example'),
				leafSubjectAltNames: [{ type: 'uri', value: 'https://blocked.example/' }],
			});
			expect(uri).toMatchObject({ ok: false, code: 'name_constraints_violated' });
			const dns = await verifyNameConstraintFixture({
				rootNameConstraints: rawUriNameConstraints(kind, 'https://blocked.example'),
				leafSubjectAltNames: [{ type: 'dns', value: 'blocked.example' }],
			});
			expect(dns).toMatchObject({ ok: true });
		}
	});

	it('returns unsupported for a directoryName constraint holding an unsupported TeletexString octet', async () => {
		const derHex = Buffer.from(
			sequence([
				setOf([
					sequence([objectIdentifier(OIDS.organizationName), tlv(0x14, Uint8Array.of(0x41, 0x80))]),
				]),
			]),
		).toString('hex');
		for (const kind of ['permittedSubtrees', 'excludedSubtrees'] as const) {
			const result = await verifyNameConstraintFixture({
				rootNameConstraints: { [kind]: [{ base: { type: 'directoryName', derHex } }] },
				leafSubject: { commonName: 'fixture-leaf', organization: 'A' },
			});
			expect(result).toMatchObject({ ok: false, code: 'unsupported', index: 0 });
		}
	});

	it('refuses an initial URI constraint that is not a domain name', async () => {
		const root = await createSelfSignedCertificateWithRawExtensions({
			subject: { commonName: 'Initial URI Constraint Root' },
			extensions: { basicConstraints: { ca: true }, keyUsage: ['keyCertSign', 'cRLSign'] },
		});
		for (const value of [
			'https://blocked.example',
			'blocked.example/',
			'*.example.com',
			'192.0.2.1',
		]) {
			const result = await verifyCertificateChain({
				leaf: root.certificate.pem,
				roots: [root.certificate.pem],
				allowSelfSignedLeaf: true,
				nameConstraints: { excludedSubtrees: [{ base: { type: 'uri', value } }] },
			});
			expect(result).toMatchObject({ ok: false, code: 'unsupported_initial_name_constraints' });
		}
	});

	it('matches rfc822Name local-part case-sensitively and host case-insensitively', async () => {
		const localMismatch = await verifyNameConstraintFixture({
			rootNameConstraints: legacyMailboxNameConstraints('permitted', 'admin@example.com'),
			leafSubjectAltNames: [{ type: 'email', value: 'ADMIN@example.com' }],
		});
		expect(localMismatch).toMatchObject({ ok: false, code: 'name_constraints_violated' });

		const hostCaseFold = await verifyNameConstraintFixture({
			rootNameConstraints: legacyMailboxNameConstraints('permitted', 'admin@example.com'),
			leafSubjectAltNames: [{ type: 'email', value: 'admin@EXAMPLE.com' }],
		});
		expect(hostCaseFold).toMatchObject({ ok: true });
	});

	// RFC 5280 §7.1 matches attributes after RFC 4518 preparation, which
	// transcodes a TeletexString (§2.1) before the remaining steps, so a
	// constraint and a name need not share a DirectoryString encoding.
	it('matches directoryName constraints across TeletexString and UTF8String encodings', async () => {
		const excludedUtf8 = await verifyNameConstraintFixture({
			rootNameConstraints: {
				excludedSubtrees: [
					{
						base: {
							type: 'directoryName',
							derHex: buildDirectoryNameDerHex([
								[{ oid: OIDS.organizationName, value: 'Blocked Org', encoding: 'utf8' }],
							]),
						},
					},
				],
			},
			leafSubjectAltNames: [
				{
					type: 'directoryName',
					derHex: buildDirectoryNameDerHex([
						[{ oid: OIDS.organizationName, value: 'Blocked Org', encoding: 'teletex' }],
					]),
				},
			],
		});
		expect(excludedUtf8).toMatchObject({ ok: false, code: 'name_constraints_violated' });

		const excludedTeletex = await verifyNameConstraintFixture({
			rootNameConstraints: {
				excludedSubtrees: [
					{
						base: {
							type: 'directoryName',
							derHex: buildDirectoryNameDerHex([
								[{ oid: OIDS.organizationName, value: 'Blocked Org', encoding: 'teletex' }],
							]),
						},
					},
				],
			},
			leafSubject: { organization: 'Blocked Org', commonName: 'fixture-leaf' },
		});
		expect(excludedTeletex).toMatchObject({ ok: false, code: 'name_constraints_violated' });

		const caseAndSpaces = await verifyNameConstraintFixture({
			rootNameConstraints: {
				excludedSubtrees: [
					{
						base: {
							type: 'directoryName',
							derHex: buildDirectoryNameDerHex([
								[{ oid: OIDS.organizationName, value: 'Blocked Org', encoding: 'teletex' }],
							]),
						},
					},
				],
			},
			leafSubjectAltNames: [
				{
					type: 'directoryName',
					derHex: buildDirectoryNameDerHex([
						[{ oid: OIDS.organizationName, value: '  BLOCKED   ORG  ', encoding: 'teletex' }],
					]),
				},
			],
		});
		expect(caseAndSpaces).toMatchObject({ ok: false, code: 'name_constraints_violated' });

		const permittedTeletex = await verifyNameConstraintFixture({
			rootNameConstraints: {
				permittedSubtrees: [
					{
						base: {
							type: 'directoryName',
							derHex: buildDirectoryNameDerHex([
								[{ oid: OIDS.organizationName, value: 'Allowed Org', encoding: 'teletex' }],
							]),
						},
					},
				],
			},
			leafSubject: { organization: '  allowed   ORG  ', commonName: 'fixture-leaf' },
		});
		expect(permittedTeletex).toMatchObject({ ok: true });
	});

	it('fails every subject DN while a directoryName constraint cannot be decoded', async () => {
		const undecodable = Buffer.from(
			sequence([
				setOf([
					sequence([objectIdentifier(OIDS.organizationName), tlv(0x02, Uint8Array.of(0x01))]),
				]),
			]),
		).toString('hex');
		const unrelated = await verifyNameConstraintFixture({
			rootNameConstraints: {
				excludedSubtrees: [
					{
						base: {
							type: 'directoryName',
							derHex: buildDirectoryNameDerHex([
								[{ oid: OIDS.organizationName, value: 'Other Org', encoding: 'utf8' }],
							]),
						},
					},
				],
			},
			leafSubject: { organization: 'Some Org', commonName: 'fixture-leaf' },
		});
		expect(unrelated).toMatchObject({ ok: true });
		const subject = await verifyNameConstraintFixture({
			rootNameConstraints: {
				excludedSubtrees: [{ base: { type: 'directoryName', derHex: undecodable } }],
			},
			leafSubject: { organization: 'Some Org', commonName: 'fixture-leaf' },
		});
		expect(subject).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});

	it.each([
		['excluded', 'Blocked', 'Blocked', false],
		['excluded', 'Blocked', 'Other', false],
		['excluded', 'Blocked', 'Other', false],
		['excluded', 'Blocked', 'Other', true],
		['permitted', 'Blocked', 'Blocked', false],
		['permitted', 'Blocked', 'Blocked', true],
	] as const)(
		'treats an RFC 4518 Undefined comparison as no permission: %s O=%s against subject O=%s validates %p',
		async (field, constraintValue, subjectValue, validates) => {
			const derHex = buildDirectoryNameDerHex([
				[{ oid: OIDS.organizationName, value: constraintValue, encoding: 'utf8' }],
			]);
			const subtrees = [{ base: { type: 'directoryName' as const, derHex } }];
			const result = await verifyNameConstraintFixture({
				rootNameConstraints:
					field === 'excluded' ? { excludedSubtrees: subtrees } : { permittedSubtrees: subtrees },
				leafSubject: { organization: subjectValue, commonName: 'fixture-leaf' },
			});
			expect(result).toMatchObject(
				validates ? { ok: true } : { ok: false, code: 'name_constraints_violated' },
			);
		},
	);

	it('cannot be bypassed by an ignorable code point in a directoryName SAN', async () => {
		const excludedDerHex = buildDirectoryNameDerHex([
			[{ oid: OIDS.organizationName, value: 'Acme', encoding: 'printable' }],
		]);
		// The leaf SAN organization carries a SOFT HYPHEN (U+00AD), which RFC 4518
		// maps to nothing, so it prepares to "acme" and the excluded subtree still
		// catches it.
		const softHyphen = String.fromCodePoint(0x00ad);
		const result = await verifyNameConstraintFixture({
			rootNameConstraints: {
				excludedSubtrees: [{ base: { type: 'directoryName', derHex: excludedDerHex } }],
			},
			leafSubjectAltNames: [
				{
					type: 'directoryName',
					derHex: buildDirectoryNameDerHex([
						[{ oid: OIDS.organizationName, value: `Ac${softHyphen}me`, encoding: 'utf8' }],
					]),
				},
			],
		});
		expect(result).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});
});

function rawExcludedDomainConstraint(tag: 0x81 | 0x82, value: string): Uint8Array {
	return sequence([tlv(0xa1, sequence([tlv(tag, new TextEncoder().encode(value))]))]);
}

function rawSrvNameConstraints(field: 0xa0 | 0xa1, restriction: string): Uint8Array {
	const srvName = tlv(
		0xa0,
		concatBytes([objectIdentifier(OIDS.idOnDnsSrv), tlv(0xa0, ia5String(restriction))]),
	);
	return sequence([tlv(field, sequence([srvName]))]);
}

describe('RFC 4985 §4 SRVName constraints', () => {
	it.each([
		['example.com', '_mail.example.com', true],
		['example.com', '_ntp.example.com', true],
		['example.com', '_mail.1.example.com', true],
		['example.com', '_mail.1example.com', false],
		['_mail', '_mail.example.com', true],
		['_mail', '_mail.1example.com', true],
		['_mail', '_ntp.example.com', false],
		['_mail.example.com', '_mail.example.com', true],
		['_mail.example.com', '_mail.1.example.com', true],
		['_mail.example.com', '_mail.1example.com', false],
		['_mail.example.com', '_ntp.example.com', false],
	] as const)('restriction %s against %s permits: %p', async (restriction, san, permits) => {
		const result = await verifyNameConstraintFixture({
			rootNameConstraints: { permittedSubtrees: [{ base: { type: 'srv', value: restriction } }] },
			leafSubjectAltNames: [{ type: 'srv', value: san }],
		});
		expect(result).toMatchObject(
			permits ? { ok: true } : { ok: false, code: 'name_constraints_violated' },
		);
	});

	it('rejects an SRVName inside an excluded restriction', async () => {
		const result = await verifyNameConstraintFixture({
			rootNameConstraints: { excludedSubtrees: [{ base: { type: 'srv', value: '_mail' } }] },
			leafSubjectAltNames: [{ type: 'srv', value: '_mail.example.com' }],
		});
		expect(result).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});

	it('matches the service and the Name case-insensitively', async () => {
		const result = await verifyNameConstraintFixture({
			rootNameConstraints: rawSrvNameConstraints(0xa0, '_MAIL.Example.COM'),
			leafSubjectAltNames: [{ type: 'srv', value: '_mail.mx.example.com' }],
		});
		expect(result).toMatchObject({ ok: true });
	});

	it.each([
		['example.com.', '_mail.example.com', true],
		['example.com', '_mail.example.com.', true],
		['example.com.', '_mail.1.example.com.', true],
		['_mail.example.com.', '_mail.example.com', true],
		['_mail.example.com', '_mail.example.com.', true],
		['example.com.', '_mail.1example.com.', false],
		['_mail.example.com.', '_ntp.example.com.', false],
	] as const)(
		'compares the absolute or relative restriction %s and SRVName %s by their labels, permits: %p',
		async (restriction, san, permits) => {
			const result = await verifyNameConstraintFixture({
				rootNameConstraints: { permittedSubtrees: [{ base: { type: 'srv', value: restriction } }] },
				leafSubjectAltNames: [{ type: 'srv', value: san }],
			});
			expect(result).toMatchObject(
				permits ? { ok: true } : { ok: false, code: 'name_constraints_violated' },
			);
		},
	);

	it.each([
		['example.com', '_mail.example.com.'],
		['example.com.', '_mail.example.com'],
		['_mail.example.com', '_mail.www.example.com.'],
	])(
		'the excluded restriction %s catches the SRVName %s across the root dot',
		async (restriction, san) => {
			const result = await verifyNameConstraintFixture({
				rootNameConstraints: { excludedSubtrees: [{ base: { type: 'srv', value: restriction } }] },
				leafSubjectAltNames: [{ type: 'srv', value: san }],
			});
			expect(result).toMatchObject({ ok: false, code: 'name_constraints_violated' });
		},
	);

	it('leaves SRVNames unconstrained by a dNSName constraint', async () => {
		// RFC 9525 §7.6: constraints apply only to the name forms they enumerate.
		const result = await verifyNameConstraintFixture({
			rootNameConstraints: { permittedSubtrees: [{ base: { type: 'dns', value: 'example.com' } }] },
			leafSubjectAltNames: [{ type: 'srv', value: '_mail.example.net' }],
		});
		expect(result).toMatchObject({ ok: true });
	});

	it.each(['.example.com', '_mail.', '_.example.com', '_mail..example.com'])(
		'fails every SRVName while the restriction %s is malformed',
		async (restriction) => {
			const result = await verifyNameConstraintFixture({
				rootNameConstraints: rawSrvNameConstraints(0xa1, restriction),
				leafSubjectAltNames: [{ type: 'srv', value: '_mail.example.com' }],
			});
			expect(result).toMatchObject({ ok: false, code: 'name_constraints_violated' });
		},
	);

	it('treats a received SRVName outside STD3 or RFC 6335 syntax as not _Service.Name', async () => {
		for (const presented of ['_mail.example_com', '_123.example.com', '_mail.-example.com']) {
			const result = await verifyNameConstraintFixture({
				rootNameConstraints: {
					permittedSubtrees: [{ base: { type: 'srv', value: 'example.com' } }],
				},
				leafSubjectAltNames: [
					{
						type: 'unknown',
						tag: 0xa0,
						value: concatBytes([
							objectIdentifier(OIDS.idOnDnsSrv),
							tlv(0xa0, ia5String(presented)),
						]),
					},
				],
			});
			expect(result).toMatchObject({ ok: false, code: 'name_constraints_violated' });
		}
	});

	it('fails every SRVName while a received restriction breaks STD3 or RFC 6335 syntax', async () => {
		for (const restriction of ['example_com', '_123', '_mail.example-.com']) {
			const result = await verifyNameConstraintFixture({
				rootNameConstraints: rawSrvNameConstraints(0xa1, restriction),
				leafSubjectAltNames: [{ type: 'srv', value: '_mail.example.com' }],
			});
			expect(result).toMatchObject({ ok: false, code: 'name_constraints_violated' });
		}
	});

	it('fails an SRVName that is not _Service.Name while SRVName constraints apply', async () => {
		const result = await verifyNameConstraintFixture({
			rootNameConstraints: { excludedSubtrees: [{ base: { type: 'srv', value: '_ntp' } }] },
			leafSubjectAltNames: [
				{
					type: 'unknown',
					tag: 0xa0,
					value: concatBytes([
						objectIdentifier(OIDS.idOnDnsSrv),
						tlv(0xa0, ia5String('mail.example.com')),
					]),
				},
			],
		});
		expect(result).toMatchObject({ ok: false, code: 'name_constraints_violated' });
	});
});
